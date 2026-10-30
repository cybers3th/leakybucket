"""Parameterized, tenant-scoped SQLite and PostgreSQL trace storage."""
from __future__ import annotations

import json
import sqlite3
import threading
from pathlib import Path


class TraceStore:
    def __init__(self, location):
        self._lock = threading.Lock()
        self.postgres = location.startswith(('postgresql://', 'postgres://'))
        if self.postgres:
            import psycopg
            self.connection = psycopg.connect(location, autocommit=True, connect_timeout=5,
                                             options='-c statement_timeout=5000')
        else:
            if location != ':memory:':
                path = Path(location)
                path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
                path.touch(mode=0o600, exist_ok=True)
                if path.is_symlink() or not path.is_file() or path.stat().st_mode & 0o077:
                    raise ValueError('Trace database permissions must be 0600 or stricter')
            self.connection = sqlite3.connect(location, check_same_thread=False, timeout=5)
            self.connection.execute('PRAGMA journal_mode=WAL')
            self.connection.execute('PRAGMA synchronous=FULL')
        self._execute('CREATE TABLE IF NOT EXISTS lb_traces (id TEXT PRIMARY KEY, tenant TEXT NOT NULL, '
                      'model TEXT NOT NULL, started DOUBLE PRECISION NOT NULL, cost DOUBLE PRECISION, data TEXT NOT NULL, summary TEXT NOT NULL)')
        self._execute('CREATE INDEX IF NOT EXISTS lb_traces_query ON lb_traces (tenant, started, id)')

    def _execute(self, sql, params=(), fetch=False):
        if self.postgres:
            sql = sql.replace('?', '%s')
        with self._lock:
            with self.connection.cursor() if self.postgres else self.connection as context:
                cursor = context if self.postgres else self.connection.cursor()
                try:
                    cursor.execute(sql, params)
                    return cursor.fetchall() if fetch else None
                finally:
                    if not self.postgres:
                        cursor.close()

    def insert(self, trace):
        self._execute('INSERT INTO lb_traces (id, tenant, model, started, cost, data, summary) VALUES (?, ?, ?, ?, ?, ?, ?)',
                      (trace['id'], trace['tenant'], trace['model'], trace['started'], trace['cost_usd'],
                       json.dumps(trace, allow_nan=False, separators=(',', ':')),
                       json.dumps({k: v for k, v in trace.items() if k not in {'prompt', 'response', 'spans'}},
                                  allow_nan=False, separators=(',', ':'))))

    def query(self, tenant, *, model=None, since=0, until=253402300799, min_cost=None, limit=100, offset=0):
        sql = 'SELECT summary FROM lb_traces WHERE tenant = ? AND started >= ? AND started <= ?'
        params = [tenant, since, until]
        if model is not None:
            sql += ' AND model = ?'
            params.append(model)
        if min_cost is not None:
            sql += ' AND cost >= ?'
            params.append(min_cost)
        sql += ' ORDER BY started DESC, id DESC LIMIT ? OFFSET ?'
        params.extend((limit, offset))
        return [json.loads(row[0]) for row in self._execute(sql, params, fetch=True)]

    def get(self, tenant, trace_id):
        rows = self._execute('SELECT data FROM lb_traces WHERE tenant = ? AND id = ?', (tenant, trace_id), fetch=True)
        return json.loads(rows[0][0]) if rows else None

    def close(self):
        with self._lock:
            self.connection.close()
