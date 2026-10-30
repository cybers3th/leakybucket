"""Bounded, tenant-scoped connection and request lifecycle accounting."""
from dataclasses import dataclass, replace
from enum import Enum
import math
import threading
import time


class ConnectionRejected(RuntimeError):
    pass


class ConnectionState(str, Enum):
    NEW = 'new'
    ESTABLISHED = 'established'
    BLOCKED = 'blocked'


@dataclass
class ConnectionRecord:
    tenant: str
    connection_id: str
    peer: tuple[str, int]
    created_at: float
    last_seen: float
    state: ConnectionState = ConnectionState.NEW
    host: str = ''
    port: int = 0
    requests: int = 0
    in_flight: int = 0
    request_bytes: int = 0
    response_bytes: int = 0


class ConnTracker:
    def __init__(self, max_connections=1024, max_per_tenant=256, max_in_flight=16,
                 max_bytes=16_777_216, idle_timeout=60, max_lifetime=3600, clock=time.monotonic):
        if any(type(n) is not int or n <= 0 for n in
               (max_connections, max_per_tenant, max_in_flight, max_bytes)):
            raise ValueError('Connection limits must be positive integers')
        if any(type(n) not in {int, float} or not math.isfinite(n) or n <= 0
               for n in (idle_timeout, max_lifetime)):
            raise ValueError('Connection timeouts must be finite and positive')
        self.max_connections, self.max_per_tenant = max_connections, max_per_tenant
        self.max_in_flight, self.max_bytes = max_in_flight, max_bytes
        self.idle_timeout, self.max_lifetime, self.clock = idle_timeout, max_lifetime, clock
        self._records = {}
        self._requests = {}
        self._lock = threading.RLock()
        self._totals = dict(opened=0, closed=0, expired=0, blocked=0)

    def _expire(self):
        now = self.clock()
        for key, record in list(self._records.items()):
            if now - record.last_seen >= self.idle_timeout or now - record.created_at >= self.max_lifetime:
                self._remove(key)
                self._totals['expired'] += 1

    def _remove(self, key):
        self._records.pop(key, None)
        for flow in [flow for flow, owner in self._requests.items() if owner == key]:
            del self._requests[flow]

    def _get(self, tenant, connection_id):
        self._expire()
        record = self._records.get((tenant, connection_id))
        if record is None or record.state == ConnectionState.BLOCKED:
            raise ConnectionRejected('Unknown, expired, or blocked connection')
        return record

    def open(self, tenant, connection_id, peer):
        if not all(isinstance(value, str) and 1 <= len(value) <= 256 for value in (tenant, connection_id)):
            raise ValueError('Invalid connection identity')
        if (not isinstance(peer, tuple) or len(peer) < 2 or not isinstance(peer[0], str)
                or len(peer[0]) > 128 or type(peer[1]) is not int or not 0 <= peer[1] <= 65535):
            raise ValueError('Invalid connection peer')
        with self._lock:
            self._expire()
            key = (tenant, connection_id)
            if key in self._records:
                raise ConnectionRejected('Connection already tracked')
            if (len(self._records) >= self.max_connections
                    or sum(r.tenant == tenant for r in self._records.values()) >= self.max_per_tenant):
                raise ConnectionRejected('Connection capacity exhausted')
            now = self.clock()
            self._records[key] = ConnectionRecord(tenant, connection_id, peer[:2], now, now)
            self._totals['opened'] += 1
            return replace(self._records[key])

    def bind(self, tenant, connection_id, host, port):
        if (not isinstance(host, str) or not 1 <= len(host) <= 253
                or type(port) is not int or not 1 <= port <= 65535):
            raise ValueError('Invalid connection target')
        with self._lock:
            record = self._get(tenant, connection_id)
            if record.host and (record.host, record.port) != (host, port):
                self.block(tenant, connection_id)
                raise ConnectionRejected('Connection target changed')
            record.host, record.port, record.last_seen = host, port, self.clock()

    def establish(self, tenant, connection_id):
        with self._lock:
            record = self._get(tenant, connection_id)
            if not record.host:
                raise ConnectionRejected('Connection has no approved target')
            record.state = ConnectionState.ESTABLISHED
            record.last_seen = self.clock()

    def lookup(self, tenant, connection_id):
        with self._lock:
            return replace(self._get(tenant, connection_id))

    def begin(self, tenant, connection_id, flow_id):
        if not isinstance(flow_id, str) or not 1 <= len(flow_id) <= 256:
            raise ValueError('Invalid request identity')
        with self._lock:
            record = self._get(tenant, connection_id)
            key = (tenant, flow_id)
            if record.state != ConnectionState.ESTABLISHED:
                raise ConnectionRejected('TLS is not established')
            if key in self._requests or record.in_flight >= self.max_in_flight:
                raise ConnectionRejected('Request is duplicate or exceeds connection capacity')
            self._requests[key] = (tenant, connection_id)
            record.in_flight += 1
            record.requests += 1
            record.last_seen = self.clock()

    def account(self, tenant, connection_id, flow_id, direction, size):
        if direction not in {'request', 'response'} or type(size) is not int or size < 0:
            raise ValueError('Invalid byte accounting')
        with self._lock:
            record = self._get(tenant, connection_id)
            if self._requests.get((tenant, flow_id)) != (tenant, connection_id):
                raise ConnectionRejected('Request is not bound to this connection')
            if record.request_bytes + record.response_bytes + size > self.max_bytes:
                self.block(tenant, connection_id)
                raise ConnectionRejected('Connection byte budget exhausted')
            name = direction + '_bytes'
            setattr(record, name, getattr(record, name) + size)
            record.last_seen = self.clock()

    def finish(self, tenant, connection_id, flow_id):
        with self._lock:
            key = (tenant, flow_id)
            if self._requests.get(key) != (tenant, connection_id):
                return
            del self._requests[key]
            record = self._records.get((tenant, connection_id))
            if record:
                record.in_flight -= 1
                record.last_seen = self.clock()

    def block(self, tenant, connection_id):
        with self._lock:
            record = self._records.get((tenant, connection_id))
            if record and record.state != ConnectionState.BLOCKED:
                record.state = ConnectionState.BLOCKED
                self._totals['blocked'] += 1

    def close(self, tenant, connection_id):
        with self._lock:
            key = (tenant, connection_id)
            if key in self._records:
                self._remove(key)
                self._totals['closed'] += 1

    def snapshot(self):
        with self._lock:
            self._expire()
            return {**self._totals, 'active': len(self._records), 'in_flight': len(self._requests)}
