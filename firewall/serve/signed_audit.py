"""Chain-hashed audit records authenticated with HMAC-SHA256.
Includes optional SIEM sinks and chain verification."""
from __future__ import annotations

import dataclasses
import enum
import hashlib
import hmac
import json
import os
import queue
import socket
import ssl
import sys
import threading
import time
import urllib.request
from pathlib import Path
from collections import deque

from firewall.core.audit import AuditLog
from typing import Any, TextIO

from firewall.core.events import SecurityEvent


def _canonical(obj: Any) -> str:
    """Deterministic JSON serialization for signing."""
    def _default(o):
        if dataclasses.is_dataclass(o): return dataclasses.asdict(o)
        if isinstance(o, enum.Enum): return o.value
        if isinstance(o, (set, tuple)): return list(o)
        if isinstance(o, bytes): return o.decode("utf-8", "replace")
        return str(o)
    return json.dumps(obj, default=_default, sort_keys=True, ensure_ascii=False,
                       separators=(",", ":"))


class SIEMSink:
    """Interface for SIEM shippers."""
    def ship(self, record: dict) -> None: ...


class SplunkHEC(SIEMSink):
    def __init__(self, url: str, token: str, verify_tls: bool = True):
        self.url = url.rstrip("/") + "/services/collector/event"
        self.token = token
        self.ctx = ssl.create_default_context()
        if not verify_tls:
            self.ctx.check_hostname = False
            self.ctx.verify_mode = ssl.CERT_NONE

    def ship(self, record: dict):
        body = json.dumps({"event": record, "sourcetype": "leakybucket"}).encode()
        req = urllib.request.Request(self.url, data=body, method="POST", headers={
            "Authorization": f"Splunk {self.token}",
            "Content-Type": "application/json",
        })
        urllib.request.urlopen(req, context=self.ctx, timeout=5).read()


class ElasticBulk(SIEMSink):
    def __init__(self, url: str, index: str, api_key: str | None = None, verify_tls: bool = True):
        self.url = url.rstrip("/") + f"/{index}/_bulk"
        self.index = index
        self.headers = {"Content-Type": "application/x-ndjson"}
        if api_key: self.headers["Authorization"] = f"ApiKey {api_key}"
        self.ctx = ssl.create_default_context()
        if not verify_tls:
            self.ctx.check_hostname = False
            self.ctx.verify_mode = ssl.CERT_NONE

    def ship(self, record: dict):
        body = (json.dumps({"index": {"_index": self.index}}) + "\n"
                 + json.dumps(record) + "\n").encode()
        req = urllib.request.Request(self.url, data=body, method="POST", headers=self.headers)
        urllib.request.urlopen(req, context=self.ctx, timeout=5).read()


class DatadogLogs(SIEMSink):
    def __init__(self, api_key: str, site: str = "datadoghq.com"):
        self.url = f"https://http-intake.logs.{site}/api/v2/logs"
        self.api_key = api_key

    def ship(self, record: dict):
        body = json.dumps([{"ddsource": "leakybucket", "service": "firewall",
                              "message": json.dumps(record)}]).encode()
        req = urllib.request.Request(self.url, data=body, method="POST", headers={
            "DD-API-KEY": self.api_key, "Content-Type": "application/json",
        })
        urllib.request.urlopen(req, timeout=5).read()


class SyslogUDP(SIEMSink):
    def __init__(self, host: str, port: int = 514, facility: int = 1,
                 hostname: str | None = None, app_name: str = "leakybucket"):
        self.host = host; self.port = port
        self.facility = facility
        self.hostname = hostname or socket.gethostname()
        self.app_name = app_name
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    def ship(self, record: dict):
        pri = self.facility * 8 + 6  # info
        ts = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        msg = f"<{pri}>1 {ts} {self.hostname} {self.app_name} - - - {json.dumps(record)}"
        self.sock.sendto(msg.encode()[:64000], (self.host, self.port))


class SignedAuditLog:
    def __init__(
        self,
        path: str | Path | None = None,
        key: bytes | None = None,
        key_id: str = "k1",
        echo: bool = False,
        siem: SIEMSink | None = None,
        async_ship: bool = True,
        max_records: int = 1000,
        include_sensitive_details: bool = False,
    ):
        if type(max_records) is not int or max_records < 1:
            raise ValueError("Audit retention must be a positive integer")
        if key is not None and (not isinstance(key, bytes) or len(key) < 32):
            raise ValueError("Audit HMAC keys must contain at least 32 bytes")
        if path and key is None:
            raise ValueError("Persistent signed audit requires an externally managed key")
        self.path = Path(path) if path else None
        self.echo = echo
        self.key = key if key is not None else os.urandom(32)
        self.key_id = key_id
        self._lock = threading.Lock()
        self._file: TextIO | None = None
        self._closed = False
        self._failed = False
        self.records = deque(maxlen=max_records)
        self._redactor = AuditLog(max_records=1, include_sensitive_details=include_sensitive_details)
        if self.path:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            descriptor = os.open(self.path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
            self._file = os.fdopen(descriptor, "a", encoding="utf-8")
            try:
                import fcntl
                fcntl.flock(self._file.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            except Exception:
                self._file.close()
                raise RuntimeError("Persistent audit requires an exclusive local file lock")
        try:
            self._prev_hash, self._sequence = self._recover_last_hash()
        except Exception:
            if self._file:
                self._file.close()
            raise
        self._anchor = self._prev_hash
        self.siem = siem
        self.async_ship = async_ship
        self._ship_q: queue.Queue = queue.Queue(maxsize=10_000)
        self._ship_stop = threading.Event()
        self._ship_thread = None
        self.ship_failures = 0
        if siem and async_ship:
            self._ship_thread = threading.Thread(target=self._ship_worker, daemon=True)
            self._ship_thread.start()

    def _recover_last_hash(self):
        previous = "0" * 64
        sequence = 0
        if self.path and self.path.exists():
            with self.path.open(encoding="utf-8") as source:
                for line in iter(lambda: source.readline(1_048_577), ""):
                    if len(line) > 1_048_576:
                        raise ValueError("Persisted audit record exceeds bounds")
                    record = json.loads(line)
                    ok, message = self._verify_record(record, previous)
                    if not ok or record.get("seq") != sequence:
                        raise ValueError("Invalid persisted audit chain: " + message)
                    previous = record["hash"]
                    sequence += 1
        return previous, sequence

    def _verify_record(self, record, previous):
        if not isinstance(record, dict) or record.get("prev_hash") != previous:
            return False, "previous hash mismatch"
        if record.get("key_id") != self.key_id:
            return False, "key identity mismatch"
        canonical = _canonical({k: v for k, v in record.items() if k not in {"hash", "sig"}})
        digest = hashlib.sha256(canonical.encode()).hexdigest()
        if not hmac.compare_digest(digest.encode(), str(record.get("hash", "")).encode()):
            return False, "hash mismatch"
        signature = hmac.new(self.key, digest.encode(), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(signature.encode(), str(record.get("sig", "")).encode()):
            return False, "signature mismatch"
        return True, "valid"

    @property
    def healthy(self):
        with self._lock:
            return not self._closed and not self._failed

    def write(self, event: SecurityEvent) -> dict:
        with self._lock:
            if self._closed or self._failed:
                raise RuntimeError("Audit log is closed or unhealthy")
            if self.siem and self.async_ship and self._ship_q.full():
                raise RuntimeError("Audit shipping queue exhausted")
            self._redactor.write(event)
            record = dict(self._redactor.records[-1])
            record.update(prev_hash=self._prev_hash, key_id=self.key_id, seq=self._sequence)
            canonical = _canonical(record)
            record["hash"] = hashlib.sha256(canonical.encode()).hexdigest()
            record["sig"] = hmac.new(self.key, record["hash"].encode(), hashlib.sha256).hexdigest()
            line = json.dumps(record, ensure_ascii=False)
            try:
                if self._file:
                    self._file.write(line + "\n")
                    self._file.flush()
                    os.fsync(self._file.fileno())
                if self.echo:
                    sys.stderr.write("AUDIT " + line + "\n")
                if self.siem and not self.async_ship:
                    self.siem.ship(record)
            except Exception:
                self._failed = True
                raise
            if len(self.records) == self.records.maxlen:
                self._anchor = self.records[0]["hash"]
            self._prev_hash = record["hash"]
            self._sequence += 1
            self.records.append(record)
            if self.siem and self.async_ship:
                self._ship_q.put_nowait(record)
            return record

    def close(self) -> None:
        with self._lock:
            if self._closed:
                return
            self._closed = True
        self._ship_stop.set()
        if self._ship_thread:
            self._ship_thread.join(timeout=5)
        if self._file:
            self._file.close()
        self._redactor.close()

    def verify(self, records: list[dict] | None = None) -> tuple[bool, str]:
        with self._lock:
            recs = list(self.records) if records is None else records
            previous = self._anchor if records is None else "0" * 64
            for index, record in enumerate(recs):
                ok, message = self._verify_record(record, previous)
                if not ok:
                    return False, f"Invalid record {index}: {message}"
                previous = record["hash"]
            return True, "Retained chain and signatures valid"

    def _ship_worker(self) -> None:
        while not self._ship_stop.is_set() or not self._ship_q.empty():
            try:
                record = self._ship_q.get(timeout=.1)
            except queue.Empty:
                continue
            try:
                self.siem.ship(record)
            except Exception:
                with self._lock:
                    self.ship_failures += 1
                    self._failed = True
            finally:
                self._ship_q.task_done()
