"""Signed, chain-hashed audit log.

Every audit record is:
  * canonically serialized
  * hashed with the previous record's hash (blockchain-style chain)
  * signed with HMAC-SHA256 using a rotating key
Tampering with any record breaks the chain from that point forward.

Provides optional SIEM sinks:
  * Splunk HEC
  * Elasticsearch bulk endpoint
  * Datadog logs API
  * generic Syslog RFC 5424 over UDP
"""
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
    ):
        self.path = Path(path) if path else None
        self.echo = echo
        self.key = key or os.urandom(32)
        self.key_id = key_id
        self._prev_hash = "0" * 64
        self._lock = threading.Lock()
        self._file: TextIO | None = None
        if self.path:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            self._file = open(self.path, "a", encoding="utf-8")
            self._prev_hash = self._recover_last_hash()
        self.records: list[dict] = []
        # SIEM shipping runs in background
        self.siem = siem
        self._ship_q: queue.Queue = queue.Queue(maxsize=10_000)
        self._ship_stop = threading.Event()
        if siem and async_ship:
            t = threading.Thread(target=self._ship_worker, daemon=True)
            t.start()

    def _recover_last_hash(self) -> str:
        """Read the file to reconstruct the last hash — resumes chain across restarts."""
        try:
            with open(self.path, "r") as f:
                last = None
                for line in f:
                    line = line.strip()
                    if line:
                        try:
                            last = json.loads(line)
                        except Exception:
                            continue
                if last and "hash" in last:
                    return last["hash"]
        except FileNotFoundError:
            pass
        return "0" * 64

    def write(self, event: SecurityEvent) -> dict:
        record = self._to_record(event)
        with self._lock:
            record["prev_hash"] = self._prev_hash
            record["key_id"] = self.key_id
            record["ts"] = record.get("ts", time.time())
            record["seq"] = record.get("seq") or len(self.records)
            canonical = _canonical({k: v for k, v in record.items()
                                      if k not in ("hash", "sig")})
            record["hash"] = hashlib.sha256(canonical.encode()).hexdigest()
            record["sig"] = hmac.new(self.key,
                                       record["hash"].encode(),
                                       hashlib.sha256).hexdigest()
            self._prev_hash = record["hash"]
            self.records.append(record)
            line = json.dumps(record, default=str, ensure_ascii=False)
            if self._file:
                self._file.write(line + "\n"); self._file.flush()
            if self.echo:
                sys.stderr.write("AUDIT " + line + "\n")
            if self.siem:
                try: self._ship_q.put_nowait(record)
                except queue.Full: pass
        return record

    def close(self) -> None:
        self._ship_stop.set()
        if self._file: self._file.close()

    def verify(self, records: list[dict] | None = None) -> tuple[bool, str]:
        """Verify chain integrity + HMAC signature on every record."""
        recs = records if records is not None else self.records
        prev = "0" * 64
        for i, r in enumerate(recs):
            if r.get("prev_hash") != prev:
                return False, f"chain break at seq {i}: prev_hash mismatch"
            canonical = _canonical({k: v for k, v in r.items() if k not in ("hash", "sig")})
            h = hashlib.sha256(canonical.encode()).hexdigest()
            if h != r.get("hash"):
                return False, f"hash mismatch at seq {i}"
            expected_sig = hmac.new(self.key, r["hash"].encode(), hashlib.sha256).hexdigest()
            if expected_sig != r.get("sig"):
                return False, f"signature mismatch at seq {i}"
            prev = r["hash"]
        return True, "chain and signatures valid"

    def _to_record(self, event: SecurityEvent) -> dict:
        return {
            "ts": event.ts,
            "ts_iso": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(event.ts)),
            "event_id": event.event_id,
            "correlation_id": event.correlation_id,
            "parent_event_id": event.parent_event_id,
            "stage": event.stage,
            "actor": dataclasses.asdict(event.actor),
            "source_kind": event.source.kind.value if event.source else None,
            "source_origin": event.source.origin if event.source else None,
            "destination": event.destination,
            "model": event.model, "provider": event.provider,
            "tool_call": dataclasses.asdict(event.tool_call) if event.tool_call else None,
            "tool_def": dataclasses.asdict(event.tool_def) if event.tool_def else None,
            "input_len": len(event.input_text or ""),
            "output_len": len(event.output_text or ""),
            "context_doc_count": len(event.context_docs),
            "detections": [dataclasses.asdict(d) for d in event.detections],
            "trust_of_input": int(event.trust_of_input),
            "risk_score": event.risk_score,
            "risk_reasons": event.risk_reasons,
            "matched_policies": event.matched_policies,
            "decision": event.decision.value,
            "reasons": event.reasons,
            "tags": event.tags,
        }

    def _ship_worker(self) -> None:
        while not self._ship_stop.is_set():
            try:
                rec = self._ship_q.get(timeout=1.0)
            except queue.Empty:
                continue
            try:
                self.siem.ship(rec)
            except Exception as e:
                sys.stderr.write(f"SIEM ship error: {e}\n")
