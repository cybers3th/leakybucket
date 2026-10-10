"""Structured audit log — JSONL, SIEM-friendly, one event per line."""
from __future__ import annotations

from collections import deque
import dataclasses
import enum
import json
import sys
import threading
import time
from pathlib import Path
from typing import Any, TextIO

from firewall.core.events import SecurityEvent


def _default(o: Any) -> Any:
    if dataclasses.is_dataclass(o):
        return dataclasses.asdict(o)
    if isinstance(o, enum.Enum):
        return o.value
    if isinstance(o, (set, tuple)):
        return list(o)
    if isinstance(o, bytes):
        return o.decode("utf-8", "replace")
    return str(o)


class AuditLog:
    def __init__(self, path: str | Path | None = None, echo: bool = False,
                 max_records: int = 1000, include_sensitive_details: bool = False):
        if max_records < 0:
            raise ValueError("max_records must be nonnegative")
        self.include_sensitive_details = include_sensitive_details
        self.path = Path(path) if path else None
        self.echo = echo
        self._lock = threading.Lock()
        self._file: TextIO | None = None
        if self.path:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            self._file = open(self.path, "a", encoding="utf-8")
        self.records = deque(maxlen=max_records)

    def close(self) -> None:
        if self._file:
            self._file.close()

    def write(self, event: SecurityEvent) -> None:
        record = {
            "ts": event.ts,
            "ts_iso": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(event.ts)),
            "event_id": event.event_id,
            "correlation_id": event.correlation_id,
            "stage": event.stage,
            "actor": dataclasses.asdict(event.actor),
            "source_kind": event.source.kind.value if event.source else None,
            "source_origin": event.source.origin if event.source else None,
            "destination": event.destination,
            "model": event.model,
            "provider": event.provider,
            "tool_call": dataclasses.asdict(event.tool_call) if event.tool_call else None,
            "tool_def": dataclasses.asdict(event.tool_def) if event.tool_def else None,
            "input_len": len(event.input_text or ""),
            "output_len": len(event.output_text or ""),
            "context_doc_count": len(event.context_docs),
            "detections": [dataclasses.asdict(d) for d in event.detections],
            "classifications": [c.value for c in event.classifications],
            "trust_of_input": int(event.trust_of_input),
            "risk_score": event.risk_score,
            "risk_reasons": event.risk_reasons,
            "matched_policies": event.matched_policies,
            "decision": event.decision.value,
            "reasons": event.reasons,
            "approval_required_from": event.approval_required_from,
            "tags": event.tags,
        }
        if not self.include_sensitive_details:
            # Keep identifiers and rule outcomes; omit arbitrary content that
            # can include credentials and attacker-controlled log injection.
            record["actor"]["metadata"] = {}
            if record["tool_call"]:
                record["tool_call"]["arguments"] = {"redacted": True}
            if record["tool_def"]:
                record["tool_def"]["description"] = "[omitted]"
                record["tool_def"]["metadata"] = {}
            record["source_origin"] = "[omitted]" if event.source else None
            record["destination"] = "[omitted]"
            record["reasons"] = ["decision details omitted"] if event.reasons else []
            record["risk_reasons"] = []
            for detection in record["detections"]:
                detection["evidence"] = ""
                detection["message"] = "[omitted]"
                detection["metadata"] = {key: value for key, value in detection["metadata"].items()
                                          if key in {"rule_id", "location", "decoded", "asi", "kind"}}
        line = json.dumps(record, default=_default, ensure_ascii=False)
        with self._lock:
            self.records.append(record)
            if self._file:
                self._file.write(line + "\n")
                self._file.flush()
            if self.echo:
                sys.stderr.write("AUDIT " + line + "\n")
