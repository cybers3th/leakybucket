"""Supply-chain detector.

Tracks provenance of model providers, tools, plugins, packages, prompts,
datasets, and RAG sources. Compares against a configured registry of
trusted identities (name+version+optional sha256) and raises detections
for anything unexpected.

Provides:
  * SupplyChainRegistry — the source of truth (loaded from JSON or code)
  * SupplyChainDetector — a runtime detector for events
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from firewall.core.events import Detection, SecurityEvent


@dataclass
class TrustedArtifact:
    kind: str                  # provider, model, tool, plugin, package, dataset, prompt, rag_source, mcp_server
    name: str
    versions: list[str] = field(default_factory=list)    # empty = any
    sha256: str | None = None
    owner: str = ""
    approved: bool = True
    notes: str = ""


class SupplyChainRegistry:
    def __init__(self):
        self.entries: dict[tuple[str, str], TrustedArtifact] = {}
        self.blocked: set[tuple[str, str]] = set()
        self.advisories: dict[tuple[str, str], list[str]] = {}   # (kind, name) -> list

    def add(self, art: TrustedArtifact) -> None:
        self.entries[(art.kind, art.name)] = art

    def block(self, kind: str, name: str) -> None:
        self.blocked.add((kind, name))

    def advise(self, kind: str, name: str, advisory: str) -> None:
        self.advisories.setdefault((kind, name), []).append(advisory)

    def lookup(self, kind: str, name: str) -> TrustedArtifact | None:
        return self.entries.get((kind, name))

    def is_blocked(self, kind: str, name: str) -> bool:
        return (kind, name) in self.blocked

    def check(self, kind: str, name: str, version: str = "", sha256: str = "") -> tuple[str, str]:
        """Return (status, reason). status in trusted, unknown, mismatch, blocked, advisory."""
        if self.is_blocked(kind, name):
            return "blocked", f"{kind}:{name} is on the block list"
        art = self.lookup(kind, name)
        if not art:
            return "unknown", f"{kind}:{name} not in registry"
        if art.versions and version and version not in art.versions:
            return "mismatch", f"{kind}:{name} version {version} not in allowed {art.versions}"
        if art.sha256 and sha256 and sha256.lower() != art.sha256.lower():
            return "mismatch", f"{kind}:{name} sha256 mismatch"
        if (kind, name) in self.advisories:
            return "advisory", "; ".join(self.advisories[(kind, name)])
        return "trusted", ""

    @classmethod
    def from_json(cls, path: str | Path) -> "SupplyChainRegistry":
        data = json.loads(Path(path).read_text())
        reg = cls()
        for a in data.get("trusted", []):
            reg.add(TrustedArtifact(**a))
        for b in data.get("blocked", []):
            reg.block(b["kind"], b["name"])
        for a in data.get("advisories", []):
            reg.advise(a["kind"], a["name"], a["message"])
        return reg


class SupplyChainDetector:
    NAME = "supply_chain"

    def __init__(self, registry: SupplyChainRegistry | None = None,
                 default_allow_unknown: bool = False):
        self.reg = registry or SupplyChainRegistry()
        self.default_allow_unknown = default_allow_unknown

    def scan(self, event: SecurityEvent) -> list[Detection]:
        out: list[Detection] = []
        # Provider / model
        if event.provider:
            out += self._check("provider", event.provider, "")
        if event.model:
            out += self._check("model", event.model, "")
        # Tool
        if event.tool_def:
            v = event.tool_def.version
            sha = event.tool_def.sha256 or ""
            out += self._check("tool", event.tool_def.name, v, sha)
            if event.tool_def.provider and event.tool_def.provider != "local":
                out += self._check("mcp_server", event.tool_def.provider, "")
        return out

    def _check(self, kind: str, name: str, version: str = "", sha256: str = "") -> list[Detection]:
        status, reason = self.reg.check(kind, name, version, sha256)
        if status == "trusted":
            return []
        sev, conf = {
            "blocked": ("critical", 1.0),
            "mismatch": ("high", 0.95),
            "advisory": ("medium", 0.85),
            "unknown": ("high" if not self.default_allow_unknown else "low", 0.7),
        }[status]
        return [Detection(
            detector=self.NAME, category="supply_chain",
            subcategory=status, technique=kind,
            severity=sev, confidence=conf,
            message=f"[{kind}] {name} {version or ''} -> {status}: {reason}",
            metadata={"kind": kind, "name": name, "version": version, "sha256": sha256},
        )]


def sha256_of(data: bytes | str) -> str:
    if isinstance(data, str):
        data = data.encode("utf-8", "replace")
    return hashlib.sha256(data).hexdigest()
