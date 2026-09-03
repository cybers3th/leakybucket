"""Trusted MCP server registry.

Pins tool + prompt fingerprints per server so a subsequent ``tools/list``
that returns a differently-described tool is caught as drift/rug-pull.
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import asdict
from pathlib import Path
from typing import Any

from firewall.mcp.types import MCPServerDef, MCPToolFingerprint


class MCPServerRegistry:
    """In-memory registry, optionally loaded from and saved to JSON."""

    def __init__(self):
        self.servers: dict[str, MCPServerDef] = {}
        self.blocked_servers: set[str] = set()

    # ---- registration ----
    def register(self, server: MCPServerDef) -> None:
        self.servers[server.server_id] = server

    def block(self, server_id: str) -> None:
        self.blocked_servers.add(server_id)

    def is_blocked(self, server_id: str) -> bool:
        return server_id in self.blocked_servers

    def get(self, server_id: str) -> MCPServerDef | None:
        return self.servers.get(server_id)

    # ---- pinning ----
    def pin_tool(self, server_id: str, tool: dict[str, Any], **kwargs) -> MCPToolFingerprint:
        fp = MCPToolFingerprint.compute(tool, **kwargs)
        srv = self.servers.setdefault(server_id, MCPServerDef(server_id=server_id, name=server_id))
        srv.tools[fp.name] = fp
        return fp

    def pin_prompt(self, server_id: str, name: str, content: str) -> str:
        h = hashlib.sha256(content.encode("utf-8", "replace")).hexdigest()
        srv = self.servers.setdefault(server_id, MCPServerDef(server_id=server_id, name=server_id))
        srv.prompts[name] = h
        return h

    # ---- drift detection ----
    def check_tool_drift(self, server_id: str, tool: dict[str, Any]
                         ) -> tuple[str, str, MCPToolFingerprint | None]:
        """Return (status, reason, pinned_fp).

        status: 'trusted' | 'drifted' | 'unpinned' | 'unknown_server'
        """
        srv = self.get(server_id)
        if not srv:
            return "unknown_server", f"server {server_id} not registered", None
        name = tool.get("name", "")
        pinned = srv.tools.get(name)
        if not pinned:
            return "unpinned", f"tool '{name}' not pinned on server {server_id}", None
        current = MCPToolFingerprint.compute(tool, risk_level=pinned.risk_level)
        if current.description_hash != pinned.description_hash:
            return "drifted", f"tool '{name}' description changed since pinning", pinned
        if current.schema_hash != pinned.schema_hash:
            return "drifted", f"tool '{name}' input schema changed since pinning", pinned
        return "trusted", "", pinned

    def check_prompt_drift(self, server_id: str, name: str, content: str
                           ) -> tuple[str, str]:
        srv = self.get(server_id)
        if not srv:
            return "unknown_server", f"server {server_id} not registered"
        pinned = srv.prompts.get(name)
        if not pinned:
            return "unpinned", f"prompt '{name}' not pinned"
        h = hashlib.sha256(content.encode("utf-8", "replace")).hexdigest()
        if h != pinned:
            return "drifted", f"prompt '{name}' content changed since pinning"
        return "trusted", ""

    # ---- persistence ----
    def to_dict(self) -> dict[str, Any]:
        return {
            "servers": {sid: asdict(s) for sid, s in self.servers.items()},
            "blocked": sorted(self.blocked_servers),
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "MCPServerRegistry":
        reg = cls()
        for sid, sd in data.get("servers", {}).items():
            tools = {k: MCPToolFingerprint(**v) for k, v in sd.pop("tools", {}).items()}
            reg.servers[sid] = MCPServerDef(**sd, tools=tools)
        for sid in data.get("blocked", []):
            reg.blocked_servers.add(sid)
        return reg

    @classmethod
    def from_json(cls, path: str | Path) -> "MCPServerRegistry":
        return cls.from_dict(json.loads(Path(path).read_text()))

    def to_json(self, path: str | Path) -> None:
        Path(path).write_text(json.dumps(self.to_dict(), indent=2, default=str))
