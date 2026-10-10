"""MCP protocol types + fingerprinting.

We only model the JSON-RPC surface we need to inspect. The gateway does not
implement MCP transport itself — callers hand messages to
``MCPGateway.inspect_inbound`` / ``inspect_outbound`` and act on the returned
decision. That keeps this layer transport-agnostic (stdio, HTTP/SSE, etc.)
"""
from __future__ import annotations

import copy
import enum
import hashlib
import json
from dataclasses import dataclass, field
from typing import Any


class MCPDirection(str, enum.Enum):
    INBOUND  = "inbound"   # server -> client (results, notifications, sampling requests)
    OUTBOUND = "outbound"  # client -> server (requests, tool calls)


@dataclass
class MCPServerDef:
    """A declared MCP server in the trusted registry."""
    server_id: str
    name: str
    transport: str = "stdio"        # stdio | http | sse
    command: str = ""               # for stdio
    args: list[str] = field(default_factory=list)
    url: str = ""                   # for http/sse
    version: str = ""
    owner: str = ""
    allowed_capabilities: list[str] = field(default_factory=list)   # tools, resources, prompts, sampling
    allowed_hosts: list[str] = field(default_factory=list)          # for network-capable tools
    allowed_resource_uris: list[str] = field(default_factory=list)  # custom resource URI patterns
    allow_sampling: bool = False    # if False, sampling/createMessage requests are blocked
    max_sampling_tokens: int = 4096
    max_sampling_messages: int = 32
    max_sampling_calls_per_minute: int = 10
    max_tool_calls_per_minute: int = 60
    tools: dict[str, "MCPToolFingerprint"] = field(default_factory=dict)
    prompts: dict[str, str] = field(default_factory=dict)           # name -> sha256
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class MCPToolFingerprint:
    """A pinned fingerprint for one MCP tool.

    On every ``tools/list`` response from a server, we recompute the fingerprint
    of each advertised tool and compare against the pinned one. A change is a
    rug-pull — a tool that was audited under one description silently morphs
    into something else. Fail closed.
    """
    name: str
    description_hash: str = ""      # sha256 of description
    schema_hash: str = ""           # sha256 of input schema JSON canonical form
    risk_level: str = "medium"      # low | medium | high | critical
    requires_human_approval: bool = False
    allowed_hosts: list[str] = field(default_factory=list)
    allowed_resources: list[str] = field(default_factory=list)
    notes: str = ""
    definition_hash: str = ""
    input_schema: dict[str, Any] | None = None

    @classmethod
    def compute(cls, tool: dict[str, Any], risk_level: str = "medium",
                 requires_human_approval: bool = False,
                 allowed_hosts: list[str] | None = None,
                 allowed_resources: list[str] | None = None) -> "MCPToolFingerprint":
        desc = tool.get("description", "") or ""
        schema = tool.get("inputSchema", tool.get("parameters", {})) or {}
        return cls(
            name=tool.get("name", ""),
            description_hash=hashlib.sha256(desc.encode("utf-8", "replace")).hexdigest(),
            definition_hash=hashlib.sha256(json.dumps(
                tool, sort_keys=True, ensure_ascii=False, allow_nan=False
            ).encode("utf-8")).hexdigest(),
            input_schema=copy.deepcopy(schema),
            schema_hash=hashlib.sha256(
                json.dumps(schema, sort_keys=True, default=str).encode("utf-8", "replace")
            ).hexdigest(),
            risk_level=risk_level,
            requires_human_approval=requires_human_approval,
            allowed_hosts=list(allowed_hosts or []),
            allowed_resources=list(allowed_resources or []),
        )


@dataclass
class MCPMessage:
    """A single JSON-RPC message crossing the gateway."""
    server_id: str
    direction: MCPDirection
    method: str = ""                # jsonrpc "method"; empty for responses
    id: Any = None                  # jsonrpc id (None for notifications)
    params: dict[str, Any] | None = None
    result: Any = None              # for responses
    error: dict[str, Any] | None = None
    raw: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_json(cls, server_id: str, direction: MCPDirection, obj: dict[str, Any]) -> "MCPMessage":
        return cls(
            server_id=server_id,
            direction=direction,
            method=obj.get("method", ""),
            id=obj.get("id"),
            params=obj.get("params"),
            result=obj.get("result"),
            error=obj.get("error"),
            raw=obj,
        )

    def is_request(self) -> bool:
        return bool(self.method) and self.id is not None

    def is_notification(self) -> bool:
        return bool(self.method) and self.id is None

    def is_response(self) -> bool:
        return not self.method and self.id is not None


# ---- helpers for canonical MCP method names ----

M_INITIALIZE          = "initialize"
M_TOOLS_LIST          = "tools/list"
M_TOOLS_CALL          = "tools/call"
M_PROMPTS_LIST        = "prompts/list"
M_PROMPTS_GET         = "prompts/get"
M_RESOURCES_LIST      = "resources/list"
M_RESOURCES_READ      = "resources/read"
M_RESOURCES_SUBSCRIBE = "resources/subscribe"
M_SAMPLING_CREATE     = "sampling/createMessage"
M_COMPLETION_COMPLETE = "completion/complete"
M_LOGGING_SET_LEVEL   = "logging/setLevel"
M_NOTIF_INITIALIZED   = "notifications/initialized"
M_NOTIF_PROGRESS      = "notifications/progress"
M_PING                = "ping"
