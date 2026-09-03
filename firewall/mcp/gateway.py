"""MCP gateway — transport-agnostic proxy hook.

A caller (stdio wrapper, HTTP proxy, SDK middleware) hands raw JSON-RPC
messages to ``inspect_inbound(...)`` / ``inspect_outbound(...)``. The
gateway returns an InspectionResult; the caller is responsible for
delivering / dropping the message accordingly.

Every inspected message is written to the AuditLog with a correlation ID
derived from the session, so an entire multi-server transcript can be
reconstructed.
"""
from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Any, Callable

from firewall.core.audit import AuditLog
from firewall.core.events import Actor, Decision, SecurityEvent
from firewall.enforcement.rate_limits import RateLimiter
from firewall.mcp.inspector import (
    InspectionResult, MCPDataFlowTracker, MCPInspector,
)
from firewall.mcp.registry import MCPServerRegistry
from firewall.mcp.types import (
    MCPDirection, MCPMessage, M_TOOLS_CALL,
)


class MCPBlocked(RuntimeError):
    def __init__(self, reasons: list[str], detections: list[Any] | None = None):
        super().__init__("mcp message blocked")
        self.reasons = reasons
        self.detections = detections or []


class MCPApprovalRequired(RuntimeError):
    def __init__(self, reasons: list[str]):
        super().__init__("mcp message requires approval")
        self.reasons = reasons


class MCPGateway:
    def __init__(
        self,
        registry: MCPServerRegistry | None = None,
        audit: AuditLog | None = None,
        approval_callback: Callable[[SecurityEvent | None, InspectionResult], bool] | None = None,
        rate_limiter: RateLimiter | None = None,
    ):
        self.registry = registry or MCPServerRegistry()
        self.audit = audit or AuditLog()
        self.approval_callback = approval_callback
        self.data_flow = MCPDataFlowTracker()
        self.inspector = MCPInspector(self.registry, data_flow=self.data_flow)
        self.rate = rate_limiter or RateLimiter()

    # ---- primary API ----

    def inspect_inbound(self, server_id: str, actor: Actor,
                         message: dict) -> InspectionResult:
        msg = MCPMessage.from_json(server_id, MCPDirection.INBOUND, message)
        return self._run(msg, actor)

    def inspect_outbound(self, server_id: str, actor: Actor,
                          message: dict) -> InspectionResult:
        msg = MCPMessage.from_json(server_id, MCPDirection.OUTBOUND, message)
        # Rate limit outbound tool calls per session:server:tool
        if msg.method == M_TOOLS_CALL:
            tool_name = (msg.params or {}).get("name", "?")
            srv = self.registry.get(server_id)
            cap = srv.max_tool_calls_per_minute if srv else 60
            key = f"{actor.session_id or 'anon'}:mcp:{server_id}:{tool_name}"
            ok, why = self.rate.allow(key, rate_per_minute=cap, capacity=cap)
            if not ok:
                r = self._audit_and_return(
                    msg, actor,
                    InspectionResult(decision=Decision.BLOCK,
                                      reasons=[f"rate_limit: {why}"]),
                )
                return r
        return self._run(msg, actor)

    # ---- helpers ----

    def _run(self, msg: MCPMessage, actor: Actor) -> InspectionResult:
        result = self.inspector.inspect(msg, actor)
        return self._audit_and_return(msg, actor, result)

    def _audit_and_return(self, msg: MCPMessage, actor: Actor,
                           result: InspectionResult) -> InspectionResult:
        ev = result.event or SecurityEvent(
            actor=actor, destination=f"mcp:{msg.server_id}:{msg.method or 'response'}",
        )
        for d in result.detections:
            ev.add_detection(d)
        ev.decision = result.decision
        ev.reasons.extend(result.reasons)
        ev.stage = f"mcp_{msg.direction.value}"
        ev.tags.append("mcp")
        ev.tags.append(f"server:{msg.server_id}")
        if msg.method:
            ev.tags.append(f"method:{msg.method}")
        self.audit.write(ev)
        return result

    def enforce(self, result: InspectionResult) -> None:
        """Raise MCPBlocked / MCPApprovalRequired based on the result.

        Approval is delegated to the configured callback. Fail-closed if no
        callback is configured.
        """
        if result.decision == Decision.BLOCK:
            raise MCPBlocked(result.reasons, result.detections)
        if result.decision == Decision.REQUIRE_APPROVAL:
            approved = False
            if self.approval_callback:
                try:
                    approved = bool(self.approval_callback(result.event, result))
                except Exception:
                    approved = False
            if not approved:
                raise MCPApprovalRequired(result.reasons)

    # ---- convenience: full round-trip ----

    def gate_outbound(self, server_id: str, actor: Actor, message: dict) -> InspectionResult:
        r = self.inspect_outbound(server_id, actor, message)
        self.enforce(r)
        return r

    def gate_inbound(self, server_id: str, actor: Actor, message: dict) -> InspectionResult:
        r = self.inspect_inbound(server_id, actor, message)
        self.enforce(r)
        return r
