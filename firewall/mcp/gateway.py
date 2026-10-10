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
import json
import threading
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
        max_message_bytes: int = 1_048_576,
        max_depth: int = 32,
        max_nodes: int = 20_000,
        require_correlated_responses: bool = False,
        max_pending_requests: int = 4096,
        request_ttl_seconds: float = 300,
    ):
        if min(max_message_bytes, max_depth, max_nodes) <= 0:
            raise ValueError("message limits must be positive")
        if max_pending_requests <= 0 or request_ttl_seconds <= 0:
            raise ValueError("pending request limits must be positive")
        self.require_correlated_responses = require_correlated_responses
        self.max_pending_requests = max_pending_requests
        self.request_ttl_seconds = request_ttl_seconds
        self._pending = {}
        self._pending_lock = threading.RLock()
        self.max_message_bytes = max_message_bytes
        self.max_depth = max_depth
        self.max_nodes = max_nodes
        self.registry = registry or MCPServerRegistry()
        self.audit = audit or AuditLog()
        self.approval_callback = approval_callback
        self.data_flow = MCPDataFlowTracker()
        self.inspector = MCPInspector(self.registry, data_flow=self.data_flow)
        self.rate = rate_limiter or RateLimiter()

    # ---- primary API ----

    def inspect_inbound(self, server_id: str, actor: Actor,
                         message: dict) -> InspectionResult:
        rejected = self._validate(server_id, actor, message, MCPDirection.INBOUND)
        if rejected is not None:
            return rejected
        msg = MCPMessage.from_json(server_id, MCPDirection.INBOUND, message)
        return self._run(msg, actor)

    def inspect_outbound(self, server_id: str, actor: Actor,
                          message: dict) -> InspectionResult:
        rejected = self._validate(server_id, actor, message, MCPDirection.OUTBOUND)
        if rejected is not None:
            return rejected
        msg = MCPMessage.from_json(server_id, MCPDirection.OUTBOUND, message)
        # Rate limit outbound tool calls per session:server:tool
        if msg.method == M_TOOLS_CALL:
            tool_name = (msg.params or {}).get("name", "?")
            srv = self.registry.get(server_id)
            cap = srv.max_tool_calls_per_minute if srv else 60
            key = json.dumps([actor.tenant, actor.user_id, actor.session_id, server_id, tool_name])
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

    def _validate(self, server_id, actor, message, direction):
        """Bound work before recursive detectors; reject malformed envelopes."""
        reason = ""
        if not isinstance(message, dict):
            reason = "JSON-RPC message must be an object (batches are not accepted)"
        else:
            stack = [(message, 0)]
            nodes = 0
            size = 0
            while stack and not reason:
                value, depth = stack.pop()
                nodes += 1
                if nodes > self.max_nodes or depth > self.max_depth:
                    reason = "message structure exceeds inspection limits"
                    break
                if isinstance(value, dict):
                    if not all(isinstance(k, str) for k in value):
                        reason = "JSON object keys must be strings"
                        break
                    if len(value) + nodes > self.max_nodes or sum(map(len, value)) > self.max_message_bytes:
                        reason = "message object exceeds inspection limits"
                        break
                    size += sum(len(k.encode("utf-8")) for k in value)
                    stack.extend((v, depth + 1) for v in value.values())
                elif isinstance(value, list):
                    if len(value) + nodes > self.max_nodes:
                        reason = "message array exceeds inspection limits"
                        break
                    stack.extend((v, depth + 1) for v in value)
                elif isinstance(value, str):
                    if len(value) > self.max_message_bytes:
                        reason = "message exceeds byte limit"
                        break
                    size += len(value.encode("utf-8", "replace"))
                elif value is not None and type(value) not in (int, float, bool):
                    reason = "message contains non-JSON values"
                if size > self.max_message_bytes:
                    reason = "message exceeds byte limit"
            if not reason:
                try:
                    encoded = json.dumps(message, allow_nan=False).encode("utf-8")
                    if len(encoded) > self.max_message_bytes:
                        reason = "message exceeds byte limit"
                except (ValueError, TypeError, RecursionError, OverflowError):
                    reason = "message cannot be represented as finite JSON"
            if not reason:
                method = message.get("method")
                if message.get("jsonrpc", "2.0") != "2.0":
                    reason = "unsupported JSON-RPC version"
                elif "id" in message and type(message["id"]) not in (str, int):
                    reason = "request id must be a string or integer"
                elif isinstance(message.get("id"), str) and len(message["id"]) > 128:
                    reason = "request id exceeds inspection limit"
                elif "method" in message:
                    if not isinstance(method, str) or not method:
                        reason = "method must be a nonempty string"
                    elif "result" in message or "error" in message:
                        reason = "request cannot also be a response"
                    elif "params" in message and not isinstance(message["params"], dict):
                        reason = "MCP params must be an object"
                    elif method == M_TOOLS_CALL:
                        params = message.get("params", {})
                        if not isinstance(params.get("name"), str) or not params.get("name"):
                            reason = "tool name must be a nonempty string"
                        elif not isinstance(params.get("arguments", {}), dict):
                            reason = "tool arguments must be an object"
                elif "id" not in message or (("result" in message) == ("error" in message)):
                    reason = "response must have id and exactly one of result or error"
                elif "error" in message and not isinstance(message["error"], dict):
                    reason = "error must be an object"
        if not reason and "result" in message and isinstance(message["result"], dict):
            result = message["result"]
            for field in ("tools", "prompts", "resources", "contents", "content", "messages"):
                if field not in result:
                    continue
                items = result[field]
                if not isinstance(items, list) or not all(isinstance(item, dict) for item in items):
                    reason = "result collections must contain objects"
                    break
                if field in ("tools", "prompts"):
                    names = set()
                    for item in items:
                        name = item.get("name")
                        if not isinstance(name, str) or not name or name in names:
                            reason = "advertised names must be nonempty and unique"
                            break
                        names.add(name)
                        if "description" in item and not isinstance(item["description"], str):
                            reason = "description must be a string"
                            break
                        if field == "tools" and not isinstance(item.get("inputSchema", {}), dict):
                            reason = "inputSchema must be an object"
                            break
        if reason:
            msg = MCPMessage(server_id=server_id, direction=direction)
            return self._audit_and_return(msg, actor, InspectionResult(
                decision=Decision.BLOCK, reasons=["invalid_message: " + reason]))
        return None

    def _run(self, msg: MCPMessage, actor: Actor) -> InspectionResult:
        if msg.direction == MCPDirection.INBOUND and msg.method == "sampling/createMessage":
            server = self.registry.get(msg.server_id)
            if server is not None and server.allow_sampling:
                key = json.dumps([actor.tenant, actor.user_id, actor.session_id, msg.server_id, "sampling"])
                allowed, reason = self.rate.allow(key, rate_per_minute=server.max_sampling_calls_per_minute,
                                                   capacity=server.max_sampling_calls_per_minute)
                if not allowed:
                    return self._audit_and_return(msg, actor, InspectionResult(
                        Decision.BLOCK, reasons=["Sampling rate limit exceeded"]))
        with self._pending_lock:
            now = time.monotonic()
            if self.require_correlated_responses:
                expired = [key for key, value in self._pending.items() if value[1] <= now]
                for key in expired:
                    del self._pending[key]
                key = (actor.tenant, actor.user_id, actor.session_id, msg.server_id,
                       type(msg.id).__name__, msg.id)
                if msg.direction == MCPDirection.INBOUND and msg.is_response():
                    pending = self._pending.pop(key, None)
                    if pending is None:
                        return self._audit_and_return(msg, actor, InspectionResult(
                            Decision.BLOCK, reasons=["Unsolicited, expired, or replayed response"]))
                elif msg.direction == MCPDirection.OUTBOUND and msg.is_request():
                    if key in self._pending or len(self._pending) >= self.max_pending_requests:
                        return self._audit_and_return(msg, actor, InspectionResult(
                            Decision.BLOCK, reasons=["Duplicate request id or pending request limit exceeded"]))
                elif msg.direction == MCPDirection.OUTBOUND and msg.method == M_TOOLS_CALL:
                    return self._audit_and_return(msg, actor, InspectionResult(
                        Decision.BLOCK, reasons=["Tool call requires a request id"]))
            try:
                result = self.inspector.inspect(msg, actor)
            except (ValueError, TypeError, RecursionError):
                result = InspectionResult(Decision.BLOCK, reasons=["Message inspection failed closed"])
            if self.require_correlated_responses and msg.direction == MCPDirection.OUTBOUND \
                    and msg.is_request() and result.decision in (Decision.ALLOW, Decision.REQUIRE_APPROVAL):
                self._pending[key] = (msg.method, now + self.request_ttl_seconds)
            return self._audit_and_return(msg, actor, result)

    def _audit_and_return(self, msg: MCPMessage, actor: Actor,
                           result: InspectionResult) -> InspectionResult:
        ev = result.event or SecurityEvent(
            actor=actor, destination=f"mcp:{msg.server_id}:{msg.method or 'response'}",
        )
        if result.event is None:
            for d in result.detections:
                ev.add_detection(d)
        ev.decision = result.decision
        if not ev.reasons:
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
        if result.decision == Decision.SANITIZE:
            raise MCPBlocked(["MCP sanitization requires a verified replacement; message withheld"],
                             result.detections)
        if result.decision == Decision.BLOCK:
            raise MCPBlocked(result.reasons, result.detections)
        if result.decision == Decision.REQUIRE_APPROVAL:
            approved = False
            if self.approval_callback:
                try:
                    approved = self.approval_callback(result.event, result) is True
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
