"""Per-message MCP inspection logic.

Turns a JSON-RPC MCPMessage into one or more Detections + a Decision.
Every inspection consults the trusted registry AND the existing reusable
detectors (prompt injection, sensitive data, output security, tool security,
poisoning). MCP is treated as another carrier — nothing is trusted just
because it came from a "registered" server.

Also exposes MCPDataFlowTracker: keeps a per-session lineage of data
returned by server A that later reappears in a tool_call to server B — the
classic confused-deputy shape.
"""
from __future__ import annotations

import fnmatch
import json
import hashlib
import re
import urllib.parse
from collections import defaultdict, deque
from dataclasses import dataclass, field
from typing import Any

from firewall.core.behavior import (
    ACT_NETWORK_EGRESS, ACT_SEND_MESSAGE, ACT_SHELL_EXEC, ACT_TOOL_CALL,
    ACT_UNTRUSTED_INPUT,
)
from firewall.core.events import (
    Actor, DataClassification, Decision, Detection, RetrievedDoc, SecurityEvent,
    Source, SourceKind, ToolCall, ToolDefinition, ToolResult, TrustLevel,
)
from firewall.core.trust import wrap_untrusted
from firewall.detectors import (
    PromptInjectionDetector, SensitiveDataDetector, OutputSecurityDetector,
    ToolSecurityDetector, PoisoningDetector,
)
from firewall.enforcement.network import EgressController, EgressPolicy
from firewall.mcp.schema import validate_arguments
from firewall.mcp.registry import MCPServerRegistry
from firewall.mcp.types import (
    M_INITIALIZE, M_PROMPTS_GET, M_PROMPTS_LIST, M_RESOURCES_LIST,
    M_RESOURCES_READ, M_RESOURCES_SUBSCRIBE, M_SAMPLING_CREATE,
    M_TOOLS_CALL, M_TOOLS_LIST,
    MCPDirection, MCPMessage, MCPServerDef,
)


# --------------------------------------------------------------------------- #
# Confused-deputy data-flow tracker
# --------------------------------------------------------------------------- #

@dataclass
class _FlowFragment:
    server_id: str
    source_method: str
    content_hash: str
    excerpt: str


class MCPDataFlowTracker:
    """Tracks data returned by server A that later appears in a call to server B.

    Uses coarse content fingerprints (sha256 of chunks) — a match indicates
    the client is echoing content from one MCP server into another server's
    arguments, which is the classic confused-deputy / exfiltration channel.
    """

    def __init__(self, min_len: int = 24, window: int = 500, max_sessions: int = 4096):
        self.max_sessions = max_sessions
        self.min_len = min_len
        self.by_session: dict[str, deque[_FlowFragment]] = defaultdict(
            lambda: deque(maxlen=window)
        )

    @staticmethod
    def scope(actor: Actor) -> str:
        return json.dumps([actor.tenant, actor.user_id, actor.session_id])

    def clear_session(self, actor: Actor) -> None:
        self.by_session.pop(self.scope(actor), None)

    def observe_result(self, session_id: str, server_id: str,
                       method: str, content: Any) -> None:
        if session_id not in self.by_session and len(self.by_session) >= self.max_sessions:
            raise ValueError("MCP data-flow session budget exceeded")
        for chunk in _iter_string_chunks(content, self.min_len):
            self.by_session[session_id].append(_FlowFragment(
                server_id=server_id,
                source_method=method,
                content_hash=_h(chunk),
                excerpt=chunk[:120],
            ))

    def check_leak(self, session_id: str, target_server_id: str,
                   args: Any) -> list[_FlowFragment]:
        seen = list(self.by_session.get(session_id, []))
        if not seen:
            return []
        # Flatten every string in the outbound args, then substring-match against
        # the excerpt of each previously-seen fragment. Substring match catches
        # the common case where an attacker's payload is URL-encoded, wrapped,
        # concatenated, or otherwise embedded rather than exactly re-emitted.
        arg_blob = " ".join(_iter_all_strings(args))
        for _ in range(2):
            arg_blob = urllib.parse.unquote(arg_blob)
        hits: list[_FlowFragment] = []
        seen_hashes = set()
        for frag in seen:
            if frag.server_id == target_server_id:
                continue
            if frag.excerpt and len(frag.excerpt) >= self.min_len and frag.excerpt in arg_blob:
                if frag.content_hash in seen_hashes:
                    continue
                seen_hashes.add(frag.content_hash)
                hits.append(frag)
        return hits


def _h(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8", "replace")).hexdigest()


def _iter_string_chunks(obj: Any, min_len: int):
    """Yield string fragments to fingerprint. Splits on sentence-ish boundaries."""
    if isinstance(obj, str):
        parts = re.split(r"(?<=[.!?\n])\s+", obj)
        for p in parts:
            p = p.strip()
            if len(p) >= min_len:
                yield p
        # Also yield the whole string for exact-match cases (URLs, tokens without periods)
        if len(obj) >= min_len:
            yield obj.strip()
    elif isinstance(obj, dict):
        for v in obj.values():
            yield from _iter_string_chunks(v, min_len)
    elif isinstance(obj, (list, tuple)):
        for v in obj:
            yield from _iter_string_chunks(v, min_len)


def _iter_all_strings(obj: Any):
    if isinstance(obj, str):
        yield obj
    elif isinstance(obj, dict):
        for v in obj.values():
            yield from _iter_all_strings(v)
    elif isinstance(obj, (list, tuple)):
        for v in obj:
            yield from _iter_all_strings(v)


# --------------------------------------------------------------------------- #
# Inspector
# --------------------------------------------------------------------------- #

_URL_RE = re.compile(r"\bhttps?://[^\s'\"<>)]+", re.IGNORECASE)


@dataclass
class InspectionResult:
    decision: Decision
    detections: list[Detection] = field(default_factory=list)
    reasons: list[str] = field(default_factory=list)
    sanitized_content: Any = None
    approval_required_from: str | None = None
    event: SecurityEvent | None = None


class MCPInspector:
    """Turns an MCPMessage into a SecurityEvent, runs detectors, returns Decision."""

    def __init__(self, registry: MCPServerRegistry,
                 data_flow: MCPDataFlowTracker | None = None):
        self.registry = registry
        self.pi   = PromptInjectionDetector()
        self.dlp  = SensitiveDataDetector()
        self.out  = OutputSecurityDetector()
        self.ts   = ToolSecurityDetector()
        self.pois = PoisoningDetector()
        self.data_flow = data_flow or MCPDataFlowTracker()

    # ------------------- top-level entrypoints -------------------

    def inspect(self, msg: MCPMessage, actor: Actor) -> InspectionResult:
        # Server-level checks come first
        if self.registry.is_blocked(msg.server_id):
            return self._deny(f"MCP server '{msg.server_id}' is on the block list.",
                              severity="critical", category="supply_chain",
                              subcategory="blocked_mcp_server")

        srv = self.registry.get(msg.server_id)
        if srv is None:
            return self._deny("MCP server is not registered", "critical",
                              "supply_chain", "unknown_mcp_server")

        if msg.direction == MCPDirection.INBOUND:
            return self._inspect_inbound(msg, srv, actor)
        return self._inspect_outbound(msg, srv, actor)

    # ------------------- inbound (server -> client) -------------------

    def _inspect_inbound(self, msg: MCPMessage, srv: MCPServerDef,
                          actor: Actor) -> InspectionResult:
        # Sampling requests from server: server is asking the LLM to do something
        if msg.method == M_SAMPLING_CREATE:
            if not srv.allow_sampling:
                return self._deny(
                    f"Server '{srv.server_id}' attempted sampling/createMessage but is not permitted.",
                    severity="critical", category="excessive_agency",
                    subcategory="mcp_sampling_denied",
                )
            params = msg.params or {}
            tokens = params.get("maxTokens")
            messages = params.get("messages")
            if type(tokens) is not int or not 0 < tokens <= srv.max_sampling_tokens \
                    or not isinstance(messages, list) or not 0 < len(messages) <= srv.max_sampling_messages:
                return self._deny("Sampling exceeds configured token/message limits", "critical",
                                  "unbounded_consumption", "mcp_sampling_budget_denied")
            # Sampling params include a messages array — treat everything as untrusted
            text = _extract_all_text(msg.params or {})
            ev = self._input_event(actor, text, srv, method=msg.method)
            self._run_input_detectors(ev)
            return self._decide(ev)

        # Responses to earlier client requests
        if msg.is_response():
            # Prefer method-specific handlers by re-deriving intent from result shape
            r = msg.result
            # Inspect the whole response before dispatching by shape. Otherwise
            # an innocuous tools/resources field could hide a malicious sibling.
            generic = self._input_event(actor, _extract_all_text(
                msg.error if msg.error is not None else r), srv)
            self._run_input_detectors(generic)
            for detector in (self.dlp, self.out):
                for detection in detector.scan(generic):
                    generic.add_detection(detection)
            verdict = self._decide(generic)
            if isinstance(r, dict) and "tools" in r:
                return self._merge(self._inspect_tools_list(msg, srv, actor, r), verdict)
            if isinstance(r, dict) and "prompts" in r:
                return self._merge(self._inspect_prompts_list(msg, srv, actor, r), verdict)
            if isinstance(r, dict) and "resources" in r:
                return self._merge(self._inspect_resources_list(msg, srv, actor, r), verdict)
            if isinstance(r, dict) and "contents" in r:
                return self._merge(self._inspect_resources_read(msg, srv, actor, r), verdict)
            if isinstance(r, dict) and ("content" in r or "isError" in r):
                return self._merge(self._inspect_tool_call_result(msg, srv, actor, r), verdict)
            return verdict

        # Server-initiated requests require explicit capability authorization.
        if msg.is_request():
            return self._deny("Server-initiated request is not authorized", "critical",
                              "excessive_agency", "mcp_server_request_denied")
        ev = self._input_event(actor, _extract_all_text(msg.params or {}), srv, msg.method)
        self._run_input_detectors(ev)
        for d in self.dlp.scan(ev):
            ev.add_detection(d)
        return self._decide(ev)

    def _inspect_tools_list(self, msg, srv, actor, result):
        tools = result.get("tools", []) or []
        detections: list[Detection] = []
        for t in tools:
            status, reason, _ = self.registry.check_tool_drift(srv.server_id, t)
            if status == "drifted":
                detections.append(Detection(
                    detector="mcp.registry", category="supply_chain",
                    subcategory="tool_drift", severity="critical", confidence=1.0,
                    message=f"[{srv.server_id}] {reason}",
                    metadata={"server_id": srv.server_id, "tool": t.get("name")},
                ))
            elif status == "unpinned":
                detections.append(Detection(
                    detector="mcp.registry", category="supply_chain",
                    subcategory="tool_unpinned", severity="critical", confidence=1.0,
                    message=f"[{srv.server_id}] {reason}",
                    metadata={"server_id": srv.server_id, "tool": t.get("name")},
                ))
            elif status == "unknown_server":
                detections.append(Detection(
                    detector="mcp.registry", category="supply_chain",
                    subcategory="unknown_mcp_server", severity="high", confidence=0.95,
                    message=f"[{srv.server_id}] {reason}",
                    metadata={"server_id": srv.server_id},
                ))
            # Tool-description poisoning
            desc = t.get("description", "")
            if desc:
                td = ToolDefinition(name=t.get("name", ""), description=desc)
                ev = SecurityEvent(actor=actor, tool_def=td,
                                    tool_call=ToolCall(tool=td.name, arguments={}))
                for d in self.pois.scan(ev):
                    detections.append(d)
                for d in self.ts.scan(ev):
                    if d.category == "tool_security":
                        detections.append(d)
        return self._package(detections, category_hint="supply_chain")

    def _inspect_prompts_list(self, msg, srv, actor, result):
        prompts = result.get("prompts", []) or []
        detections: list[Detection] = []
        for p in prompts:
            name = p.get("name", "")
            desc = p.get("description", "") + " " + str(p.get("arguments", ""))
            status, reason = self.registry.check_prompt_drift(srv.server_id, name, desc)
            if status in ("drifted", "unpinned", "unknown_server"):
                detections.append(Detection(
                    detector="mcp.registry", category="supply_chain",
                    subcategory="prompt_drift" if status == "drifted" else "prompt_unpinned", severity="high", confidence=1.0,
                    message=f"[{srv.server_id}] {reason}",
                    metadata={"server_id": srv.server_id, "prompt": name},
                ))
        return self._package(detections, category_hint="supply_chain")

    def _inspect_prompts_get(self, msg, srv, actor, result):
        text = _extract_all_text(result)
        ev = self._input_event(actor, text, srv, method=msg.method)
        self._run_input_detectors(ev)
        return self._decide(ev)

    def _inspect_resources_list(self, msg, srv, actor, result):
        # Just structural for now — resources/read is where content flows
        return InspectionResult(decision=Decision.ALLOW)

    def _inspect_resources_read(self, msg, srv, actor, result):
        contents = result.get("contents", []) or []
        text = _extract_all_text(result)
        ev = self._input_event(actor, text, srv, method=msg.method)
        self._run_input_detectors(ev)
        for d in self.dlp.scan(ev):
            ev.add_detection(d)
        # Track flow for later confused-deputy check
        self.data_flow.observe_result(
            self.data_flow.scope(actor), srv.server_id, msg.method, text,
        )
        return self._decide(ev)

    def _inspect_tool_call_result(self, msg, srv, actor, result):
        # Tool result — content is untrusted, may carry secondary injection / secrets / exploit output
        text = _extract_all_text(result)
        ev = self._output_event(actor, text, srv)
        ev.input_text = text
        ev.trust_of_input = TrustLevel.UNTRUSTED
        # Model output detectors AND input detectors run — the result IS input to the LLM
        for d in self.pi.scan(ev):  ev.add_detection(d)
        for d in self.dlp.scan(ev): ev.add_detection(d)
        for d in self.out.scan(ev): ev.add_detection(d)
        self.data_flow.observe_result(
            self.data_flow.scope(actor), srv.server_id, msg.method or "tools/call", text,
        )
        return self._decide(ev)

    # ------------------- outbound (client -> server) -------------------

    def _inspect_outbound(self, msg: MCPMessage, srv: MCPServerDef,
                           actor: Actor) -> InspectionResult:
        methods = {M_INITIALIZE, M_TOOLS_CALL, M_TOOLS_LIST, M_PROMPTS_LIST,
                   M_PROMPTS_GET, M_RESOURCES_LIST, M_RESOURCES_READ, M_RESOURCES_SUBSCRIBE,
                   "resources/unsubscribe", "completion/complete", "logging/setLevel", "ping",
                   "notifications/initialized", "notifications/cancelled", "notifications/progress"}
        if msg.method and msg.method not in methods:
            return self._deny("MCP method is not authorized", "critical",
                              "excessive_agency", "mcp_method_denied")
        capability = msg.method.split("/", 1)[0]
        if srv.allowed_capabilities and capability in {"tools", "resources", "prompts"} \
                and capability not in srv.allowed_capabilities:
            return self._deny("MCP capability is not granted to this server", "critical",
                              "excessive_agency", "mcp_capability_denied")
        # initialize opens a session under the configured trust registry.
        if msg.method == M_INITIALIZE:
            return InspectionResult(decision=Decision.ALLOW)

        if msg.method == M_TOOLS_CALL:
            return self._inspect_outbound_tool_call(msg, srv, actor)

        if msg.method == M_RESOURCES_READ:
            uri = (msg.params or {}).get("uri", "")
            return self._check_uri_against_srv(uri, srv, actor)

        if msg.method == M_RESOURCES_SUBSCRIBE:
            uri = (msg.params or {}).get("uri", "")
            return self._check_uri_against_srv(uri, srv, actor)

        if msg.method == M_PROMPTS_GET:
            return InspectionResult(decision=Decision.ALLOW)

        # Any other method — allow but log at gateway layer.
        return InspectionResult(decision=Decision.ALLOW)

    def _inspect_outbound_tool_call(self, msg, srv, actor):
        params = msg.params or {}
        name = params.get("name", "")
        args = params.get("arguments", {}) or {}
        pinned = srv.tools.get(name)
        if pinned is None:
            return self._deny("Tool is not pinned in the trusted registry", "critical",
                              "supply_chain", "tool_unpinned")
        if pinned.input_schema is None:
            return self._deny("Pinned tool schema missing; repin the reviewed tool", "critical",
                              "tool_security", "mcp_schema_missing")
        valid, why = validate_arguments(pinned.input_schema, args)
        if not valid:
            return self._deny(why, "critical", "tool_security", "mcp_invalid_arguments")
        td = ToolDefinition(
            name=name,
            description="",
            risk_level=(pinned.risk_level if pinned else "medium"),
            allowed_hosts=(pinned.allowed_hosts or srv.allowed_hosts),
            allowed_resources=(pinned.allowed_resources if pinned else []),
            requires_human_approval=(pinned.requires_human_approval if pinned else False),
            provider=srv.server_id,
        )
        ev = SecurityEvent(
            actor=actor,
            source=Source(kind=SourceKind.USER, origin="mcp_client"),
            tool_call=ToolCall(tool=name, arguments=args),
            tool_def=td,
            destination=f"mcp:{srv.server_id}:{name}",
        )
        for d in self.ts.scan(ev):  ev.add_detection(d)
        for d in self.dlp.scan(ev): ev.add_detection(d)
        for d in self.out.scan(ev): ev.add_detection(d)

        # Cross-server confused-deputy check
        leaks = self.data_flow.check_leak(self.data_flow.scope(actor),
                                           srv.server_id, args)
        for frag in leaks[:5]:
            ev.add_detection(Detection(
                detector="mcp.dataflow", category="attack_chain",
                subcategory="confused_deputy",
                severity="critical", confidence=0.95,
                message=(f"Data returned by server '{frag.server_id}' via {frag.source_method} "
                          f"is being forwarded into a tool call on server '{srv.server_id}'."),
                metadata={"origin_server": frag.server_id,
                          "target_server": srv.server_id,
                          "excerpt": frag.excerpt},
            ))

        # Egress check: URLs in args must sit inside server-declared allowed_hosts
        for u in _URL_RE.findall(_stringify(args)):
            ok, why = EgressController(EgressPolicy(allowed_hosts=td.allowed_hosts)).check(u)
            if not ok:
                ev.add_detection(Detection(
                    detector="mcp.egress", category="network_security",
                    subcategory="mcp_egress_denied", severity="critical", confidence=1.0,
                    message=f"MCP tool URL denied: {why}",
                    metadata={"allowed": td.allowed_hosts},
                ))

        result = self._decide(ev)
        if pinned.requires_human_approval and result.decision.severity < Decision.REQUIRE_APPROVAL.severity:
            result.decision = Decision.REQUIRE_APPROVAL
            ev.decision = result.decision
            result.reasons.append("Pinned tool requires human approval")
        return result

    def _check_uri_against_srv(self, uri: str, srv: MCPServerDef, actor: Actor):
        if not isinstance(uri, str) or not uri:
            return self._deny("Resource URI must be a nonempty string", "critical",
                              "network_security", "mcp_invalid_resource_uri")
        try:
            parsed = urllib.parse.urlparse(uri)
        except ValueError:
            return self._deny("Resource URI is malformed", "critical",
                              "network_security", "mcp_invalid_resource_uri")
        if parsed.scheme in ("http", "https"):
            ok, why = EgressController(EgressPolicy(allowed_hosts=srv.allowed_hosts)).check(uri)
            if not ok:
                return self._deny(f"MCP resource denied: {why}", "critical",
                                  "network_security", "mcp_resource_egress_denied")
        elif parsed.scheme in ("file", "data", "javascript", "ftp") or not parsed.scheme:
            return self._deny("Resource URI scheme is not allowed", "critical",
                              "network_security", "mcp_resource_scheme_denied")
        elif not any(fnmatch.fnmatchcase(uri, pattern) for pattern in srv.allowed_resource_uris):
            return self._deny("Custom resource URI is not allowlisted", "critical",
                              "network_security", "mcp_resource_scope_denied")
        return InspectionResult(decision=Decision.ALLOW)

    # ------------------- helpers -------------------

    def _input_event(self, actor, text, srv, method=""):
        return SecurityEvent(
            actor=actor,
            source=Source(kind=SourceKind.AGENT_MESSAGE, origin=f"mcp:{srv.server_id}:{method}",
                           tenant=actor.tenant),
            input_text=text,
            destination=f"llm:from_mcp:{srv.server_id}",
        )

    def _output_event(self, actor, text, srv):
        return SecurityEvent(
            actor=actor,
            source=Source(kind=SourceKind.TOOL_RESULT, origin=f"mcp:{srv.server_id}",
                           tenant=actor.tenant),
            output_text=text,
            destination=f"llm:from_mcp:{srv.server_id}",
        )

    def _run_input_detectors(self, ev: SecurityEvent) -> None:
        ev.trust_of_input = TrustLevel.UNTRUSTED
        for d in self.pi.scan(ev):
            ev.add_detection(d)

    def _decide(self, ev: SecurityEvent) -> InspectionResult:
        # Simple decision: any critical severity => block; any high => require approval;
        # any medium => sanitize; otherwise allow.
        dec = Decision.ALLOW
        for d in ev.detections:
            if d.severity == "critical" and dec.severity < Decision.BLOCK.severity:
                dec = Decision.BLOCK
            elif d.severity == "high" and dec.severity < Decision.REQUIRE_APPROVAL.severity:
                dec = Decision.REQUIRE_APPROVAL
            elif d.severity == "medium" and dec.severity < Decision.SANITIZE.severity:
                dec = Decision.SANITIZE
        ev.decision = dec
        reasons = [f"{d.category}/{d.subcategory} sev={d.severity}"
                    for d in ev.detections[:6]]
        return InspectionResult(decision=dec, detections=list(ev.detections),
                                 reasons=reasons, event=ev)

    def _merge(self, structural, content):
        decision = max((structural.decision, content.decision), key=lambda d: d.severity)
        detections = structural.detections + content.detections
        event = content.event
        if event is not None:
            event.detections = detections
            event.decision = decision
        return InspectionResult(decision=decision, detections=detections,
                                reasons=structural.reasons + content.reasons, event=event)

    def _package(self, detections: list[Detection],
                  category_hint: str = "") -> InspectionResult:
        dec = Decision.ALLOW
        for d in detections:
            if d.severity == "critical" and dec.severity < Decision.BLOCK.severity:
                dec = Decision.BLOCK
            elif d.severity == "high" and dec.severity < Decision.REQUIRE_APPROVAL.severity:
                dec = Decision.REQUIRE_APPROVAL
            elif d.severity == "medium" and dec.severity < Decision.SANITIZE.severity:
                dec = Decision.SANITIZE
        reasons = [f"{d.category}/{d.subcategory} sev={d.severity}" for d in detections[:6]]
        return InspectionResult(decision=dec, detections=detections, reasons=reasons)

    def _deny(self, msg: str, severity: str, category: str, subcategory: str
              ) -> InspectionResult:
        d = Detection(detector="mcp.gateway", category=category,
                       subcategory=subcategory, severity=severity, confidence=1.0,
                       message=msg)
        dec = Decision.BLOCK if severity == "critical" else Decision.REQUIRE_APPROVAL
        return InspectionResult(decision=dec, detections=[d], reasons=[msg])


# --------------------------------------------------------------------------- #
# text extraction helpers
# --------------------------------------------------------------------------- #

def _stringify(obj: Any) -> str:
    import json as _json
    if isinstance(obj, str):
        return obj
    try:
        return _json.dumps(obj, default=str)
    except Exception:
        return str(obj)


def _extract_all_text(obj: Any) -> str:
    """Recursively concatenate every string leaf — used for scanning JSON params/results."""
    if isinstance(obj, str):
        return obj
    if isinstance(obj, dict):
        return "\n".join(_extract_all_text(v) for v in obj.values())
    if isinstance(obj, (list, tuple)):
        return "\n".join(_extract_all_text(v) for v in obj)
    return ""
