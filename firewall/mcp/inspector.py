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

    def __init__(self, min_len: int = 24, window: int = 500):
        self.min_len = min_len
        self.by_session: dict[str, deque[_FlowFragment]] = defaultdict(
            lambda: deque(maxlen=window)
        )

    def observe_result(self, session_id: str, server_id: str,
                       method: str, content: Any) -> None:
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
            # An unknown server is still allowed to be observed, but every
            # message from it is treated as untrusted and non-privileged.
            srv = MCPServerDef(server_id=msg.server_id, name=msg.server_id,
                                allowed_capabilities=[], allow_sampling=False)

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
            # Sampling params include a messages array — treat everything as untrusted
            text = _extract_all_text(msg.params or {})
            ev = self._input_event(actor, text, srv, method=msg.method)
            self._run_input_detectors(ev)
            return self._decide(ev)

        # Responses to earlier client requests
        if msg.is_response():
            # Prefer method-specific handlers by re-deriving intent from result shape
            r = msg.result
            if isinstance(r, dict) and "tools" in r:
                return self._inspect_tools_list(msg, srv, actor, r)
            if isinstance(r, dict) and "prompts" in r:
                return self._inspect_prompts_list(msg, srv, actor, r)
            if isinstance(r, dict) and "resources" in r:
                return self._inspect_resources_list(msg, srv, actor, r)
            if isinstance(r, dict) and "contents" in r:
                return self._inspect_resources_read(msg, srv, actor, r)
            if isinstance(r, dict) and ("content" in r or "isError" in r):
                return self._inspect_tool_call_result(msg, srv, actor, r)
            # generic response — DLP + output_sec on the JSON-stringified body
            ev = self._output_event(actor, _stringify(r), srv)
            for d in self.dlp.scan(ev):  ev.add_detection(d)
            for d in self.out.scan(ev):  ev.add_detection(d)
            return self._decide(ev)

        # notifications / progress / logging
        return InspectionResult(decision=Decision.ALLOW)

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
                    subcategory="tool_unpinned", severity="high", confidence=0.9,
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
            if status == "drifted":
                detections.append(Detection(
                    detector="mcp.registry", category="supply_chain",
                    subcategory="prompt_drift", severity="high", confidence=1.0,
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
        text = "\n\n".join(str(c.get("text", "")) for c in contents if isinstance(c, dict))
        ev = self._input_event(actor, text, srv, method=msg.method)
        self._run_input_detectors(ev)
        for d in self.dlp.scan(ev):
            ev.add_detection(d)
        # Track flow for later confused-deputy check
        self.data_flow.observe_result(
            actor.session_id or actor.user_id, srv.server_id, msg.method, text,
        )
        return self._decide(ev)

    def _inspect_tool_call_result(self, msg, srv, actor, result):
        # Tool result — content is untrusted, may carry secondary injection / secrets / exploit output
        content_pieces = result.get("content", []) or []
        text = ""
        for piece in content_pieces:
            if isinstance(piece, dict):
                text += "\n" + str(piece.get("text", ""))
            else:
                text += "\n" + str(piece)
        ev = self._output_event(actor, text, srv)
        # Model output detectors AND input detectors run — the result IS input to the LLM
        for d in self.pi.scan(ev):  ev.add_detection(d)
        for d in self.dlp.scan(ev): ev.add_detection(d)
        for d in self.out.scan(ev): ev.add_detection(d)
        self.data_flow.observe_result(
            actor.session_id or actor.user_id, srv.server_id, msg.method or "tools/call", text,
        )
        return self._decide(ev)

    # ------------------- outbound (client -> server) -------------------

    def _inspect_outbound(self, msg: MCPMessage, srv: MCPServerDef,
                           actor: Actor) -> InspectionResult:
        # initialize — client is about to open a session. Nothing risky per se.
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
        td = ToolDefinition(
            name=name,
            description="",
            risk_level=(pinned.risk_level if pinned else "medium"),
            allowed_hosts=(pinned.allowed_hosts if pinned else srv.allowed_hosts),
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
        leaks = self.data_flow.check_leak(actor.session_id or actor.user_id,
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
        if td.allowed_hosts:
            for u in _URL_RE.findall(_stringify(args)):
                host = urllib.parse.urlparse(u).hostname or ""
                if not any(fnmatch.fnmatch(host, pat) for pat in td.allowed_hosts):
                    ev.add_detection(Detection(
                        detector="mcp.egress", category="network_security",
                        subcategory="mcp_egress_denied",
                        severity="high", confidence=0.95,
                        message=f"URL {u} in MCP tool arg not in server allowed_hosts.",
                        metadata={"host": host, "allowed": td.allowed_hosts},
                    ))

        return self._decide(ev)

    def _check_uri_against_srv(self, uri: str, srv: MCPServerDef, actor: Actor):
        if not srv.allowed_hosts:
            return InspectionResult(decision=Decision.ALLOW)
        parsed = urllib.parse.urlparse(uri)
        host = parsed.hostname or ""
        if parsed.scheme in ("http", "https") and host \
                and not any(fnmatch.fnmatch(host, pat) for pat in srv.allowed_hosts):
            return self._deny(
                f"MCP resource {uri} not in server allowed_hosts.",
                severity="high", category="network_security",
                subcategory="mcp_resource_egress_denied",
            )
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
