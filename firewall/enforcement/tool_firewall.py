"""Tool firewall.

Sits in front of every tool/function invocation. Runs the full pipeline
around the call:

    identify actor → validate args → detect injection/secrets → determine target
    → risk score → policy → allow/block/approval → execute → inspect result
    → update behavior → audit.

The gateway can call `Gateway.request_tool(...)` for the higher-level
entrypoint; `ToolFirewall` handles the low-level enforcement + execution.
"""
from __future__ import annotations

import inspect
import time
import traceback
from typing import Any, Callable

from firewall.core.audit import AuditLog
from firewall.core.behavior import ACT_TOOL_CALL, BehaviorEngine
from firewall.core.events import (
    Decision, SecurityEvent, ToolCall, ToolDefinition, ToolResult,
    Source, SourceKind, TrustLevel,
)
from firewall.core.policy import PolicyEngine
from firewall.core.risk import RiskEngine
from firewall.core.trust import TrustResolver
from firewall.detectors.output_security import OutputSecurityDetector
from firewall.detectors.sensitive_data import SensitiveDataDetector
from firewall.detectors.supply_chain import SupplyChainDetector
from firewall.detectors.tool_security import ToolSecurityDetector
from firewall.enforcement.network import EgressController, EgressPolicy
from firewall.enforcement.rate_limits import RateLimiter


class ApprovalRequired(RuntimeError):
    def __init__(self, decision_reasons: list[str]):
        super().__init__("approval required")
        self.reasons = decision_reasons


class ToolBlocked(RuntimeError):
    def __init__(self, decision_reasons: list[str]):
        super().__init__("tool blocked")
        self.reasons = decision_reasons


class ToolFirewall:
    def __init__(
        self,
        policy_engine: PolicyEngine,
        risk_engine: RiskEngine,
        behavior: BehaviorEngine,
        audit: AuditLog,
        registry: dict[str, tuple[ToolDefinition, Callable[..., Any]]] | None = None,
        trust: TrustResolver | None = None,
        supply_chain: SupplyChainDetector | None = None,
        egress: EgressController | None = None,
        rate_limiter: RateLimiter | None = None,
        approval_callback: Callable[[SecurityEvent], bool] | None = None,
    ):
        self.policy = policy_engine
        self.risk = risk_engine
        self.behavior = behavior
        self.audit = audit
        self.registry = registry or {}
        self.trust = trust or TrustResolver()
        self.supply_chain = supply_chain
        self.egress = egress
        self.rate = rate_limiter or RateLimiter()
        self.approval_callback = approval_callback
        self._tool_sec = ToolSecurityDetector()
        self._data = SensitiveDataDetector()
        self._output = OutputSecurityDetector()

    # ---- registration ----
    def register(self, td: ToolDefinition, fn: Callable[..., Any]) -> None:
        self.registry[td.name] = (td, fn)

    # ---- main entrypoint ----
    def call(self, event: SecurityEvent) -> ToolResult:
        assert event.tool_call is not None, "ToolFirewall.call requires event.tool_call"
        tc = event.tool_call
        td, fn = self._resolve(tc.tool)
        event.tool_def = td
        event.destination = f"tool:{tc.tool}"
        event.stage = "tool_pre"

        # Rate limit per session:tool
        key = f"{event.actor.session_id or 'anon'}:{tc.tool}"
        ok, why = self.rate.allow(
            key,
            rate_per_minute=(td.rate_limit_per_minute if td else None),
            capacity=(td.rate_limit_per_minute if td else None),
        )
        if not ok:
            event.decision = Decision.BLOCK
            event.reasons.append(f"rate_limit: {why}")
            self.audit.write(event)
            raise ToolBlocked(event.reasons)

        # Detectors on the pre-call event
        for d in self._tool_sec.scan(event):
            event.add_detection(d)
        for d in self._data.scan(event):
            event.add_detection(d)
        if self.supply_chain:
            for d in self.supply_chain.scan(event):
                event.add_detection(d)

        # Egress check for URL arguments if the tool is network-capable
        if td and self.egress and "network" in (td.capabilities or []):
            for u in _extract_urls(tc.arguments):
                ok_url, why_url = self.egress.check(u)
                if not ok_url:
                    event.add_detection(_make_egress_detection(u, why_url))

        # Behavior: record intent
        self.behavior.observe(event, ACT_TOOL_CALL, tc.tool)
        for d in self.behavior.check_limits(event):
            event.add_detection(d)
        for d in self.behavior.match_chains(event):
            event.add_detection(d)

        # Trust of input
        if event.source:
            event.trust_of_input = self.trust.resolve(event.source)

        # Score + policy
        self.risk.score(event)
        self.policy.evaluate(event)

        # Tool metadata may force human approval
        if td and td.requires_human_approval and event.decision.severity < Decision.REQUIRE_APPROVAL.severity:
            event.decision = Decision.REQUIRE_APPROVAL
            event.approval_required_from = event.approval_required_from or "human"
            event.reasons.append("tool_def.requires_human_approval=True")

        self.audit.write(event)

        if event.decision == Decision.BLOCK:
            raise ToolBlocked(event.reasons)

        if event.decision == Decision.REQUIRE_APPROVAL:
            approved = False
            if self.approval_callback:
                try:
                    approved = bool(self.approval_callback(event))
                except Exception as e:
                    event.reasons.append(f"approval_callback error: {e}")
            if not approved:
                # Track a denied-approval count for behavior engine
                sid = event.actor.session_id or event.correlation_id
                self.behavior._s(sid).approvals_denied += 1
                raise ApprovalRequired(event.reasons)

        # Execute (either SANITIZE or ALLOW past this point)
        start = time.time()
        try:
            content = fn(**(tc.arguments or {}))
            ok = True
            err = None
        except Exception as e:
            content = None
            ok = False
            err = f"{type(e).__name__}: {e}\n{traceback.format_exc(limit=3)}"

        duration_ms = int((time.time() - start) * 1000)

        result = ToolResult(
            call_id=tc.call_id, tool=tc.tool, ok=ok, content=content,
            source=Source(kind=SourceKind.TOOL_RESULT, origin=tc.tool),
            duration_ms=duration_ms, error=err,
        )
        event.tool_result = result

        # Post-execution inspection
        event.stage = "tool_post"
        post_event = SecurityEvent(
            correlation_id=event.correlation_id,
            actor=event.actor,
            source=result.source,
            destination=event.destination,
            tool_call=tc, tool_result=result, tool_def=td,
            trust_of_input=TrustLevel.UNTRUSTED,
            stage="tool_post",
        )
        for d in self._data.scan(post_event):
            post_event.add_detection(d)
        for d in self._output.scan(post_event):
            post_event.add_detection(d)
        self.risk.score(post_event)
        self.policy.evaluate(post_event)
        # If the result itself is malicious (e.g. contains injection or shell payload),
        # sanitize/redact before returning
        if post_event.decision in (Decision.SANITIZE, Decision.REQUIRE_APPROVAL, Decision.BLOCK):
            if isinstance(result.content, str):
                result.content = self._data.redact(result.content)
            post_event.sanitized_text = str(result.content)[:2000]
        self.audit.write(post_event)

        return result

    # ---- internals ----
    def _resolve(self, name: str) -> tuple[ToolDefinition | None, Callable[..., Any] | None]:
        entry = self.registry.get(name)
        if not entry:
            def _missing(**_kw):
                raise KeyError(f"tool {name} not registered")
            return None, _missing
        return entry


def _make_egress_detection(url: str, why: str):
    from firewall.core.events import Detection
    return Detection(
        detector="egress", category="network_security",
        subcategory="egress_denied",
        severity="high", confidence=1.0,
        message=f"Egress denied for {url}: {why}",
        metadata={"url": url},
    )


def _extract_urls(obj: Any) -> list[str]:
    import re
    text = ""
    if isinstance(obj, str):
        text = obj
    else:
        try:
            import json as _json
            text = _json.dumps(obj, default=str)
        except Exception:
            text = str(obj)
    return re.findall(r"\bhttps?://[^\s'\"<>)]+", text)
