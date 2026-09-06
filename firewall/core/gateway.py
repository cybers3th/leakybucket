"""Central security pipeline / gateway.

Runs every request through:

    INPUT → NORMALIZE → CONTEXT/PROVENANCE → DETECTORS → RISK → POLICY
    → ALLOW/BLOCK/SANITIZE/APPROVAL → LLM or TOOL → OUTPUT INSPECTION
    → TOOL/ACTION INSPECTION → FINAL ENFORCEMENT → AUDIT

Every stage annotates the SecurityEvent that flows through, so nothing
is thrown away — every audit line reconstructs the full decision path.
"""
from __future__ import annotations

from dataclasses import replace
from typing import Any, Callable

from firewall.core.audit import AuditLog
from firewall.core.behavior import BehaviorEngine, ACT_UNTRUSTED_INPUT
from firewall.core.events import (
    Decision, Detection, SecurityEvent, Source, SourceKind, TrustLevel,
    Message, ToolCall, ToolDefinition, ToolResult,
)
from firewall.core.policy import Policy, PolicyEngine, default_baseline_policy
from firewall.core.risk import RiskEngine
from firewall.core.trust import TrustResolver, wrap_untrusted
from firewall.detectors import (
    PromptInjectionDetector, SensitiveDataDetector, OutputSecurityDetector,
    SystemPromptLeakDetector, RAGSecurityDetector, MisinformationDetector,
    ToolSecurityDetector, SupplyChainDetector, PoisoningDetector,
    ConsumptionDetector, AISpecificDetector, InfraExposureDetector,
    AgenticSecurityDetector,
)
from firewall.enforcement.rate_limits import RateLimiter
from firewall.enforcement.tool_firewall import (
    ApprovalRequired, ToolBlocked, ToolFirewall,
)


class Gateway:
    """The primary application-facing entrypoint."""

    def __init__(
        self,
        policies: list[Policy] | None = None,
        audit_path: str | None = None,
        audit_echo: bool = False,
        trust_resolver: TrustResolver | None = None,
        supply_chain: SupplyChainDetector | None = None,
        approval_callback: Callable[[SecurityEvent], bool] | None = None,
    ):
        self.audit = AuditLog(path=audit_path, echo=audit_echo)
        self.policy = PolicyEngine(policies or [default_baseline_policy()])
        self.risk = RiskEngine()
        self.behavior = BehaviorEngine()
        self.trust = trust_resolver or TrustResolver()
        self.supply_chain = supply_chain
        self.rate = RateLimiter()

        self.pi = PromptInjectionDetector()
        self.dlp = SensitiveDataDetector()
        self.out_sec = OutputSecurityDetector()
        self.sys_leak = SystemPromptLeakDetector()
        self.rag = RAGSecurityDetector()
        self.misinfo = MisinformationDetector()
        self.tool_sec = ToolSecurityDetector()
        self.poison = PoisoningDetector()
        self.consume = ConsumptionDetector()
        self.ai_spec = AISpecificDetector()
        self.infra   = InfraExposureDetector()
        self.agentic = AgenticSecurityDetector()

        self.tool_firewall = ToolFirewall(
            policy_engine=self.policy, risk_engine=self.risk,
            behavior=self.behavior, audit=self.audit,
            trust=self.trust, supply_chain=self.supply_chain,
            rate_limiter=self.rate,
            approval_callback=approval_callback,
        )

    # =========================================================================
    # Public API
    # =========================================================================

    def register_tool(self, td: ToolDefinition, fn) -> None:
        self.tool_firewall.register(td, fn)

    def process_input(self, event: SecurityEvent) -> SecurityEvent:
        """Run the input-side pipeline. Sets event.decision and event.sanitized_text.

        Callers should check event.decision before dispatching to the model.
        If decision == SANITIZE, use event.sanitized_text as the input instead.
        """
        event.stage = "input"
        self._normalize(event)
        self._provenance(event)
        self._run_input_detectors(event)
        self._score_and_decide(event)
        self.audit.write(event)
        return event

    def process_output(self, event: SecurityEvent) -> SecurityEvent:
        """Run the output-side pipeline on a fresh event carrying output_text.

        Should be called with the model's raw output as event.output_text.
        The gateway inspects, classifies, redacts if needed, and applies
        policy. Callers must not deliver output_text if decision == BLOCK.
        """
        event.stage = "output"
        # Output is model-generated → untrusted from the perspective of downstream
        if event.source is None:
            event.source = Source(kind=SourceKind.MODEL_OUTPUT, origin=event.model or "model")
        event.trust_of_input = TrustLevel.UNTRUSTED

        for d in self.dlp.scan(event):
            event.add_detection(d)
        for d in self.out_sec.scan(event):
            event.add_detection(d)
        for d in self.sys_leak.scan(event):
            event.add_detection(d)
        for d in self.misinfo.scan(event):
            event.add_detection(d)
        for d in self.consume.scan(event):
            event.add_detection(d)
        for d in self.ai_spec.scan(event):
            event.add_detection(d)
        for d in self.infra.scan(event):
            event.add_detection(d)
        for d in self.agentic.scan(event):
            event.add_detection(d)
        # Update behavior — output stage may raise the chain
        self.behavior.observe(event, action="model_output", detail=event.model)
        for d in self.behavior.match_chains(event):
            event.add_detection(d)

        self._score_and_decide(event)

        # If sanitize/require_approval, redact secrets/PII from output_text
        if event.decision in (Decision.SANITIZE, Decision.REQUIRE_APPROVAL):
            event.sanitized_text = self.dlp.redact(event.output_text or "")

        self.audit.write(event)
        return event

    def request_tool(
        self,
        actor,
        tool: str,
        arguments: dict[str, Any] | None = None,
        source: Source | None = None,
    ) -> ToolResult:
        """Convenience wrapper. Raises ToolBlocked / ApprovalRequired on denial."""
        ev = SecurityEvent(
            actor=actor,
            source=source,
            tool_call=ToolCall(tool=tool, arguments=arguments or {}),
        )
        return self.tool_firewall.call(ev)

    # =========================================================================
    # Internal stages
    # =========================================================================

    def _normalize(self, event: SecurityEvent) -> None:
        # We wrap untrusted context docs so downstream never mistakes them
        # for authoritative instructions. The wrapping-marker stripper runs
        # first on raw content so an attacker can't inject their own closer.
        for doc in event.context_docs:
            if doc.source and self.trust.is_untrusted_kind(doc.source.kind):
                doc.content = wrap_untrusted(doc.content, doc.source)

    def _provenance(self, event: SecurityEvent) -> None:
        # Resolve trust of the primary input
        if event.source is not None:
            event.trust_of_input = self.trust.resolve(event.source)
        else:
            # Best-effort default: user input
            event.trust_of_input = TrustLevel.USER if event.actor.authenticated else TrustLevel.ANONYMOUS

        if event.trust_of_input == TrustLevel.UNTRUSTED and event.input_text:
            self.behavior.observe(event, ACT_UNTRUSTED_INPUT, "input")

        # Poisoning ingest-style checks on the context docs
        for d in self.poison.scan(event):
            event.add_detection(d)

    def _run_input_detectors(self, event: SecurityEvent) -> None:
        for d in self.pi.scan(event):
            event.add_detection(d)
        for d in self.dlp.scan(event):
            event.add_detection(d)
        for d in self.rag.scan(event):
            event.add_detection(d)
        for d in self.sys_leak.scan(event):
            event.add_detection(d)
        for d in self.consume.scan(event):
            event.add_detection(d)
        # Output-security patterns are also relevant on the input side —
        # a user prompt that contains a SQLi/command payload should not silently
        # pass through to a downstream tool. The detector already knows how to
        # inspect input_text / tool_args / tool_result.
        for d in self.out_sec.scan(event):
            event.add_detection(d)
        for d in self.ai_spec.scan(event):
            event.add_detection(d)
        for d in self.infra.scan(event):
            event.add_detection(d)
        for d in self.agentic.scan(event):
            event.add_detection(d)
        # Misinformation is output-only in scope; skipped here.
        if self.supply_chain:
            for d in self.supply_chain.scan(event):
                event.add_detection(d)
        # Feed inferred behavior actions from this event
        for act in self.behavior.infer_actions(event):
            self.behavior.observe(event, act, event.destination or "input")
        # Attack-chain check with the current session state
        for d in self.behavior.match_chains(event):
            event.add_detection(d)

    def _score_and_decide(self, event: SecurityEvent) -> None:
        # Track classifications from detections
        for det in event.detections:
            k = det.metadata.get("kind", "")
            if det.subcategory == "secret":
                from firewall.core.events import DataClassification
                event.classifications.append(DataClassification.SECRET)
            elif det.subcategory == "pii":
                from firewall.core.events import DataClassification
                event.classifications.append(DataClassification.CONFIDENTIAL)
        self.risk.score(event)
        # Policy — the deterministic final say
        self.policy.evaluate(event)
        # Risk-based fallback (only escalates, never downgrades)
        r_dec = self.risk.score_to_decision(event.risk_score)
        if r_dec.severity > event.decision.severity:
            event.decision = r_dec
            event.reasons.append(f"risk_score={event.risk_score} -> {r_dec.value}")
        # If we sanitized because of PI or DLP, produce a redacted input
        if event.decision == Decision.SANITIZE and event.input_text:
            event.sanitized_text = self.dlp.redact(event.input_text)

    # =========================================================================
    # Helpers
    # =========================================================================

    def close(self) -> None:
        self.audit.close()
