"""Security inspection, policy enforcement, and auditing for input, output, and tools."""
from __future__ import annotations

from dataclasses import replace
from functools import wraps

from firewall.core.deadline import InspectionTimeout, inspection_budget, positive_seconds, remaining_seconds
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
from firewall.enforcement.output_validators import OutputConstraints
from firewall.ml.classifier import MLDetector
from firewall.enforcement.tool_firewall import (
    ApprovalRequired, ToolBlocked, ToolFirewall,
)


def _bounded_event(method):
    @wraps(method)
    def inspect(self, event):
        try:
            with inspection_budget(self.inspection_timeout):
                result = method(self, event)
                remaining_seconds()
                return result
        except InspectionTimeout:
            event.decision = Decision.BLOCK
            event.add_detection(Detection(detector="gateway.deadline", category="unbounded_consumption",
                subcategory="inspection_timeout", severity="critical", confidence=1.0,
                message="Inspection deadline exceeded; request withheld"))
            event.reasons.append("Inspection deadline exceeded")
            self.audit.write(event)
            return event
    return inspect


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
        injection_classifier=None,
        output_constraints: OutputConstraints | None = None,
        output_validators: tuple[Callable[[SecurityEvent], bool], ...] = (),
        inspection_timeout: float = 10,
        audit_log: AuditLog | None = None,
    ):
        self.inspection_timeout = positive_seconds(inspection_timeout)
        if audit_log is not None and (audit_path is not None or audit_echo):
            raise ValueError("Configure audit_log or audit_path/audit_echo, not both")
        self.audit = audit_log if audit_log is not None else AuditLog(path=audit_path, echo=audit_echo)
        self.policy = PolicyEngine(policies or [default_baseline_policy()])
        self.risk = RiskEngine()
        self.behavior = BehaviorEngine()
        self.trust = trust_resolver or TrustResolver()
        self.supply_chain = supply_chain
        self.rate = RateLimiter()
        self.semantic = MLDetector(injection_classifier) if injection_classifier is not None else None
        self.output_constraints = output_constraints or OutputConstraints()
        self.output_validators = tuple(output_validators)

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
            output_constraints=self.output_constraints,
            injection_detector=self.semantic,
        )


    def register_tool(self, td: ToolDefinition, fn) -> None:
        self.tool_firewall.register(td, fn)

    @_bounded_event
    def process_input(self, event: SecurityEvent) -> SecurityEvent:
        """Run the input-side pipeline. Sets event.decision and event.sanitized_text.

        Callers should check event.decision before dispatching to the model.
        If decision == SANITIZE, use event.sanitized_text as the input instead.
        """
        event.stage = "input"
        if self._reject_oversize(event):
            return event
        self._normalize(event)
        self._provenance(event)
        self._run_input_detectors(event)
        self._score_and_decide(event)
        remaining_seconds()
        self.audit.write(event)
        return event

    @_bounded_event
    def process_output(self, event: SecurityEvent) -> SecurityEvent:
        """Run the output-side pipeline on a fresh event carrying output_text.

        Should be called with the model's raw output as event.output_text.
        The gateway inspects, classifies, redacts if needed, and applies
        policy. Callers must not deliver output_text if decision == BLOCK.
        """
        event.stage = "output"
        if self._reject_oversize(event):
            return event
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
        for d in self.ai_spec.scan(event):
            event.add_detection(d)
        for d in self.infra.scan(event):
            event.add_detection(d)
        for d in self.agentic.scan(event):
            event.add_detection(d)
        self._validate_output(event)
        self.behavior.observe(event, action="model_output", detail=event.model)
        for d in self.behavior.match_chains(event):
            event.add_detection(d)

        self._score_and_decide(event)

        if event.decision in (Decision.SANITIZE, Decision.REQUIRE_APPROVAL):
            event.sanitized_text = self.dlp.redact(event.output_text or "")

        remaining_seconds()
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
            tool_call=ToolCall(tool=tool, arguments={} if arguments is None else arguments),
        )
        with inspection_budget(self.inspection_timeout):
            return self.tool_firewall.call(ev)


    def _reject_oversize(self, event: SecurityEvent) -> bool:
        signals = self.consume.scan(event)
        if any(d.subcategory == "inspection_budget_exceeded" for d in signals):
            event.detections.extend(signals)
            event.decision = Decision.BLOCK
            event.reasons.append("Inspection resource budget exceeded")
            self.audit.write(event)
            return True
        event.detections.extend(signals)
        return False

    def _normalize(self, event: SecurityEvent) -> None:
        # Strip attacker-supplied boundary markers before wrapping untrusted documents.
        for doc in event.context_docs:
            if doc.source and self.trust.is_untrusted_kind(doc.source.kind):
                doc.content = wrap_untrusted(doc.content, doc.source)

    def _provenance(self, event: SecurityEvent) -> None:
        if event.source is not None:
            event.trust_of_input = self.trust.resolve(event.source)
        else:
            event.trust_of_input = TrustLevel.USER if event.actor.authenticated else TrustLevel.ANONYMOUS

        if event.trust_of_input == TrustLevel.UNTRUSTED and event.input_text:
            self.behavior.observe(event, ACT_UNTRUSTED_INPUT, "input")

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
        if self.semantic is not None:
            event.detections.extend(self.semantic.scan(event))
        # Misinformation is output-only in scope; skipped here.
        if self.supply_chain:
            for d in self.supply_chain.scan(event):
                event.add_detection(d)
        for act in self.behavior.infer_actions(event):
            self.behavior.observe(event, act, event.destination or "input")
        for d in self.behavior.match_chains(event):
            event.add_detection(d)

    def _validate_output(self, event: SecurityEvent, complete: bool = True) -> None:
        constraints = self.output_constraints if complete else replace(self.output_constraints, schema=None)
        event.detections.extend(constraints.scan(event))
        for validator in self.output_validators if complete else ():
            try:
                valid = validator(event) is True
            except Exception:
                valid = False
            if not valid:
                event.add_detection(Detection(
                    detector="application_output", category="output_security",
                    subcategory="application_validator_rejected", severity="critical",
                    confidence=1.0, message="Application output validator rejected the response",
                ))

    def _score_and_decide(self, event: SecurityEvent) -> None:
        for det in event.detections:
            k = det.metadata.get("kind", "")
            if det.subcategory == "secret":
                from firewall.core.events import DataClassification
                event.classifications.append(DataClassification.SECRET)
            elif det.subcategory == "pii":
                from firewall.core.events import DataClassification
                event.classifications.append(DataClassification.CONFIDENTIAL)
        self.risk.score(event)
        self.policy.evaluate(event)
        # Risk-based fallback (only escalates, never downgrades)
        r_dec = self.risk.score_to_decision(event.risk_score)
        if r_dec.severity > event.decision.severity:
            event.decision = r_dec
            event.reasons.append(f"risk_score={event.risk_score} -> {r_dec.value}")
        if event.decision == Decision.SANITIZE and event.input_text:
            event.sanitized_text = self.dlp.redact(event.input_text)


    def close(self) -> None:
        self.audit.close()
