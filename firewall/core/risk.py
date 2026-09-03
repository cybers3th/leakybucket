"""Risk engine — combines detection signals + context signals into a score 0..100.

The score is intentionally NOT the sole security boundary. Hard policy rules
can block regardless of the score, and any detection at critical severity
will independently trigger blocking through policy.
"""
from __future__ import annotations

from firewall.core.events import (
    DataClassification, Decision, SecurityEvent, TrustLevel,
)


# Weight table: category slug -> contribution multiplier applied to per-detection severity
CATEGORY_WEIGHT: dict[str, float] = {
    "prompt_injection":      1.0,
    "sensitive_data":        1.0,
    "output_security":       1.1,
    "excessive_agency":      1.2,
    "system_prompt_leak":    0.9,
    "rag_security":          1.0,
    "supply_chain":          0.9,
    "poisoning":             1.0,
    "misinformation":        0.6,
    "unbounded_consumption": 0.8,
    "tool_security":         1.1,
    "network_security":      1.1,
}


class RiskEngine:
    def __init__(self):
        pass

    def score(self, event: SecurityEvent) -> int:
        reasons: list[str] = []
        score = 0.0

        # Per-detection contribution
        for d in event.detections:
            w = CATEGORY_WEIGHT.get(d.category, 1.0)
            contrib = d.severity_int * d.confidence * w
            score += contrib
            reasons.append(
                f"{d.detector}:{d.category}/{d.subcategory or '-'} "
                f"sev={d.severity} conf={d.confidence:.2f} +{contrib:.1f}"
            )

        # Provenance modifier — untrusted content raises the ceiling
        trust = int(event.trust_of_input)
        if trust <= int(TrustLevel.UNTRUSTED):
            score += 15
            reasons.append("provenance: untrusted input +15")
        elif trust <= int(TrustLevel.ANONYMOUS):
            score += 5
            reasons.append("provenance: anonymous actor +5")

        # Destination modifier
        dest = (event.destination or "").lower()
        if dest.startswith("http") or "external" in dest or "network" in dest:
            score += 8
            reasons.append("destination: external +8")
        if "shell" in dest or "exec" in dest:
            score += 15
            reasons.append("destination: shell/exec +15")
        if "delete" in dest or "prod" in dest:
            score += 10
            reasons.append("destination: destructive/prod +10")

        # Tool sensitivity
        if event.tool_def:
            risk = event.tool_def.risk_level
            add = {"low": 0, "medium": 5, "high": 15, "critical": 25}.get(risk, 0)
            score += add
            reasons.append(f"tool_risk={risk} +{add}")
            if "delete" in event.tool_def.capabilities or "execute" in event.tool_def.capabilities:
                score += 10
                reasons.append("tool capability: destructive +10")

        # Data classification — only count if data is heading to an external/downstream destination,
        # or if we're inspecting the model's OUTPUT. Inbound PII from a user typing their own email
        # is not a leak.
        dest_l = (event.destination or "").lower()
        is_egress = (dest_l.startswith("http") or "external" in dest_l or "email" in dest_l
                     or "network" in dest_l or "tool:" in dest_l)
        if event.stage in ("output", "tool_pre", "tool_post") or is_egress:
            for c in event.classifications:
                if int(c) >= int(DataClassification.SECRET):
                    score += 20
                    reasons.append("data: SECRET egress +20")
                elif int(c) >= int(DataClassification.RESTRICTED):
                    score += 12
                    reasons.append("data: RESTRICTED egress +12")
                elif int(c) >= int(DataClassification.CONFIDENTIAL):
                    score += 6
                    reasons.append("data: CONFIDENTIAL egress +6")
        else:
            # secrets remain risky even on input (credential exposure), but at lower weight
            if any(int(c) >= int(DataClassification.SECRET) for c in event.classifications):
                score += 10
                reasons.append("data: SECRET in inbound +10")

        # Privilege risk — anonymous actor asking for high-impact ops
        if not event.actor.authenticated and event.tool_def and event.tool_def.risk_level in ("high", "critical"):
            score += 20
            reasons.append("privilege: unauthenticated actor on high-risk tool +20")

        score = max(0.0, min(100.0, score))
        event.risk_score = int(score)
        event.risk_reasons = reasons
        return event.risk_score

    def score_to_decision(self, score: int) -> Decision:
        # Suggested mapping; policy engine may override.
        if score >= 85: return Decision.BLOCK
        if score >= 65: return Decision.REQUIRE_APPROVAL
        if score >= 40: return Decision.SANITIZE
        return Decision.ALLOW
