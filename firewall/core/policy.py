"""Deterministic, auditable policy engine.

Policies are expressed as simple JSON-serializable rules. Each rule has
a match block and an action. Matching is deterministic; the first rule
that fires whose action is more severe than the current decision wins
(later rules can only escalate, never downgrade). This makes policy
evaluation predictable and auditable — the final decision always has a
concrete list of matched rules and reasons.
"""
from __future__ import annotations

import fnmatch
import json
import operator
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

from firewall.core.events import DataClassification, Decision, SecurityEvent, TrustLevel


# ---------------------------------------------------------------------------
# Rule matching primitives
# ---------------------------------------------------------------------------

_OPS: dict[str, Callable[[Any, Any], bool]] = {
    "eq":       operator.eq,
    "neq":      operator.ne,
    "gt":       operator.gt,
    "gte":      operator.ge,
    "lt":       operator.lt,
    "lte":      operator.le,
    "in":       lambda a, b: a in b,
    "not_in":   lambda a, b: a not in b,
    "contains": lambda a, b: b in a if a is not None else False,
    "glob":     lambda a, b: bool(a) and fnmatch.fnmatch(str(a), b),
    "regex":    lambda a, b: bool(a) and re.search(b, str(a)) is not None,
    "any":      lambda a, b: any(item in b for item in (a or [])),
    "all":      lambda a, b: all(item in b for item in (a or [])),
    "has":      lambda a, b: b in (a or []),
    "empty":    lambda a, _b: not a,
    "nonempty": lambda a, _b: bool(a),
}


def _dotted(obj: Any, path: str) -> Any:
    """Resolve a dotted path against an object, supporting attrs and dict keys."""
    cur = obj
    for part in path.split("."):
        if cur is None:
            return None
        if isinstance(cur, dict):
            cur = cur.get(part)
        else:
            cur = getattr(cur, part, None)
    return cur


def _match_condition(event: SecurityEvent, cond: dict[str, Any]) -> bool:
    field_path = cond.get("field")
    op = cond.get("op", "eq")
    value = cond.get("value")
    if field_path is None:
        # composite
        if "any_of" in cond:
            return any(_match_condition(event, c) for c in cond["any_of"])
        if "all_of" in cond:
            return all(_match_condition(event, c) for c in cond["all_of"])
        if "not" in cond:
            return not _match_condition(event, cond["not"])
        return False
    actual = _dotted(event, field_path)
    # convenience: match a detection subfield across all detections
    if field_path.startswith("detections.") and isinstance(actual, list) is False:
        if hasattr(event, "detections"):
            sub = field_path.split(".", 1)[1]
            vals = [_dotted(d, sub) for d in event.detections]
            fn = _OPS.get(op)
            if fn is None:
                return False
            return any(fn(v, value) for v in vals)
    # Special: enums by name
    if hasattr(actual, "value"):
        actual = actual.value if not isinstance(actual, (TrustLevel, DataClassification)) else int(actual)
    fn = _OPS.get(op)
    if fn is None:
        return False
    try:
        return bool(fn(actual, value))
    except Exception:
        return False


@dataclass
class PolicyRule:
    id: str
    description: str = ""
    when: dict[str, Any] = field(default_factory=dict)   # composite condition
    action: str = "allow"                                  # allow, sanitize, require_approval, block
    approver: str | None = None
    tags: list[str] = field(default_factory=list)
    priority: int = 100

    def action_decision(self) -> Decision:
        return Decision(self.action)

    def matches(self, event: SecurityEvent) -> bool:
        if not self.when:
            return False
        return _match_condition(event, self.when)


@dataclass
class Policy:
    name: str
    rules: list[PolicyRule] = field(default_factory=list)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Policy":
        rules = [PolicyRule(**r) for r in data.get("rules", [])]
        return cls(name=data.get("name", "policy"), rules=rules)

    @classmethod
    def from_json(cls, path: str | Path) -> "Policy":
        return cls.from_dict(json.loads(Path(path).read_text()))


class PolicyEngine:
    """Evaluates one or more Policy objects against an event."""

    def __init__(self, policies: list[Policy] | None = None):
        self.policies = policies or []

    def add(self, policy: Policy) -> None:
        self.policies.append(policy)

    def evaluate(self, event: SecurityEvent) -> Decision:
        best = event.decision
        for policy in self.policies:
            for rule in sorted(policy.rules, key=lambda r: -r.priority):
                if rule.matches(event):
                    event.matched_policies.append(f"{policy.name}:{rule.id}")
                    dec = rule.action_decision()
                    if dec.severity > best.severity:
                        best = dec
                        event.reasons.append(
                            f"policy[{policy.name}:{rule.id}] -> {dec.value}"
                            + (f" ({rule.description})" if rule.description else "")
                        )
                    if rule.approver:
                        event.approval_required_from = rule.approver
        event.decision = best
        return best


# ---------------------------------------------------------------------------
# Default baseline policy — sensible defense-in-depth defaults
# ---------------------------------------------------------------------------

def default_baseline_policy() -> Policy:
    return Policy(
        name="baseline",
        rules=[
            PolicyRule(
                id="critical_detection_blocks",
                description="Any critical-severity detection blocks the request.",
                when={"field": "detections.severity", "op": "eq", "value": "critical"},
                action="block", priority=1000,
            ),
            PolicyRule(
                id="high_risk_score",
                description="Risk score >= 85 blocks.",
                when={"field": "risk_score", "op": "gte", "value": 85},
                action="block", priority=900,
            ),
            PolicyRule(
                id="medium_high_risk_approval",
                description="Risk score >= 65 requires approval.",
                when={"field": "risk_score", "op": "gte", "value": 65},
                action="require_approval", priority=800, approver="security",
            ),
            PolicyRule(
                id="secret_egress_blocked",
                description="Secrets must not egress to an external destination.",
                when={"all_of": [
                    {"field": "detections.category", "op": "eq", "value": "sensitive_data"},
                    {"field": "detections.subcategory", "op": "eq", "value": "secret"},
                    {"field": "destination", "op": "regex", "value": r"^(http|external|network|email|tool)"},
                ]},
                action="block", priority=950,
            ),
            PolicyRule(
                id="untrusted_instruction_no_privileged_tool",
                description="Untrusted content requesting a privileged tool -> block.",
                when={"all_of": [
                    {"field": "trust_of_input", "op": "lte", "value": int(TrustLevel.UNTRUSTED)},
                    {"field": "tool_def.risk_level", "op": "in", "value": ["high", "critical"]},
                ]},
                action="block", priority=940,
            ),
            PolicyRule(
                id="critical_tool_requires_approval",
                description="Critical-risk tools always require human approval.",
                when={"field": "tool_def.risk_level", "op": "eq", "value": "critical"},
                action="require_approval", priority=880, approver="human",
            ),
            PolicyRule(
                id="prompt_injection_high",
                description="High-confidence prompt injection -> sanitize+approval.",
                when={"all_of": [
                    {"field": "detections.category", "op": "eq", "value": "prompt_injection"},
                    {"field": "detections.severity", "op": "in", "value": ["high", "critical"]},
                ]},
                action="require_approval", priority=700, approver="security",
            ),
            PolicyRule(
                id="prompt_injection_any_sanitize",
                description="Any medium+ prompt injection detection sanitizes the input.",
                when={"all_of": [
                    {"field": "detections.category", "op": "eq", "value": "prompt_injection"},
                    {"field": "detections.severity", "op": "in", "value": ["medium", "high", "critical"]},
                ]},
                action="sanitize", priority=500,
            ),
            PolicyRule(
                id="pii_egress_sanitize",
                description="PII being sent to an external destination is sanitized.",
                when={"all_of": [
                    {"field": "detections.subcategory", "op": "eq", "value": "pii"},
                    {"field": "destination", "op": "regex", "value": r"^(http|external|network|email)"},
                ]},
                action="sanitize", priority=600,
            ),
        ],
    )
