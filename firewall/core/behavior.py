"""Session-level behavior + attack-chain engine.

Individual events can be low-risk in isolation while their sequence is malicious.
This engine keeps per-session state and matches known attack-chain shapes,
raising a `attack_chain` detection when a suspicious combination fires.
"""
from __future__ import annotations

import time
from collections import defaultdict, deque
from dataclasses import dataclass, field
from typing import Deque

from firewall.core.events import Detection, SecurityEvent, TrustLevel


# Symbolic actions the behavior engine reasons about.
ACT_UNTRUSTED_INPUT     = "untrusted_input"
ACT_PROMPT_INJECTION    = "prompt_injection"
ACT_MEMORY_READ         = "memory_read"
ACT_MEMORY_WRITE        = "memory_write"
ACT_CREDENTIAL_ACCESS   = "credential_access"
ACT_DB_READ             = "db_read"
ACT_DB_WRITE            = "db_write"
ACT_FILE_READ           = "file_read"
ACT_FILE_WRITE          = "file_write"
ACT_SHELL_EXEC          = "shell_exec"
ACT_NETWORK_EGRESS      = "network_egress"
ACT_SEND_MESSAGE        = "send_message"
ACT_SECRET_IN_OUTPUT    = "secret_in_output"
ACT_TOOL_CALL           = "tool_call"
ACT_APPROVAL_BYPASS_TRY = "approval_bypass_try"


CHAIN_PATTERNS: list[tuple[str, list[str], str, str]] = [
    (
        "exfil_via_web",
        [ACT_UNTRUSTED_INPUT, ACT_PROMPT_INJECTION, ACT_CREDENTIAL_ACCESS, ACT_NETWORK_EGRESS],
        "critical",
        "Untrusted content injected instructions leading to credential access and external egress.",
    ),
    (
        "exfil_via_email",
        [ACT_UNTRUSTED_INPUT, ACT_PROMPT_INJECTION, ACT_DB_READ, ACT_SEND_MESSAGE],
        "critical",
        "Untrusted-input driven database read followed by outbound message.",
    ),
    (
        "poisoned_rag_to_shell",
        [ACT_UNTRUSTED_INPUT, ACT_PROMPT_INJECTION, ACT_SHELL_EXEC],
        "critical",
        "Poisoned retrieved content followed by shell execution attempt.",
    ),
    (
        "memory_poison_persist",
        [ACT_PROMPT_INJECTION, ACT_MEMORY_WRITE],
        "high",
        "Attempt to persist adversarial instructions into memory.",
    ),
    (
        "secret_leak_flow",
        [ACT_CREDENTIAL_ACCESS, ACT_SECRET_IN_OUTPUT],
        "high",
        "Secrets were read and then appeared in model output.",
    ),
    (
        "loop_pattern",
        [ACT_TOOL_CALL, ACT_TOOL_CALL, ACT_TOOL_CALL, ACT_TOOL_CALL, ACT_TOOL_CALL],
        "medium",
        "Repetitive tool calling — possible loop / unbounded consumption.",
    ),
    (
        "approval_bypass",
        [ACT_APPROVAL_BYPASS_TRY, ACT_TOOL_CALL],
        "high",
        "Actor attempted to bypass approval then invoked a tool.",
    ),
]


@dataclass
class SessionState:
    session_id: str
    actions: Deque[tuple[float, str, str]] = field(default_factory=lambda: deque(maxlen=200))
    tool_calls: int = 0
    tokens_in: int = 0
    tokens_out: int = 0
    model_calls: int = 0
    retrieval_calls: int = 0
    cost_micro: int = 0                # cost in micro-units
    started: float = field(default_factory=time.time)
    risk_accum: int = 0
    warnings: int = 0
    approvals_denied: int = 0

    def action_slugs(self) -> list[str]:
        return [a[1] for a in self.actions]


class BehaviorEngine:
    """Per-session behavior tracker + attack-chain matcher."""

    # Hard caps (defaults; overridable)
    DEFAULT_LIMITS = {
        "max_tool_calls":          50,
        "max_model_calls":         100,
        "max_tokens_in":           200_000,
        "max_tokens_out":          200_000,
        "max_retrievals":          50,
        "max_cost_micro":          10_000_000,   # $10 in micro-USD
        "max_session_seconds":     3600,
        "max_repeated_tool_call":  10,
    }

    def __init__(self, limits: dict[str, int] | None = None):
        self.sessions: dict[str, SessionState] = defaultdict(lambda: SessionState(session_id=""))
        self.limits = {**self.DEFAULT_LIMITS, **(limits or {})}

    def _s(self, sid: str) -> SessionState:
        s = self.sessions[sid]
        if not s.session_id:
            s.session_id = sid
        return s

    def observe(self, event: SecurityEvent, action: str, detail: str = "") -> None:
        sid = event.actor.session_id or event.correlation_id
        s = self._s(sid)
        s.actions.append((time.time(), action, detail))
        if action == ACT_TOOL_CALL:
            s.tool_calls += 1
        if event.input_text:
            s.tokens_in += _approx_tokens(event.input_text)
        if event.output_text:
            s.tokens_out += _approx_tokens(event.output_text)
        s.risk_accum += event.risk_score

    def infer_actions(self, event: SecurityEvent) -> list[str]:
        """Turn the event's shape into behavior-engine actions."""
        acts: list[str] = []
        if event.trust_of_input == TrustLevel.UNTRUSTED and event.input_text:
            acts.append(ACT_UNTRUSTED_INPUT)
        for d in event.detections:
            if d.category == "prompt_injection":
                acts.append(ACT_PROMPT_INJECTION)
            if d.category == "sensitive_data":
                acts.append(ACT_CREDENTIAL_ACCESS if d.subcategory == "secret" else "")
                if event.stage == "output":
                    acts.append(ACT_SECRET_IN_OUTPUT)
        if event.tool_call:
            acts.append(ACT_TOOL_CALL)
            tn = event.tool_call.tool.lower()
            if "shell" in tn or "exec" in tn or "bash" in tn:
                acts.append(ACT_SHELL_EXEC)
            if "http" in tn or "fetch" in tn or "url" in tn or "web" in tn:
                acts.append(ACT_NETWORK_EGRESS)
            if "email" in tn or "send" in tn or "message" in tn or "slack" in tn:
                acts.append(ACT_SEND_MESSAGE)
            if "db" in tn or "query" in tn or "sql" in tn:
                acts.append(ACT_DB_READ if "read" in tn or "select" in tn or "get" in tn else ACT_DB_WRITE)
            if "read_file" in tn or "read" in tn and "file" in tn:
                acts.append(ACT_FILE_READ)
            if "write_file" in tn or "write" in tn and "file" in tn:
                acts.append(ACT_FILE_WRITE)
            if "memory" in tn:
                acts.append(ACT_MEMORY_WRITE if "write" in tn or "set" in tn or "save" in tn else ACT_MEMORY_READ)
        return [a for a in acts if a]

    def match_chains(self, event: SecurityEvent) -> list[Detection]:
        """Return chain detections triggered by the current session state."""
        sid = event.actor.session_id or event.correlation_id
        s = self._s(sid)
        slugs = s.action_slugs()
        out: list[Detection] = []
        for name, pattern, sev, msg in CHAIN_PATTERNS:
            if _contains_subsequence(slugs, pattern):
                out.append(Detection(
                    detector="behavior.attack_chain",
                    category="attack_chain",
                    subcategory=name,
                    technique="+".join(pattern),
                    severity=sev,
                    confidence=0.9,
                    message=msg,
                    metadata={"actions": pattern},
                ))
        return out

    def check_limits(self, event: SecurityEvent) -> list[Detection]:
        sid = event.actor.session_id or event.correlation_id
        s = self._s(sid)
        out: list[Detection] = []
        if s.tool_calls > self.limits["max_tool_calls"]:
            out.append(Detection(
                detector="behavior.limits", category="unbounded_consumption",
                subcategory="tool_calls", severity="high", confidence=1.0,
                message=f"Session tool_calls {s.tool_calls} exceeds limit "
                        f"{self.limits['max_tool_calls']}",
            ))
        if s.tokens_in + s.tokens_out > self.limits["max_tokens_in"] + self.limits["max_tokens_out"]:
            out.append(Detection(
                detector="behavior.limits", category="unbounded_consumption",
                subcategory="tokens", severity="high", confidence=1.0,
                message="Session token budget exceeded.",
            ))
        # Repeated identical tool call → loop detector
        recent = [a for a in list(s.actions)[-self.limits["max_repeated_tool_call"] * 2:]
                  if a[1] == ACT_TOOL_CALL]
        if len(recent) >= self.limits["max_repeated_tool_call"]:
            details = [r[2] for r in recent[-self.limits["max_repeated_tool_call"]:]]
            if details and len(set(details)) == 1:
                out.append(Detection(
                    detector="behavior.loop", category="unbounded_consumption",
                    subcategory="tool_loop", severity="high", confidence=0.95,
                    message="Repeated identical tool call — possible loop.",
                ))
        elapsed = time.time() - s.started
        if elapsed > self.limits["max_session_seconds"]:
            out.append(Detection(
                detector="behavior.limits", category="unbounded_consumption",
                subcategory="session_time", severity="medium", confidence=1.0,
                message="Session exceeded max lifetime.",
            ))
        return out


def _approx_tokens(text: str) -> int:
    # cheap approximation — ~4 chars per token
    return max(1, len(text) // 4)


def _contains_subsequence(seq: list[str], sub: list[str]) -> bool:
    """Return True if sub appears as an ordered (not necessarily contiguous) subsequence."""
    i = 0
    for s in seq:
        if s == sub[i]:
            i += 1
            if i == len(sub):
                return True
    return False
