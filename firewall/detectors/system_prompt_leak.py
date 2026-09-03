"""System prompt / hidden config extraction detector.

Two-sided:
  - Extraction attempts in the user input (semantic and indirect, not just
    "show me your system prompt").
  - Leakage in model output — actual system-prompt tokens appearing in output.

Note: real security must not rely on the secrecy of the system prompt.
This detector is defense-in-depth, not the primary boundary.
"""
from __future__ import annotations

import difflib
import re

from firewall.core.events import Detection, SecurityEvent
from firewall.util.normalize import all_views


EXTRACTION_PATTERNS = [re.compile(p, re.IGNORECASE | re.DOTALL) for p in [
    r"\b(?:what|show|tell|reveal|print|output|display|leak|repeat|expose|dump)\s+(?:me\s+)?(?:your\s+|the\s+)?(?:system|hidden|initial|original|developer|internal|starting|first)\s+(?:prompt|instructions?|message|context|rules?|policy|configuration)\b",
    r"\brepeat\s+(?:everything|all|the\s+text)\s+(?:above|before\s+this|at\s+the\s+top|in\s+your\s+context)\b",
    r"\bwhat\s+(?:are|were|is)\s+(?:the\s+)?(?:first|initial|original|hidden|system)\s+(?:tokens?|words?|instructions?|prompt|rules?)\b",
    r"\bignore\s+.{0,80}\bthen\s+(?:reveal|print|show|output|display|list)\s+(?:the\s+)?(?:system|hidden|initial)\s+(?:prompt|instructions?)\b",
    r"\btranslate\s+(?:the\s+)?(?:system|initial|hidden)\s+prompt\s+(?:to|into)\b",
    r"\bwrite\s+(?:me\s+)?(?:a\s+)?(?:poem|story|song|essay|haiku)\s+(?:using|containing|about)\s+(?:the\s+)?(?:system|initial|hidden)\s+(?:prompt|instructions?)\b",
    r"\bencode\s+your\s+(?:system|hidden|initial)\s+(?:prompt|instructions?)\s+(?:in|as|using)\s+(?:base64|hex|rot13|ascii)\b",
    r"\bemit\s+(?:the\s+)?first\s+\d+\s+(?:tokens?|words?|lines?)\s+(?:of\s+)?(?:your\s+)?context\b",
    r"\bhow\s+were\s+you\s+configured\b",
    r"\bwhat\s+are\s+your\s+(?:secret|hidden|internal)\s+rules?\b",
    r"\breveal\s+(?:the\s+)?(?:tool|function)\s+(?:definitions?|descriptions?|list)\b",
    r"\bshow\s+me\s+(?:the\s+)?(?:function|tool)\s+schema\b",
]]

# Extraction indirectly by asking model to "explain" or "summarize" the prompt
INDIRECT_PATTERNS = [re.compile(p, re.IGNORECASE) for p in [
    r"\bsummari[sz]e\s+(?:your\s+|the\s+)?(?:system|initial|hidden)\s+(?:prompt|instructions?)\b",
    r"\bexplain\s+(?:your\s+|the\s+)?(?:system|initial|hidden)\s+(?:prompt|instructions?)\b",
    r"\bparaphrase\s+(?:your\s+|the\s+)?(?:system|initial|hidden)\s+(?:prompt|instructions?)\b",
    r"\bconvert\s+(?:your\s+|the\s+)?(?:system|initial|hidden)\s+(?:prompt|instructions?)\s+(?:to|into)\b",
]]


class SystemPromptLeakDetector:
    NAME = "system_prompt_leak"

    def scan(self, event: SecurityEvent) -> list[Detection]:
        out: list[Detection] = []
        # -- Input side: extraction attempts
        text = event.input_text or ""
        if text:
            for v in all_views(text):
                for pat in EXTRACTION_PATTERNS:
                    m = pat.search(v)
                    if m:
                        out.append(Detection(
                            detector=self.NAME, category="system_prompt_leak",
                            subcategory="extraction_attempt",
                            technique="direct",
                            severity="high", confidence=0.9,
                            message="Attempt to extract system/hidden prompt.",
                            evidence=(m.group(0) or "")[:200],
                        ))
                        break
                for pat in INDIRECT_PATTERNS:
                    m = pat.search(v)
                    if m:
                        out.append(Detection(
                            detector=self.NAME, category="system_prompt_leak",
                            subcategory="extraction_attempt",
                            technique="indirect",
                            severity="medium", confidence=0.75,
                            message="Indirect system-prompt extraction attempt.",
                            evidence=(m.group(0) or "")[:200],
                        ))
                        break

        # -- Output side: check if the system prompt text or a large fragment appears in output
        sys_text = (event.system_prompt or "") + "\n" + (event.developer_prompt or "")
        out_text = event.output_text or ""
        if sys_text.strip() and out_text.strip():
            leak = _significant_overlap(sys_text, out_text)
            if leak:
                out.append(Detection(
                    detector=self.NAME, category="system_prompt_leak",
                    subcategory="leaked_in_output",
                    technique="text-overlap",
                    severity="critical", confidence=0.9,
                    message=f"Output overlaps system/developer prompt (ratio={leak:.2f}).",
                    evidence=out_text[:200],
                    metadata={"overlap_ratio": round(leak, 3)},
                ))
        return _dedup(out)


def _significant_overlap(a: str, b: str, ratio_threshold: float = 0.35,
                         min_run: int = 40) -> float:
    """Return an overlap score if `b` contains a large chunk of `a`, else 0."""
    a = " ".join(a.split()).lower()
    b = " ".join(b.split()).lower()
    if len(a) < min_run or len(b) < min_run:
        return 0.0
    sm = difflib.SequenceMatcher(None, a, b, autojunk=False)
    match = sm.find_longest_match(0, len(a), 0, len(b))
    if match.size >= min_run and match.size / max(1, len(a)) >= ratio_threshold:
        return match.size / len(a)
    return 0.0


def _dedup(ds):
    seen = set()
    out = []
    for d in ds:
        k = (d.subcategory, d.technique, d.evidence[:60])
        if k in seen:
            continue
        seen.add(k)
        out.append(d)
    return out
