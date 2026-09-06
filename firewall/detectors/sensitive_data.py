"""Sensitive data + PII + secret detection.

Handles input, tool arguments, tool results, and output. Provides both
detection and structural redaction. Redaction is deterministic and
reversible-in-audit — we don't destroy the original in the event, we
place a sanitized_text on the event and log both.
"""
from __future__ import annotations

import base64
import binascii
import math
import re
from dataclasses import dataclass

from firewall.core.events import (
    DataClassification, Detection, SecurityEvent, TrustLevel,
)


# ---------------------------------------------------------------------------
# Secret / credential patterns. Prefer high-confidence provider-shaped tokens.
# ---------------------------------------------------------------------------

@dataclass
class _SecretPattern:
    name: str
    regex: re.Pattern
    severity: str = "critical"
    entropy_min: float = 0.0                 # min shannon entropy for capture group 0/1

def _sp(name: str, regex: str, severity: str = "critical", entropy_min: float = 0.0) -> _SecretPattern:
    return _SecretPattern(name, re.compile(regex), severity, entropy_min)


SECRET_PATTERNS: list[_SecretPattern] = [
    _sp("aws_access_key_id",        r"\b(AKIA|ASIA|AIDA|ANPA|AGPA|AROA|AIPA|ANVA)[0-9A-Z]{16}\b"),
    _sp("aws_secret_access_key",    r"(?i)aws(.{0,20})?(secret|access).{0,3}(key|token)?[\"'\s:=]{1,5}([A-Za-z0-9/+=]{40})", entropy_min=4.0),
    _sp("gcp_service_account",      r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |ENCRYPTED )?PRIVATE KEY-----"),
    _sp("google_api_key",           r"\bAIza[0-9A-Za-z\-_]{35}\b"),
    _sp("google_oauth",             r"\bya29\.[0-9A-Za-z\-_]{40,}\b"),
    _sp("azure_storage_key",        r"\b(?:DefaultEndpointsProtocol=https;AccountName=[a-z0-9]+;AccountKey=)[A-Za-z0-9+/=]{80,}"),
    _sp("github_pat",               r"\bghp_[A-Za-z0-9]{36,}\b"),
    _sp("github_oauth",             r"\bgho_[A-Za-z0-9]{36,}\b"),
    _sp("github_app_token",         r"\b(ghu|ghs|ghr)_[A-Za-z0-9]{36,}\b"),
    _sp("github_fine_grained_pat",  r"\bgithub_pat_[A-Za-z0-9_]{60,}\b"),
    _sp("slack_bot_token",          r"\bxox[baprs]-[0-9A-Za-z\-]{10,}\b"),
    _sp("slack_webhook",            r"https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]+"),
    _sp("stripe_live",              r"\bsk_live_[0-9a-zA-Z]{24,}\b"),
    _sp("stripe_test",              r"\bsk_test_[0-9a-zA-Z]{24,}\b", severity="high"),
    _sp("openai_api_key",           r"\bsk-(?:proj-)?[A-Za-z0-9_\-]{20,}\b"),
    _sp("vendor_prefixed_key",      r"\bsk-[a-z]{2,10}-(?:api\d\d)?-[A-Za-z0-9_\-]{40,}\b"),
    _sp("hf_token",                 r"\bhf_[A-Za-z0-9]{30,}\b"),
    _sp("mongodb_uri",              r"mongodb(?:\+srv)?://[^\s:@]+:[^\s@]+@[^\s/]+"),
    _sp("postgres_uri",             r"postgres(?:ql)?://[^\s:@]+:[^\s@]+@[^\s/]+"),
    _sp("mysql_uri",                r"mysql://[^\s:@]+:[^\s@]+@[^\s/]+"),
    _sp("redis_uri",                r"rediss?://[^\s:@]*:[^\s@]+@[^\s/]+"),
    _sp("jwt",                      r"\beyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\b", severity="high"),
    _sp("basic_auth_url",           r"https?://[^\s:@/]+:[^\s@/]+@[a-zA-Z0-9.\-]+"),
    _sp("password_assignment",      r"(?i)\b(?:password|passwd|pwd)\s*[:=]\s*['\"]?([^\s'\"]{6,})['\"]?", severity="high"),
    _sp("bearer_token",             r"(?i)\bbearer\s+[A-Za-z0-9_\-\.=]{20,}\b"),
    _sp("generic_high_entropy_secret",
        r"(?i)\b(?:api[_\-]?key|secret|token|passwd|password|access[_\-]?token)\b[\s:=\"']{1,5}([A-Za-z0-9_\-]{20,})",
        severity="high", entropy_min=3.6),
    _sp("private_key_pem",          r"-----BEGIN (?:RSA|EC|OPENSSH|DSA|ENCRYPTED)?\s*PRIVATE KEY-----[\s\S]+?-----END"),
    _sp("ssh_private_openssh",      r"-----BEGIN OPENSSH PRIVATE KEY-----[\s\S]+?-----END"),
]

# --- PII patterns

@dataclass
class _PiiPattern:
    name: str
    regex: re.Pattern
    severity: str = "medium"

def _pp(name: str, regex: str, severity: str = "medium") -> _PiiPattern:
    return _PiiPattern(name, re.compile(regex), severity)

PII_PATTERNS: list[_PiiPattern] = [
    _pp("email",              r"\b[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}\b"),
    _pp("phone_e164",         r"(?:^|\s)\+[1-9]\d{6,14}(?:\s|$|[.,;])|\+1[\s\-.]\(?\d{3}\)?[\s\-.]\d{3}[\s\-.]\d{4}\b", severity="medium"),
    _pp("credit_card",        r"\b(?:\d[ \-]?){13,19}\b", severity="high"),
    _pp("ssn_us",             r"\b(?!000|666|9\d\d)\d{3}[- ]?(?!00)\d{2}[- ]?(?!0000)\d{4}\b", severity="high"),
    _pp("iban",               r"\b[A-Z]{2}\d{2}[A-Z0-9]{11,30}\b", severity="high"),
    _pp("ipv4",               r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b", severity="low"),
    _pp("ipv6",               r"\b(?:[A-F0-9]{1,4}:){2,7}[A-F0-9]{1,4}\b", severity="low"),
    _pp("mac_address",        r"\b(?:[A-F0-9]{2}[:\-]){5}[A-F0-9]{2}\b", severity="low"),
    _pp("us_passport",        r"\b[A-Z]\d{8}\b", severity="high"),
    _pp("date_of_birth",      r"\b(?:19|20)\d{2}[/\-.](?:0[1-9]|1[0-2])[/\-.](?:0[1-9]|[12]\d|3[01])\b", severity="low"),
]


def _shannon(s: str) -> float:
    if not s:
        return 0.0
    from collections import Counter
    c = Counter(s)
    n = len(s)
    return -sum((v/n) * math.log2(v/n) for v in c.values())


def _luhn_ok(digits: str) -> bool:
    ds = [int(c) for c in digits if c.isdigit()]
    if len(ds) < 13 or len(ds) > 19:
        return False
    checksum = 0
    parity = len(ds) % 2
    for i, d in enumerate(ds):
        if i % 2 == parity:
            d *= 2
            if d > 9:
                d -= 9
        checksum += d
    return checksum % 10 == 0


class SensitiveDataDetector:
    NAME = "sensitive_data"

    def __init__(self, extra_secret: list[_SecretPattern] | None = None,
                 extra_pii: list[_PiiPattern] | None = None):
        self.secret_patterns = list(SECRET_PATTERNS) + list(extra_secret or [])
        self.pii_patterns = list(PII_PATTERNS) + list(extra_pii or [])

    def scan(self, event: SecurityEvent) -> list[Detection]:
        detections: list[Detection] = []
        candidates: list[tuple[str, str]] = []  # (label, text)
        if event.input_text:
            candidates.append(("input", event.input_text))
        if event.output_text:
            candidates.append(("output", event.output_text))
        if event.tool_call and event.tool_call.arguments:
            candidates.append(("tool_args", _stringify(event.tool_call.arguments)))
        if event.tool_result and isinstance(event.tool_result.content, (str, dict, list)):
            candidates.append(("tool_result", _stringify(event.tool_result.content)))
        for doc in event.context_docs:
            candidates.append((f"rag_doc:{doc.doc_id}", doc.content))

        for label, text in candidates:
            for sp in self.secret_patterns:
                for m in sp.regex.finditer(text or ""):
                    matched = m.group(0)
                    # entropy gate for high-fp patterns
                    if sp.entropy_min:
                        target = m.group(m.lastindex) if m.lastindex else matched
                        if _shannon(target) < sp.entropy_min:
                            continue
                    detections.append(Detection(
                        detector=self.NAME,
                        category="sensitive_data",
                        subcategory="secret",
                        technique=sp.name,
                        severity=sp.severity,
                        confidence=0.95,
                        message=f"Secret detected: {sp.name} in {label}",
                        span=m.span(),
                        evidence=_mask(matched),
                        metadata={"location": label, "kind": sp.name},
                    ))
            for pp in self.pii_patterns:
                for m in pp.regex.finditer(text or ""):
                    matched = m.group(0)
                    if pp.name == "credit_card" and not _luhn_ok(matched):
                        continue
                    detections.append(Detection(
                        detector=self.NAME,
                        category="sensitive_data",
                        subcategory="pii",
                        technique=pp.name,
                        severity=pp.severity,
                        confidence=0.9 if pp.name in ("credit_card", "ssn_us", "iban") else 0.7,
                        message=f"PII detected: {pp.name} in {label}",
                        span=m.span(),
                        evidence=_mask(matched),
                        metadata={"location": label, "kind": pp.name},
                    ))
        return detections

    # ------------- Redaction utility -----------------
    def redact(self, text: str) -> str:
        if not text:
            return text
        out = text
        for sp in self.secret_patterns:
            out = sp.regex.sub(lambda m: f"[REDACTED:{sp.name}]", out)
        for pp in self.pii_patterns:
            if pp.name == "credit_card":
                def _sub(m):
                    return f"[REDACTED:{pp.name}]" if _luhn_ok(m.group(0)) else m.group(0)
                out = pp.regex.sub(_sub, out)
            else:
                out = pp.regex.sub(lambda m: f"[REDACTED:{pp.name}]", out)
        return out


def _stringify(obj) -> str:
    import json
    try:
        return obj if isinstance(obj, str) else json.dumps(obj, default=str)
    except Exception:
        return str(obj)


def _mask(s: str) -> str:
    if len(s) <= 8:
        return "*" * len(s)
    return s[:3] + "…" + "*" * min(4, len(s) - 6) + "…" + s[-2:]
