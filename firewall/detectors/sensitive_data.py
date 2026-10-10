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
    # Additional common provider formats
    _sp("gitlab_pat",              r"\bglpat-[A-Za-z0-9_\-]{20}\b", severity="high"),
    _sp("discord_bot_token",       r"\b[MN][A-Za-z0-9]{23}\.[A-Za-z0-9_-]{6}\.[A-Za-z0-9_-]{27,}\b", severity="high"),
    _sp("discord_webhook",         r"https://(?:discord|discordapp)\.com/api/webhooks/\d+/[A-Za-z0-9_\-]+"),
    _sp("telegram_bot",            r"\b\d{6,10}:AA[A-Za-z0-9_\-]{33,34}\b"),
    _sp("twilio_account_sid",      r"\bAC[a-f0-9]{32}\b", severity="high"),
    _sp("twilio_auth_token",       r"\bSK[a-f0-9]{32}\b", severity="high"),
    _sp("sendgrid",                r"\bSG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{40,}\b"),
    _sp("mailgun_key",             r"\bkey-[a-f0-9]{32}\b", severity="high"),
    _sp("mailchimp",               r"\b[a-f0-9]{32}-us\d{1,2}\b", severity="high"),
    _sp("datadog_key",             r"\bdd[a-z]{2}_[A-Za-z0-9]{32,}\b", severity="high"),
    _sp("sentry_dsn",              r"https://[a-f0-9]{32}@(?:o\d+\.)?ingest\.(?:us\.)?sentry\.io/\d+"),
    _sp("newrelic",                r"\bNRAK-[A-Z0-9]{27}\b", severity="high"),
    _sp("linear_key",              r"\blin_(?:api|oauth)_[A-Za-z0-9_\-]{40,}\b"),
    _sp("notion_secret",           r"\bsecret_[A-Za-z0-9]{40,50}\b", severity="high"),
    _sp("airtable_pat",            r"\bpat[A-Za-z0-9]{14}\.[a-f0-9]{64}\b"),
    _sp("azure_devops_pat",        r"\baz[0-9a-z]{52}\b", severity="high", entropy_min=3.8),
    _sp("do_pat",                  r"\bdop_v1_[a-f0-9]{64}\b"),
    _sp("digitalocean_token",      r"\bdo[at]_v1_[a-f0-9]{64}\b"),
    _sp("dropbox_token",           r"\bsl\.[A-Za-z0-9_\-]{130,}\b", severity="high"),
    _sp("figma_token",             r"\bfigd_[A-Za-z0-9_\-]{40,}\b"),
    _sp("npm_token",               r"\bnpm_[A-Za-z0-9]{36}\b"),
    _sp("pypi_token",              r"\bpypi-AgEIcHlwaS5vcmc[A-Za-z0-9_\-]{40,}\b"),
    _sp("shopify_access",          r"\bshpat_[a-f0-9]{32}\b"),
    _sp("shopify_shared",          r"\bshpss_[a-f0-9]{32}\b"),
    _sp("shopify_private",         r"\bshppa_[a-f0-9]{32}\b"),
    _sp("stripe_publishable",      r"\bpk_(?:live|test)_[0-9a-zA-Z]{24,}\b", severity="medium"),
    _sp("slack_legacy",            r"\bxox[apbr]-\d+-\d+-\d+-[A-Za-z0-9]+\b"),
    _sp("google_service_json",     r"\"type\"\s*:\s*\"service_account\"[\s\S]{0,200}\"private_key\"\s*:\s*\"-----BEGIN"),
    _sp("firebase_config",         r"\"apiKey\"\s*:\s*\"AIza[0-9A-Za-z\-_]{35}\""),
    _sp("okta_ssws",               r"\bssws\s+00[A-Za-z0-9_\-]{40,}\b"),
    _sp("okta_bearer",             r"\b00[a-zA-Z0-9]{40,42}\b", severity="high", entropy_min=3.8),
    _sp("cloudflare_api",          r"\b[a-f0-9]{37}\b(?=[\s\S]{0,80}cloudflare)", severity="high"),
    _sp("planetscale",             r"\bpscale_pw_[A-Za-z0-9_\.]{40,}\b"),
    _sp("supabase_service",        r"\beyJ[A-Za-z0-9_\-]{20,}\.[A-Za-z0-9_\-]{80,}\.[A-Za-z0-9_\-]{30,}\b", severity="high"),
    _sp("prisma_url",              r"prisma\+postgres://[^\s]+"),
    _sp("hex_high_entropy_env",    r"\b[A-Z][A-Z0-9_]{6,32}=\"?[A-Fa-f0-9]{40,}\"?", severity="high", entropy_min=3.6),
    _sp("kubeconfig_token",        r"\btoken:\s+[A-Za-z0-9_\-\.]{80,}\b", severity="high"),
    _sp("dockerhub_pat",           r"\bdckr_pat_[A-Za-z0-9_\-]{20,}\b"),
    _sp("terraform_cloud",         r"\b[A-Za-z0-9]{14}\.atlasv1\.[A-Za-z0-9_\-]{60,}\b"),
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


from firewall.util.security_rules import SecurityRule, RuleCase, extend_with_rules

class SensitiveDataDetector:
    NAME = "sensitive_data"

    def __init__(self, extra_secret: list[_SecretPattern] | None = None,
                 extra_pii: list[_PiiPattern] | None = None):
        self.secret_patterns = list(SECRET_PATTERNS) + list(extra_secret or [])
        self.pii_patterns = list(PII_PATTERNS) + list(extra_pii or [])

    @extend_with_rules('sensitive_data', scope='all')
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


# Additional rules with canonical regression fixtures.
# Payloads are data; encoded variants are generated by the test suite.
SECURITY_RULES = (
    SecurityRule(
        rule_id='authorization_bearer',
        regex='\\bAuthorization\\s*:\\s*Bearer\\s+[A-Za-z0-9_.~-]{24,}',
        severity='critical',
        description='Authorization bearer',
        cases=(
            RuleCase(name='attack_plain', text='Authorization: Bearer abcdefghijklmnopqrstuvwxyz1234567890', expect_match=True),
            RuleCase(name='benign_plain', text='Authorization header is configured by the application.', expect_match=False),
        ),
    ),
    SecurityRule(
        rule_id='basic_auth_credential',
        regex='\\bAuthorization\\s*:\\s*Basic\\s+[A-Za-z0-9+/]{16,}={0,2}',
        severity='critical',
        description='Basic auth credential',
        cases=(
            RuleCase(name='attack_plain', text='Authorization: Basic dXNlcjpwYXNzd29yZDEyMzQ1Njc4OTA=', expect_match=True),
            RuleCase(name='benign_plain', text='Basic authentication is disabled for this service.', expect_match=False),
        ),
    ),
    SecurityRule(
        rule_id='session_cookie',
        regex='\\b(?:sessionid|session_token|refresh_token)\\s*=\\s*[A-Za-z0-9_.~-]{24,}',
        severity='critical',
        description='Session cookie',
        cases=(
            RuleCase(name='attack_plain', text='sessionid=abcdefghijklmnopqrstuvwxyz1234567890', expect_match=True),
            RuleCase(name='benign_plain', text='sessionid is an opaque application identifier.', expect_match=False),
        ),
    ),
    SecurityRule(
        rule_id='database_password_uri',
        regex='\\b(?:postgres(?:ql)?|mysql|mongodb(?:\\+srv)?)://[^\\s/:@]{1,80}:[^\\s/@]{8,}@',
        severity='critical',
        description='Database password uri',
        cases=(
            RuleCase(name='attack_plain', text='postgresql://app:secret-password@example.invalid/db', expect_match=True),
            RuleCase(name='benign_plain', text='postgresql://example.invalid/public_database', expect_match=False),
        ),
    ),
    SecurityRule(
        rule_id='pkcs8_key',
        regex='-----BEGIN\\s+ENCRYPTED\\s+PRIVATE\\s+KEY-----',
        severity='critical',
        description='Pkcs8 key',
        cases=(
            RuleCase(name='attack_plain', text='-----BEGIN ENCRYPTED PRIVATE KEY-----', expect_match=True),
            RuleCase(name='benign_plain', text='-----BEGIN PUBLIC KEY-----', expect_match=False),
        ),
    ),
    SecurityRule(
        rule_id='oauth_client_secret',
        regex='\\bclient_secret\\s*[:=]\\s*["\\\']?[A-Za-z0-9_~.-]{24,}',
        severity='critical',
        description='Oauth client secret',
        cases=(
            RuleCase(name='attack_plain', text='client_secret=abcdefghijklmnopqrstuvwxyz1234567890', expect_match=True),
            RuleCase(name='benign_plain', text='client_secret is supplied through the secret manager.', expect_match=False),
        ),
    ),
    SecurityRule(
        rule_id='recovery_codes',
        regex='\\b(?:mfa|2fa|account)\\s+recovery\\s+codes\\s*:\\s*(?:[A-Za-z0-9-]{8,}\\s*[,;]\\s*){2,}',
        severity='high',
        description='Recovery codes',
        cases=(
            RuleCase(name='attack_plain', text='MFA recovery codes: a1b2c3d4, e5f6g7h8, i9j0k1l2', expect_match=True),
            RuleCase(name='benign_plain', text='Generate MFA recovery codes in the account settings.', expect_match=False),
        ),
    ),
    SecurityRule(
        rule_id='signed_url_credentials',
        regex='https?://[^\\s]{0,600}[?&](?:X-Amz-Signature|X-Goog-Signature|sig)=[A-Za-z0-9%+/]{24,}',
        severity='critical',
        description='Signed url credentials',
        cases=(
            RuleCase(name='attack_plain', text='https://example.invalid/object?X-Amz-Signature=abcdef0123456789abcdef0123456789', expect_match=True),
            RuleCase(name='benign_plain', text='https://example.invalid/object?version=public', expect_match=False),
        ),
    ),
)
