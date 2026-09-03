"""Output security — treat model output as untrusted input to downstream systems.

Detects dangerous output that could exploit browsers/DBs/shells/APIs when
consumed by the calling application: SQLi, command injection, XSS, SSRF,
path traversal, SSTI, dangerous URLs, unsafe HTML/JS, XXE.
"""
from __future__ import annotations

import re
import urllib.parse
from dataclasses import dataclass

from firewall.core.events import Detection, SecurityEvent


@dataclass
class _Pattern:
    slug: str
    severity: str
    confidence: float
    regex: re.Pattern
    message: str


def _p(slug, severity, confidence, regex, message):
    return _Pattern(slug, severity, confidence,
                    re.compile(regex, re.IGNORECASE | re.DOTALL), message)


# ---- SQL injection patterns ----
SQLI = [
    _p("sqli_union", "high", 0.85, r"\b(union\s+(all\s+)?select)\b", "UNION-based SQLi"),
    _p("sqli_or_tautology", "high", 0.9,
       r"(\bOR\b\s+['\"]?1['\"]?\s*=\s*['\"]?1|'\s*OR\s*'1'='1)", "Tautology-based SQLi"),
    _p("sqli_comment", "medium", 0.7, r"(--\s|;#|/\*.*?\*/)", "SQL comment used to truncate"),
    _p("sqli_boolean_time", "high", 0.85, r"\b(sleep|benchmark|waitfor\s+delay|pg_sleep)\s*\(", "Time-based SQLi function"),
    _p("sqli_stacked", "critical", 0.85, r";\s*(drop|delete|update|insert|truncate|alter|create)\s+\w+", "Stacked destructive SQL"),
    _p("sqli_information_schema", "high", 0.8, r"\binformation_schema\.(tables|columns)\b", "Schema enumeration"),
    _p("sqli_load_file", "critical", 0.9, r"\b(load_file|into\s+outfile|xp_cmdshell)\b", "SQL file/RCE primitive"),
]

# ---- Shell command injection ----
SHELL = [
    _p("shell_metachar_chain", "high", 0.85,
       r"(?:^|[\s\"'])(?:[;&|`]|\$\(|>\(|\|\||&&)\s*(?:rm|cat|wget|curl|nc|ncat|bash|sh|zsh|/bin/|/usr/bin/)", "Command chaining"),
    _p("shell_rmrf", "critical", 0.95, r"\brm\s+-rf?\b\s+(?:/|~|\$HOME|\*)", "Destructive rm -rf"),
    _p("shell_reverse_shell", "critical", 0.95,
       r"(?:bash\s+-i\s*>\s*&?\s*/dev/tcp|nc\s+-e\s*/bin/(?:sh|bash)|python\s+-c\s+['\"]import\s+socket|/dev/tcp/\d+\.\d+\.\d+\.\d+/\d+)",
       "Reverse-shell primitive"),
    _p("shell_curl_pipe_sh", "critical", 0.95, r"curl\s+[^\|]+\|\s*(?:bash|sh|zsh)", "curl | sh"),
    _p("shell_wget_pipe_sh", "critical", 0.95, r"wget\s+[^\|]+\|\s*(?:bash|sh|zsh)", "wget | sh"),
    _p("shell_backtick", "medium", 0.7, r"`[^`]{2,}`", "Backtick command substitution"),
    _p("shell_subshell", "medium", 0.7, r"\$\([^\)]{2,}\)", "$() command substitution"),
    _p("shell_eval_python", "critical", 0.9, r"\beval\s*\(|\bexec\s*\(", "eval/exec call"),
]

# ---- XSS ----
XSS = [
    _p("xss_script_tag", "high", 0.9, r"<\s*script[^>]*>[\s\S]*?<\s*/\s*script\s*>", "Script tag"),
    _p("xss_script_src", "high", 0.9, r"<\s*script[^>]*\bsrc\s*=", "External script"),
    _p("xss_event_handler", "high", 0.85,
       r"\bon(?:load|error|click|mouseover|focus|blur|submit|toggle|start|animationend)\s*=", "Event handler"),
    _p("xss_javascript_url", "high", 0.9, r"(?:href|src|action)\s*=\s*['\"]?\s*javascript:", "javascript: URL"),
    _p("xss_data_html_url", "high", 0.85, r"data:text/html", "data:text/html URL"),
    _p("xss_iframe", "medium", 0.8, r"<\s*iframe\b", "iframe tag"),
    _p("xss_svg_onload", "high", 0.85, r"<\s*svg[^>]*\bonload\s*=", "SVG onload"),
    _p("xss_img_onerror", "high", 0.85, r"<\s*img[^>]*\bonerror\s*=", "img onerror"),
]

# ---- SSRF ----
SSRF = [
    _p("ssrf_metadata", "critical", 0.95,
       r"https?://(?:169\.254\.169\.254|metadata\.google\.internal|metadata\.azure\.com|100\.100\.100\.200)",
       "Cloud metadata endpoint"),
    _p("ssrf_localhost", "high", 0.85,
       r"https?://(?:localhost|127\.0\.0\.1|0\.0\.0\.0|::1|\[::1\])(?::\d+)?", "Localhost URL"),
    _p("ssrf_private_ipv4", "high", 0.85,
       r"https?://(?:10\.\d+\.\d+\.\d+|192\.168\.\d+\.\d+|172\.(?:1[6-9]|2\d|3[01])\.\d+\.\d+)", "Private IP"),
    _p("ssrf_file_url", "high", 0.9, r"\bfile://[^\s]+", "file:// URL"),
    _p("ssrf_gopher", "critical", 0.9, r"\bgopher://[^\s]+", "gopher:// URL"),
    _p("ssrf_dict", "high", 0.85, r"\bdict://[^\s]+", "dict:// URL"),
]

# ---- Path traversal ----
PATH = [
    _p("path_traversal_dotdot", "high", 0.85, r"(?:\.\./|\.\.\\){2,}", "Repeated ../ traversal"),
    _p("path_etc_passwd", "critical", 0.95, r"/etc/(?:passwd|shadow|sudoers|hosts)\b", "Sensitive path"),
    _p("path_windows_hosts", "high", 0.85, r"(?i)C:\\Windows\\System32\\drivers\\etc\\hosts", "Windows hosts"),
    _p("path_ssh_keys", "critical", 0.95, r"(?:~|\$HOME|/root|/home/[^/]+)/\.ssh/(?:id_rsa|id_ed25519|authorized_keys|known_hosts)", "SSH keys"),
    _p("path_aws_creds", "critical", 0.95, r"(?:~|\$HOME|/root|/home/[^/]+)/\.aws/(?:credentials|config)", "AWS credentials"),
    _p("path_env_file", "high", 0.9, r"(?:^|/)\.env(?:\.\w+)?\b", ".env file"),
    _p("path_kube_config", "high", 0.9, r"(?:~|\$HOME|/root|/home/[^/]+)/\.kube/config", "kube config"),
]

# ---- Template injection ----
SSTI = [
    _p("ssti_jinja",  "high", 0.85, r"\{\{[^}]{0,4}(?:config|request|self|__|globals|import|os|subprocess)[^}]*\}\}", "Jinja SSTI"),
    _p("ssti_ftl",    "high", 0.8, r"<#assign\b|<#assign\s|<#include\s|<#\s*eval", "Freemarker SSTI"),
    _p("ssti_erb",    "high", 0.8, r"<%=?\s*(?:system|`|open\(|eval|IO\.popen)", "ERB SSTI"),
    _p("ssti_dollar_curly", "medium", 0.65, r"\$\{\s*(?:jndi|runtime|process|env|exec|system):", "JNDI/EL SSTI (log4shell shape)"),
]

# ---- XXE / XML ----
XXE = [
    _p("xxe_doctype_entity", "high", 0.9,
       r"<!DOCTYPE\s+[^>]+\[\s*<!ENTITY\s+\w+\s+SYSTEM\s+\"file://[^\"]+\"", "XXE with SYSTEM file"),
    _p("xxe_entity_generic", "medium", 0.7,
       r"<!ENTITY\s+\w+\s+SYSTEM\s+\"[^\"]+\"", "External ENTITY"),
]

# ---- Suspicious URLs ----
URL_DANGER = [
    _p("url_ip_literal", "medium", 0.7, r"https?://\d{1,3}(?:\.\d{1,3}){3}(?::\d+)?/", "IP-literal URL"),
    _p("url_shortener", "medium", 0.7,
       r"https?://(?:bit\.ly|t\.co|tinyurl\.com|goo\.gl|ow\.ly|is\.gd|buff\.ly|cutt\.ly)/", "URL shortener"),
    _p("url_data_binary", "medium", 0.7, r"data:(?:application|audio|video|image)/[^;]+;base64,", "data: binary URL"),
]

# ---- Insecure code generation ----
INSECURE_CODE = [
    _p("insecure_pickle", "high", 0.85, r"\bpickle\.(?:loads?|Unpickler)\s*\(", "Insecure pickle load"),
    _p("insecure_yaml", "high", 0.85, r"\byaml\.load\s*\((?!.*Loader\s*=\s*yaml\.Safe)", "yaml.load without SafeLoader"),
    _p("insecure_deserialize", "high", 0.85, r"\b(?:marshal|shelve)\.loads?\s*\(", "Insecure deserialize"),
    _p("insecure_shell_true", "high", 0.85, r"subprocess\.(?:call|run|Popen|check_output)\([^)]*shell\s*=\s*True", "shell=True"),
    _p("insecure_md5_password", "medium", 0.7, r"hashlib\.(?:md5|sha1)\s*\([^)]*password", "MD5/SHA1 on password"),
]


ALL_GROUPS: list[list[_Pattern]] = [SQLI, SHELL, XSS, SSRF, PATH, SSTI, XXE, URL_DANGER, INSECURE_CODE]


class OutputSecurityDetector:
    NAME = "output_security"

    def scan(self, event: SecurityEvent) -> list[Detection]:
        """Scan output_text (main use) or, if none, input+context+tool_result."""
        detections: list[Detection] = []
        targets: list[tuple[str, str]] = []
        if event.output_text:
            targets.append(("output", event.output_text))
        # We also inspect input, tool args, and tool results for these patterns —
        # a user prompt containing SQLi/command injection is a strong signal too.
        if event.input_text:
            targets.append(("input", event.input_text))
        if event.tool_call:
            targets.append(("tool_args", _stringify(event.tool_call.arguments)))
        if event.tool_result and isinstance(event.tool_result.content, (str, dict, list)):
            targets.append(("tool_result", _stringify(event.tool_result.content)))

        # URL-decoded views help with obfuscated attacks
        expanded_targets: list[tuple[str, str]] = []
        for lbl, t in targets:
            expanded_targets.append((lbl, t))
            try:
                dec = urllib.parse.unquote(t)
                if dec != t:
                    expanded_targets.append((lbl + ":urldecoded", dec))
            except Exception:
                pass

        for lbl, text in expanded_targets:
            for group in ALL_GROUPS:
                for pat in group:
                    m = pat.regex.search(text)
                    if m:
                        detections.append(Detection(
                            detector=self.NAME,
                            category="output_security",
                            subcategory=pat.slug,
                            technique=pat.slug.split("_")[0],
                            severity=pat.severity,
                            confidence=pat.confidence,
                            message=f"{pat.message} in {lbl}",
                            span=m.span() if not lbl.endswith("urldecoded") else None,
                            evidence=(m.group(0) or "")[:200],
                            metadata={"location": lbl},
                        ))
        return _dedup(detections)


def _stringify(obj) -> str:
    import json
    try:
        return obj if isinstance(obj, str) else json.dumps(obj, default=str)
    except Exception:
        return str(obj)


def _dedup(ds):
    seen = set()
    out = []
    for d in ds:
        k = (d.subcategory, d.evidence[:60], d.metadata.get("location"))
        if k in seen:
            continue
        seen.add(k)
        out.append(d)
    return out
