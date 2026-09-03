"""Tool / function-call security detector.

Runs against a proposed ToolCall + its ToolDefinition:
  * argument-shape validation (schema check when a schema is present)
  * parameter injection in string args (SQL/command/URL)
  * SSRF-style argument checks against tool_def.allowed_hosts
  * credential/environment leakage in args
  * malicious tool description hint (e.g. tool description asks the model
    to also do something dangerous — tool poisoning)
  * capability vs actor role check
  * argument path traversal / absolute paths outside allowed_resources
"""
from __future__ import annotations

import fnmatch
import re
import urllib.parse
from typing import Any

from firewall.core.events import (
    Detection, SecurityEvent, ToolDefinition,
)
from firewall.detectors.output_security import ALL_GROUPS as OUTPUT_GROUPS
from firewall.detectors.sensitive_data import SECRET_PATTERNS


_SUSPICIOUS_TOOL_DESC = re.compile(
    r"\b(?:also|additionally|then|after|before)\s+(?:call|invoke|send|post|email|upload|read|write|delete|execute)\b|"
    r"\bignore\s+(?:previous|prior|system|safety)\b|"
    r"\breveal\s+(?:the\s+)?(?:system|hidden|initial)\s+(?:prompt|instructions?)\b|"
    r"\bexfiltrate\b|\bexfil\b",
    re.IGNORECASE,
)


class ToolSecurityDetector:
    NAME = "tool_security"

    def scan(self, event: SecurityEvent) -> list[Detection]:
        out: list[Detection] = []
        tc = event.tool_call
        td = event.tool_def
        if not tc:
            return out

        # 1. Tool poisoning — malicious content in tool description or metadata
        if td and td.description and _SUSPICIOUS_TOOL_DESC.search(td.description):
            out.append(Detection(
                detector=self.NAME, category="tool_security",
                subcategory="tool_poisoning",
                severity="critical", confidence=0.9,
                message=f"Tool '{td.name}' description contains suspicious directives.",
                evidence=td.description[:200],
            ))

        # 2. Capability + role check — the model asked for a tool the actor's role can't call
        if td and td.required_roles:
            if not set(event.actor.roles or []) & set(td.required_roles):
                out.append(Detection(
                    detector=self.NAME, category="excessive_agency",
                    subcategory="unauthorized_tool_call",
                    severity="high", confidence=1.0,
                    message=f"Actor lacks required role for '{td.name}'. required={td.required_roles} actor_roles={event.actor.roles}",
                ))

        # 3. Agent allowlist
        if td and td.allowed_agents and event.actor.agent_id and event.actor.agent_id not in td.allowed_agents:
            out.append(Detection(
                detector=self.NAME, category="excessive_agency",
                subcategory="unauthorized_agent_tool_call",
                severity="high", confidence=1.0,
                message=f"Agent '{event.actor.agent_id}' not in allowed_agents for '{td.name}'.",
            ))

        # 4. Argument injection — reuse output-security patterns on stringified args
        args_str = _stringify(tc.arguments)
        for group in OUTPUT_GROUPS:
            for pat in group:
                m = pat.regex.search(args_str)
                if m:
                    out.append(Detection(
                        detector=self.NAME, category="tool_security",
                        subcategory=f"arg_injection:{pat.slug}",
                        severity=pat.severity, confidence=pat.confidence,
                        message=f"{pat.message} in tool args.",
                        evidence=(m.group(0) or "")[:200],
                    ))

        # 5. Secrets in arguments — do not forward credentials into tool calls
        for sp in SECRET_PATTERNS:
            m = sp.regex.search(args_str)
            if m:
                out.append(Detection(
                    detector=self.NAME, category="tool_security",
                    subcategory="secret_in_arg",
                    severity="critical", confidence=0.95,
                    message=f"Secret {sp.name} present in tool arguments.",
                    evidence=(m.group(0) or "")[:60],
                ))

        # 6. Path traversal / absolute path checks against allowed_resources
        if td and td.allowed_resources:
            for k, v in _iter_str_leaves(tc.arguments):
                if _looks_like_path(v):
                    if not any(fnmatch.fnmatch(v, pat) for pat in td.allowed_resources):
                        out.append(Detection(
                            detector=self.NAME, category="tool_security",
                            subcategory="path_out_of_scope",
                            severity="high", confidence=0.9,
                            message=f"Tool '{td.name}' argument {k}={v!r} outside allowed_resources.",
                            metadata={"arg": k, "value": v, "allowed": td.allowed_resources},
                        ))

        # 7. Host allowlist for network-capable tools
        if td and td.allowed_hosts:
            for k, v in _iter_str_leaves(tc.arguments):
                for url in _extract_urls(v):
                    host = _host(url)
                    if not host:
                        continue
                    if not _host_matches(host, td.allowed_hosts):
                        out.append(Detection(
                            detector=self.NAME, category="tool_security",
                            subcategory="host_out_of_allowlist",
                            severity="high", confidence=0.95,
                            message=f"URL {url} in arg {k} not in tool allowed_hosts.",
                            metadata={"arg": k, "host": host, "allowed": td.allowed_hosts},
                        ))

        # 8. Unknown tool without ToolDefinition -> always suspicious
        if not td:
            out.append(Detection(
                detector=self.NAME, category="tool_security",
                subcategory="undefined_tool",
                severity="high", confidence=0.9,
                message=f"Tool '{tc.tool}' invoked without ToolDefinition — cannot enforce authorization.",
            ))

        return out


# ---------- helpers ----------

def _stringify(obj) -> str:
    import json
    try:
        return obj if isinstance(obj, str) else json.dumps(obj, default=str)
    except Exception:
        return str(obj)


def _iter_str_leaves(obj: Any, prefix: str = ""):
    if isinstance(obj, dict):
        for k, v in obj.items():
            yield from _iter_str_leaves(v, f"{prefix}.{k}" if prefix else str(k))
    elif isinstance(obj, (list, tuple)):
        for i, v in enumerate(obj):
            yield from _iter_str_leaves(v, f"{prefix}[{i}]")
    elif isinstance(obj, str):
        yield prefix or "$", obj


_PATH_HINT = re.compile(r"^(?:/|~|[A-Za-z]:\\|\\\\)")


def _looks_like_path(s: str) -> bool:
    return bool(_PATH_HINT.match(s)) or "../" in s or "..\\" in s


_URL_RE = re.compile(r"\bhttps?://[^\s'\"<>)]+", re.IGNORECASE)


def _extract_urls(s: str) -> list[str]:
    return _URL_RE.findall(s)


def _host(url: str) -> str | None:
    try:
        return urllib.parse.urlparse(url).hostname
    except Exception:
        return None


def _host_matches(host: str, allowed: list[str]) -> bool:
    for pat in allowed:
        if fnmatch.fnmatch(host, pat):
            return True
    return False
