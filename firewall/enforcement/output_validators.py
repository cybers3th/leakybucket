"""Output-shape / schema validation.

Uses the same offline JSON Schema validation as approved MCP/tool arguments.
Application constraints are trusted configuration and fail closed.
"""
from __future__ import annotations

from dataclasses import dataclass
import json
import re
from typing import Any


class SchemaError(ValueError):
    pass


def validate_json_schema(instance: Any, schema: dict, path: str = "$") -> list[str]:
    """Return a list of error messages. Empty list = valid."""
    from firewall.mcp.schema import validate_arguments
    valid, reason = validate_arguments(schema, instance)
    return [] if valid else [f"{path}: {reason}"]


def try_parse_json(text: str) -> tuple[Any, str | None]:
    try:
        return json.loads(text), None
    except Exception as e:
        return None, str(e)


@dataclass(frozen=True)
class OutputConstraints:
    """Trusted application configuration; never populate from model/event data.

    Marker matching ignores punctuation/case. Literal matching includes bounded
    decoded representations and ignores whitespace to cover split disclosures.
    These checks enforce explicit strings, not general factual correctness.
    """
    forbidden_literals: tuple[str, ...] = ()
    forbidden_markers: tuple[str, ...] = ()
    forbidden_action_prefixes: tuple[str, ...] = ()
    schema: dict | None = None

    def __post_init__(self):
        for values in (self.forbidden_literals, self.forbidden_markers, self.forbidden_action_prefixes):
            if any(not isinstance(value, str) or not value.strip() for value in values):
                raise ValueError("output constraints must contain nonempty strings")
        if any(not _marker(value) for value in self.forbidden_markers):
            raise ValueError("markers must contain letters or numbers")

    def scan(self, event):
        from firewall.core.events import Detection
        from firewall.util.normalize import normalize_basic
        from firewall.util.security_rules import inspection_views
        if not (self.forbidden_literals or self.forbidden_markers or self.forbidden_action_prefixes or self.schema is not None):
            return []
        text = event.output_text or ""
        failures = set()
        for view in inspection_views(text):
            compact = re.sub(r"\s+", "", view)
            if any(re.sub(r"\s+", "", normalize_basic(value)) in compact
                   for value in self.forbidden_literals):
                failures.add("forbidden_literal")
            if any(_marker(value) in _marker(view) for value in self.forbidden_markers):
                failures.add("forbidden_marker")
            if any(normalize_basic(value).casefold() in view.casefold()
                   for value in self.forbidden_action_prefixes):
                failures.add("forbidden_action")
        if self.schema is not None:
            from firewall.mcp.schema import validate_arguments
            try:
                valid, _ = validate_arguments(self.schema, json.loads(text))
            except (ValueError, TypeError):
                valid = False
            if not valid:
                failures.add("output_schema_violation")
        return [Detection(detector="application_output", category="output_security",
                          subcategory=code, severity="critical", confidence=1.0,
                          message="Configured application output constraint violated")
                for code in sorted(failures)]


def _marker(text):
    import unicodedata
    return ''.join(c for c in unicodedata.normalize('NFKC', text).casefold() if c.isalnum())


class CredentialAdviceValidator:
    """Opt-in rejection of clear affirmative advice to publish private credentials.

    Narrow textual check; not a factual verifier or a general security-advice judge.
    Configure an independent domain validator for broader correctness requirements.
    """
    _affirmative = re.compile(
        r"\b(?:(?:private|secret|sensitive)\s+)?(?:credentials?|passwords?|api\s+keys?|private\s+keys?)"
        r"\s+(?:should|must|can|need\s+to)\s+(?:be\s+)?"
        r"(?:publish(?:ed)?|post(?:ed)?\s+publicly|shar(?:e|ed)\s+publicly|made\s+public)\b", re.I)
    _imperative = re.compile(
        r"^\s*(?:(?:yes|you\s+should|you\s+must)[,:]?\s+)?"
        r"(?:publish|post\s+publicly|share\s+publicly)\s+(?:your|the|all)?\s*"
        r"(?:private\s+|secret\s+)?(?:credentials?|passwords?|api\s+keys?|private\s+keys?)\b", re.I)

    def __call__(self, event) -> bool:
        for sentence in re.split(r"(?<=[.!?])\s+|\n", event.output_text or ""):
            if self._imperative.search(sentence):
                return False
            match = self._affirmative.search(sentence)
            if match and not re.search(r"\b(?:incorrect|unsafe|bad\s+advice|do\s+not|never)\b",
                                      sentence[:match.start()], re.I):
                return False
        return True
