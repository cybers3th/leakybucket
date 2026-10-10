"""Declarative detector rule engine and executable regression-case format.

Rule examples are data, never evaluated as code. Regexes are authored locally;
callers cannot supply arbitrary expressions through a security event.
"""
from __future__ import annotations

from dataclasses import dataclass
from functools import lru_cache
import re
import base64
import binascii
from typing import Iterable

from firewall.core.events import Detection, SecurityEvent
from firewall.util.normalize import all_views, normalize_basic
import urllib.parse


@dataclass(frozen=True)
class RuleCase:
    name: str
    text: str
    expect_match: bool


@dataclass(frozen=True)
class SecurityRule:
    rule_id: str
    regex: str
    severity: str
    description: str
    cases: tuple[RuleCase, ...]

    @property
    def compiled(self):
        return compile_rule(self.regex)


@lru_cache(maxsize=1024)
def compile_rule(expression):
    return re.compile(expression, re.IGNORECASE | re.DOTALL)


def _inspection_views_uncached(text):
    """Bounded decoding, retaining original text and avoiding duplicate work."""
    views = list(dict.fromkeys(all_views(text)))
    if len(text) >= 12 and re.fullmatch(r"[A-Za-z0-9+/]+={0,2}", text):
        try:
            direct = base64.b64decode(text, validate=True).decode("utf-8")
            view = normalize_basic(direct)
            if view not in views:
                views.append(view)
        except (binascii.Error, UnicodeDecodeError, ValueError):
            pass
    decoded = text
    for _ in range(2):
        next_view = urllib.parse.unquote(decoded)
        if next_view == decoded:
            break
        decoded = next_view
        for view in all_views(decoded):
            if view not in views:
                views.append(view)
    return tuple(views)


@lru_cache(maxsize=256)
def _small_views(text):
    return _inspection_views_uncached(text)


def inspection_views(text):
    # Reuse decoding across detectors while bounding cache retention.
    return _small_views(text) if len(text) <= 4096 else _inspection_views_uncached(text)


def string_leaves(value, max_nodes=20_000, max_depth=32):
    """Iterative traversal. Cycles and over-budget structures are errors."""
    stack = [(value, 0)]
    count = 0
    while stack:
        value, depth = stack.pop()
        count += 1
        if count > max_nodes or depth > max_depth:
            raise ValueError("content exceeds traversal limits")
        if isinstance(value, str):
            yield value
        elif isinstance(value, dict):
            if count + len(value) > max_nodes:
                raise ValueError("content exceeds traversal limits")
            stack.extend((v, depth + 1) for v in value.values())
        elif isinstance(value, (list, tuple)):
            if count + len(value) > max_nodes:
                raise ValueError("content exceeds traversal limits")
            stack.extend((v, depth + 1) for v in value)


def candidate_texts(event: SecurityEvent, scope: str):
    """Keep policy domains scoped: misinformation inspects outputs only."""
    if scope == "output":
        if event.output_text:
            yield "output", event.output_text
        return
    if scope in ("rag", "poisoning"):
        for doc in event.context_docs:
            yield "rag:" + doc.doc_id, doc.content
            for text in string_leaves(doc.metadata):
                yield "rag_metadata:" + doc.doc_id, text
            if doc.source:
                for text in string_leaves(doc.source.metadata):
                    yield "rag_source_metadata:" + doc.doc_id, text
        if scope == "poisoning" and event.tool_def:
            yield "tool_description", event.tool_def.description
        return
    if scope == "tool":
        if event.tool_call:
            for text in string_leaves(event.tool_call.arguments):
                yield "tool_arguments", text
        if event.tool_def:
            yield "tool_description", event.tool_def.description
        return
    if event.input_text:
        yield "input", event.input_text
    if event.output_text:
        yield "output", event.output_text
    if event.tool_call:
        for text in string_leaves(event.tool_call.arguments):
            yield "tool_arguments", text
    if event.tool_result:
        for text in string_leaves(event.tool_result.content):
            yield "tool_result", text
    if event.tool_def:
        yield "tool_description", event.tool_def.description
        for text in string_leaves(event.tool_def.metadata):
            yield "tool_metadata", text
    for doc in event.context_docs:
        yield "rag:" + doc.doc_id, doc.content
        for text in string_leaves(doc.metadata):
            yield "rag_metadata:" + doc.doc_id, text
        if doc.source:
            for text in string_leaves(doc.source.metadata):
                yield "rag_source_metadata:" + doc.doc_id, text
    if event.source:
        for text in string_leaves(event.source.metadata):
            yield "source_metadata", text
    if event.tool_result and event.tool_result.source:
        for text in string_leaves(event.tool_result.source.metadata):
            yield "tool_result_source_metadata", text
    for msg in event.messages:
        if msg.role not in ("system", "developer"):
            yield "history:" + msg.role, msg.content


def scan_rules(event, rules: Iterable[SecurityRule], detector, category, scope):
    result = []
    seen = set()
    total_chars = 0
    candidates = 0
    try:
        for location, text in candidate_texts(event, scope):
            candidates += 1
            if candidates > 512:
                raise ValueError("content exceeds carrier inspection budget")
            total_chars += len(text)
            if total_chars > 1_000_000 or len(text) > 200_000:
                raise ValueError("content exceeds rule inspection budget")
            for view_index, view in enumerate(inspection_views(text)):
                for rule in rules:
                    key = (location, rule.rule_id)
                    if key in seen:
                        continue
                    match = rule.compiled.search(view)
                    if match is None:
                        continue
                    seen.add(key)
                    result.append(Detection(
                        detector=detector,
                        category=category,
                        subcategory=rule.rule_id,
                        technique="declarative-rule",
                        severity=rule.severity,
                        confidence=0.9,
                        message=rule.description,
                        # Credentials and content do not belong in audit evidence.
                        evidence="",
                        span=match.span() if location in ("input", "output") and view_index == 0 else None,
                        metadata={"location": location, "decoded": view_index > 0,
                                  "rule_id": rule.rule_id},
                    ))
    except ValueError as error:
        result.append(Detection(
            detector=detector, category="unbounded_consumption",
            subcategory="inspection_budget_exceeded", severity="critical",
            confidence=1.0, message=str(error),
        ))
    return result


def extend_with_rules(category, scope="all"):
    """Preserve existing detector API and add local, reviewable rule families."""
    from functools import wraps

    def decorate(scan):
        @wraps(scan)
        def expanded(self, event):
            rules = scan.__globals__["SECURITY_RULES"]
            extra = scan_rules(event, rules, self.NAME, category, scope)
            if any(d.subcategory == "inspection_budget_exceeded" for d in extra):
                return extra
            return scan(self, event) + extra
        return expanded
    return decorate
