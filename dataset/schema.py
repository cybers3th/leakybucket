"""Structured dataset schema shared by every generator + evaluator.

An Example represents anything from a single-turn malicious prompt to a
multi-step attack chain involving RAG + tools + external egress. Any field
not applicable to the specific example is left None or empty.
"""
from __future__ import annotations

import dataclasses as dc
import enum
import hashlib
import json
from dataclasses import dataclass, field
from typing import Any


class ExpectedBehavior(str, enum.Enum):
    ALLOW    = "allow"
    SANITIZE = "sanitize"
    APPROVE  = "require_approval"
    BLOCK    = "block"


OWASP_CATEGORIES = [
    "prompt_injection",
    "sensitive_data",
    "supply_chain",
    "poisoning",
    "output_security",
    "excessive_agency",
    "system_prompt_leak",
    "rag_security",
    "misinformation",
    "unbounded_consumption",
    "benign",
    "attack_chain",
]


@dataclass
class ConversationTurn:
    role: str                     # user, assistant, tool, system, developer
    content: str
    source_kind: str | None = None
    source_origin: str | None = None


@dataclass
class Example:
    # identity
    id: str
    category: str                                # OWASP category
    subcategory: str = ""
    attack_type: str = ""                        # generator subtype
    severity: str = "medium"                     # low, medium, high, critical
    difficulty: str = "medium"                   # easy, medium, hard, expert
    language: str = "en"
    attack_family: str = ""                      # e.g. "role_manipulation"
    source_type: str = "generated"               # generated, curated, real_world_anon

    # payload
    attack_text: str = ""
    context: str = ""
    system_instruction: str = ""
    user_message: str = ""
    retrieved_documents: list[dict[str, Any]] = field(default_factory=list)
    conversation_history: list[ConversationTurn] = field(default_factory=list)
    tool_definition: dict[str, Any] | None = None
    tool_call: dict[str, Any] | None = None
    tool_result: Any = None
    output_text: str = ""

    # expectations
    expected_behavior: ExpectedBehavior = ExpectedBehavior.BLOCK
    expected_decision: str = "block"
    expected_categories: list[str] = field(default_factory=list)   # which detectors should fire
    attack_success_condition: str = ""

    # metadata
    indicators: list[str] = field(default_factory=list)
    techniques: list[str] = field(default_factory=list)
    data_types_involved: list[str] = field(default_factory=list)
    affected_component: list[str] = field(default_factory=list)    # llm, tool, rag, memory, network, ...
    mitigation: str = ""
    tags: list[str] = field(default_factory=list)

    # provenance
    seed: str = ""
    generator: str = ""
    parent_id: str | None = None
    split: str = "train"                # train, val, test

    def deterministic_id(self) -> str:
        base = f"{self.category}|{self.subcategory}|{self.attack_family}|{self.attack_text}|{self.context}"
        return hashlib.sha1(base.encode("utf-8", "replace")).hexdigest()[:16]

    def content_hash(self) -> str:
        # Used for dedup / cross-split leak checks
        parts = [self.attack_text, self.context, self.user_message,
                 json.dumps(self.retrieved_documents, sort_keys=True, default=str),
                 json.dumps(self.tool_call, sort_keys=True, default=str)]
        return hashlib.sha1("||".join(parts).encode("utf-8", "replace")).hexdigest()

    def to_dict(self) -> dict[str, Any]:
        d = dc.asdict(self)
        d["expected_behavior"] = self.expected_behavior.value
        return d


def dumps(ex: Example) -> str:
    return json.dumps(ex.to_dict(), ensure_ascii=False, default=str)


def loads(line: str) -> Example:
    d = json.loads(line)
    d["expected_behavior"] = ExpectedBehavior(d.get("expected_behavior", "block"))
    hist = [ConversationTurn(**t) for t in d.pop("conversation_history", [])]
    ex = Example(**{**d, "conversation_history": hist})
    return ex
