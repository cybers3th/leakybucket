"""Core event, trust and classification model shared by every component."""
from __future__ import annotations

import enum
import hashlib
import time
import uuid
from dataclasses import dataclass, field
from typing import Any


# ---------------------------------------------------------------------------
# Trust / classification enums
# ---------------------------------------------------------------------------

class TrustLevel(enum.IntEnum):
    """Trust rank of a piece of content. Higher = more authoritative.

    Instructions from an untrusted source must NEVER silently become
    authoritative directives to the model.
    """
    UNTRUSTED   = 0   # RAG, tool result, web, email, file, another agent
    ANONYMOUS   = 10  # unauthenticated user
    USER        = 30  # authenticated user
    DEVELOPER   = 60  # application developer (embedded prompts)
    SYSTEM      = 80  # system prompt configured by app owner
    SECURITY    = 100 # firewall policy — never overridable


class DataClassification(enum.IntEnum):
    PUBLIC       = 0
    INTERNAL     = 20
    CONFIDENTIAL = 40
    RESTRICTED   = 60
    SECRET       = 80


class SourceKind(str, enum.Enum):
    USER            = "user"
    SYSTEM_PROMPT   = "system_prompt"
    DEV_PROMPT      = "dev_prompt"
    RAG_DOCUMENT    = "rag_document"
    TOOL_RESULT     = "tool_result"
    WEB_CONTENT     = "web_content"
    EMAIL           = "email"
    FILE            = "file"
    MEMORY          = "memory"
    AGENT_MESSAGE   = "agent_message"
    MODEL_OUTPUT    = "model_output"


class Decision(str, enum.Enum):
    ALLOW            = "allow"
    SANITIZE         = "sanitize"
    REQUIRE_APPROVAL = "require_approval"
    BLOCK            = "block"

    @property
    def severity(self) -> int:
        return {"allow": 0, "sanitize": 1, "require_approval": 2, "block": 3}[self.value]


# Trust defaults per source kind. Overridable via config.
DEFAULT_SOURCE_TRUST: dict[SourceKind, TrustLevel] = {
    SourceKind.SYSTEM_PROMPT: TrustLevel.SYSTEM,
    SourceKind.DEV_PROMPT:    TrustLevel.DEVELOPER,
    SourceKind.USER:          TrustLevel.USER,
    SourceKind.RAG_DOCUMENT:  TrustLevel.UNTRUSTED,
    SourceKind.TOOL_RESULT:   TrustLevel.UNTRUSTED,
    SourceKind.WEB_CONTENT:   TrustLevel.UNTRUSTED,
    SourceKind.EMAIL:         TrustLevel.UNTRUSTED,
    SourceKind.FILE:          TrustLevel.UNTRUSTED,
    SourceKind.MEMORY:        TrustLevel.UNTRUSTED,
    SourceKind.AGENT_MESSAGE: TrustLevel.UNTRUSTED,
    SourceKind.MODEL_OUTPUT:  TrustLevel.UNTRUSTED,
}


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------

def _new_id(prefix: str = "evt") -> str:
    return f"{prefix}_{uuid.uuid4().hex[:16]}"


@dataclass
class Source:
    """Provenance of a piece of content."""
    kind: SourceKind
    origin: str = ""            # URL, filename, tool name, doc id, etc.
    tenant: str = "default"
    owner: str = ""
    ingested_at: float = field(default_factory=time.time)
    trust: TrustLevel | None = None
    classification: DataClassification = DataClassification.INTERNAL
    hash: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)

    def effective_trust(self) -> TrustLevel:
        if self.trust is not None:
            return self.trust
        return DEFAULT_SOURCE_TRUST.get(self.kind, TrustLevel.UNTRUSTED)


@dataclass
class Actor:
    """Who is making the request."""
    user_id: str = "anonymous"
    tenant: str = "default"
    session_id: str = ""
    agent_id: str = ""
    application_id: str = ""
    roles: list[str] = field(default_factory=list)
    trust: TrustLevel = TrustLevel.USER
    authenticated: bool = False
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class RetrievedDoc:
    """A single RAG-retrieved document."""
    doc_id: str
    content: str
    source: Source
    score: float = 0.0
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class Message:
    role: str                                    # system, developer, user, assistant, tool
    content: str
    source: Source | None = None
    timestamp: float = field(default_factory=time.time)


@dataclass
class ToolDefinition:
    name: str
    description: str = ""
    owner: str = ""
    risk_level: str = "medium"                   # low, medium, high, critical
    capabilities: list[str] = field(default_factory=list)  # read, write, delete, execute, network
    required_roles: list[str] = field(default_factory=list)
    allowed_agents: list[str] = field(default_factory=list)  # empty = any
    allowed_resources: list[str] = field(default_factory=list)  # glob patterns
    allowed_hosts: list[str] = field(default_factory=list)   # egress allowlist
    requires_human_approval: bool = False
    rate_limit_per_minute: int = 60
    data_classifications_allowed: DataClassification = DataClassification.SECRET  # max
    provider: str = "local"
    version: str = "1.0"
    sha256: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class ToolCall:
    tool: str
    arguments: dict[str, Any] = field(default_factory=dict)
    call_id: str = field(default_factory=lambda: _new_id("call"))


@dataclass
class ToolResult:
    call_id: str
    tool: str
    ok: bool
    content: Any = None
    source: Source | None = None
    duration_ms: int = 0
    error: str | None = None


# ---------------------------------------------------------------------------
# The unified security event
# ---------------------------------------------------------------------------

@dataclass
class SecurityEvent:
    """Passes through every stage of the pipeline. Everything is optional."""
    event_id: str = field(default_factory=lambda: _new_id("evt"))
    correlation_id: str = ""
    parent_event_id: str | None = None
    ts: float = field(default_factory=time.time)

    # who / where
    actor: Actor = field(default_factory=Actor)
    source: Source | None = None
    destination: str = ""                        # model, tool name, network host, output sink

    # what
    model: str = ""
    provider: str = ""
    system_prompt: str = ""
    developer_prompt: str = ""
    messages: list[Message] = field(default_factory=list)
    input_text: str = ""                         # the primary text being evaluated
    context_docs: list[RetrievedDoc] = field(default_factory=list)
    tool_call: ToolCall | None = None
    tool_result: ToolResult | None = None
    tool_def: ToolDefinition | None = None
    output_text: str = ""

    # security state, filled in by pipeline
    classifications: list[DataClassification] = field(default_factory=list)
    trust_of_input: TrustLevel = TrustLevel.USER
    detections: list["Detection"] = field(default_factory=list)
    risk_score: int = 0
    risk_reasons: list[str] = field(default_factory=list)
    matched_policies: list[str] = field(default_factory=list)
    decision: Decision = Decision.ALLOW
    reasons: list[str] = field(default_factory=list)
    sanitized_text: str | None = None
    approval_required_from: str | None = None

    # audit metadata
    stage: str = "input"
    tags: list[str] = field(default_factory=list)
    extra: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self):
        if not self.correlation_id:
            self.correlation_id = self.actor.session_id or _new_id("corr")

    def add_detection(self, d: "Detection") -> None:
        self.detections.append(d)

    def worst_decision(self, d: Decision) -> Decision:
        return d if d.severity > self.decision.severity else self.decision

    def content_hash(self) -> str:
        return hashlib.sha256(self.input_text.encode("utf-8", "replace")).hexdigest()


@dataclass
class Detection:
    """A single security signal raised by a detector."""
    detector: str
    category: str                                # owasp category slug
    subcategory: str = ""
    technique: str = ""
    severity: str = "medium"                     # low, medium, high, critical
    confidence: float = 0.5                      # 0..1
    message: str = ""
    span: tuple[int, int] | None = None          # char offsets in input if applicable
    evidence: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)

    @property
    def severity_int(self) -> int:
        return {"low": 20, "medium": 50, "high": 75, "critical": 95}.get(self.severity, 50)
