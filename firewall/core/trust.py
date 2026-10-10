"""Trust resolution + provenance helpers.

Content that came from an untrusted source (RAG doc, tool result, web page,
email, file) must not be treated as authoritative instruction to the model.
This module is the single place that decides trust for a chunk of content
and provides utilities for wrapping untrusted content so downstream detectors
know what they're looking at.
"""
from __future__ import annotations

import hashlib
import html
from dataclasses import dataclass
from typing import Iterable

from firewall.core.events import (
    DEFAULT_SOURCE_TRUST, DataClassification, RetrievedDoc, Source,
    SourceKind, TrustLevel,
)


UNTRUSTED_KINDS = {
    SourceKind.RAG_DOCUMENT, SourceKind.TOOL_RESULT, SourceKind.WEB_CONTENT,
    SourceKind.EMAIL, SourceKind.FILE, SourceKind.MEMORY,
    SourceKind.AGENT_MESSAGE, SourceKind.MODEL_OUTPUT,
}


class TrustResolver:
    """Resolves trust for a Source, honoring policy overrides.

    Policy can raise a specific origin (e.g. an internal, curated RAG collection)
    or lower a specific origin (e.g. a public web feed known to be risky).
    """

    def __init__(
        self,
        trusted_origins: Iterable[str] = (),
        untrusted_origins: Iterable[str] = (),
    ) -> None:
        self.trusted_origins = set(trusted_origins)
        self.untrusted_origins = set(untrusted_origins)

    def resolve(self, source: Source) -> TrustLevel:
        if source.origin in self.untrusted_origins:
            return TrustLevel.UNTRUSTED
        base = source.effective_trust()
        if source.origin in self.trusted_origins and source.kind in UNTRUSTED_KINDS:
            # Origin is on the trusted list, promote to DEVELOPER not SYSTEM —
            # we don't want a document to override the actual system prompt.
            return TrustLevel.DEVELOPER
        return base

    def is_untrusted_kind(self, kind: SourceKind) -> bool:
        return kind in UNTRUSTED_KINDS


UNTRUSTED_OPEN  = "<untrusted-content source=\"{origin}\" kind=\"{kind}\">"
UNTRUSTED_CLOSE = "</untrusted-content>"


def wrap_untrusted(content: str, source: Source) -> str:
    """Wrap content coming from an untrusted source with structural markers.

    The gateway also strips any occurrences of these markers in the raw
    content first (otherwise an attacker could inject their own closing tag
    to escape). See ``strip_wrapping_markers``.
    """
    clean = strip_wrapping_markers(content)
    return (
        UNTRUSTED_OPEN.format(origin=html.escape(source.origin or "unknown", quote=True), kind=source.kind.value)
        + clean
        + UNTRUSTED_CLOSE
    )


def strip_wrapping_markers(content: str) -> str:
    return content.replace(UNTRUSTED_OPEN.split("{", 1)[0], "") \
                  .replace(UNTRUSTED_CLOSE, "") \
                  .replace("<untrusted-content", "<blocked-tag") \
                  .replace("</untrusted-content>", "</blocked-tag>")


def hash_doc(content: str) -> str:
    return hashlib.sha256(content.encode("utf-8", "replace")).hexdigest()


def new_rag_source(
    origin: str,
    tenant: str,
    owner: str = "",
    classification: DataClassification = DataClassification.INTERNAL,
    content: str = "",
) -> Source:
    return Source(
        kind=SourceKind.RAG_DOCUMENT,
        origin=origin, tenant=tenant, owner=owner,
        classification=classification,
        hash=hash_doc(content) if content else "",
    )
