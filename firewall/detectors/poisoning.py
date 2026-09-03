"""Data & model poisoning detector.

Runs at RAG ingestion time (via scan_ingest) AND at retrieval time
(via scan). Uses provenance + content heuristics to catch:
  * poisoned documents (invisible instructions, HTML comments)
  * poisoned tool descriptions
  * anomalous metadata
  * missing provenance (unknown source / owner / tenant)
  * cross-tenant contamination in ingest batches
"""
from __future__ import annotations

import re
from firewall.core.events import (
    Detection, RetrievedDoc, SecurityEvent, Source, SourceKind,
)
from firewall.detectors.rag_security import (
    _HTML_INSTR, _INSTR_MARK, _TOOL_INSTR,
)
from firewall.util.normalize import INVISIBLE_CHARS


class PoisoningDetector:
    NAME = "poisoning"

    def scan(self, event: SecurityEvent) -> list[Detection]:
        out: list[Detection] = []
        # Retrieval-time
        for doc in event.context_docs:
            out += self._doc_signals(doc)
        # Tool-description poisoning
        if event.tool_def and event.tool_def.description:
            if _INSTR_MARK.search(event.tool_def.description):
                out.append(Detection(
                    detector=self.NAME, category="poisoning",
                    subcategory="tool_description_poisoning",
                    severity="critical", confidence=0.95,
                    message=f"Tool '{event.tool_def.name}' description carries injection payload.",
                    evidence=event.tool_def.description[:200],
                ))
        return out

    def _doc_signals(self, doc: RetrievedDoc) -> list[Detection]:
        out: list[Detection] = []
        if not doc.source or not doc.source.origin:
            out.append(Detection(
                detector=self.NAME, category="poisoning",
                subcategory="missing_provenance",
                severity="medium", confidence=0.9,
                message=f"Doc {doc.doc_id} has no origin/provenance metadata.",
            ))
        content = doc.content or ""
        if any(c in content for c in INVISIBLE_CHARS) and _INSTR_MARK.search(content):
            out.append(Detection(
                detector=self.NAME, category="poisoning",
                subcategory="hidden_injection_payload",
                severity="critical", confidence=0.95,
                message=f"Doc {doc.doc_id} has hidden-character + injection payload.",
                metadata={"doc_id": doc.doc_id},
            ))
        if _HTML_INSTR.search(content) or _TOOL_INSTR.search(content):
            out.append(Detection(
                detector=self.NAME, category="poisoning",
                subcategory="instruction_carrier",
                severity="high", confidence=0.9,
                message=f"Doc {doc.doc_id} carries HTML/tool instruction payload.",
                metadata={"doc_id": doc.doc_id},
            ))
        return out

    # ------------- Ingest-time API -------------

    def scan_ingest(self, doc: RetrievedDoc,
                    expected_tenant: str) -> list[Detection]:
        out: list[Detection] = []
        if doc.source is None:
            out.append(Detection(
                detector=self.NAME, category="poisoning",
                subcategory="ingest_missing_source",
                severity="high", confidence=1.0,
                message="Ingest doc lacks a Source.",
            ))
            return out
        if doc.source.kind != SourceKind.RAG_DOCUMENT:
            out.append(Detection(
                detector=self.NAME, category="poisoning",
                subcategory="ingest_wrong_kind",
                severity="high", confidence=1.0,
                message=f"Ingest doc source kind is {doc.source.kind.value}, expected rag_document.",
            ))
        if doc.source.tenant and expected_tenant and doc.source.tenant != expected_tenant:
            out.append(Detection(
                detector=self.NAME, category="poisoning",
                subcategory="ingest_wrong_tenant",
                severity="critical", confidence=1.0,
                message=f"Doc tenant {doc.source.tenant} != expected {expected_tenant}.",
            ))
        out += self._doc_signals(doc)
        return out
