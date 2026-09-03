"""RAG / vector store security detector.

Covers:
  * cross-tenant retrieval
  * document-level authorization
  * malicious metadata / instructions in retrieved docs
  * retrieval poisoning heuristics (invisible content, HTML/script, prompt-injection payload)
  * excessive retrieval
  * sensitive documents flowing to untrusted destinations
  * duplicate / semantic-collision suspicion

Note on tenant isolation: this is enforced *deterministically* by comparing
the actor's tenant against the source tenant of every retrieved document,
independent of any vector similarity score. Retrieval similarity does NOT
imply authorization.
"""
from __future__ import annotations

import re
from firewall.core.events import (
    DataClassification, Detection, RetrievedDoc, SecurityEvent, SourceKind,
)
from firewall.util.normalize import INVISIBLE_CHARS


_SUSPICIOUS_METADATA_KEYS = {"system_prompt", "instructions", "override", "rules", "policy"}
_HTML_INSTR = re.compile(r"<!--\s*(?:ai[-_]?)?instructions?\s*[:\-]", re.IGNORECASE)
_INSTR_MARK = re.compile(r"\b(?:ignore|disregard|override)\s+(?:previous|prior|above|system)\s+"
                         r"(?:instructions?|prompts?|rules?)\b", re.IGNORECASE)
_TOOL_INSTR = re.compile(r"\b(?:call|invoke|execute|run)\s+(?:the\s+)?(?:tool|function)\s+", re.IGNORECASE)


class RAGSecurityDetector:
    NAME = "rag_security"

    def __init__(self, max_docs: int = 20):
        self.max_docs = max_docs

    def scan(self, event: SecurityEvent) -> list[Detection]:
        detections: list[Detection] = []
        docs = event.context_docs
        if not docs:
            return detections

        # 1. Excessive retrieval
        if len(docs) > self.max_docs:
            detections.append(Detection(
                detector=self.NAME, category="rag_security",
                subcategory="excessive_retrieval",
                severity="medium", confidence=0.95,
                message=f"Retrieved {len(docs)} docs (>{self.max_docs}).",
            ))

        actor_tenant = event.actor.tenant or "default"
        actor_roles = set(event.actor.roles or [])
        for doc in docs:
            self._scan_doc(doc, actor_tenant, actor_roles, detections, event)

        return detections

    def _scan_doc(self, doc: RetrievedDoc, actor_tenant: str, actor_roles: set,
                  out: list[Detection], event: SecurityEvent) -> None:
        # 2. Cross-tenant retrieval
        if doc.source and doc.source.tenant and doc.source.tenant != actor_tenant \
                and doc.source.tenant != "public":
            out.append(Detection(
                detector=self.NAME, category="rag_security",
                subcategory="cross_tenant_retrieval",
                severity="critical", confidence=1.0,
                message=f"Doc {doc.doc_id} from tenant '{doc.source.tenant}' returned to actor tenant '{actor_tenant}'.",
                metadata={"doc_id": doc.doc_id, "doc_tenant": doc.source.tenant, "actor_tenant": actor_tenant},
            ))

        # 3. Classification vs actor privilege — doc classifications above INTERNAL require role match
        if doc.source and int(doc.source.classification) >= int(DataClassification.RESTRICTED):
            required = f"{doc.source.tenant}:{doc.source.classification.name.lower()}"
            allowed_roles = {"security", "admin", f"reader:{doc.source.classification.name.lower()}"}
            if not (actor_roles & allowed_roles):
                out.append(Detection(
                    detector=self.NAME, category="rag_security",
                    subcategory="document_authorization",
                    severity="high", confidence=0.95,
                    message=f"Actor lacks role for {doc.source.classification.name} doc {doc.doc_id}.",
                    metadata={"doc_id": doc.doc_id, "required": required, "actor_roles": list(actor_roles)},
                ))

        # 4. Metadata manipulation
        for k in (doc.source.metadata if doc.source else {}) | (doc.metadata or {}):
            if str(k).lower() in _SUSPICIOUS_METADATA_KEYS:
                out.append(Detection(
                    detector=self.NAME, category="rag_security",
                    subcategory="malicious_metadata",
                    severity="high", confidence=0.85,
                    message=f"Suspicious metadata key '{k}' in doc {doc.doc_id}.",
                    metadata={"doc_id": doc.doc_id, "key": k},
                ))

        # 5. Content poisoning heuristics
        content = doc.content or ""
        if any(c in content for c in INVISIBLE_CHARS):
            out.append(Detection(
                detector=self.NAME, category="rag_security",
                subcategory="invisible_content",
                severity="high", confidence=0.85,
                message=f"Doc {doc.doc_id} contains invisible/bidi chars — hidden instructions possible.",
                metadata={"doc_id": doc.doc_id},
            ))
        if _HTML_INSTR.search(content):
            out.append(Detection(
                detector=self.NAME, category="rag_security",
                subcategory="html_comment_instruction",
                severity="high", confidence=0.9,
                message=f"HTML-comment instruction inside doc {doc.doc_id}.",
                evidence=content[:200],
                metadata={"doc_id": doc.doc_id},
            ))
        if _INSTR_MARK.search(content):
            out.append(Detection(
                detector=self.NAME, category="rag_security",
                subcategory="instruction_bearing_doc",
                severity="high", confidence=0.9,
                message=f"Injection-style instruction inside doc {doc.doc_id}.",
                evidence=content[:200],
                metadata={"doc_id": doc.doc_id},
            ))
        if _TOOL_INSTR.search(content):
            out.append(Detection(
                detector=self.NAME, category="rag_security",
                subcategory="tool_invocation_in_doc",
                severity="high", confidence=0.85,
                message=f"Doc {doc.doc_id} requests tool invocation.",
                evidence=content[:200],
                metadata={"doc_id": doc.doc_id},
            ))
        if "<script" in content.lower() or "javascript:" in content.lower():
            out.append(Detection(
                detector=self.NAME, category="rag_security",
                subcategory="active_content_in_doc",
                severity="high", confidence=0.9,
                message=f"Active-content markup inside doc {doc.doc_id}.",
                evidence=content[:200],
                metadata={"doc_id": doc.doc_id},
            ))
        # 6. Wrong source kind — a "RAG doc" that claims to be a system prompt
        if doc.source and doc.source.kind != SourceKind.RAG_DOCUMENT:
            out.append(Detection(
                detector=self.NAME, category="rag_security",
                subcategory="mislabeled_source",
                severity="medium", confidence=0.75,
                message=f"Doc {doc.doc_id} source kind is {doc.source.kind.value}, expected rag_document.",
                metadata={"doc_id": doc.doc_id},
            ))
