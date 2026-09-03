"""Misinformation / high-risk-domain output policy.

We don't try to build a general "is this true" oracle. Instead:
  * flag high-risk domains (financial, medical, legal, security, infra)
    where output requires citation and/or approval
  * detect uncertainty markers vs confident claims without sources
  * detect fabricated citation shapes (broken URL, made-up DOI, made-up
    court case citation) — cheap heuristics
"""
from __future__ import annotations

import re

from firewall.core.events import Detection, SecurityEvent


HIGH_RISK_DOMAINS = {
    "financial":  re.compile(r"\b(?:invest|buy|sell|trade|allocate|portfolio|hedge|short|long)\s+(?:the\s+)?(?:stock|bond|option|crypto|token|nft|ETF|index)|"
                             r"\b(?:transfer|wire|send)\s+\$?\d[\d,]*(?:\.\d+)?\s+(?:USD|EUR|GBP|BTC|ETH|to)\b", re.I),
    "medical":    re.compile(r"\b(?:diagnos|treatment|prescription|dose|dosage|contraindicat|medication|therapy)\b", re.I),
    "legal":      re.compile(r"\b(?:sue|lawsuit|contract|liability|jurisdiction|statute|clause|GDPR|HIPAA|indictment)\b", re.I),
    "security":   re.compile(r"\b(?:vulnerab|CVE-\d{4}-\d+|exploit|payload|shellcode|malware|ransomware)\b", re.I),
    "infra":      re.compile(r"\b(?:kubectl|helm|terraform)\s+(?:apply|destroy|delete)|\b(?:drop\s+table|truncate\s+table|delete\s+from)\b", re.I),
}


UNCERTAINTY = re.compile(
    r"\b(?:I('m| am) not sure|I'm uncertain|might be|could be|possibly|probably|likely|"
    r"as far as I know|to my knowledge|it seems|I believe|I think)\b", re.I,
)

CITATION = re.compile(
    r"(?:\[?\d+\]?\s*(?:https?://\S+))|"
    r"(?:doi:\s*10\.\d{4,9}/[\w\-.;()/:]+)|"
    r"(?:https?://\S+)|"
    r"(?:\b(?:According to|Source:|Ref\.?:|Reference:)\s+\S+)",
    re.I,
)

FAB_DOI = re.compile(r"\bdoi:\s*10\.(\d{4,9})/([\w\-.;()/:]+)", re.I)
FAB_CASE = re.compile(r"\b([A-Z][a-zA-Z]+)\s+v\.?\s+([A-Z][a-zA-Z]+),?\s+\d{1,4}\s+U\.S\.\s+\d{1,4}\s+\(\d{4}\)")


class MisinformationDetector:
    NAME = "misinformation"

    def scan(self, event: SecurityEvent) -> list[Detection]:
        out: list[Detection] = []
        text = event.output_text or ""
        if not text:
            return out

        matched_domains = [d for d, rgx in HIGH_RISK_DOMAINS.items() if rgx.search(text)]
        has_uncertainty = bool(UNCERTAINTY.search(text))
        has_citation = bool(CITATION.search(text))

        for d in matched_domains:
            sev = "high" if d in ("financial", "medical", "legal", "security", "infra") else "medium"
            out.append(Detection(
                detector=self.NAME, category="misinformation",
                subcategory=f"high_risk_domain:{d}",
                severity=sev, confidence=0.7,
                message=f"Output touches high-risk domain '{d}'.",
                metadata={"domain": d, "has_citation": has_citation, "has_uncertainty": has_uncertainty},
            ))
            if not has_citation:
                out.append(Detection(
                    detector=self.NAME, category="misinformation",
                    subcategory=f"missing_citation:{d}",
                    severity="high", confidence=0.8,
                    message=f"High-risk-domain output lacks a citation/source.",
                ))
            if not has_uncertainty and not has_citation:
                out.append(Detection(
                    detector=self.NAME, category="misinformation",
                    subcategory=f"confident_no_source:{d}",
                    severity="high", confidence=0.75,
                    message="Confident claim in high-risk domain with no source or uncertainty marker.",
                ))

        # Heuristic fabrication signals
        for m in FAB_DOI.finditer(text):
            registrant = m.group(1)
            # DOIs from real registrants start with 4-5 digits and follow prefixes we can't verify offline;
            # we flag rather than block.
            out.append(Detection(
                detector=self.NAME, category="misinformation",
                subcategory="unverified_doi",
                severity="low", confidence=0.5,
                message=f"DOI {m.group(0)} present — verify externally.",
                evidence=m.group(0),
            ))
        for m in FAB_CASE.finditer(text):
            out.append(Detection(
                detector=self.NAME, category="misinformation",
                subcategory="unverified_case_citation",
                severity="medium", confidence=0.5,
                message=f"Legal-case citation {m.group(0)} — verify externally.",
                evidence=m.group(0),
            ))
        return out
