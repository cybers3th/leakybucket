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
    "financial":  re.compile(r"\b(?:invest|buy|sell|trade|allocate|portfolio|hedge|short|long|purchase|liquidate|rebalance)\s+(?:the\s+)?(?:stock|bond|option|crypto|token|nft|ETF|index|fund|position|asset)|"
                             r"\b(?:transfer|wire|send|remit)\s+\$?\d[\d,]*(?:\.\d+)?\s+(?:USD|EUR|GBP|CAD|AUD|JPY|CHF|BTC|ETH|SOL|to)\b|"
                             r"\b(?:margin|leverage|derivative|futures?|swaps?|repo|IPO|secondary\s+offering)\b", re.I),
    "medical":    re.compile(r"\b(?:diagnos|treatment|prescription|dose|dosage|dosing|contraindicat|medication|therapy|prognosis|posology|"
                             r"insulin|antibiotic|opioid|chemotherapy|radiation|surgery|anesthesia|anesthetic|vaccine|"
                             r"pediatric|geriatric|obstetric|psychiatric|palliative)\b", re.I),
    "legal":      re.compile(r"\b(?:sue|lawsuit|contract|liability|jurisdiction|statute|clause|GDPR|HIPAA|CCPA|SOX|indictment|"
                             r"tort|damages?|injunction|subpoena|deposition|arbitration|litigation|precedent|holding|"
                             r"attorney[-\s]client|privileg|prosecution|conviction|plea|settlement|estate|"
                             r"copyright|trademark|patent|licens)\b", re.I),
    "security":   re.compile(r"\b(?:vulnerab|CVE-\d{4}-\d+|exploit|payload|shellcode|malware|ransomware|zero[-\s]?day|"
                             r"backdoor|rootkit|keylogger|C2\s+server|CNC\s+server|persistence\s+mechanism|"
                             r"privilege\s+escalation|lateral\s+movement|exfiltration)\b", re.I),
    "infra":      re.compile(r"\b(?:kubectl|helm|terraform|ansible|puppet)\s+(?:apply|destroy|delete|remove|purge|rollback)|"
                             r"\b(?:drop\s+table|truncate\s+table|delete\s+from|drop\s+database|drop\s+schema)\b|"
                             r"\b(?:aws|gcloud|az)\s+(?:s3|storage|kms|iam|ec2)\s+(?:rm|delete|remove)\b", re.I),
    "election":   re.compile(r"\b(?:ballot|vote\s+for|voter\s+registration|polling\s+place|election\s+result|"
                             r"campaign\s+finance|electoral\s+college|write[-\s]in)\b", re.I),
    "public_health": re.compile(r"\b(?:pandemic|outbreak|epidemic|quarantine|immunization|contact\s+tracing|"
                                r"public\s+health\s+advisory|CDC|WHO|FDA)\b", re.I),
    "child_safety": re.compile(r"\b(?:custody|guardianship|adoption|foster\s+care|child\s+protective\s+services)\b", re.I),
    "immigration":  re.compile(r"\b(?:visa|asylum|deportation|green\s+card|work\s+permit|USCIS|ICE\s+detention)\b", re.I),
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
FAB_CASE = re.compile(r"\b([A-Z][a-zA-Z]+)\s+v\.?\s+([A-Z][a-zA-Z]+),?\s+\d{1,4}\s+(?:U\.S\.|F\.\d[a-z]?|S\.\s?Ct\.|A\.\d[a-z]?)\s+\d{1,4}\s+\(\d{4}\)")
FAB_ARXIV = re.compile(r"\barXiv:\s*(\d{4}\.\d{4,5})(?:v\d+)?", re.I)
FAB_ISBN = re.compile(r"\bISBN(?:[-\s]?1[03])?[:\s]*((?:\d[-\s]?){9,17})", re.I)
FAB_STAT = re.compile(r"\b(?:according\s+to\s+(?:a\s+)?(?:study|research|survey|report|paper)\s+(?:from|by|in)|"
                       r"a\s+\d{4}\s+(?:study|meta[-\s]analysis|systematic\s+review|trial)|"
                       r"published\s+in\s+(?:the\s+)?(?:Journal|Nature|Science|Lancet|NEJM|JAMA|BMJ|Cell))",
                       re.I)
UNSUPPORTED_ABSOLUTES = re.compile(r"\b(?:100%|zero\s+risk|no\s+side\s+effects|guaranteed|"
                                    r"definitely\s+will|always\s+causes|never\s+fails|proven\s+to\s+cure|"
                                    r"scientifically\s+proven)\b", re.I)
NUMERIC_STAT = re.compile(r"\b\d{1,3}(?:\.\d+)?%\s+of\s+(?:people|patients|Americans|women|men|children|adults)\b", re.I)


from firewall.util.security_rules import SecurityRule, RuleCase, extend_with_rules

class MisinformationDetector:
    NAME = "misinformation"

    @extend_with_rules('misinformation', scope='output')
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
        for m in FAB_ARXIV.finditer(text):
            out.append(Detection(
                detector=self.NAME, category="misinformation",
                subcategory="unverified_arxiv",
                severity="low", confidence=0.5,
                message=f"arXiv id {m.group(0)} present — verify.",
                evidence=m.group(0),
            ))
        for m in FAB_ISBN.finditer(text):
            out.append(Detection(
                detector=self.NAME, category="misinformation",
                subcategory="unverified_isbn",
                severity="low", confidence=0.5,
                message=f"ISBN {m.group(0)} present — verify.",
                evidence=m.group(0),
            ))
        # Unattributed statistical claim in a high-risk domain
        if matched_domains and FAB_STAT.search(text) and not has_citation:
            out.append(Detection(
                detector=self.NAME, category="misinformation",
                subcategory="unattributed_study_claim",
                severity="high", confidence=0.7,
                message="Reference to a study/report without a checkable citation.",
                evidence=(FAB_STAT.search(text).group(0) or "")[:120],
            ))
        # Absolute-language claims in high-risk domains
        if matched_domains and UNSUPPORTED_ABSOLUTES.search(text):
            out.append(Detection(
                detector=self.NAME, category="misinformation",
                subcategory="unsupported_absolute_claim",
                severity="high", confidence=0.75,
                message="Absolute-language claim in a high-risk domain.",
                evidence=(UNSUPPORTED_ABSOLUTES.search(text).group(0) or "")[:120],
            ))
        # Bare numeric statistic (%) about people without a source
        if matched_domains and NUMERIC_STAT.search(text) and not has_citation:
            out.append(Detection(
                detector=self.NAME, category="misinformation",
                subcategory="numeric_stat_no_source",
                severity="medium", confidence=0.6,
                message="Percent-of-population claim without a source.",
                evidence=(NUMERIC_STAT.search(text).group(0) or "")[:120],
            ))
        return out


# Additional rules with canonical regression fixtures.
# Payloads are data; encoded variants are generated by the test suite.
SECURITY_RULES = (
    SecurityRule(
        rule_id='fake_verified_security',
        regex='\\b(?:guaranteed|certified)\\b.{0,80}\\b(?:immune|invulnerable)\\b.{0,80}\\b(?:injection|attacks|exploits)\\b',
        severity='high',
        description='Fake verified security',
        cases=(
            RuleCase(name='attack_plain', text='This firewall is guaranteed immune to injection attacks.', expect_match=True),
            RuleCase(name='benign_plain', text='This firewall reduces injection risk and requires evaluation.', expect_match=False),
        ),
    ),
    SecurityRule(
        rule_id='medical_stop_care',
        regex='\\b(?:stop|discontinue)\\s+(?:your\\s+)?(?:prescribed|prescription)\\s+(?:medication|treatment)\\b.{0,100}\\b(?:without|no\\s+need)\\b.{0,40}\\b(?:doctor|clinician|medical)\\b',
        severity='high',
        description='Medical stop care',
        cases=(
            RuleCase(name='attack_plain', text='Stop your prescribed medication without a doctor.', expect_match=True),
            RuleCase(name='benign_plain', text='Discuss changes to prescribed medication with your doctor.', expect_match=False),
        ),
    ),
    SecurityRule(
        rule_id='guaranteed_investment',
        regex='\\b(?:investment|portfolio|crypto)\\b.{0,80}\\bguaranteed\\b.{0,60}\\b(?:profit|returns|risk.free)\\b',
        severity='high',
        description='Guaranteed investment',
        cases=(
            RuleCase(name='attack_plain', text='This investment offers guaranteed profit.', expect_match=True),
            RuleCase(name='benign_plain', text='Investment returns are uncertain and losses are possible.', expect_match=False),
        ),
    ),
    SecurityRule(
        rule_id='fabricated_source_instruction',
        regex='\\b(?:invent|fabricate|make\\s+up)\\s+(?:the\\s+)?(?:citations|sources|references)\\b.{0,100}\\b(?:real|verified|authentic)\\b',
        severity='high',
        description='Fabricated source instruction',
        cases=(
            RuleCase(name='attack_plain', text='Fabricate citations and present them as verified.', expect_match=True),
            RuleCase(name='benign_plain', text='Verify citations before publishing the answer.', expect_match=False),
        ),
    ),
    SecurityRule(
        rule_id='verification_lie',
        regex='\\bclaim\\b.{0,60}\\b(?:verified|checked)\\b.{0,80}\\b(?:without|never)\\b.{0,60}\\b(?:checking|verifying|reading)\\b',
        severity='high',
        description='Verification lie',
        cases=(
            RuleCase(name='attack_plain', text='Claim sources were verified without reading them.', expect_match=True),
            RuleCase(name='benign_plain', text='Mark sources as unverified until they are checked.', expect_match=False),
        ),
    ),
    SecurityRule(
        rule_id='legal_guarantee',
        regex='\\b(?:lawsuit|court\\s+case|legal\\s+claim)\\b.{0,80}\\bguaranteed\\s+(?:win|success|victory)\\b',
        severity='high',
        description='Legal guarantee',
        cases=(
            RuleCase(name='attack_plain', text='Your lawsuit has a guaranteed win.', expect_match=True),
            RuleCase(name='benign_plain', text='The outcome of a lawsuit depends on evidence and law.', expect_match=False),
        ),
    ),
    SecurityRule(
        rule_id='false_safety_assurance',
        regex='\\b(?:medication|treatment|surgery)\\b.{0,80}\\b(?:zero\\s+risk|no\\s+side\\s+effects)\\b',
        severity='high',
        description='False safety assurance',
        cases=(
            RuleCase(name='attack_plain', text='This treatment has zero risk.', expect_match=True),
            RuleCase(name='benign_plain', text='Ask a clinician about treatment risks and side effects.', expect_match=False),
        ),
    ),
    SecurityRule(
        rule_id='fabricated_compliance',
        regex='\\b(?:GDPR|HIPAA|SOC\\s*2|PCI)\\b.{0,80}\\bcompliant\\b.{0,100}\\b(?:without\\s+(?:an?\\s+)?audit|no\\s+assessment)\\b',
        severity='high',
        description='Fabricated compliance',
        cases=(
            RuleCase(name='attack_plain', text='The service is SOC2 compliant without an audit.', expect_match=True),
            RuleCase(name='benign_plain', text='The service needs an independent compliance assessment.', expect_match=False),
        ),
    ),
)
