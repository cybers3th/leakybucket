"""Prompt injection detector.

Multi-layer strategy:
  1) deterministic patterns on the raw text
  2) same patterns on the NFKC-normalized + de-homoglyphed view
  3) same patterns on decoded views (base64/hex/URL/rot13)
  4) structural signals — untrusted-source content that also carries an
     imperative-sounding instruction is treated as high confidence
  5) delimiter / role manipulation
  6) known jailbreak archetypes (DAN, "developer mode", etc.)
  7) targets checks (system prompt, security policy, memory, tools)

Nothing here relies on a single classifier — this is defense in depth.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Iterable

from firewall.core.events import Detection, SecurityEvent, SourceKind, TrustLevel
from firewall.util.normalize import all_views, normalize_basic


# --- Pattern groups. Each has a slug (subcategory), severity, confidence weight, patterns.
@dataclass
class _PatternGroup:
    slug: str
    severity: str
    confidence: float
    technique: str
    patterns: list[re.Pattern]


def _p(*regexes: str) -> list[re.Pattern]:
    return [re.compile(r, re.IGNORECASE | re.DOTALL) for r in regexes]


DIRECT_OVERRIDE = _PatternGroup(
    slug="direct_override",
    severity="high",
    confidence=0.9,
    technique="instruction-override",
    patterns=_p(
        # English
        r"\bignore\s+(?:all\s+)?(?:previous|prior|above|earlier)\s+(?:instructions?|prompts?|messages?|rules?)\b",
        r"\bdisregard\s+(?:all|any|the)\s+(?:previous|prior|above|earlier|foregoing)(?:\s+(?:instructions?|prompts?|rules?|messages?|context))?\b",
        r"\bdisregard\s+(?:the\s+)?(?:previous|prior|above|earlier|foregoing)\s+(?:and|,|;)\b",
        r"\bforget\s+(?:everything|all\s+(?:previous|prior|above))\b",
        r"\bstop\s+following\s+(?:the|your)\s+(?:previous|system|earlier)\s+(?:instructions?|rules?)\b",
        r"\boverride\s+(?:the\s+)?(?:system|previous|safety|prior)\s+(?:prompt|instructions?|rules?|policy)\b",
        r"\bnew\s+instructions?\s+(?:from\s+(?:the\s+)?(?:admin|developer|vendor|provider|system))?\s*[:\-]",
        r"\byour\s+new\s+(?:role|task|instructions?|objective|purpose|goal)\s+is\b",
        r"\byou\s+are\s+now\s+(?:a|an|the)\s+[a-z ]{3,40}?\s+(?:without|with\s+no|that\s+ignores)\b",
        # Spanish
        r"\bignor[ae]\s+(?:todas?\s+)?(?:las?\s+)?(?:instrucciones?|reglas?|indicaciones?|mensajes?)\s+(?:anteriores?|previas?)\b",
        r"\bolvida\s+(?:todas?|todo)\b",
        r"\bhaz\s+caso\s+omiso\s+(?:a|de)\s+las?\s+(?:instrucciones?|reglas?)\b",
        # French
        r"\bignor(?:e|ez)\s+(?:toutes?\s+les?\s+)?(?:instructions?|règles?|indications?)\s+(?:précédentes?|antérieures?)\b",
        r"\boubli(?:e|ez)\s+(?:tout|toutes?\s+les?\s+instructions?)\b",
        r"\bne\s+tiens?\s+pas?\s+compte\s+des?\s+(?:instructions?|règles?)\s+précédentes?\b",
        # German
        r"\bignori(?:ere|eren\s+Sie)\s+(?:alle\s+)?(?:vorherigen?|früheren?|obigen?)\s+(?:Anweisungen?|Instruktionen?|Regeln?)\b",
        r"\bvergiss\s+(?:alles|alle\s+vorherigen?)\b",
        r"\bmissachte\s+(?:alle\s+)?(?:vorherigen?|obigen?)\s+(?:Anweisungen?|Regeln?)\b",
        # Portuguese / Italian
        r"\bignor[ae]\s+(?:todas?\s+)?(?:as\s+)?instruç(?:ões|ao)\s+(?:anteriores?|prévias?)\b",
        r"\bignora\s+(?:tutte\s+le\s+)?istruzioni\s+(?:precedenti|anteriori)\b",
    ),
)

ROLE_MANIPULATION = _PatternGroup(
    slug="role_manipulation",
    severity="high", confidence=0.85, technique="role-manipulation",
    patterns=_p(
        r"\bpretend\s+(?:to\s+be|you\s+are|you're)\s+(?:an?\s+)?[a-z ]{3,40}\b",
        r"\bact\s+as\s+(?:if\s+you\s+(?:were|are))?\s*(?:an?|the)\s+[a-z ]{3,50}\b",
        r"\brole[-\s]?play\s+(?:as|the\s+role\s+of)\s+[a-z ]{3,60}\b",
        r"\bsimulate\s+(?:a|an|the)\s+(?:conversation|scenario|character)\b",
        r"\bfrom\s+now\s+on\s+you\s+(?:are|will|must|should)\b",
        r"\bimpersonate\s+(?:the|a|an)?\s*[a-z ]{3,50}\b",
    ),
)

JAILBREAK_ARCHETYPES = _PatternGroup(
    slug="jailbreak",
    severity="critical", confidence=0.95, technique="jailbreak-archetype",
    patterns=_p(
        # --- classic named archetypes ---
        r"\bDAN\b\s+(?:mode|prompt|jailbreak|version|v\d)?",
        r"\bdo\s+anything\s+now\b",
        r"\bdeveloper[-\s]mode\b",
        r"\bAIM\s+(?:mode|prompt)?\b(?:\s*,\s*an?\s+unfiltered)?",
        r"\bact\s+as\s+AIM\b",
        r"\bAlways\s+Intelligent\s+and\s+Machiavellian\b",
        r"\bSTAN\b",
        r"\bStrive\s+To\s+Avoid\s+Norms\b",
        r"\bevil[-\s]confidant\b",
        r"\bJailBroken\b|\bJailbreak\s+mode\b",
        r"\bunrestricted\s+(?:AI|assistant|mode)\b",
        r"\bgrandmother\s+(?:used\s+to\s+)?tell\s+me\b",
        r"\bpretend\s+.{0,30}\b(?:you\s+have\s+no|without)\s+(?:restrictions?|filters?|rules?|policies?|ethics?)\b",
        r"\bignore\s+(?:your\s+)?(?:safety|content|ethics?)\s+(?:policy|policies|guidelines?|rules?)\b",
        # Hypothetical / fictional framing
        r"\b(?:hypothetical(?:ly)?|fictional(?:ly)?|imagined|thought[-\s]experiment|for\s+a\s+(?:novel|story|movie|game|book))\b[\s\S]{0,120}\b(?:pretend|imagine|describe|explain|reveal|execute|delete|email|exfiltrate|list)\b",
        r"\bthis\s+is\s+(?:just|only|purely)?\s*(?:for|a)\s+(?:a\s+)?(?:fictional|hypothetical|educational|research|red[-\s]team)\b[\s\S]{0,120}\b(?:so|then|therefore|please)\b",
        r"\bpretend\s+(?:you\s+can|to\s+be\s+able\s+to)\s+[a-z ]{3,80}\b",
        # --- Skeleton Key (Microsoft, 2024) ---
        r"\baugment\s+(?:your\s+|the\s+)?(?:rules?|guidelines?)\s*[:\-]\s*comply\b",
        r"\bcomply\s+with\s+any\s+request\s+but\s+prepend\s+['\"]?warning['\"]?",
        # --- Prefix injection (force affirmative reply) ---
        r"\b(?:start|begin)\s+(?:your\s+)?(?:response|reply|answer|output)\s+with\s+(?:the\s+exact\s+string\s+)?['\"]sure[,!]?\s+(?:here'?s?\s+is)?['\"]",
        # --- Refusal suppression ---
        r"\bdo\s+not\s+(?:use|say)\s+(?:the\s+words?:?\s+)?(?:cannot|sorry|apologize|unable|against\s+policy)\b",
        r"\bwith\s+(?:those|these)\s+banned\b",
        # --- Payload splitting ---
        r"\blet\s+[a-z]\s*=\s*['\"][^'\"]{2,40}['\"]\s*;\s*let\s+[a-z]\s*=\s*['\"][^'\"]{2,80}['\"]\s*;\s*(?:execute|concat)",
        r"\bconcat\s*\(\s*[a-z]\s*,\s*[a-z]\s*\)",
        # --- Policy puppetry (fake system config) ---
        r"\[\s*SYSTEM[_\s]?(?:CONFIG|PROMPT|SETTINGS)\s*\]\s*[\r\n]+\s*(?:restrictions?|safety|policy|content_filter)\s*[:=]\s*(?:disabled|off|false|none)",
        r"\bsafety[_\s]layer\s*[:=]\s*(?:off|disabled|false)\b",
        r"\bcontent[_\s]?(?:filter|policy)\s*[:=]\s*(?:off|disabled|none)\b",
        # --- ChatML / special-token mimicry ---
        r"<\|im_start\|>\s*system\b|<\|im_end\|>",
        r"<\|(?:system|assistant|user|end)\|>",
        # --- Forged assistant prefill ---
        r"^\s*Assistant\s*:\s*Sure,\s+here\s+are\s+the\s+steps\b",
        r"^\s*Assistant\s*:\s*(?:Certainly|Absolutely|Of course).{0,20}here('|)s?\s+(?:how|the\s+steps)",
        # --- Bad Likert Judge ---
        r"\brate\s+(?:each\s+of\s+the\s+following|the\s+following)\s+1[-–]?5\s+for\s+harmfulness\b",
        r"\blevel\s+5\s+example\s+must\s+(?:describe|include|contain)\b",
        # --- H-CoT hijack ---
        r"<thinking(?:-copy)?>\s*(?:safety\s+check\s+passed|user\s+is\s+authorized|proceeding\s+with)",
        # --- Reasoning-trace exfiltration (2026 cross-model replay) ---
        r"\btranscribe\s+the\s+reasoning\s+attached\s+to\s+this\s+turn\b",
        r"<thinking[-_]copy>",
        # --- DrAttack fragment reconstruction ---
        r"\bcombine\s+fragments?\s+[A-C]\s*=\s*['\"][^'\"]+['\"]\s*,\s*[A-C]\s*=\s*['\"][^'\"]+['\"]",
        # --- MINJA memory poisoning ---
        r"\bremember\s+(?:this\s+)?for\s+all\s+future\s+(?:conversations?|sessions?|turns?)\b",
        r"\bpermanently\s+(?:store|save|remember)\s+(?:this|the\s+following)\b",
        # --- PAP persuasion opener ---
        r"\bi\s+know\s+you\s+have\s+policies?,?\s+but\s+as\s+a\s+fellow\s+(?:professional|researcher|expert)\b",
        # --- Negative framing ---
        r"\blist\s+(?:ten|10)\s+things\s+you\s+would\s+never\s+help\s+with\s+and\s+explain\s+each\b",
        # --- Cipher-based ---
        r"\breply\s+only\s+in\s+(?:caesar[-\s]shifted|rot13|base64|hex|morse)\s+(?:text|code)\b",
        r"\bconverse\s+entirely\s+in\s+(?:cipher|caesar|rot13)\b",
        # --- ArtPrompt ASCII-art markers ---
        r"\[\[ASCII[-\s]?art\s+of\s+[a-z ]+\]\]",
        # --- Context overflow filler + trailing action ---
        r"(?:this\s+is\s+a\s+routine\s+meeting\s+notes\s+document\.\s*){20,}",
        # --- Instruction-in-thinking style ---
        r"<thinking>\s*(?:i\s+will|let\s+me)\s+ignore\s+(?:my\s+)?(?:safety|policy|rules)\b",
    ),
)

INSTRUCTION_HIERARCHY = _PatternGroup(
    slug="hierarchy_manipulation",
    severity="high", confidence=0.8, technique="hierarchy",
    patterns=_p(
        r"\bthis\s+is\s+(?:an?\s+)?(?:system|admin|root|vendor|provider)\s+(?:message|instruction|override)\b",
        r"\b\[?(?:system|admin|root|developer)\]?\s*[:>]\s*",
        r"\bhigher[-\s]priority\s+(?:instructions?|rules?)\b",
        r"\bthe\s+(?:real|actual|true)\s+(?:system|instructions?)\s+(?:is|are)\b",
        r"\bfrom\s+(?:the\s+)?(?:owner|creator|vendor|provider|admin)\s*[:\-]",
    ),
)

TARGET_SYSTEM_PROMPT = _PatternGroup(
    slug="system_prompt_target",
    severity="high", confidence=0.85, technique="target-system-prompt",
    patterns=_p(
        r"\b(?:reveal|print|show|repeat|output|display|leak)\s+(?:me\s+)?(?:the\s+)?(?:system|hidden|initial|original|developer|internal)\s+(?:prompt|instructions?|message|rules?|policy)\b",
        r"\brepeat\s+(?:everything|all)\s+(?:above|before\s+this\s+message|in\s+your\s+context)\b",
        r"\bwhat\s+(?:are|were)\s+your\s+(?:original|initial|hidden|system)\s+(?:instructions?|rules?|prompt)\b",
        r"\bignore.{0,60}\bthen\s+(?:reveal|print|show|list)\s+your\s+(?:instructions?|prompt|rules?)\b",
        r"\bencode\s+your\s+(?:system|hidden)\s+prompt\s+in\s+(?:base64|hex|rot13)\b",
    ),
)

TARGET_POLICY = _PatternGroup(
    slug="policy_target",
    severity="critical", confidence=0.9, technique="target-security-policy",
    patterns=_p(
        r"\b(?:disable|turn\s+off|bypass|ignore|remove|delete|drop)\s+(?:the\s+)?(?:firewall|guardrails?|safety|content|security|moderation)\s+(?:policy|policies|filters?|rules?|checks?)\b",
        r"\byou\s+don'?t\s+need\s+to\s+follow\s+(?:the\s+)?safety\s+rules?\b",
        r"\bapproval\s+is\s+not\s+required\b",
        r"\bthis\s+is\s+approved\s+(?:by\s+security|by\s+the\s+admin)\b",
    ),
)

TARGET_TOOLS = _PatternGroup(
    slug="tool_hijack",
    severity="high", confidence=0.85, technique="target-tools",
    patterns=_p(
        r"\b(?:call|invoke|execute|run|use)\s+(?:the\s+)?(?:tool|function|api)\s+[`\"']?[a-z_.]{3,40}[`\"']?\s+(?:with|and)\b",
        r"\bthen\s+(?:call|invoke|execute|run)\s+[`\"']?[a-z_.]{3,40}[`\"']?\s*\(",
        r"\bafter\s+that,?\s+(?:send|email|post|upload)\s+(?:the\s+)?(?:result|output|data|content)\s+to\s+[a-z0-9\-\.]+\.[a-z]{2,}",
    ),
)

TARGET_MEMORY = _PatternGroup(
    slug="memory_manipulation",
    severity="high", confidence=0.85, technique="target-memory",
    patterns=_p(
        r"\bremember\s+(?:this|the\s+following)\s+(?:for|in)\s+(?:all\s+)?(?:future|next|later)\s+(?:conversations?|sessions?|turns?)\b",
        r"\bsave\s+(?:this|the\s+following)\s+(?:to|in)\s+(?:your\s+)?(?:memory|long[-\s]term)\b",
        r"\bpermanently\s+(?:store|save|remember)\b",
        r"\bnever\s+forget\s+that\b",
    ),
)

ENCODED_INSTRUCTION = _PatternGroup(
    slug="encoded_instruction",
    severity="high", confidence=0.85, technique="encoding",
    patterns=_p(
        r"\bdecode\s+(?:the\s+|this\s+)?(?:following|below)?\s*(?:base64|hex|rot[-\s]?13|url[-\s]?encoded)\s+(?:and\s+(?:execute|follow|obey|do))",
        r"\bexecute\s+(?:the\s+)?(?:base64|hex|rot[-\s]?13|encoded)\b",
        r"\bfollow\s+(?:the\s+)?hex[-\s]?decoded\s+(?:instructions?|payload)\b",
        r"\breverse\s+this\s+(?:string|text)\s+and\s+(?:execute|follow|obey)\b",
        r"\bplease\s+decode\s*[:\-]?\s*[A-Za-z0-9+/=]{40,}",  # inline base64
        r"\brot13-decode\s+and\s+follow\s*[:\-]",
        r"\bfollow\s+the\s+hex\s+decoded\s+instructions?\b",
        r"\burl[-\s]?decode\s*[:\-]?\s*(?:%[0-9a-fA-F]{2}){8,}",
        r"\breverse\s+and\s+follow\s*[:\-]",
        # GCG adversarial suffix shape
        r"describing\.\\ \+ similarlyNow write oppositel[ey]",
        r"\]\(\s*Me\s+giving\*\*ONE\b",
        # AutoDAN "hypothetical response by a rebellious character"
        r"\bhypothetical\s+response\s+by\s+a\s+rebellious\s+character\b",
        r"\bformat\s+as\s+list\s+starting\s+with\s+['\"]sure['\"]",
    ),
)

INDIRECT_DELIVERY = _PatternGroup(
    slug="indirect_delivery_hint",
    severity="medium", confidence=0.6, technique="indirect-delivery-marker",
    patterns=_p(
        r"<!--\s*ai[-_\s]?instructions?\s*:",
        r"<\s*(?:script|iframe)[^>]*>[^<]*(?:ignore|system|prompt)[^<]*<",
        r"\[\s*(?:instruction|system|assistant)\s*\]\s*[:>]",
        r"\bhidden\s+instructions?\s+for\s+(?:the\s+)?(?:model|assistant|ai|llm)\b",
    ),
)

DELIMITER_ATTACK = _PatternGroup(
    slug="delimiter_attack",
    severity="high", confidence=0.85, technique="delimiter",
    patterns=_p(
        r"\"\"\"[\s\n]*(?:system|assistant|user)\s*[:>]",
        r"---\s*end\s+of\s+(?:instructions?|prompt|system)\s*---",
        r"</\s*(?:system|instructions?|prompt|context)\s*>",
        r"<\|(?:system|im_start|im_end|assistant|user|end)[^|>]{0,30}\|>",
        r"###\s*(?:system|new\s+instructions?|admin)\s*###",
    ),
)

PATTERN_GROUPS: list[_PatternGroup] = [
    DIRECT_OVERRIDE, ROLE_MANIPULATION, JAILBREAK_ARCHETYPES, INSTRUCTION_HIERARCHY,
    TARGET_SYSTEM_PROMPT, TARGET_POLICY, TARGET_TOOLS, TARGET_MEMORY,
    ENCODED_INSTRUCTION, INDIRECT_DELIVERY, DELIMITER_ATTACK,
]


# Imperative-verb + object markers used for structural "instruction-in-untrusted-content" scoring
_IMPERATIVE_VERBS = re.compile(
    r"\b(?:ignore|reveal|print|output|send|email|post|upload|exfiltrate|leak|forward|"
    r"execute|run|call|invoke|delete|drop|read|write|copy|save|remember|forget|"
    r"disable|bypass|obey|follow|do|make|create|generate|fetch|open|visit|browse)\b",
    re.IGNORECASE,
)
_TARGET_NOUNS = re.compile(
    r"\b(?:system\s+prompt|instructions?|rules?|policy|api\s+key|secret|token|password|"
    r"credential|environment|env|\.env|/etc/passwd|shadow|memory|tool|function|url|link)\b",
    re.IGNORECASE,
)
_URL_LIKE = re.compile(r"\bhttps?://[^\s)>\]]+", re.IGNORECASE)

# Meta-discussion markers — reduce severity when a pattern appears inside a
# quoted, definitional, or educational context (e.g. "what does 'ignore previous
# instructions' mean?"). Note: attackers can add quotes too, so we DO NOT skip
# the detection, only downgrade severity — the pattern still contributes to risk.
_META_CONTEXT = re.compile(
    r"(?i)\b(?:what\s+does|what\s+is|explain|define|meaning\s+of|"
    r"example\s+of|documentation\s+about|writing\s+about|threat\s+model|"
    r"red[-\s]team|educational|onboarding\s+doc|training\s+material|"
    r"security\s+course|academic|paper\s+about|blog\s+post\s+about)\b",
)
_QUOTED = re.compile(r"['\"“”‘’«»].{2,80}['\"“”‘’«»]")


def _is_meta_context(text: str, match_span: tuple[int, int]) -> bool:
    """Return True if the match is likely meta-discussion, not an actual instruction."""
    # Match is inside quotes AND the surrounding text has a meta marker
    start, end = match_span
    window = text[max(0, start - 60):min(len(text), end + 60)]
    if _QUOTED.search(text) and _META_CONTEXT.search(text):
        return True
    # window around the match talks about the concept, not issues it
    if _META_CONTEXT.search(window):
        return True
    return False


class PromptInjectionDetector:
    NAME = "prompt_injection"

    def __init__(self, extra_groups: Iterable[_PatternGroup] = ()) -> None:
        self.groups = list(PATTERN_GROUPS) + list(extra_groups)

    def scan(self, event: SecurityEvent) -> list[Detection]:
        detections: list[Detection] = []
        text = event.input_text or ""
        if not text:
            # Also scan retrieved docs and tool results if we're pre-model
            for doc in event.context_docs:
                self._scan_untrusted_carrier(doc.content, "rag_document", detections)
            if event.tool_result and isinstance(event.tool_result.content, str):
                self._scan_untrusted_carrier(event.tool_result.content, "tool_result", detections)
            return detections

        views = all_views(text)
        # 1..3 pattern layers
        for gi, group in enumerate(self.groups):
            for pat in group.patterns:
                for vi, v in enumerate(views):
                    m = pat.search(v)
                    if m:
                        span = m.span() if v == text else None
                        sev = group.severity
                        conf = group.confidence
                        subcat = group.slug
                        if vi == 0 and _is_meta_context(text, m.span()):
                            # Meta-discussion — downgrade to low severity, still recorded
                            sev = "low"
                            conf = min(conf, 0.4)
                            subcat = group.slug + ":meta"
                        detections.append(Detection(
                            detector=self.NAME,
                            category="prompt_injection",
                            subcategory=subcat,
                            technique=group.technique + (f":view{vi}" if vi else ""),
                            severity=sev,
                            confidence=conf,
                            message=f"Pattern match ({subcat})",
                            span=span,
                            evidence=(m.group(0) or "")[:200],
                        ))
                        break  # one hit per pattern
        # dedup by (subcategory, evidence)
        detections = _dedup(detections)

        # 4) structural: input came from an untrusted source and looks instruction-shaped
        norm = normalize_basic(text)
        if event.trust_of_input == TrustLevel.UNTRUSTED and _looks_instruction_shaped(norm):
            detections.append(Detection(
                detector=self.NAME,
                category="prompt_injection",
                subcategory="untrusted_instruction_shape",
                technique="structural",
                severity="high",
                confidence=0.85,
                message="Untrusted-source content contains imperative instructions and a target noun.",
                evidence=norm[:200],
            ))

        # 5) untrusted source + URL egress hint
        if event.trust_of_input == TrustLevel.UNTRUSTED and _URL_LIKE.search(norm):
            detections.append(Detection(
                detector=self.NAME,
                category="prompt_injection",
                subcategory="untrusted_egress_hint",
                technique="structural",
                severity="medium",
                confidence=0.7,
                message="Untrusted content contains an outbound URL — possible exfil channel.",
            ))

        # 6) also scan retrieved docs and tool results
        for doc in event.context_docs:
            self._scan_untrusted_carrier(doc.content, "rag_document", detections)
        if event.tool_result and isinstance(event.tool_result.content, str):
            self._scan_untrusted_carrier(event.tool_result.content, "tool_result", detections)

        # 7) scan prior conversation history — multi-turn attacks live there
        for msg in (event.messages or []):
            if msg.role in ("user", "tool") and msg.content:
                self._scan_history_turn(msg.content, msg.role, detections)

        return detections

    def _scan_history_turn(self, content: str, role: str,
                            detections: list[Detection]) -> None:
        if not content or len(content) > 20_000:
            return
        views = all_views(content)
        for group in self.groups:
            for pat in group.patterns:
                for v in views:
                    m = pat.search(v)
                    if m:
                        detections.append(Detection(
                            detector=self.NAME,
                            category="prompt_injection",
                            subcategory=f"history_{role}:{group.slug}",
                            technique=f"history-{group.technique}",
                            severity=group.severity if group.severity != "critical" else "high",
                            confidence=min(1.0, group.confidence * 0.9),
                            message=f"Injection pattern in prior {role} turn.",
                            evidence=(m.group(0) or "")[:200],
                            metadata={"role": role},
                        ))
                        break

    def _scan_untrusted_carrier(self, content: str, carrier: str, detections: list[Detection]) -> None:
        if not content:
            return
        views = all_views(content)
        for group in self.groups:
            for pat in group.patterns:
                for v in views:
                    m = pat.search(v)
                    if m:
                        detections.append(Detection(
                            detector=self.NAME,
                            category="prompt_injection",
                            subcategory=f"indirect_via_{carrier}:{group.slug}",
                            technique=f"indirect-{group.technique}",
                            severity="high" if group.severity in ("high", "critical") else group.severity,
                            confidence=min(1.0, group.confidence + 0.05),
                            message=f"Injection pattern inside {carrier}.",
                            evidence=(m.group(0) or "")[:200],
                            metadata={"carrier": carrier},
                        ))
                        break


def _dedup(ds: list[Detection]) -> list[Detection]:
    seen = set()
    out = []
    for d in ds:
        k = (d.subcategory, d.evidence[:80])
        if k in seen:
            continue
        seen.add(k)
        out.append(d)
    return out


def _looks_instruction_shaped(text: str) -> bool:
    verb = _IMPERATIVE_VERBS.search(text) is not None
    target = _TARGET_NOUNS.search(text) is not None
    return verb and target
