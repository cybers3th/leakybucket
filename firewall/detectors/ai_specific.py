"""AI-specific attacks the traditional detectors don't cover.

Covers:
  * Model extraction — systematic behavior/parameter probing
  * Training-data extraction — canary/verbatim-repetition attacks
  * Membership inference queries
  * Model / weights file poisoning (pickle-backed formats: .pt / .pth / .bin /
    .pkl / .joblib and Jinja2-templated GGUF chat templates)
  * Adversarial model config (safetensors metadata carrying instructions,
    tool metadata carrying hidden capabilities)
  * Watermark stripping / prompt canary bypass
"""
from __future__ import annotations

import re
from dataclasses import dataclass

from firewall.core.events import Detection, SecurityEvent


@dataclass
class _P:
    slug: str
    severity: str
    confidence: float
    regex: re.Pattern
    message: str


def _p(slug, sev, conf, rx, msg):
    return _P(slug, sev, conf, re.compile(rx, re.IGNORECASE | re.DOTALL), msg)


# Model extraction — repeated systematic queries that try to reproduce
# weights/behavior. We only match single-message signals; behavioral rate
# tracking is done separately in BehaviorEngine.
MODEL_EXTRACTION = [
    _p("mex_logit_probing",     "high", 0.85,
       r"\bfor\s+each\s+of\s+the\s+following\s+\d{2,}\s+prompts,?\s+return\s+the\s+(?:log[-\s]?probs?|token\s+probabilities|softmax\s+outputs?)\b",
       "systematic logprob probing"),
    _p("mex_temperature_zero",  "medium", 0.6,
       r"\bset\s+temperature\s*=\s*0[\s\S]{0,40}and\s+(?:return|output)\s+(?:the\s+)?exact\s+response",
       "deterministic-output probing"),
    _p("mex_distillation_batch","high", 0.85,
       r"\b(?:for|please\s+process)\s+(?:each|all)\s+of\s+the\s+following\s+\d{3,}\s+(?:inputs?|prompts?|questions?)\b",
       "large-batch distillation query"),
    _p("mex_weights_ask",       "critical", 0.9,
       r"\b(?:return|reveal|dump|output)\s+(?:your\s+)?(?:weights?|parameters|embeddings?)\s+(?:for|of)\s+layer\b",
       "direct weight/parameter ask"),
    _p("mex_architecture_ask",  "medium", 0.7,
       r"\b(?:describe|reveal|output)\s+(?:your\s+)?(?:architecture|layer\s+count|number\s+of\s+parameters?|hidden\s+dim|attention\s+heads?)\b",
       "architecture probing"),
]

# Training-data extraction — attempts to elicit memorized data
TDX = [
    _p("tdx_verbatim_repeat",   "high", 0.85,
       r"\brepeat\s+(?:the\s+word\s+['\"]?[a-z]+['\"]?\s+)?(?:forever|infinitely|indefinitely|until\s+you\s+run\s+out)",
       "repeat-word extraction attack (Nasr et al. 2023)"),
    _p("tdx_prefix_completion", "high", 0.8,
       r"\bcomplete\s+(?:the\s+following\s+)?(?:passage|paragraph|document)\s+(?:verbatim|word[-\s]for[-\s]word|from\s+your\s+training\s+data)",
       "training-data prefix completion"),
    _p("tdx_canary_query",      "medium", 0.75,
       r"\bcanary\s*(?:token|string|phrase)?\s*[:=]\s*['\"][^'\"]{6,80}['\"]",
       "canary phrase probe"),
    _p("tdx_did_you_see",       "medium", 0.7,
       r"\b(?:have\s+you\s+seen|did\s+you\s+see|were\s+you\s+trained\s+on)\s+(?:this|the\s+following)\s+(?:exact\s+)?(?:text|passage|snippet|document)",
       "membership-inference phrasing"),
    _p("tdx_pii_recall",        "high", 0.85,
       r"\b(?:what\s+is|list|provide)\s+(?:the\s+)?(?:email|phone|address|SSN|password|credit\s+card)\s+of\s+[A-Z][a-z]+\s+[A-Z][a-z]+\b",
       "PII recall by named person"),
]

# Model file loading — dangerous file types being loaded, especially pickle-backed
MODEL_FILE = [
    _p("mfp_torch_load_url",    "critical", 0.95,
       r"torch\.load\s*\(\s*(?:['\"]https?://|urllib\.request|requests\.get)",
       "torch.load fetching remote pickle"),
    _p("mfp_joblib_load_url",   "critical", 0.9,
       r"joblib\.load\s*\(\s*(?:['\"]https?://|BytesIO)",
       "joblib.load remote / bytes"),
    _p("mfp_pickle_load_bytes", "critical", 0.9,
       r"pickle\.loads?\s*\(\s*(?:request|urlopen|response|payload|user)",
       "pickle load from network/request"),
    _p("mfp_from_pretrained_untrusted","high", 0.8,
       r"\.from_pretrained\s*\(\s*['\"](?:https?://|/tmp/|/var/tmp/|C:\\\\|~[^'\"]+)['\"]",
       "from_pretrained from writable / untrusted path"),
    _p("mfp_trust_remote_code", "critical", 0.95,
       r"\btrust_remote_code\s*=\s*True\b",
       "trust_remote_code=True enables arbitrary code from a repo"),
    _p("mfp_gguf_jinja_rce",    "critical", 0.95,
       r"chat_template\s*[:=]\s*['\"][^'\"]*\{\{[^}]*(?:__class__|__mro__|__subclasses__|__import__|os\.popen|subprocess)",
       "GGUF/Jinja2 chat_template RCE (CVE-2024-34359 shape)"),
    _p("mfp_h5_untrusted",      "high", 0.8,
       r"\bkeras\.models\.load_model\s*\(\s*(?:['\"]https?://|BytesIO)",
       "keras load_model from untrusted source"),
    _p("mfp_onnx_ext_ops",      "medium", 0.7,
       r"\bonnxruntime\.InferenceSession\s*\([^)]*providers\s*=\s*\[[^\]]*CustomOpLibrary",
       "ONNX custom-op library (potential loader)"),
    _p("mfp_msgpack_unpack",    "high", 0.8,
       r"\bmsgpack\.(?:unpackb|unpack)\s*\([^)]*(?:raw\s*=\s*False)?\s*[),]",
       "msgpack unpack of untrusted data"),
]

# Watermark / canary bypass and adversarial config
BYPASS_CFG = [
    _p("bypass_watermark",      "medium", 0.7,
       r"\b(?:strip|remove|bypass|defeat)\s+(?:the\s+)?(?:watermark|canary|fingerprint)\b",
       "watermark strip request"),
    _p("safetensors_meta_inject","high", 0.85,
       r"__metadata__\s*[:=]\s*\{[^}]{0,200}(?:system_prompt|instructions|jailbreak|override)",
       "safetensors metadata carrying instructions"),
]


ALL_AI = [MODEL_EXTRACTION, TDX, MODEL_FILE, BYPASS_CFG]


class AISpecificDetector:
    NAME = "ai_specific"

    def scan(self, event: SecurityEvent) -> list[Detection]:
        out: list[Detection] = []
        candidates: list[tuple[str, str]] = []
        if event.input_text:
            candidates.append(("input", event.input_text))
        if event.output_text:
            candidates.append(("output", event.output_text))
        if event.tool_call and event.tool_call.arguments:
            candidates.append(("tool_args", _stringify(event.tool_call.arguments)))
        if event.tool_def and event.tool_def.description:
            candidates.append(("tool_desc", event.tool_def.description))

        for lbl, text in candidates:
            for group in ALL_AI:
                for pat in group:
                    m = pat.regex.search(text)
                    if m:
                        out.append(Detection(
                            detector=self.NAME,
                            category="ai_specific" if pat.slug.startswith(("mex_", "tdx_", "bypass_"))
                                     else "supply_chain",
                            subcategory=pat.slug,
                            technique=pat.slug.split("_", 1)[0],
                            severity=pat.severity,
                            confidence=pat.confidence,
                            message=f"{pat.message} in {lbl}",
                            span=m.span(),
                            evidence=(m.group(0) or "")[:200],
                            metadata={"location": lbl},
                        ))
        return _dedup(out)


def _stringify(obj):
    import json
    try:
        return obj if isinstance(obj, str) else json.dumps(obj, default=str)
    except Exception:
        return str(obj)


def _dedup(ds):
    seen = set()
    out = []
    for d in ds:
        k = (d.subcategory, d.evidence[:60], d.metadata.get("location"))
        if k in seen:
            continue
        seen.add(k)
        out.append(d)
    return out
