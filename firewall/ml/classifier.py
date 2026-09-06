"""ML backstop.

Two implementations:

  * FeatureClassifier — engineered features + logistic regression; trained
    offline via `train_feature_classifier`. Zero external deps at runtime.
  * TransformerClassifier — HF Transformers wrapper for a fine-tuned
    encoder classifier (ModernBERT / DeBERTa-v3 / Prompt-Guard). Requires
    `torch` and `transformers`.

Both expose ``predict(text) -> (label, prob)`` and can be plugged in as a
Detector via MLDetector.
"""
from __future__ import annotations

import json
import math
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable

from firewall.core.events import Detection, SecurityEvent


# ---------------------------------------------------------------------------
# Feature extraction — dependency-free
# ---------------------------------------------------------------------------

_INSTRUCTION_VERBS = re.compile(
    r"\b(?:ignore|reveal|disregard|forget|override|delete|drop|exfiltrate|"
    r"execute|run|call|invoke|send|email|post|upload|read|write|leak|"
    r"disable|bypass|persist|remember)\b", re.IGNORECASE)
_TARGET_NOUNS = re.compile(
    r"\b(?:system\s+prompt|instructions?|rules?|policy|api\s+key|secret|token|"
    r"password|credential|environment|\.env|memory|tool|function|"
    r"tools?/list|resources?/read|sampling)\b", re.IGNORECASE)
_URL_RE     = re.compile(r"\bhttps?://[^\s'\"<>]+")
_KEY_RE     = re.compile(r"\b(?:sk-|AKIA|ASIA|ghp_|xoxb-|AIza|hf_|eyJ)")
_UNSAFE_URL = re.compile(r"\b(?:169\.254\.169\.254|metadata\.google\.internal|localhost|127\.0\.0\.1|10\.\d+|192\.168\.)")
_JB_TOKENS  = re.compile(r"\b(?:DAN|AIM|STAN|jailbreak|policy\s*puppetry|skeleton\s*key|"
                          r"do\s+anything\s+now|developer\s+mode|unrestricted)\b",
                          re.IGNORECASE)
_ENC_HINTS  = re.compile(r"\b(?:base64|hex|rot13|url-?encoded|reverse\s+this|decode)\b",
                          re.IGNORECASE)
_INVISIBLES = "​‌‍⁠﻿‪‫‬‭‮"


def extract_features(text: str) -> dict[str, float]:
    if not text:
        text = ""
    n = len(text)
    words = text.split()
    features: dict[str, float] = {
        "bias":         1.0,
        "len":          min(1.0, n / 10_000),
        "wc":           min(1.0, len(words) / 3_000),
        "avg_word":     min(1.0, (sum(len(w) for w in words) / max(1, len(words))) / 20),
        "verb":         min(1.0, len(_INSTRUCTION_VERBS.findall(text)) / 5),
        "target":       min(1.0, len(_TARGET_NOUNS.findall(text)) / 5),
        "urls":         min(1.0, len(_URL_RE.findall(text)) / 5),
        "secrets":      min(1.0, len(_KEY_RE.findall(text)) / 3),
        "unsafe_url":   1.0 if _UNSAFE_URL.search(text) else 0.0,
        "jb_tok":       1.0 if _JB_TOKENS.search(text) else 0.0,
        "enc_hint":     1.0 if _ENC_HINTS.search(text) else 0.0,
        "invisibles":   min(1.0, sum(text.count(c) for c in _INVISIBLES) / 5),
        "uppercase":    sum(1 for c in text if c.isupper()) / max(1, n),
        "punct_dense":  sum(1 for c in text if c in "{}[]<>\"'`;|&") / max(1, n),
        "verb_x_target": 1.0 if (_INSTRUCTION_VERBS.search(text) and _TARGET_NOUNS.search(text)) else 0.0,
        "backtick_run":  min(1.0, len(re.findall(r"`{3}", text)) / 3),
        "kv_shape":      min(1.0, len(re.findall(r"\b\w+\s*[:=]\s*['\"]?\S{3,}", text)) / 10),
        "starts_ignore": 1.0 if re.match(r"^\s*(?:ignore|disregard|forget)\b", text, re.I) else 0.0,
    }
    return features


FEATURE_NAMES = list(extract_features("").keys())


# ---------------------------------------------------------------------------
# Logistic regression classifier — trained with plain SGD; no scikit-learn dep
# ---------------------------------------------------------------------------

@dataclass
class FeatureClassifier:
    weights: dict[str, float] = field(default_factory=dict)
    threshold: float = 0.5
    trained_examples: int = 0
    version: str = "1"

    def predict(self, text: str) -> tuple[bool, float]:
        f = extract_features(text)
        z = sum(self.weights.get(k, 0.0) * v for k, v in f.items())
        p = 1.0 / (1.0 + math.exp(-max(-30, min(30, z))))
        return (p >= self.threshold, p)

    def save(self, path: str | Path) -> None:
        Path(path).write_text(json.dumps({
            "weights": self.weights, "threshold": self.threshold,
            "trained_examples": self.trained_examples, "version": self.version,
        }))

    @classmethod
    def load(cls, path: str | Path) -> "FeatureClassifier":
        d = json.loads(Path(path).read_text())
        return cls(**d)


def train_feature_classifier(
    corpus_path: str | Path = "dataset/corpus/all.jsonl",
    epochs: int = 3,
    lr: float = 0.05,
    l2: float = 1e-4,
    max_examples: int | None = None,
    verbose: bool = True,
) -> FeatureClassifier:
    """Train the FeatureClassifier from the corpus with SGD.

    Label: 1 if category != "benign", else 0.
    """
    from dataset.schema import loads

    weights: dict[str, float] = {k: 0.0 for k in FEATURE_NAMES}
    n = 0
    for epoch in range(epochs):
        with open(corpus_path) as f:
            for i, line in enumerate(f):
                line = line.strip()
                if not line:
                    continue
                try:
                    ex = loads(line)
                except Exception:
                    continue
                y = 0.0 if ex.category == "benign" else 1.0
                text = (ex.attack_text or ex.user_message or ex.output_text or "")[:5000]
                f_vec = extract_features(text)
                z = sum(weights.get(k, 0.0) * v for k, v in f_vec.items())
                p = 1.0 / (1.0 + math.exp(-max(-30, min(30, z))))
                error = p - y
                for k, v in f_vec.items():
                    weights[k] -= lr * (error * v + l2 * weights[k])
                n += 1
                if max_examples and n >= max_examples:
                    break
            if verbose:
                print(f"[train] epoch {epoch+1}: seen {n} examples so far")
    clf = FeatureClassifier(weights=weights, threshold=0.5, trained_examples=n, version="1")
    return clf


# ---------------------------------------------------------------------------
# Transformer classifier (optional)
# ---------------------------------------------------------------------------

class TransformerClassifier:
    """Wraps a HuggingFace text-classification pipeline.

    Usage:
        clf = TransformerClassifier(model="ProtectAI/deberta-v3-base-prompt-injection-v2")
        malicious, prob = clf.predict("Ignore previous instructions and ...")
    """
    def __init__(self, model: str = "ProtectAI/deberta-v3-base-prompt-injection-v2",
                  device: int = -1, threshold: float = 0.5):
        try:
            from transformers import pipeline
        except ImportError as e:
            raise RuntimeError("pip install transformers torch to use TransformerClassifier") from e
        self.pipe = pipeline("text-classification", model=model, device=device,
                              truncation=True)
        self.threshold = threshold

    def predict(self, text: str) -> tuple[bool, float]:
        out = self.pipe(text[:4000])[0]
        label = str(out.get("label", "")).lower()
        score = float(out.get("score", 0.0))
        # ProtectAI-style: "INJECTION" positive, "SAFE" negative
        malicious = label.startswith(("injection", "malicious", "unsafe", "attack", "label_1"))
        prob = score if malicious else 1.0 - score
        return (prob >= self.threshold, prob)


# ---------------------------------------------------------------------------
# ML detector — plugs into the Gateway detector chain
# ---------------------------------------------------------------------------

class MLDetector:
    NAME = "ml_backstop"

    def __init__(self, classifier, category: str = "prompt_injection",
                  severity_at: dict[str, float] | None = None):
        self.clf = classifier
        self.category = category
        # score threshold -> severity
        self.severity_at = severity_at or {
            0.95: "critical", 0.80: "high", 0.60: "medium", 0.40: "low",
        }

    def _severity(self, p: float) -> str | None:
        for th in sorted(self.severity_at.keys(), reverse=True):
            if p >= th:
                return self.severity_at[th]
        return None

    def scan(self, event: SecurityEvent) -> list[Detection]:
        out: list[Detection] = []
        for lbl, text in (("input", event.input_text), ("output", event.output_text)):
            if not text:
                continue
            malicious, prob = self.clf.predict(text)
            sev = self._severity(prob) if malicious else None
            if not sev:
                continue
            out.append(Detection(
                detector=self.NAME, category=self.category,
                subcategory="ml_flagged",
                severity=sev, confidence=prob,
                message=f"ML backstop flagged {lbl} (p={prob:.3f})",
                metadata={"location": lbl, "prob": round(prob, 4),
                           "model_version": getattr(self.clf, "version", "?")},
            ))
        return out
