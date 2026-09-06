"""ML backstop layer — small trained classifier as an ensemble member.

The classifier is NOT the security boundary. It's an additional detector
that fires alongside patterns + policy. Two implementations:

  * FeatureClassifier: dependency-free logistic-regression over engineered
    features; ships and runs with no torch/HF requirement. Trained offline
    from the corpus by ``train.py`` and loaded from a JSON model file.
  * TransformerClassifier: HF Transformers pipeline over DeBERTa / ModernBERT
    / Prompt-Guard checkpoints. Optional; needs torch + transformers.

Both expose the same MLDetector interface used by the Gateway.
"""
from firewall.ml.classifier import (
    FeatureClassifier, MLDetector, TransformerClassifier,
    train_feature_classifier,
)

__all__ = [
    "FeatureClassifier", "TransformerClassifier", "MLDetector",
    "train_feature_classifier",
]
