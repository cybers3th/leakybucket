"""Optional feature-based and transformer classifiers for the detector pipeline.
Classifier predictions do not replace authorization or policy enforcement."""
from firewall.ml.semantic import LocalSemanticClassifier

from firewall.ml.classifier import (
    FeatureClassifier, MLDetector, TransformerClassifier,
    train_feature_classifier,
)

__all__ = [
    "FeatureClassifier", "TransformerClassifier", "MLDetector", "LocalSemanticClassifier",
    "train_feature_classifier",
]
