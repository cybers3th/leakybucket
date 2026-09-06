"""Train the FeatureClassifier from the built corpus.

    python -m firewall.ml.train --corpus dataset/corpus/all.jsonl --out firewall/ml/model.json

The trained model is loadable at runtime via FeatureClassifier.load(path).
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

from firewall.ml.classifier import train_feature_classifier, extract_features


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--corpus", default="dataset/corpus/all.jsonl")
    ap.add_argument("--out",    default="firewall/ml/model.json")
    ap.add_argument("--epochs", type=int, default=3)
    ap.add_argument("--lr",     type=float, default=0.05)
    ap.add_argument("--max-examples", type=int, default=None)
    args = ap.parse_args()

    clf = train_feature_classifier(
        corpus_path=args.corpus, epochs=args.epochs, lr=args.lr,
        max_examples=args.max_examples, verbose=True,
    )
    Path(args.out).parent.mkdir(parents=True, exist_ok=True)
    clf.save(args.out)
    print(f"[train] saved to {args.out}. weights sample:",
           {k: round(v, 3) for k, v in list(clf.weights.items())[:8]})


if __name__ == "__main__":
    main()
