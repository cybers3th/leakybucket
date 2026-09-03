"""Dataset integrity + a small regression smoke."""
import json
from pathlib import Path

from dataset.schema import loads


def test_corpus_files_exist():
    assert Path("dataset/corpus/all.jsonl").exists(), "run: python -m dataset.build_corpus"


def test_stats_present():
    s = json.loads(Path("dataset/corpus/stats.json").read_text())
    assert s["total"] >= 10_000
    assert s["malicious"] >= 5_000
    assert s["benign"] >= 1_000
    assert s["multi_turn"] >= 500
    assert s["attack_chains"] >= 500


def test_split_no_content_leak():
    """No content_hash should appear in both train and test."""
    train_hashes = set()
    with open("dataset/corpus/splits/train.jsonl") as f:
        for line in f:
            train_hashes.add(loads(line).content_hash())
    leaks = 0
    with open("dataset/corpus/splits/test.jsonl") as f:
        for line in f:
            if loads(line).content_hash() in train_hashes:
                leaks += 1
    assert leaks == 0, f"{leaks} content-hash duplicates between train and test"


def test_owasp_coverage():
    cats = set(json.loads(Path("dataset/corpus/stats.json").read_text())["by_category"])
    required = {
        "prompt_injection", "sensitive_data", "output_security", "rag_security",
        "excessive_agency", "system_prompt_leak", "supply_chain", "misinformation",
        "unbounded_consumption", "benign", "attack_chain",
    }
    missing = required - cats
    assert not missing, f"Missing OWASP categories in corpus: {missing}"
