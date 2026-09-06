"""Materialize the attack corpus into JSONL files under dataset/corpus/.

Runs every generator, applies mutations, deduplicates by content hash,
splits into train/val/test with attack-family stratification, and writes:

  dataset/corpus/all.jsonl
  dataset/corpus/by_category/<cat>.jsonl
  dataset/corpus/splits/{train,val,test}.jsonl
  dataset/corpus/stats.json
"""
from __future__ import annotations

import hashlib
import json
import random
from collections import Counter, defaultdict
from pathlib import Path
from typing import Iterable

from dataset import schema
from dataset.generators import (
    prompt_injection as gen_pi,
    sensitive_data as gen_sd,
    output_attacks as gen_out,
    rag_attacks as gen_rag,
    agent_attacks as gen_agent,
    benign as gen_benign,
    misc_owasp as gen_misc,
    multi_turn as gen_mt,
    attack_chains as gen_chain,
    mcp_attacks as gen_mcp,
    prompt_injection_v2 as gen_pi2,
    cve_replay as gen_cve,
    real_world_attacks as gen_rw,
    dlp_realistic as gen_dlp2,
    injection_families as gen_inj,
    benign_realistic as gen_brl,
    v03_expansion as gen_v03,
    agentic_asi as gen_asi,
    mass_expansion as gen_mass,
)
from dataset.mutations import mutate
from dataset.schema import Example, dumps


ROOT = Path(__file__).parent / "corpus"


def _all_examples() -> Iterable[Example]:
    yield from gen_pi.generate()
    yield from gen_sd.generate()
    yield from gen_out.generate()
    yield from gen_rag.generate()
    yield from gen_agent.generate()
    yield from gen_benign.generate()
    yield from gen_misc.generate()
    yield from gen_mt.generate()
    yield from gen_chain.generate()
    yield from gen_mcp.generate()
    # v2 generators — primitives-driven, with public provenance
    yield from gen_pi2.generate()
    yield from gen_cve.generate()
    yield from gen_rw.generate()
    yield from gen_dlp2.generate()
    yield from gen_inj.generate()
    yield from gen_brl.generate()
    yield from gen_v03.generate()
    yield from gen_asi.generate()
    yield from gen_mass.generate()


def _split_key(ex: Example) -> str:
    # Prevent near-duplicates leaking across splits: bucket by attack_family
    return f"{ex.category}:{ex.attack_family or ex.subcategory}"


def _split(ex: Example, rng: random.Random) -> str:
    key = _split_key(ex)
    h = int(hashlib.md5(key.encode()).hexdigest(), 16)
    r = (h % 100) / 100.0
    # 70/15/15
    if r < 0.70: return "train"
    if r < 0.85: return "val"
    return "test"


def build(mutation_multiplier: int = 2, verbose: bool = True) -> dict:
    ROOT.mkdir(parents=True, exist_ok=True)
    (ROOT / "by_category").mkdir(parents=True, exist_ok=True)
    (ROOT / "splits").mkdir(parents=True, exist_ok=True)

    seen_hashes: set[str] = set()
    per_cat: dict[str, list[Example]] = defaultdict(list)
    all_out: list[Example] = []

    rng = random.Random(1234)

    def _accept(ex: Example) -> None:
        h = ex.content_hash()
        if h in seen_hashes:
            return
        seen_hashes.add(h)
        ex.split = _split(ex, rng)
        per_cat[ex.category].append(ex)
        all_out.append(ex)

    if verbose:
        print("[build] base examples ...")
    for ex in _all_examples():
        _accept(ex)

    if verbose:
        print(f"[build] base examples accepted: {len(all_out)}")
        print("[build] mutating (multiplier=%d) ..." % mutation_multiplier)

    # Mutate malicious examples to create harder variants
    base_snapshot = list(all_out)
    for ex in base_snapshot:
        if ex.category == "benign":
            continue
        for child in mutate(ex, seed=1, per_example=mutation_multiplier):
            _accept(child)

    if verbose:
        print(f"[build] total examples after mutation: {len(all_out)}")

    # --- Write files ---
    (ROOT / "all.jsonl").write_text("")
    with open(ROOT / "all.jsonl", "w") as f:
        for ex in all_out:
            f.write(dumps(ex) + "\n")

    for cat, exs in per_cat.items():
        with open(ROOT / "by_category" / f"{cat}.jsonl", "w") as f:
            for ex in exs:
                f.write(dumps(ex) + "\n")

    splits = defaultdict(list)
    for ex in all_out:
        splits[ex.split].append(ex)
    for split, exs in splits.items():
        with open(ROOT / "splits" / f"{split}.jsonl", "w") as f:
            for ex in exs:
                f.write(dumps(ex) + "\n")

    # --- Stats ---
    stats = {
        "total": len(all_out),
        "by_category": {k: len(v) for k, v in per_cat.items()},
        "by_severity": dict(Counter(ex.severity for ex in all_out)),
        "by_difficulty": dict(Counter(ex.difficulty for ex in all_out)),
        "by_language": dict(Counter(ex.language for ex in all_out)),
        "by_expected_behavior": dict(Counter(ex.expected_behavior.value for ex in all_out)),
        "by_split": {k: len(v) for k, v in splits.items()},
        "malicious": sum(1 for e in all_out if e.category != "benign"),
        "benign": sum(1 for e in all_out if e.category == "benign"),
        "multi_turn": sum(1 for e in all_out if e.attack_type == "multi_turn" or len(e.conversation_history) > 0),
        "attack_chains": sum(1 for e in all_out if e.attack_type == "attack_chain"),
        "with_tool_call": sum(1 for e in all_out if e.tool_call),
        "with_rag": sum(1 for e in all_out if e.retrieved_documents),
    }
    (ROOT / "stats.json").write_text(json.dumps(stats, indent=2))
    if verbose:
        print(json.dumps(stats, indent=2))
    return stats


if __name__ == "__main__":
    build()
