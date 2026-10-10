"""Balanced, reproducible corpus smoke benchmark (not a full-corpus evaluation).

The first N examples of each malicious category are selected deterministically.
All benign examples up to the configured cap are included. Any non-ALLOW
inspection decision counts as an intervention; it does not prove safe enforcement.
"""
from __future__ import annotations

import argparse
from collections import Counter, defaultdict
import hashlib
import json
from pathlib import Path
import time

from dataset.schema import loads
from eval.regression import example_to_event
from firewall import Gateway


def run(corpus: Path, per_category=200, benign_cap=5000):
    selected = Counter()
    examples = []
    with corpus.open() as source:
        for line in source:
            example = loads(line)
            cap = benign_cap if example.category == 'benign' else per_category
            if selected[example.category] < cap:
                examples.append(example)
                selected[example.category] += 1
    if not examples:
        raise ValueError('Corpus contains no selected examples')
    gateway = Gateway()
    counts = defaultdict(Counter)
    latencies = []
    slowest = []
    try:
        for example in examples:
            event, stage = example_to_event(example)
            started = time.perf_counter()
            getattr(gateway, 'process_' + stage)(event)
            elapsed_ms = (time.perf_counter() - started) * 1000
            latencies.append(elapsed_ms)
            slowest.append({'id': example.id, 'category': example.category,
                            'latency_ms': elapsed_ms})
            slowest = sorted(slowest, key=lambda item: item['latency_ms'], reverse=True)[:5]
            malicious = example.category != 'benign'
            intervention = event.decision.value != 'allow'
            outcome = ('tp' if intervention else 'fn') if malicious else ('fp' if intervention else 'tn')
            counts[example.category][outcome] += 1
            # Corpus sessions are independent. Lifecycle cleanup prevents state
            # retention from influencing this benchmark or exhausting memory.
            gateway.behavior.release_session(event)
    finally:
        gateway.close()
    attacks = sum(c['tp'] + c['fn'] for c in counts.values())
    benign = sum(c['tn'] + c['fp'] for c in counts.values())
    source_hash = hashlib.sha256()
    for path in sorted(Path(__file__).parents[1].joinpath('firewall').rglob('*.py')):
        source_hash.update(str(path.relative_to(Path(__file__).parents[1])).encode())
        source_hash.update(path.read_bytes())
    return {
        'examples': len(examples), 'attack_examples': attacks, 'benign_examples': benign,
        'sampling': f'first {per_category} per malicious category; benign cap {benign_cap}',
        'measurement': 'any non-ALLOW decision is an intervention; no tool execution',
        'runtime_source_sha256': source_hash.hexdigest(),
        'by_category': {key: dict(value) for key, value in counts.items()},
        'attack_signal_recall': sum(c['tp'] for c in counts.values()) / max(1, attacks),
        'benign_intervention_rate': sum(c['fp'] for c in counts.values()) / max(1, benign),
        'latency_ms': {'mean': sum(latencies) / len(latencies),
                       'p95': sorted(latencies)[int(len(latencies) * .95)],
                       'max': max(latencies)},
        'slowest_examples': slowest,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--corpus', type=Path, default=Path('dataset/corpus/all.jsonl'))
    parser.add_argument('--per-category', type=int, default=200)
    parser.add_argument('--benign-cap', type=int, default=5000)
    parser.add_argument('--output', type=Path)
    args = parser.parse_args()
    if min(args.per_category, args.benign_cap) <= 0:
        parser.error('sample limits must be positive')
    result = run(args.corpus, args.per_category, args.benign_cap)
    serialized = json.dumps(result, indent=2)
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(serialized + '\n')
    print(serialized)


if __name__ == '__main__':
    main()
