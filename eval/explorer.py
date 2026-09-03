"""Dataset explorer CLI.

Filter and browse the corpus + optionally run each example through the
firewall on the fly so you can see exactly why it was classified.

    python -m eval.explorer --category prompt_injection --limit 10
    python -m eval.explorer --difficulty hard --run
    python -m eval.explorer --search "system prompt"
    python -m eval.explorer --id pi_direct_000001 --run
    python -m eval.explorer --tags fp_test --run
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from firewall import Gateway
from firewall.core.events import Decision

from dataset.schema import loads
from eval.regression import example_to_event


def _iter(path: Path):
    with open(path) as f:
        for line in f:
            line = line.strip()
            if line:
                yield loads(line)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--corpus", default="dataset/corpus/all.jsonl")
    ap.add_argument("--category", default=None)
    ap.add_argument("--subcategory", default=None)
    ap.add_argument("--family", default=None)
    ap.add_argument("--severity", default=None)
    ap.add_argument("--difficulty", default=None)
    ap.add_argument("--language", default=None)
    ap.add_argument("--tags", default=None, help="comma-separated tags all-of")
    ap.add_argument("--search", default=None, help="substring in attack_text")
    ap.add_argument("--id", default=None)
    ap.add_argument("--limit", type=int, default=20)
    ap.add_argument("--run", action="store_true", help="also run each through the firewall")
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args()

    tags = set(args.tags.split(",")) if args.tags else None
    gw = Gateway() if args.run else None

    p = Path(args.corpus)
    if not p.exists():
        print(f"corpus not found at {p}")
        sys.exit(2)

    n = 0
    for ex in _iter(p):
        if args.id and ex.id != args.id:
            continue
        if args.category and ex.category != args.category:
            continue
        if args.subcategory and ex.subcategory != args.subcategory:
            continue
        if args.family and ex.attack_family != args.family:
            continue
        if args.severity and ex.severity != args.severity:
            continue
        if args.difficulty and ex.difficulty != args.difficulty:
            continue
        if args.language and ex.language != args.language:
            continue
        if tags and not tags.issubset(set(ex.tags)):
            continue
        if args.search and args.search.lower() not in (ex.attack_text or "").lower() \
                and args.search.lower() not in (ex.user_message or "").lower():
            continue

        n += 1
        row = {
            "id": ex.id,
            "category": ex.category,
            "subcategory": ex.subcategory,
            "family": ex.attack_family,
            "severity": ex.severity,
            "difficulty": ex.difficulty,
            "expected": ex.expected_behavior.value,
            "attack_text": (ex.attack_text or ex.user_message)[:200],
        }
        if args.run:
            event, stage = example_to_event(ex)
            try:
                if stage == "input":
                    gw.process_input(event)
                else:
                    gw.process_output(event)
                row["decision"] = event.decision.value
                row["risk"] = event.risk_score
                row["detections"] = [{"cat": d.category, "sub": d.subcategory,
                                       "sev": d.severity, "conf": d.confidence,
                                       "msg": d.message[:120]}
                                      for d in event.detections[:6]]
                row["reasons"] = event.reasons[:3]
            except Exception as e:
                row["decision"] = f"error:{e}"
        if args.json:
            print(json.dumps(row, ensure_ascii=False))
        else:
            print("=" * 90)
            print(f"[{n}] {row['id']}   ({row['category']}/{row['subcategory']}, "
                  f"{row['severity']}/{row['difficulty']}, expected={row['expected']})")
            print(f"    text: {row['attack_text']}")
            if args.run:
                print(f"    decision: {row['decision']}   risk: {row.get('risk')}")
                for d in row.get("detections", []):
                    print(f"      - {d['cat']}/{d['sub']} sev={d['sev']} conf={d['conf']:.2f}  :: {d['msg']}")
                for r in row.get("reasons", []):
                    print(f"      reason: {r}")
        if n >= args.limit:
            break


if __name__ == "__main__":
    main()
