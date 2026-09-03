"""End-to-end regression: run the corpus through the firewall and report metrics.

For every Example we build a matching SecurityEvent (with retrieved docs,
conversation history, tool_call, output text, etc.), route it through the
appropriate stage of the firewall, and compare the decision to the
expected behavior.

Reports precision / recall / F1 per OWASP category, per attack family, and
per severity — plus false-positive stats on the benign set and lists the
attacks that bypassed detection.

Run:

    python -m eval.regression
    python -m eval.regression --sample 2000
    python -m eval.regression --split test
    python -m eval.regression --categories prompt_injection,rag_security
"""
from __future__ import annotations

import argparse
import dataclasses
import json
import sys
import time
from collections import Counter, defaultdict
from pathlib import Path
from typing import Iterable

from firewall import Gateway
from firewall.core.events import (
    Actor, DataClassification, Decision, RetrievedDoc, SecurityEvent, Source,
    SourceKind, ToolCall, ToolDefinition, ToolResult, TrustLevel, Message,
)
from firewall.detectors.supply_chain import SupplyChainDetector, SupplyChainRegistry, TrustedArtifact

from dataset import schema
from dataset.schema import Example, ExpectedBehavior, loads


# ---------------------------------------------------------------------------
# Bridging: Example -> SecurityEvent
# ---------------------------------------------------------------------------

def _source_from(dict_or_none) -> Source | None:
    if not dict_or_none:
        return None
    kind = dict_or_none.get("kind", "rag_document")
    try:
        sk = SourceKind(kind)
    except ValueError:
        sk = SourceKind.RAG_DOCUMENT
    classification = dict_or_none.get("classification", 20)
    try:
        c = DataClassification(int(classification))
    except Exception:
        c = DataClassification.INTERNAL
    return Source(
        kind=sk,
        origin=dict_or_none.get("origin", ""),
        tenant=dict_or_none.get("tenant", "default"),
        classification=c,
        metadata=dict_or_none.get("metadata", {}) or {},
    )


def _tool_def_from(td: dict | None) -> ToolDefinition | None:
    if not td:
        return None
    return ToolDefinition(
        name=td.get("name", "unknown"),
        description=td.get("description", ""),
        risk_level=td.get("risk_level", "medium"),
        capabilities=td.get("capabilities", []),
        required_roles=td.get("required_roles", []),
        allowed_agents=td.get("allowed_agents", []),
        allowed_resources=td.get("allowed_resources", []),
        allowed_hosts=td.get("allowed_hosts", []),
        requires_human_approval=td.get("requires_human_approval", False),
        provider=td.get("provider", "local"),
        version=td.get("version", "1.0"),
    )


def example_to_event(ex: Example) -> tuple[SecurityEvent, str]:
    """Return (event, stage) — stage is 'input' or 'output' depending on the example."""
    actor = Actor(user_id="regression", tenant="default", session_id=ex.id,
                  authenticated=True, roles=["user"])
    docs = [
        RetrievedDoc(
            doc_id=d.get("doc_id", ""),
            content=d.get("content", ""),
            source=_source_from(d.get("source")) or Source(kind=SourceKind.RAG_DOCUMENT, origin=""),
            metadata=d.get("metadata", {}) or {},
        )
        for d in (ex.retrieved_documents or [])
    ]
    tool_call = None
    if ex.tool_call:
        tool_call = ToolCall(tool=ex.tool_call.get("tool", ""),
                             arguments=ex.tool_call.get("arguments", {}) or {})
    src = None
    # If the example is an indirect attack, treat the input source as untrusted
    if docs:
        src = docs[0].source
    elif ex.category == "attack_chain" and ex.conversation_history:
        for turn in ex.conversation_history:
            if turn.source_kind:
                src = Source(kind=SourceKind(turn.source_kind), origin=turn.source_origin or "")
                break

    # Also pull tool_result if the last turn is a tool
    tool_result = None
    if ex.conversation_history:
        for t in reversed(ex.conversation_history):
            if t.role == "tool":
                tool_result = ToolResult(
                    call_id="regression",
                    tool="from_history",
                    ok=True,
                    content=t.content,
                    source=Source(kind=SourceKind(t.source_kind or "tool_result"),
                                  origin=t.source_origin or ""),
                )
                break

    # Prefer the actual role assignments. If an example only carries output_text,
    # don't also inject that same text into input_text (which would mis-route stage).
    if ex.output_text and not ex.user_message:
        input_text = ""
        output_text = ex.output_text
    else:
        input_text = ex.user_message or ex.attack_text or ""
        output_text = ex.output_text or ""

    # Rebuild the message list from conversation history so multi-turn
    # detectors get to see prior turns.
    msgs = []
    for turn in (ex.conversation_history or []):
        try:
            src_obj = None
            if turn.source_kind:
                src_obj = Source(kind=SourceKind(turn.source_kind),
                                  origin=turn.source_origin or "")
            msgs.append(Message(role=turn.role, content=turn.content, source=src_obj))
        except Exception:
            pass

    event = SecurityEvent(
        actor=actor,
        source=src,
        input_text=input_text,
        output_text=output_text,
        context_docs=docs,
        messages=msgs,
        tool_call=tool_call,
        tool_result=tool_result,
        tool_def=_tool_def_from(ex.tool_definition),
    )
    stage = "output" if (output_text and not input_text) else "input"
    return event, stage


# ---------------------------------------------------------------------------
# Bridging: firewall decision -> comparable label
# ---------------------------------------------------------------------------

_EXPECTED_TO_DECISION = {
    ExpectedBehavior.ALLOW:    Decision.ALLOW,
    ExpectedBehavior.SANITIZE: Decision.SANITIZE,
    ExpectedBehavior.APPROVE:  Decision.REQUIRE_APPROVAL,
    ExpectedBehavior.BLOCK:    Decision.BLOCK,
}


def _severity_of(sev: str) -> int:
    return {"low": 20, "medium": 50, "high": 75, "critical": 95}.get(sev, 50)


def _classify(expected: ExpectedBehavior, actual: Decision) -> str:
    """One of: tp_exact, tp_stricter, tp_weaker, fp, fn, tn."""
    exp_dec = _EXPECTED_TO_DECISION[expected]
    if expected == ExpectedBehavior.ALLOW:
        if actual == Decision.ALLOW:
            return "tn"
        return "fp"           # firewall blocked/sanitized a benign example
    else:
        if actual == Decision.ALLOW:
            return "fn"       # firewall let an attack through
        if actual.severity == exp_dec.severity:
            return "tp_exact"
        if actual.severity > exp_dec.severity:
            return "tp_stricter"
        return "tp_weaker"


# ---------------------------------------------------------------------------
# Main runner
# ---------------------------------------------------------------------------

def load(split: str | None = None, categories: set[str] | None = None,
         sample: int | None = None) -> Iterable[Example]:
    path = Path("dataset/corpus")
    if split:
        p = path / "splits" / f"{split}.jsonl"
    else:
        p = path / "all.jsonl"
    if not p.exists():
        print(f"[eval] corpus file {p} not found — run python -m dataset.build_corpus first")
        sys.exit(2)
    n = 0
    with open(p) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            ex = loads(line)
            if categories and ex.category not in categories:
                continue
            yield ex
            n += 1
            if sample and n >= sample:
                return


def _prepare_registry(gw: Gateway, examples) -> None:
    """Pre-register every tool name that appears in the corpus with a sensible
    default definition — otherwise the firewall correctly raises
    'undefined_tool' detections that count as FPs for benign tool calls.
    """
    seen: dict[str, ToolDefinition] = {}
    for ex in examples:
        if not ex.tool_call:
            continue
        name = ex.tool_call.get("tool", "")
        if not name or name in seen:
            continue
        # If the example brings a definition, use it. Otherwise infer risk from name.
        if ex.tool_definition:
            td = ToolDefinition(**{k: v for k, v in ex.tool_definition.items()
                                    if k in {"name", "description", "risk_level",
                                             "capabilities", "requires_human_approval",
                                             "provider", "version", "allowed_hosts",
                                             "allowed_resources", "required_roles"}})
        else:
            risk = "medium"
            caps = []
            n = name.lower()
            if "delete" in n or "wire" in n or "execute" in n or "shell" in n:
                risk = "critical"; caps = ["execute", "delete"]
            elif "write" in n or "send" in n or "email" in n or "transfer" in n:
                risk = "high"; caps = ["write", "network"]
            elif "http" in n or "fetch" in n or "web" in n:
                risk = "high"; caps = ["network"]
            elif "read" in n or "search" in n or "get" in n or "list" in n or "status" in n:
                risk = "low"; caps = ["read"]
            elif "db" in n:
                risk = "medium"; caps = ["read"]
            td = ToolDefinition(name=name, risk_level=risk, capabilities=caps)
        seen[name] = td
        gw.register_tool(td, lambda **kw: {"ok": True, "kw": kw})


def run(split: str | None = None, categories: set[str] | None = None,
        sample: int | None = None, verbose: bool = False) -> dict:
    gw = Gateway()
    # Register a small trusted-supply-chain registry so unknown-provider tests fire
    reg = SupplyChainRegistry()
    reg.add(TrustedArtifact(kind="provider", name="anthropic"))
    reg.add(TrustedArtifact(kind="provider", name="openai"))
    reg.add(TrustedArtifact(kind="model", name="claude-opus-4-7"))
    reg.add(TrustedArtifact(kind="model", name="gpt-4o"))
    gw.supply_chain = SupplyChainDetector(reg, default_allow_unknown=False)
    gw.tool_firewall.supply_chain = gw.supply_chain
    # Register every tool name that appears in benign examples so the supply-chain
    # detector doesn't count them as "unknown". Attack examples deliberately use
    # names not on this list (badllm.example, evil-mcp-server, shady_tool_v2) so
    # supply-chain detections still fire on those.
    BENIGN_TOOLS = ("search_customers", "read_file", "http_fetch", "db_read",
                    "db_write", "send_email", "get_status", "list_files")
    for t in BENIGN_TOOLS:
        reg.add(TrustedArtifact(kind="tool", name=t))

    by_cat: dict[str, Counter] = defaultdict(Counter)
    by_family: dict[str, Counter] = defaultdict(Counter)
    by_sev: dict[str, Counter] = defaultdict(Counter)
    latencies: list[float] = []
    total = 0
    misses: list[dict] = []
    fps: list[dict] = []

    # Pre-register tools that appear in the corpus so tool-firewall decisions
    # reflect the FIREWALL, not a missing registry entry.
    all_examples = list(load(split=split, categories=categories, sample=sample))
    _prepare_registry(gw, all_examples)

    t0 = time.time()
    for ex in all_examples:
        total += 1
        event, stage = example_to_event(ex)
        t = time.time()
        try:
            if stage == "input":
                gw.process_input(event)
                # If this is an agent-attack example with a tool_call and the input
                # did not already reach the strictest decision, run the tool firewall
                # to include tool-security signals in the effective decision.
                if event.tool_call and event.decision != Decision.BLOCK:
                    ev2 = SecurityEvent(
                        actor=event.actor,
                        source=event.source,
                        tool_call=event.tool_call,
                        tool_def=event.tool_def,
                    )
                    try:
                        gw.tool_firewall.call(ev2)
                    except Exception:
                        pass
                    # Escalate the primary decision if tool firewall said worse
                    if ev2.decision.severity > event.decision.severity:
                        event.decision = ev2.decision
            else:
                gw.process_output(event)
        except Exception as e:
            # Any tool-firewall block/approval counts as a positive decision
            if "ToolBlocked" in type(e).__name__:
                event.decision = Decision.BLOCK
            elif "ApprovalRequired" in type(e).__name__:
                event.decision = Decision.REQUIRE_APPROVAL
            else:
                event.decision = Decision.ALLOW
        dt = (time.time() - t) * 1000
        latencies.append(dt)

        outcome = _classify(ex.expected_behavior, event.decision)
        by_cat[ex.category][outcome] += 1
        by_family[ex.attack_family or ex.subcategory][outcome] += 1
        by_sev[ex.severity][outcome] += 1

        if outcome == "fn":
            misses.append({"id": ex.id, "category": ex.category,
                            "subcategory": ex.subcategory,
                            "family": ex.attack_family, "severity": ex.severity,
                            "attack_text": (ex.attack_text or ex.user_message)[:200]})
        if outcome == "fp":
            fps.append({"id": ex.id, "attack_text": (ex.attack_text or ex.user_message)[:200],
                         "decision": event.decision.value,
                         "reasons": event.reasons[:3]})

        if verbose and total % 500 == 0:
            print(f"  ...{total} processed", file=sys.stderr)

    total_time = time.time() - t0
    print(f"\nProcessed {total} examples in {total_time:.1f}s "
          f"({total/max(total_time,1e-6):.0f}/s, avg {sum(latencies)/max(len(latencies),1):.2f}ms)\n")

    # ---- Compute metrics ----
    def prf(c: Counter) -> tuple[float, float, float]:
        tp = c["tp_exact"] + c["tp_stricter"] + c["tp_weaker"]
        fp = c["fp"]
        fn = c["fn"]
        precision = tp / (tp + fp) if (tp + fp) else 0.0
        recall    = tp / (tp + fn) if (tp + fn) else 0.0
        f1        = (2 * precision * recall / (precision + recall)) if (precision + recall) else 0.0
        return precision, recall, f1

    def _fmt(counter):
        p, r, f = prf(counter)
        tp = counter["tp_exact"] + counter["tp_stricter"] + counter["tp_weaker"]
        return (f"tp={tp:5d}  fp={counter['fp']:4d}  fn={counter['fn']:4d}  "
                f"tn={counter['tn']:4d}  P={p:.3f} R={r:.3f} F1={f:.3f}")

    print("=" * 88)
    print(f"{'CATEGORY':<24} {'REPORT'}")
    print("=" * 88)
    for cat in sorted(by_cat):
        print(f"{cat:<24} {_fmt(by_cat[cat])}")
    print("-" * 88)
    print("BY SEVERITY:")
    for sev in ("critical", "high", "medium", "low"):
        if sev in by_sev:
            print(f"  {sev:<10} {_fmt(by_sev[sev])}")
    print("-" * 88)
    # Overall
    overall = Counter()
    for c in by_cat.values():
        overall.update(c)
    p, r, f = prf(overall)
    tp = overall["tp_exact"] + overall["tp_stricter"] + overall["tp_weaker"]
    print(f"OVERALL: {_fmt(overall)}")
    print(f"latency avg={sum(latencies)/max(len(latencies),1):.2f}ms  "
          f"p95={sorted(latencies)[int(len(latencies)*0.95)-1] if latencies else 0:.2f}ms")
    print("=" * 88)
    if misses:
        print(f"\nFALSE NEGATIVES: {len(misses)} (showing first 20)")
        for m in misses[:20]:
            print(f"  [{m['category']}/{m['subcategory']}] {m['id']}  ::  {m['attack_text'][:120]}")
    if fps:
        print(f"\nFALSE POSITIVES: {len(fps)} (showing first 20)")
        for f_ in fps[:20]:
            print(f"  {f_['id']}  -> {f_['decision']} ({'; '.join(f_['reasons'])[:120]})  ::  {f_['attack_text'][:100]}")

    # Machine-readable
    report = {
        "total": total,
        "elapsed_s": total_time,
        "throughput_per_s": total / max(total_time, 1e-6),
        "latency_ms": {
            "avg": sum(latencies) / max(len(latencies), 1),
            "p95": sorted(latencies)[int(len(latencies) * 0.95) - 1] if latencies else 0,
            "max": max(latencies) if latencies else 0,
        },
        "by_category": {k: dict(v) for k, v in by_cat.items()},
        "by_severity": {k: dict(v) for k, v in by_sev.items()},
        "overall": dict(overall),
        "overall_prf": {"precision": p, "recall": r, "f1": f},
        "false_negatives_top": misses[:200],
        "false_positives_top": fps[:200],
    }
    out_path = Path("eval/last_report.json")
    out_path.parent.mkdir(exist_ok=True)
    out_path.write_text(json.dumps(report, indent=2, default=str))
    print(f"\nFull report -> {out_path}")
    return report


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--split", default=None, help="train/val/test; default all")
    ap.add_argument("--sample", type=int, default=None)
    ap.add_argument("--categories", default=None,
                    help="comma-separated list; default all")
    ap.add_argument("--verbose", action="store_true")
    args = ap.parse_args()
    cats = set(args.categories.split(",")) if args.categories else None
    run(split=args.split, categories=cats, sample=args.sample, verbose=args.verbose)


if __name__ == "__main__":
    main()
