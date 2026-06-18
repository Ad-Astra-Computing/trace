#!/usr/bin/env python3
"""
Score Reviewer-LoRA v1.0 generated responses against the test fold.

Reads responses.jsonl (produced by lora/hf_eval_job.py on HF infra) and the
frozen full export, aligns each response to its labelled test record by the
user-turn sha256, then scores with the IDENTICAL score_example() the frontier
baseline used — so the comparison is apples-to-apples.

Usage:
    python3 eval/score_lora_responses.py \
        --responses /tmp/responses.jsonl \
        --export exports/reviewer-v1.0/reviewer.jsonl \
        --out data/reports/lora-eval-v1.0.json
"""
from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path

from eval.frontier_baseline import score_example


def _user_sha(rec: dict) -> str:
    user_text = ""
    for m in rec.get("messages", []):
        if m.get("role") == "user":
            content = m.get("content", "")
            if isinstance(content, list):
                content = "\n".join(
                    c.get("text", "") for c in content
                    if isinstance(c, dict) and c.get("type") == "text"
                )
            user_text = content
    return hashlib.sha256(user_text.encode()).hexdigest()


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--responses", default="/tmp/responses.jsonl")
    ap.add_argument("--export", default="exports/reviewer-v1.0/reviewer.jsonl")
    ap.add_argument("--out", default="data/reports/lora-eval-v1.0.json")
    ap.add_argument("--baseline", default="data/reports/frontier-baseline-v1.0.json")
    args = ap.parse_args()

    responses = [json.loads(l) for l in Path(args.responses).read_text().splitlines() if l.strip()]
    by_sha = {r["user_sha256"]: r for r in responses}

    export = [json.loads(l) for l in Path(args.export).read_text().splitlines() if l.strip()]
    test_records = [r for r in export if r.get("split") == "test"]

    if len(test_records) != len(responses):
        print(f"WARN: {len(test_records)} test records vs {len(responses)} responses", file=sys.stderr)

    results = []
    for rec in test_records:
        sha = _user_sha(rec)
        resp = by_sha.get(sha)
        if resp is None:
            print(f"WARN: no response for {rec.get('provenance',{}).get('cve_id','?')} (sha {sha[:12]})", file=sys.stderr)
            scored = score_example(rec, "", dry_run=False)
            scored["parse_failure"] = True
            scored["parse_error"] = "no matching response"
        else:
            scored = score_example(rec, resp["generated"], dry_run=False)
        results.append(scored)

    n = len(results)
    positives = [r for r in results if r["label"] == "positive"]
    negatives = [r for r in results if r["label"] == "negative"]
    false_accepts = [r for r in negatives if r.get("actual_verdict") == "accept"]
    false_rejects = [r for r in positives if r.get("actual_verdict") == "reject"]
    agg = {
        "model": "adastracomputing/reviewer-lora-v1.0",
        "n": n,
        "verdict_accuracy": sum(1 for r in results if r["verdict_correct"]) / n if n else 0,
        "schema_valid_rate": sum(1 for r in results if r["schema_valid"]) / n if n else 0,
        "evidence_cited_rate": sum(1 for r in results if r["evidence_cited"]) / n if n else 0,
        "parse_failure_count": sum(1 for r in results if r["parse_failure"]),
        "false_accept_count": len(false_accepts),
        "false_reject_count": len(false_rejects),
        "false_accepts": [{"cve_id": r["cve_id"], "mutation_type": r["mutation_type"]} for r in false_accepts],
        "false_rejects": [{"cve_id": r["cve_id"]} for r in false_rejects],
        "positives_n": len(positives),
        "negatives_n": len(negatives),
        "results": results,
    }

    Path(args.out).parent.mkdir(parents=True, exist_ok=True)
    Path(args.out).write_text(json.dumps(agg, indent=2))

    print(f"\nReviewer-LoRA v1.0 eval ({n} test examples)", file=sys.stderr)
    print(f"  verdict accuracy:   {agg['verdict_accuracy']:.1%}", file=sys.stderr)
    print(f"  false accepts:      {agg['false_accept_count']}  (on {len(negatives)} negatives)", file=sys.stderr)
    print(f"  false rejects:      {agg['false_reject_count']}  (on {len(positives)} positives)", file=sys.stderr)
    print(f"  parse failures:     {agg['parse_failure_count']}", file=sys.stderr)
    print(f"  schema valid:       {agg['schema_valid_rate']:.1%}", file=sys.stderr)

    # Compare to frontier baseline
    bpath = Path(args.baseline)
    if bpath.exists():
        b = json.loads(bpath.read_text())
        # frontier-baseline-v1.0.json nests its metrics under "aggregate";
        # fall back to top-level for forward-compat.
        b = b.get("aggregate", b)
        print("\n  vs frontier baseline:", file=sys.stderr)
        print(f"    accuracy:      LoRA {agg['verdict_accuracy']:.1%}  |  frontier {b.get('verdict_accuracy',0):.1%}", file=sys.stderr)
        print(f"    false_accepts: LoRA {agg['false_accept_count']}  |  frontier {b.get('false_accept_count','?')}", file=sys.stderr)
        print(f"    parse_fails:   LoRA {agg['parse_failure_count']}  |  frontier {b.get('parse_failure_count','?')}", file=sys.stderr)
    print(f"\nwrote {args.out}", file=sys.stderr)


if __name__ == "__main__":
    main()
