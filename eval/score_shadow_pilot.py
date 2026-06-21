#!/usr/bin/env python3
"""
Score Reviewer-LoRA v1.0 shadow pilot responses.

All 16 examples are post-v1.0 positives (not in training). Checks that LoRA
correctly accepts patches it was not trained on. Gate: 0 false rejects before
the adapter is promoted from advisory to auto-gate.

Usage:
    # Download responses from HF adapter repo first:
    #   hf download adastracomputing/reviewer-lora-v1.0 \\
    #     shadow_pilot_responses/shadow-pilot-responses.jsonl --repo-type model
    #
    python3 eval/score_shadow_pilot.py \\
        --responses shadow-pilot-responses.jsonl \\
        --shadow-jsonl exports/reviewer-shadow-pilot/shadow-pilot.jsonl \\
        --out data/reports/lora-shadow-pilot-v1.0.json
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(ROOT))

from eval.frontier_baseline import score_example


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--responses", required=True, help="shadow-pilot-responses.jsonl from HF")
    ap.add_argument("--shadow-jsonl", default="exports/reviewer-shadow-pilot/shadow-pilot.jsonl")
    ap.add_argument("--out", default="data/reports/lora-shadow-pilot-v1.0.json")
    args = ap.parse_args()

    responses = {
        r["cve_id"]: r
        for r in (json.loads(l) for l in Path(args.responses).read_text().splitlines() if l.strip())
    }

    shadow_records = [
        json.loads(l)
        for l in Path(args.shadow_jsonl).read_text().splitlines()
        if l.strip()
    ]

    results = []
    unmatched = []
    for rec in shadow_records:
        cve_id = rec.get("provenance", {}).get("cve_id")
        resp = responses.get(cve_id)
        if resp is None:
            unmatched.append(cve_id)
            scored = score_example(rec, "")
            scored["parse_failure"] = True
            scored["parse_error"] = "no matching response"
        else:
            scored = score_example(rec, resp["lora_response"])
        results.append(scored)

    if unmatched:
        print(f"WARN: no response for {len(unmatched)} examples: {unmatched}", file=sys.stderr)

    n = len(results)
    false_rejects = [r for r in results if r.get("actual_verdict") == "reject"]
    refusals = [r for r in results if r.get("actual_verdict") == "refusal"]
    accepts = [r for r in results if r.get("actual_verdict") == "accept"]
    parse_fails = [r for r in results if r.get("parse_failure")]

    agg = {
        "model": "adastracomputing/reviewer-lora-v1.0",
        "pilot_type": "shadow_pilot_positives_only",
        "n": n,
        "accept_count": len(accepts),
        "acceptance_rate": len(accepts) / n if n else 0,
        "false_reject_count": len(false_rejects),
        "refusal_count": len(refusals),
        "parse_failure_count": len(parse_fails),
        "schema_valid_rate": sum(1 for r in results if r.get("schema_valid")) / n if n else 0,
        "evidence_cited_rate": sum(1 for r in results if r.get("evidence_cited")) / n if n else 0,
        "gate_pass": len(false_rejects) == 0 and len(parse_fails) == 0,
        "false_rejects": [{"cve_id": r["cve_id"]} for r in false_rejects],
        "refusals": [{"cve_id": r["cve_id"]} for r in refusals],
        "parse_failures": [{"cve_id": r["cve_id"], "error": r.get("parse_error")} for r in parse_fails],
        "results": results,
    }

    Path(args.out).parent.mkdir(parents=True, exist_ok=True)
    Path(args.out).write_text(json.dumps(agg, indent=2))

    gate = "PASS" if agg["gate_pass"] else "FAIL"
    print(f"\nReviewer-LoRA v1.0 shadow pilot ({n} post-training positives)", file=sys.stderr)
    print(f"  acceptance rate:  {agg['acceptance_rate']:.1%}  ({len(accepts)}/{n})", file=sys.stderr)
    print(f"  false rejects:    {agg['false_reject_count']}", file=sys.stderr)
    print(f"  refusals:         {agg['refusal_count']}", file=sys.stderr)
    print(f"  parse failures:   {agg['parse_failure_count']}", file=sys.stderr)
    print(f"  schema valid:     {agg['schema_valid_rate']:.1%}", file=sys.stderr)
    print(f"  gate ({gate}):     0 false rejects required for promotion", file=sys.stderr)
    print(f"\nwrote {args.out}", file=sys.stderr)


if __name__ == "__main__":
    main()
