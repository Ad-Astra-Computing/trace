#!/usr/bin/env python3
"""
Score gate pilot responses from hf_gate_pilot_job.py.

Usage:
  python3 eval/score_gate_pilot.py \
      --pilot  exports/reviewer-v1.1/gate-pilot.jsonl \
      --responses lora-gate-pilot-v1.1-responses.jsonl \
      --out data/reports/lora-gate-pilot-v1.1.json
"""
import argparse
import json
import re
import sys
from pathlib import Path


def parse_verdict(text: str) -> str | None:
    """Extract accept/reject from generated review text.

    Handles two formats:
      ## Verdict\n<accept|reject>   (canonical review.md format)
      verdict: <accept|reject>      (inline / LoRA free-form)

    Last-resort: earliest standalone occurrence of either keyword.
    """
    lines = text.splitlines()
    for i, line in enumerate(lines):
        stripped = line.strip().lower()
        # Canonical: section header followed by bare verdict on next line
        if stripped in ("## verdict", "verdict"):
            for j in range(i + 1, min(i + 4, len(lines))):
                nxt = lines[j].strip().lower()
                if nxt in ("accept", "reject"):
                    return nxt
        # Inline colon form: "verdict: accept"
        if re.match(r"verdict\s*:\s*(accept|reject)", stripped):
            return "accept" if "accept" in stripped else "reject"

    # Last-resort: find earliest occurrence of either keyword by character position
    low = text.lower()
    accept_pos = low.find("accept") if re.search(r"\baccept\b", low) else -1
    reject_pos = low.find("reject") if re.search(r"\breject\b", low) else -1
    if accept_pos == -1 and reject_pos == -1:
        return None
    if accept_pos == -1:
        return "reject"
    if reject_pos == -1:
        return "accept"
    return "accept" if accept_pos < reject_pos else "reject"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--pilot", required=True, type=Path)
    ap.add_argument("--responses", required=True, type=Path)
    ap.add_argument("--out", required=True, type=Path)
    args = ap.parse_args()

    pilot_records = [
        json.loads(l) for l in args.pilot.read_text().splitlines() if l.strip()
    ]
    # Key by (bundle_id, mutation_type or '') because a positive bundle and its
    # mutation share the same bundle_id — using only bundle_id causes the scorer
    # to match the wrong response when both appear in the same pilot set.
    def _resp_key(r: dict) -> tuple:
        return (r["bundle_id"], r.get("mutation_type") or "")

    responses = {
        _resp_key(r): r
        for r in (
            json.loads(l) for l in args.responses.read_text().splitlines() if l.strip()
        )
    }

    false_rejects = []   # positive → reject (bad)
    false_accepts = []   # negative → accept (bad)
    test_parse_fails = []
    retest_parse_fails = []
    correct = []
    retest_results = []

    for rec in pilot_records:
        prov = rec.get("provenance", {})
        bundle_id = prov.get("bundle_id")
        cve_id = prov.get("cve_id")
        attr_path = prov.get("attr_path")
        label = rec.get("label")
        split = rec.get("split", "test")
        mutation = prov.get("mutation_type")

        resp = responses.get((bundle_id, mutation or ""))
        if resp is None:
            entry = {"bundle_id": bundle_id, "cve_id": cve_id, "reason": "missing"}
            (retest_parse_fails if split == "train-retest" else test_parse_fails).append(entry)
            continue

        text = resp.get("generated", "")
        verdict = parse_verdict(text)
        if verdict is None:
            entry = {"bundle_id": bundle_id, "cve_id": cve_id, "reason": "parse_fail"}
            (retest_parse_fails if split == "train-retest" else test_parse_fails).append(entry)
            continue

        entry = {
            "bundle_id": bundle_id,
            "cve_id": cve_id,
            "attr_path": attr_path,
            "label": label,
            "split": split,
            "mutation_type": mutation,
            "verdict": verdict,
        }

        if split == "train-retest":
            expected = "accept" if label == "positive" else "reject"
            entry["outcome"] = "correct" if verdict == expected else (
                "false_reject" if label == "positive" else "false_accept"
            )
            retest_results.append(entry)
            continue

        if label == "positive" and verdict == "reject":
            false_rejects.append(entry)
        elif label == "negative" and verdict == "accept":
            false_accepts.append(entry)
        else:
            correct.append(entry)

    total_test = len([r for r in pilot_records if r.get("split") == "test"])
    total_retest = len([r for r in pilot_records if r.get("split") == "train-retest"])
    # Gate only applies to the held-out test split
    gate_pass = (
        len(false_rejects) == 0
        and len(false_accepts) == 0
        and len(test_parse_fails) == 0
    )

    report = {
        "gate_pass": gate_pass,
        "summary": {
            "test_total": total_test,
            "test_correct": len(correct),
            "false_rejects": len(false_rejects),
            "false_accepts": len(false_accepts),
            "test_parse_fails": len(test_parse_fails),
            "retest_total": total_retest,
            "retest_correct": sum(1 for r in retest_results if r.get("outcome") == "correct"),
            "retest_parse_fails": len(retest_parse_fails),
        },
        "details": {
            "false_rejects": false_rejects,
            "false_accepts": false_accepts,
            "test_parse_fails": test_parse_fails,
            "correct": correct,
            "retest": retest_results,
            "retest_parse_fails": retest_parse_fails,
        },
    }

    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(report, indent=2) + "\n")

    print(f"Gate: {'PASS' if gate_pass else 'FAIL'}")
    print(f"Test: {len(correct)}/{total_test} correct  (FR={len(false_rejects)} FA={len(false_accepts)} PF={len(test_parse_fails)})")
    if retest_results:
        rc = sum(1 for r in retest_results if r.get("outcome") == "correct")
        print(f"Retest (sqlite + procps): {rc}/{total_retest} fixed")
        for r in retest_results:
            print(f"  {r['cve_id']} → {r['verdict']}  ({r['outcome']})")
    if retest_parse_fails:
        print(f"Retest parse fails: {len(retest_parse_fails)}")
    if false_rejects:
        print("FALSE REJECTS:")
        for r in false_rejects:
            print(f"  {r['cve_id']} ({r['attr_path']})")
    if false_accepts:
        print("FALSE ACCEPTS:")
        for r in false_accepts:
            print(f"  {r['cve_id']} ({r['attr_path']}) mutation={r['mutation_type']}")
    print(f"\nReport → {args.out}")
    sys.exit(0 if gate_pass else 1)


if __name__ == "__main__":
    main()
