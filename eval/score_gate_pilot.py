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


def check_pc_grounding(generated: str, pilot_rec: dict) -> str | None:
    """Return a grounding failure description if the PC section quotes lines
    not found in the actual patch.diff or upstream-fix.patch from the pilot
    record's user message.  Returns None when grounding looks OK or when the
    generated review has no PC section.

    This catches the v1.3 failure mode where the model hallucinated PC section
    content from training memory rather than reading the actual input files.
    """
    if "## Patch comparison" not in generated:
        return None

    # Extract the user message (contains patch.diff and upstream-fix.patch content)
    msgs = pilot_rec.get("messages", [])
    user_content = next((m["content"] for m in msgs if m["role"] == "user"), "")
    if not user_content:
        return None

    # Extract quoted lines from the PC section (lines starting with `- ` or `+ `)
    pc_start = generated.find("## Patch comparison")
    # Find the end of the PC section (next ## heading)
    pc_end_match = re.search(r"\n## ", generated[pc_start + 1:])
    pc_text = generated[pc_start: pc_start + 1 + (pc_end_match.start() if pc_end_match else len(generated))]

    # Pull backtick-quoted lines: `- some code` or `+ some code`
    quoted_lines = re.findall(r"`[+-]\s+(.+?)`", pc_text)
    if not quoted_lines:
        return None

    # Check each quoted line against the user content
    hallucinated = []
    for q in quoted_lines:
        q_stripped = q.strip()
        if q_stripped and q_stripped not in user_content:
            hallucinated.append(q_stripped[:60])

    if not hallucinated:
        return None

    sample = hallucinated[:3]
    return f"PC section quotes {len(hallucinated)} line(s) not in input: {sample}"


def check_pc_consistency(generated: str) -> str | None:
    """Check that `comparison:` verdicts in the PC section are consistent
    with the quoted +lines.

    The v1.4 failure mode: the model correctly quoted identical +lines from
    both patch.diff and upstream-fix.patch, but wrote `comparison: mismatch`
    contradicting the evidence.  We detect this by:
      1. Parsing each hunk block inside ## Patch comparison.
      2. Collecting quoted + lines for the upstream and authored sides.
      3. Normalizing whitespace and comparing.
      4. If they are identical but `comparison: mismatch` was written, flag it.
    Also: if conclusion says `accept` but verdict is `reject` on
    hunk-equivalence grounds, flag the verdict-PC inconsistency.
    Returns None when no inconsistency is detected.
    """
    if "## Patch comparison" not in generated:
        return None

    pc_start = generated.find("## Patch comparison")
    pc_end_match = re.search(r"\n## ", generated[pc_start + 1:])
    pc_text = generated[pc_start: pc_start + 1 + (pc_end_match.start() if pc_end_match else len(generated))]

    # Extract per-hunk blocks separated by "hunk N" or "hunk:" markers
    # Strategy: split on blank lines and group lines that reference patch.diff vs upstream-fix.patch
    # Simpler: scan for hunk blocks, within each find upstream + side and authored + side
    errors = []

    # Parse all hunk sections: look for "- patch.diff:" and "- upstream-fix.patch:" headers
    # Each hunk has lines like "  - `+ code`" under each sub-section
    hunk_blocks = re.split(r"hunk\s+\d+\s*[—\-–]", pc_text, flags=re.IGNORECASE)

    for hunk_num, block in enumerate(hunk_blocks[1:], 1):
        # Extract upstream +lines and authored +lines
        upstream_section = re.search(
            r"upstream-fix\.patch\s*:(.*?)(?:- patch\.diff\s*:|comparison\s*:|$)",
            block, re.DOTALL | re.IGNORECASE
        )
        authored_section = re.search(
            r"patch\.diff\s*:(.*?)(?:- upstream-fix\.patch\s*:|comparison\s*:|$)",
            block, re.DOTALL | re.IGNORECASE
        )
        comparison_line = re.search(r"comparison\s*:\s*(\w[\w-]*)", block, re.IGNORECASE)
        if not comparison_line:
            continue
        comparison_verdict = comparison_line.group(1).lower()

        if upstream_section and authored_section:
            # Extract +lines from each section
            def extract_plus_lines(section_text: str) -> list[str]:
                lines = re.findall(r"`\+\s+(.+?)`", section_text)
                return [l.strip() for l in lines]

            upstream_plus = extract_plus_lines(upstream_section.group(1))
            authored_plus = extract_plus_lines(authored_section.group(1))

            if upstream_plus and authored_plus:
                # Normalize: strip whitespace from each line
                up_norm = [re.sub(r"\s+", " ", l).strip() for l in upstream_plus]
                au_norm = [re.sub(r"\s+", " ", l).strip() for l in authored_plus]
                lines_match = (up_norm == au_norm)

                if lines_match and comparison_verdict == "mismatch":
                    errors.append(
                        f"hunk {hunk_num}: quoted +lines are identical but comparison says mismatch"
                        f" (upstream={up_norm[:2]!r})"
                    )
        # Check: if comparison says mismatch but lines couldn't be parsed, skip (not a false positive)

    # Check verdict-PC consistency: if PC conclusion says accept, verdict must not reject
    verdict_match = re.search(r"^## Verdict\s*\n\s*(\w+)", generated, re.MULTILINE)
    verdict = verdict_match.group(1).lower() if verdict_match else None
    pc_conclusion = re.search(r"conclusion\s*:\s*(accept|reject)", pc_text, re.IGNORECASE)
    if pc_conclusion and verdict:
        pc_says = pc_conclusion.group(1).lower()
        if pc_says == "accept" and verdict == "reject":
            errors.append(
                "PC conclusion says accept but verdict is reject "
                "(reject not valid when all hunks match)"
            )

    if not errors:
        return None
    return "; ".join(errors)


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

    # test split
    test_false_rejects = []
    test_false_accepts = []
    test_parse_fails = []
    test_correct = []
    # canary split (v1.2+): mandatory gate anchors
    canary_results = []
    canary_parse_fails = []
    # train-retest (legacy v1.1)
    retest_parse_fails = []
    retest_results = []

    pilot_by_key = {
        (r["provenance"]["bundle_id"], r["provenance"].get("mutation_type") or ""): r
        for r in pilot_records
    }

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
            if split == "train-retest":
                retest_parse_fails.append(entry)
            elif split == "canary":
                canary_parse_fails.append(entry)
            else:
                test_parse_fails.append(entry)
            continue

        text = resp.get("generated", "")
        verdict = parse_verdict(text)
        if verdict is None:
            entry = {"bundle_id": bundle_id, "cve_id": cve_id, "reason": "parse_fail"}
            if split == "train-retest":
                retest_parse_fails.append(entry)
            elif split == "canary":
                canary_parse_fails.append(entry)
            else:
                test_parse_fails.append(entry)
            continue

        pilot_rec = pilot_by_key.get((bundle_id, mutation or ""), rec)
        grounding_failure = check_pc_grounding(text, pilot_rec) if split == "canary" else None
        pc_consistency_error = check_pc_consistency(text) if split == "canary" else None

        entry = {
            "bundle_id": bundle_id,
            "cve_id": cve_id,
            "attr_path": attr_path,
            "label": label,
            "split": split,
            "mutation_type": mutation,
            "verdict": verdict,
        }
        if grounding_failure:
            entry["grounding_failure"] = grounding_failure
        if pc_consistency_error:
            entry["pc_consistency_error"] = pc_consistency_error

        if split == "train-retest":
            expected = "accept" if label == "positive" else "reject"
            entry["outcome"] = "correct" if verdict == expected else (
                "false_reject" if label == "positive" else "false_accept"
            )
            retest_results.append(entry)
        elif split == "canary":
            expected = "accept" if label == "positive" else "reject"
            entry["outcome"] = "correct" if verdict == expected else (
                "false_reject" if label == "positive" else "false_accept"
            )
            canary_results.append(entry)
        else:
            if label == "positive" and verdict == "reject":
                test_false_rejects.append(entry)
            elif label == "negative" and verdict == "accept":
                test_false_accepts.append(entry)
            else:
                test_correct.append(entry)

    total_test = len([r for r in pilot_records if r.get("split") == "test"])
    total_canary = len([r for r in pilot_records if r.get("split") == "canary"])
    total_retest = len([r for r in pilot_records if r.get("split") == "train-retest"])
    canary_correct = sum(1 for r in canary_results if r.get("outcome") == "correct")
    canary_pc_consistency_errors = [r for r in canary_results if r.get("pc_consistency_error")]
    canary_pass = (
        canary_correct == total_canary
        and len(canary_parse_fails) == 0
        and len(canary_pc_consistency_errors) == 0
    )
    test_pass = (
        len(test_false_rejects) == 0
        and len(test_false_accepts) == 0
        and len(test_parse_fails) == 0
    )
    gate_pass = canary_pass and test_pass

    # Flatten for legacy callers that expect top-level false_rejects / false_accepts
    false_rejects = test_false_rejects + [r for r in canary_results if r.get("outcome") == "false_reject"]
    false_accepts = test_false_accepts + [r for r in canary_results if r.get("outcome") == "false_accept"]

    report = {
        "gate_pass": gate_pass,
        "summary": {
            "canary_total": total_canary,
            "canary_correct": canary_correct,
            "canary_pass": canary_pass,
            "canary_parse_fails": len(canary_parse_fails),
            "canary_pc_consistency_errors": len(canary_pc_consistency_errors),
            "test_total": total_test,
            "test_correct": len(test_correct),
            "test_false_rejects": len(test_false_rejects),
            "test_false_accepts": len(test_false_accepts),
            "test_parse_fails": len(test_parse_fails),
            "test_pass": test_pass,
            "retest_total": total_retest,
            "retest_correct": sum(1 for r in retest_results if r.get("outcome") == "correct"),
            "retest_parse_fails": len(retest_parse_fails),
            # legacy flat keys
            "false_rejects": len(false_rejects),
            "false_accepts": len(false_accepts),
        },
        "details": {
            "canary": canary_results,
            "canary_parse_fails": canary_parse_fails,
            "test_false_rejects": test_false_rejects,
            "test_false_accepts": test_false_accepts,
            "test_parse_fails": test_parse_fails,
            "test_correct": test_correct,
            "retest": retest_results,
            "retest_parse_fails": retest_parse_fails,
            # legacy flat keys
            "false_rejects": false_rejects,
            "false_accepts": false_accepts,
        },
    }

    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(report, indent=2) + "\n")

    print(f"Gate: {'PASS' if gate_pass else 'FAIL'}")
    if total_canary:
        print(f"Canary ({total_canary}): {canary_correct}/{total_canary} correct  ({'PASS' if canary_pass else 'FAIL'})")
        for r in canary_results:
            icon = "OK" if r.get("outcome") == "correct" else "!!"
            gf = f"  [GROUNDING:{r['grounding_failure'][:60]}]" if r.get("grounding_failure") else ""
            pce = f"  [PC-CONSISTENCY:{r['pc_consistency_error'][:80]}]" if r.get("pc_consistency_error") else ""
            print(f"  [{icon}] {r['cve_id']} ({r['label']}, mt={r['mutation_type']}) → {r['verdict']}{gf}{pce}")
        if canary_parse_fails:
            print(f"  PARSE FAILS: {len(canary_parse_fails)}")
        if canary_pc_consistency_errors:
            print(f"  PC CONSISTENCY ERRORS: {len(canary_pc_consistency_errors)}")
    print(f"Test ({total_test}): {len(test_correct)}/{total_test} correct  (FR={len(test_false_rejects)} FA={len(test_false_accepts)} PF={len(test_parse_fails)})  ({'PASS' if test_pass else 'FAIL'})")
    if retest_results:
        rc = sum(1 for r in retest_results if r.get("outcome") == "correct")
        print(f"Retest: {rc}/{total_retest} fixed")
        for r in retest_results:
            print(f"  {r['cve_id']} → {r['verdict']}  ({r['outcome']})")
    if retest_parse_fails:
        print(f"Retest parse fails: {len(retest_parse_fails)}")
    if test_false_rejects:
        print("TEST FALSE REJECTS:")
        for r in test_false_rejects:
            print(f"  {r['cve_id']} ({r['attr_path']})")
    if test_false_accepts:
        print("TEST FALSE ACCEPTS:")
        for r in test_false_accepts:
            print(f"  {r['cve_id']} ({r['attr_path']}) mutation={r['mutation_type']}")
    print(f"\nReport → {args.out}")
    sys.exit(0 if gate_pass else 1)


if __name__ == "__main__":
    main()
