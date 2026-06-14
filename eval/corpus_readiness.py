"""Reviewer-LoRA corpus readiness gate — the integration/quality control plane.

While a fleet of sessions produces bundle volume, this turns "many bundles" into a
usable training dataset by reporting, in one re-runnable place:

  * positive / negative counts vs the pilot threshold (50 positives + 25 negatives)
  * train/dev/test split + family-leakage status (training-validity invariant)
  * an ACTIONABLE exclusion breakdown — which bundles are excluded and whether the
    exclusion is RECOVERABLE (attestation mismatch / no review yet → fix + re-export)
    or STRUCTURAL (parser failure / duplicate → needs a real decision)
  * the authoring-track count (the second fine-tune dataset)
  * a baseline-freeze / pilot-ready verdict

Exit code 0 when the corpus is pilot-ready, 1 otherwise — so it can gate CI or tell
the fleet when to stop. Read-only: it shells out to `trace export {reviewer,authoring}
--format json` and analyses the manifests; it writes nothing to the corpus.

Usage:  python3 eval/corpus_readiness.py [--pos N] [--neg N] [--json]
(per docs/REVIEWER_LORA_PILOT.md; codex peer 2026-06-14 — "own the integration gate".)
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from collections import Counter

POS_THRESHOLD = 50
NEG_THRESHOLD = 25

# Exclusion reasons that a follow-up can FIX (the bundle has real model work behind
# it); vs ones that need a human/structural decision. Substring-matched.
_RECOVERABLE = ("attestation mismatch", "no reviewer target", "no review")


def _export(scope: str) -> dict | None:
    """Run `trace export <scope> --format json` and return the parsed manifest."""
    env = dict(os.environ)
    env["PYTHONPATH"] = "tools" + (os.pathsep + env["PYTHONPATH"] if env.get("PYTHONPATH") else "")
    try:
        out = subprocess.run(
            [sys.executable, "-m", "trace_cli", "export", scope, "--format", "json"],
            capture_output=True, text=True, env=env, timeout=300,
        )
    except (subprocess.SubprocessError, OSError) as exc:
        print(f"error: could not run exporter for {scope!r}: {exc}", file=sys.stderr)
        return None
    if out.returncode != 0:
        print(f"error: exporter {scope!r} exited {out.returncode}: {out.stderr[-400:]}", file=sys.stderr)
        return None
    # the manifest is the last JSON object on stdout
    try:
        return json.loads(out.stdout)
    except json.JSONDecodeError:
        start = out.stdout.find("{")
        return json.loads(out.stdout[start:]) if start >= 0 else None


def _exclusion_reason(e: dict) -> str:
    return (e.get("reason") or e.get("exclusion_reason") or "?")


def build_report(pos_threshold: int, neg_threshold: int) -> dict:
    rev = _export("reviewer") or {}
    auth = _export("authoring") or {}

    labels = rev.get("labels", {})
    pos = labels.get("positive", 0)
    neg = labels.get("negative", 0)
    leakage_ok = bool(rev.get("leakage_check_ok"))

    excluded = rev.get("excluded", [])
    by_reason = Counter()
    recoverable = []
    structural = []
    for e in excluded:
        reason = _exclusion_reason(e)
        short = reason.split(":")[0].strip()[:48]
        by_reason[short] += 1
        (recoverable if any(r in reason.lower() for r in _RECOVERABLE) else structural).append(
            {"bundle": e.get("bundle") or e.get("dir") or e.get("cve_id"), "reason": short}
        )

    pos_ready = pos >= pos_threshold
    neg_ready = neg >= neg_threshold
    pilot_ready = pos_ready and neg_ready and leakage_ok

    return {
        "reviewer": {
            "positive": pos, "negative": neg,
            "positive_gap": max(0, pos_threshold - pos),
            "negative_gap": max(0, neg_threshold - neg),
            "splits": rev.get("splits", {}),
            "families": rev.get("families") if isinstance(rev.get("families"), int)
                        else len(rev.get("families", [])),
            "leakage_check_ok": leakage_ok,
            "total_bundles_enumerated": rev.get("total_bundles_enumerated"),
        },
        "exclusions": {
            "total": len(excluded),
            "by_reason": dict(by_reason),
            "recoverable": recoverable,        # fix attestation / run reviewer → +positives
            "structural": structural,          # dedupe / parser — needs a decision
        },
        "authoring": {
            "examples": auth.get("eligible_examples"),
            "splits": auth.get("splits", {}),
        },
        "thresholds": {"positive": pos_threshold, "negative": neg_threshold},
        "pilot_ready": pilot_ready,
        "blocking": [m for m, ok in (
            (f"need +{max(0, pos_threshold - pos)} positives", pos_ready),
            (f"need +{max(0, neg_threshold - neg)} negatives", neg_ready),
            ("family leakage across splits", leakage_ok),
        ) if not ok],
    }


def _emit(r: dict) -> None:
    rv = r["reviewer"]
    print("== Reviewer-LoRA corpus readiness ==")
    print(f"  positives: {rv['positive']}/{r['thresholds']['positive']}"
          f"  (gap {rv['positive_gap']})")
    print(f"  negatives: {rv['negative']}/{r['thresholds']['negative']}"
          f"  (gap {rv['negative_gap']})")
    print(f"  splits: {rv['splits']}  families: {rv['families']}")
    print(f"  family-leakage-free: {rv['leakage_check_ok']}")
    ex = r["exclusions"]
    print(f"  excluded: {ex['total']}  by reason: {ex['by_reason']}")
    if ex["recoverable"]:
        print(f"  TRIAGE exclusions (attestation/no-review — may yield +positives if "
              f"genuinely a reviewer bundle, not retired/auto-merge-by-design): "
              f"{len(ex['recoverable'])}")
        for e in ex["recoverable"]:
            print(f"    - {e['bundle']}: {e['reason']}")
    print(f"  authoring examples: {r['authoring']['examples']}  splits: {r['authoring']['splits']}")
    verdict = "READY to freeze baseline + run pilot" if r["pilot_ready"] else "NOT YET"
    print(f"== verdict: {verdict} ==")
    if r["blocking"]:
        print("   blocking: " + "; ".join(r["blocking"]))


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description="Reviewer-LoRA corpus readiness gate")
    ap.add_argument("--pos", type=int, default=POS_THRESHOLD)
    ap.add_argument("--neg", type=int, default=NEG_THRESHOLD)
    ap.add_argument("--json", action="store_true", help="emit the report as JSON")
    args = ap.parse_args(argv)
    report = build_report(args.pos, args.neg)
    if args.json:
        print(json.dumps(report, indent=2))
    else:
        _emit(report)
    return 0 if report["pilot_ready"] else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
