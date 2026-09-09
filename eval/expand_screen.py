#!/usr/bin/env python3
"""Reproducer-gated candidate-expansion SCREENING (authoring corpus, slice B).

Wires blind-author output through the existing Tier 2 red→green behavioral gate
(`score_authoring_pilot.score_behavioral`) and an LLM judge, to SCREEN which CVEs
are viable authoring tasks (solvable + reproducible) — the step-3 automation in
docs/AUTHORING_TRAINING.md.

GUARDRAIL (codex 2026-06-26): this NEVER creates a training label. The supervised
authoring label stays the curated `upstream-fix.patch`. A model-authored candidate
is used ONLY to measure solvability (does a model author a fix?) and to gate
viability (does that fix behaviorally close the bug, and does it close every path
upstream's fix closes?). A behaviorally-passing model-authored ALTERNATE fix would
go in a separate `pseudo_label` corpus with provenance + Reviewer approval — not
the training set.

Pipeline per bundle:
  1. blind-author (author_blind_eval.eval_bundle — cache-reuse, leak-scrubbed input)
     → verdict {exact|differs|no-attempt|skip} + the candidate diff
  2. Tier 2 behavioral gate (real reproducers only; needs --behavioral + a nixpkgs
     checkout) → {ran pass|fail, exempt, ...}
  3. judge (differs only) → GOLD | PARTIAL | WRONG ("does this close EVERY path the
     upstream fix closes?")
  4. disposition → viable-exact | viable-gold | needs-review | reject-* | unscreenable

Usage:
  python3 eval/expand_screen.py --out eval/expand-screen-report.json         # blind+judge
  python3 eval/expand_screen.py --behavioral --nixpkgs <checkout> CVE-2026-42250--bzip2-backport
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from eval.author_blind_eval import eval_bundle, _api
from eval.score_authoring_pilot import (
    score_behavioral,
    _reproducer_kind,
    _make_build_fn,
    _clean_generated,
)


def judge_differs(
    cve: str, authored_diff: str, upstream_fix: str, *, api_fn=_api
) -> dict:
    """LLM judge for a candidate that DIFFERS from upstream: does it close EVERY
    path the upstream fix closes (the libxmp-partial trap), or is it a subtly
    incomplete / wrong fix? Returns GOLD | PARTIAL | WRONG."""
    prompt = (
        "You are a security reviewer. Two patches address the same CVE. The REFERENCE "
        "is the validated upstream fix. The CANDIDATE is an independently-authored fix. "
        "Question: does the CANDIDATE close EVERY code path the REFERENCE closes, with "
        "no gap (not merely 'looks plausible')? Answer with exactly one word on the "
        "first line: GOLD (semantically equivalent / closes every path), PARTIAL "
        "(fixes some but leaves a gap, or a different mechanism that misses a path), or "
        "WRONG (does not actually fix the vulnerability). Then one sentence of reason.\n\n"
        f"# CVE\n{cve}\n\n# REFERENCE (upstream fix)\n```diff\n{upstream_fix}\n```\n\n"
        f"# CANDIDATE\n```diff\n{authored_diff}\n```\n"
    )
    resp = api_fn(prompt)
    first = (resp.strip().splitlines() or [""])[0].strip().upper()
    verdict = next((v for v in ("GOLD", "PARTIAL", "WRONG") if v in first), "UNCLEAR")
    return {"judge": verdict, "reason": resp.strip()[:300]}


def _disposition(verdict: str, behavioral: dict, judge: dict | None) -> str:
    """Screening disposition. Never promotes — `viable-*` means "a good authoring
    task worth a curated-label bundle"; the label is still the upstream fix."""
    bstatus, bpass = behavioral.get("status"), behavioral.get("pass")
    if verdict in ("skip", "no-attempt"):
        return "unscreenable-no-candidate"
    # A behavioral run that FAILED means the candidate does not fix the bug — but the
    # CVE is still a viable authoring task (the reproducer works; the model just got
    # it wrong). Mark task-viable-candidate-wrong so it counts toward "reproducible".
    if bstatus == "ran" and bpass is False:
        return "task-viable-candidate-wrong"
    if verdict == "exact":
        return "viable-exact"  # candidate reproduced upstream's change
    # verdict == differs:
    if bstatus == "ran" and bpass is True:
        if judge and judge["judge"] == "GOLD":
            return "viable-gold"
        if judge and judge["judge"] == "WRONG":
            return "behavioral-pass-judge-wrong"  # passed a narrow reproducer but judge rejects
        return "needs-review"  # partial / unjudged
    # not behaviorally gated (proxy reproducer, or no --behavioral):
    if judge and judge["judge"] == "GOLD":
        return "viable-judge-only"
    if judge and judge["judge"] == "WRONG":
        return "reject-judge"
    return "needs-review"


def _bundle_record(bundle_dir: Path) -> dict:
    b = json.loads((bundle_dir / "bundle.json").read_text())
    f = json.loads((bundle_dir / "finding.json").read_text())
    return {"provenance": {"cve_id": f["cve_id"], "bundle_id": b.get("bundle_id")}}


def screen_bundle(
    bundle_dir: Path,
    *,
    traces_root: Path,
    build_fn=None,
    judge_api=_api,
    author_fn=eval_bundle,
) -> dict:
    blind = author_fn(bundle_dir)
    cve = blind.get("cve")
    if blind.get("status") == "skip":
        return {
            "cve": cve,
            "verdict": "skip",
            "reason": blind.get("reason"),
            "disposition": "unscreenable-no-source",
        }
    # Normalize the candidate to the diff BODY before the behavioral gate: a model
    # often wraps the diff in a ```diff fence or a preface, which `_changed_lines`
    # tolerates but `_rewrite_embedded_patch` would embed verbatim, failing the
    # patch-apply gate for an otherwise valid fix (codex 2026-06-26).
    authored = _clean_generated(blind.get("authored_diff", ""))
    verdict = blind["verdict"]

    # Tier 2 behavioral gate — real reproducers only.
    kind = _reproducer_kind(bundle_dir)
    if build_fn is not None and kind != "text-inspection-proxy":
        bv = score_behavioral(
            authored,
            _bundle_record(bundle_dir),
            traces_root=traces_root,
            build_fn=build_fn,
        )
        behavioral = {
            "status": bv.get("behavioral_status"),
            "pass": bv.get("behavioral_pass"),
        }
    else:
        behavioral = {
            "status": "not-gated",
            "reason": (
                "proxy reproducer"
                if kind == "text-inspection-proxy"
                else "no --behavioral build_fn"
            ),
        }

    judge = None
    # Judge the "differs" cases unless behavioral already rejected the candidate.
    if verdict == "differs" and not (
        behavioral.get("status") == "ran" and behavioral.get("pass") is False
    ):
        upstream = (bundle_dir / "upstream-fix.patch").read_text()
        judge = judge_differs(cve, authored, upstream, api_fn=judge_api)

    return {
        "cve": cve,
        "verdict": verdict,
        "src_origin": blind.get("src_origin"),
        "reproducer_kind": kind,
        "behavioral": behavioral,
        "judge": judge,
        "disposition": _disposition(verdict, behavioral, judge),
    }


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    ap.add_argument("bundles", nargs="*", help="bundle dirs (default: all *-backport)")
    ap.add_argument("--traces-root", type=Path, default=Path("traces/example"))
    ap.add_argument(
        "--behavioral",
        action="store_true",
        help="run the Tier 2 behavioral gate (needs --nixpkgs; real reproducers only)",
    )
    ap.add_argument(
        "--nixpkgs", type=Path, default=None, help="nixpkgs checkout for --behavioral"
    )
    ap.add_argument("--build-timeout", type=int, default=900)
    ap.add_argument("--out", type=Path, default=Path("eval/expand-screen-report.json"))
    args = ap.parse_args(argv)

    bundles = [Path(p) for p in args.bundles] or sorted(
        args.traces_root.glob("*-backport")
    )
    build_fn = None
    if args.behavioral:
        if args.nixpkgs is None:
            print("error: --behavioral requires --nixpkgs", file=sys.stderr)
            return 2
        build_fn = _make_build_fn(args.nixpkgs, args.build_timeout)

    results = []
    for bd in bundles:
        if not (bd / "upstream-fix.patch").is_file():
            continue
        try:
            r = screen_bundle(bd, traces_root=args.traces_root, build_fn=build_fn)
        except Exception as exc:  # noqa: BLE001 — screening harness, report don't crash
            r = {"cve": bd.name, "disposition": "error", "reason": str(exc)[:160]}
        results.append(r)
        print(
            f"  {str(r.get('cve')):<18} {r.get('verdict', '-'):<10} "
            f"behav={r.get('behavioral', {}).get('status', '-'):<10} "
            f"judge={(r.get('judge') or {}).get('judge', '-'):<8} -> {r['disposition']}"
        )

    counts: dict[str, int] = {}
    for r in results:
        counts[r["disposition"]] = counts.get(r["disposition"], 0) + 1
    report = {
        "scope": "authoring-expansion-screen",
        "n": len(results),
        "dispositions": counts,
        "results": results,
        "guardrail": "screening only; training label stays the curated upstream-fix.patch",
    }
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(report, indent=2) + "\n")
    print(f"\n{counts}  -> {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
