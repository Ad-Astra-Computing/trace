#!/usr/bin/env python3
"""Gated 3-way live eval for reviewer.v11 (the two-conjunct resolution reshape).

This is the single capped command that decides whether the adaptation lane may
flip from reviewer.v10 to reviewer.v11. It runs the Reviewer LIVE (real API
spend) exactly THREE times — once per preregistered case — using
`prompts/reviewer.v11.md` via the `--reviewer-prompt` override, WITHOUT touching
the committed v10 routing default (`REVIEWER_PROMPT_PATH_ADAPT`).

Preregistered cases (see DECISIONS 2026-07-27 "reviewer.v11 reshaped"):

  * POS         — maxima CVE-2024-34490 (package-scope cross-file `random-name`):
                  reviewer.v11 must judge `equivalent`. Graded by the adaptation
                  oracle (agents/scorers/adaptation_oracle.py) → score 1.0.
  * NEG-same-lang — a Common-Lisp variant citing `scramble-fname`, defined in NO
                  bundle file and not a CL builtin: must stay `not-equivalent`.
                  THE DISCRIMINATOR — it exercises the reshaped existence
                  conjunct within Lisp. Graded by verdict-assertion.
  * NEG-cross-lang — a libarchive C variant citing `archive_ckd_*` helpers absent
                  from pinned 3.8.7: must stay `not-equivalent` (C/TU regression
                  anchor). Graded by verdict-assertion.

ROUTING-FLIP RULE: flip v10→v11 ONLY on a full PASS, and specifically only if
NEG-same-lang blocks. POS + NEG-cross-lang passing alone proves regression-safety
(the C case is rejected under both v10 and v11); it does NOT prove the reshaped
Lisp path still discriminates. Do not flip until NEG-same-lang is not-equivalent.

SPEND GATE: this makes live Anthropic calls. It refuses to run without `--live`.
It never mutates the committed bundles — each is copied to a scratch workdir and
the Reviewer runs there.
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import tempfile
from hashlib import sha256
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
V11_PROMPT = REPO / "prompts" / "reviewer.v11.md"

# (label, bundle dir, expected equivalence verdict, grading mode)
POS = REPO / "traces" / "example" / "CVE-2024-34490--maxima-plot-tempfile-backport"
NEG_SAME = REPO / "traces" / "eval-adaptation" / "NEG-maxima-unbound-lisp-symbol"
NEG_CROSS = REPO / "traces" / "eval-adaptation" / "NEG-libarchive-unresolved-ckd-helpers"

# (label, bundle dir, expected verdict, grading mode, needs_no_verify)
# The NEGs carry intentionally-stale manifest hashes (corrupted patch.diff +
# scrubbed reviewer role), so their reviewer replay needs --no-verify; the
# pristine POS bundle verifies normally, which also catches copy drift.
CASES = [
    ("POS/maxima-package-scope", POS, "equivalent", "oracle", False),
    ("NEG-same-lang/unbound-lisp", NEG_SAME, "not-equivalent", "verdict-assertion", True),
    ("NEG-cross-lang/libarchive-ckd", NEG_CROSS, "not-equivalent", "verdict-assertion", True),
]


def _patch_sha(bundle: Path) -> str:
    return sha256((bundle / "patch.diff").read_bytes()).hexdigest()


def _expected_patch_sha(label: str, bundle: Path) -> str | None:
    """The canonical patch.diff hash the expected verdict is bound to. POS binds
    via the adaptation oracle; the NEGs bind via expect.json."""
    if label.startswith("POS"):
        sys.path.insert(0, str(REPO))
        from agents.scorers.adaptation_oracle import get_oracle

        oracle = get_oracle("CVE-2024-34490")
        return oracle.adjudicated_patch_sha256 if oracle else None
    expect = json.loads((bundle / "expect.json").read_text())
    return expect.get("adjudicated_patch_sha256")


def _preflight() -> list[str]:
    """No-spend checks: bundles present, patch.diff bytes match the hash the
    expected verdict is bound to. A drift here means the eval would grade a
    different adaptation than the one preregistered — abort before spending."""
    errors: list[str] = []
    if not V11_PROMPT.is_file():
        errors.append(f"missing {V11_PROMPT}")
    for label, bundle, _, _, _ in CASES:
        if not (bundle / "patch.diff").is_file():
            errors.append(f"{label}: missing {bundle}/patch.diff")
            continue
        want = _expected_patch_sha(label, bundle)
        got = _patch_sha(bundle)
        if want and want != got:
            errors.append(
                f"{label}: patch.diff sha {got[:12]}… != bound {want[:12]}… "
                "(fixture drift — the preregistered verdict no longer applies)"
            )
    return errors


def _run_reviewer(work: Path, model: str, no_verify: bool) -> None:
    cmd = [
        sys.executable, "-m", "tools.trace_cli", "replay", str(work),
        "--execute", "--role", "reviewer", "--model", model,
        "--reviewer-prompt", str(V11_PROMPT),
    ]
    if no_verify:
        cmd.append("--no-verify")
    subprocess.run(cmd, cwd=REPO, check=True)


def _verdict(work: Path) -> str | None:
    sys.path.insert(0, str(REPO))
    from agents.reviewer.parser import parse_reviewer_output, parse_equivalence_verdict

    review = work / "review.md"
    if not review.is_file():
        return None
    parsed = parse_reviewer_output(review.read_text())
    return parse_equivalence_verdict(parsed.equivalence_assessment_raw)


def _oracle_score(work: Path) -> float | None:
    sys.path.insert(0, str(REPO))
    from agents.scorers.reviewer_scorers import ReviewAdaptationEquivalenceScorer

    replay = json.loads((work / "replay.json").read_text()) if (work / "replay.json").is_file() else {}
    res = ReviewAdaptationEquivalenceScorer().score(bundle_dir=work, invocation=replay)
    return res.score if getattr(res, "applies", True) else None


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--live", action="store_true", help="acknowledge LIVE API spend (Jason-gated). Required to run.")
    ap.add_argument("--model", default="claude-sonnet-4-5-20250929", help="Reviewer model id")
    ap.add_argument("--no-verify", action="store_true", help="skip replay input/output sha verification (scrubbed reviewer role)")
    args = ap.parse_args()

    errors = _preflight()
    if errors:
        print("PREFLIGHT FAILED (no spend occurred):", file=sys.stderr)
        for e in errors:
            print(f"  - {e}", file=sys.stderr)
        return 2

    if not args.live:
        print(__doc__)
        print("Preflight OK. This run makes LIVE Anthropic calls (3 Reviewer invocations).")
        print("It is gated on Jason's live-spend authorization. Re-run with --live to execute.")
        return 0

    if not os.environ.get("ANTHROPIC_API_KEY"):
        print("error: ANTHROPIC_API_KEY not set (source .env). Refusing to run.", file=sys.stderr)
        return 2

    results = []
    with tempfile.TemporaryDirectory(prefix="reviewer-v11-eval-") as tmp:
        for label, bundle, expected, mode, needs_nv in CASES:
            work = Path(tmp) / bundle.name
            shutil.copytree(bundle, work)
            print(f"\n=== {label} → reviewer.v11 (model={args.model}) ===")
            _run_reviewer(work, args.model, needs_nv or args.no_verify)
            verdict = _verdict(work)
            oracle = _oracle_score(work) if mode == "oracle" else None
            if mode == "oracle":
                ok = verdict == expected and (oracle is None or oracle == 1.0)
            else:
                ok = verdict == expected
            results.append((label, expected, verdict, oracle, ok))

    print("\n================ reviewer.v11 3-way eval ================")
    for label, expected, verdict, oracle, ok in results:
        extra = f"  oracle_score={oracle}" if oracle is not None else ""
        print(f"  [{'PASS' if ok else 'FAIL'}] {label}: expected={expected} got={verdict}{extra}")

    by = {label.split('/')[0]: ok for label, _, _, _, ok in results}
    neg_same_ok = by.get("NEG-same-lang", False)
    full_pass = all(ok for *_, ok in results)
    print("\n--- routing-flip decision ---")
    if full_pass:
        print("FULL PASS. Routing flip v10→v11 is authorized (all three cases held;")
        print("the NEG-same-lang discriminator blocked). The flip slice carries its own")
        print("codex review --uncommitted + advances the security counter.")
    elif not neg_same_ok:
        print("DO NOT FLIP. The NEG-same-lang discriminator did not block — the reshaped")
        print("Lisp path is not proven to still catch genuinely-unbound symbols.")
    else:
        print("DO NOT FLIP. Not a full pass; inspect the failing case before any routing change.")
    return 0 if full_pass else 1


if __name__ == "__main__":
    raise SystemExit(main())
