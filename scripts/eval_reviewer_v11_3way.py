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


def _run_reviewer(work: Path, model: str, no_verify: bool) -> tuple[bool, str]:
    """Run the Reviewer live on `work`. Returns (ok, stderr_tail). Does not raise
    on a non-zero exit — a malformed-output rejection (execute.py exit 4) is an
    expected, recordable outcome here, not a crash."""
    cmd = [
        sys.executable, "-m", "tools.trace_cli", "replay", str(work),
        "--execute", "--role", "reviewer", "--model", model,
        "--reviewer-prompt", str(V11_PROMPT),
    ]
    if no_verify:
        cmd.append("--no-verify")
    proc = subprocess.run(cmd, cwd=REPO, capture_output=True, text=True)
    tail = ""
    if proc.returncode != 0:
        err = (proc.stderr or proc.stdout or "").strip().splitlines()
        tail = err[-1] if err else f"exit {proc.returncode}"
    return proc.returncode == 0, tail


def _capture_failure_raw(work: Path, label: str, attempt: int, diag_dir: Path) -> Path | None:
    """execute.py persists a rejected model output to
    `.reviewer-failures/<uuid>/raw-response.txt` inside the bundle dir. Copy it
    out to the diagnostics dir so the flake is inspectable after the run."""
    hits = sorted(work.glob(".reviewer-failures/*/raw-response.txt"))
    if not hits:
        return None
    dest = diag_dir / f"{label.replace('/', '_')}-attempt{attempt}-raw-response.txt"
    shutil.copyfile(hits[-1], dest)
    return dest


def _verdict(work: Path) -> str | None:
    sys.path.insert(0, str(REPO))
    from agents.reviewer.parser import parse_reviewer_output, parse_equivalence_verdict

    review = work / "review.md"
    if not review.is_file():
        return None
    # review.md on disk is the extracted body (raw_review_md) — the BEGIN/END
    # markers are stripped when execute.py persists it. Re-wrap so the parser
    # (which validates the full contract) accepts it, then pull the verdict.
    raw = "=== BEGIN review.md ===\n" + review.read_text().rstrip() + "\n=== END review.md ===\n"
    parsed = parse_reviewer_output(raw)
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

    # Persistent diagnostics dir (NOT auto-deleted) so a malformed-output flake
    # leaves its raw-response.txt behind for inspection. Retry once per case for
    # diagnostic verdict recovery ONLY — a first-attempt format drop already
    # fails the routing gate regardless of what the retry recovers (codex
    # ruling, DECISIONS 2026-07-27).
    diag_dir = Path(tempfile.mkdtemp(prefix="reviewer-v11-eval-"))
    print(f"diagnostics + workdirs: {diag_dir}")

    results = []
    format_drop_observed = False
    for label, bundle, expected, mode, needs_nv in CASES:
        attempts: list[dict] = []
        verdict = None
        oracle = None
        case_pass = False
        for attempt in (1, 2):
            work = diag_dir / f"{label.replace('/', '_')}-attempt{attempt}" / bundle.name
            work.parent.mkdir(parents=True, exist_ok=True)
            shutil.copytree(bundle, work)
            print(f"\n=== {label} attempt {attempt} → reviewer.v11 (model={args.model}) ===")
            ok, tail = _run_reviewer(work, args.model, needs_nv or args.no_verify)
            if ok:
                try:
                    verdict = _verdict(work)
                except Exception as exc:  # noqa: BLE001 — record, don't crash
                    ok, tail = False, f"verdict-parse: {exc}"
            if ok:
                oracle = _oracle_score(work) if mode == "oracle" else None
                if mode == "oracle":
                    case_pass = verdict == expected and (oracle is None or oracle == 1.0)
                else:
                    case_pass = verdict == expected
                attempts.append({"attempt": attempt, "outcome": "ok", "verdict": verdict})
                break
            raw = _capture_failure_raw(work, label, attempt, diag_dir)
            # Classify: a captured raw-response means the model RAN and emitted
            # malformed output (a genuine format drop). No raw-response means
            # execute.py refused BEFORE the model — a precondition/attestation
            # failure (fixture defect), which is NOT a v11 output-format flake.
            failure_kind = "format-drop" if raw else "precondition-refusal"
            attempts.append({
                "attempt": attempt, "outcome": failure_kind,
                "detail": tail, "raw_response": str(raw) if raw else None,
            })
            print(f"  [attempt {attempt} {failure_kind}] {tail}")
            if raw:
                print(f"  raw model output captured: {raw}")
            if attempt == 1:
                print("  retrying once (diagnostic verdict recovery only)...")

        first_ok = attempts[0]["outcome"] == "ok"
        if attempts[0]["outcome"] == "format-drop":
            format_drop_observed = True
        precondition_failure = all(a["outcome"] == "precondition-refusal" for a in attempts)
        recovered = case_pass and not first_ok
        results.append({
            "label": label, "expected": expected, "verdict": verdict,
            "oracle": oracle, "case_pass": case_pass, "first_ok": first_ok,
            "recovered": recovered, "precondition_failure": precondition_failure,
            "attempts": attempts,
        })

    (diag_dir / "results.json").write_text(json.dumps(results, indent=2) + "\n")

    print("\n================ reviewer.v11 3-way eval ================")
    for r in results:
        oc = f"  oracle_score={r['oracle']}" if r["oracle"] is not None else ""
        flag = "PASS" if r["case_pass"] else "FAIL"
        if r["recovered"]:
            note = " (recovered on retry)"
        elif r["precondition_failure"]:
            note = " (UNRUNNABLE — refused pre-model at attestation gate; discriminator not exercised)"
        elif not r["first_ok"]:
            note = " (first attempt format-drop)"
        else:
            note = ""
        print(f"  [{flag}] {r['label']}: expected={r['expected']} got={r['verdict']}{oc}{note}")

    neg_same_ok = next((r["case_pass"] for r in results if r["label"].startswith("NEG-same-lang")), False)
    discriminator_exercised = not next(
        (r["precondition_failure"] for r in results if r["label"].startswith("NEG-same-lang")), True
    )
    full_pass = all(r["case_pass"] for r in results)
    print("\n--- routing-flip decision ---")
    if not discriminator_exercised:
        print("DO NOT FLIP. The NEG-same-lang discriminator never reached the model — the")
        print("adaptation lane refused it at the Patcher canonical-compile attestation gate")
        print("(patch-applicability.json), upstream of the Reviewer's existence check. The")
        print("two-conjunct discriminator is UNPROVEN; the fixtures need a forged-compile")
        print("attestation (eval-only adversarial input) to isolate the Reviewer's check.")
        if format_drop_observed:
            print("Independently: a v11 output-format drop was also observed (see below).")
    elif format_drop_observed:
        print("DO NOT FLIP. A first-attempt output-format drop was observed (reviewer.v11")
        print("intermittently omitted the required '## Equivalence assessment' section).")
        print("Per preregistration this fails the routing gate regardless of retry-recovered")
        print("verdicts — an unroutable prompt is one the model does not reliably comply with.")
        print(f"(full_pass={full_pass}, neg_same_ok={neg_same_ok} — recorded for the writeup, not a flip basis.)")
    elif full_pass and neg_same_ok:
        print("FULL PASS, no format drop. Routing flip v10→v11 is authorized (all three cases")
        print("held first-attempt; the NEG-same-lang discriminator blocked). The flip slice")
        print("carries its own codex review --uncommitted + advances the security counter.")
    elif not neg_same_ok:
        print("DO NOT FLIP. The NEG-same-lang discriminator did not block — the reshaped")
        print("Lisp path is not proven to still catch genuinely-unbound symbols.")
    else:
        print("DO NOT FLIP. Not a full pass; inspect the failing case before any routing change.")
    return 0 if (full_pass and not format_drop_observed) else 1


if __name__ == "__main__":
    raise SystemExit(main())
