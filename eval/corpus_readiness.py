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
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
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


def _schema_invalid_bundles() -> list[dict]:
    """Real-CVE bundles on disk that the review-accept count would include but that
    FAIL policy-schema validation, or are auto-merge without a cert (build.json) — the
    pollution a review-accept count alone misses (codex 2026-06-15: a nominal 50/25 can
    hide schema-invalid bundles). READY must require this list to be empty. Returns
    [{bundle, error}, ...]; synthetic CVE-0000-* fixtures are intentionally excluded."""
    try:
        sys.path.insert(0, str(REPO))
        from tests.schema.validate import validate_fixture
    except ImportError:
        return []  # jsonschema/referencing unavailable; the CI fixture test is the backstop
    import re
    dirty = []
    for bd in sorted((REPO / "traces" / "example").glob("CVE-*")):
        if bd.name.startswith("CVE-0000-"):
            continue
        # Placeholder/short nixpkgs_rev = unverifiable pre-patch provenance: the cert
        # workflow does `git fetch origin <rev>` and an all-zero rev cannot resolve, so
        # the bundle can never be cert-green and must not count toward the training
        # corpus (codex 2026-06-15, after the salvage-backport placeholder-rev bundles).
        # The bundle-schema pattern ^[0-9a-f]{40}$ ACCEPTS 40 zeros, so this is an
        # explicit check the schema validator does not perform.
        bjson = bd / "bundle.json"
        if bjson.is_file():
            try:
                rev = json.loads(bjson.read_text()).get("nixpkgs_rev", "")
            except (OSError, json.JSONDecodeError):
                rev = ""
            if not re.fullmatch(r"[0-9a-f]{40}", rev or "") or set(rev) == {"0"}:
                dirty.append({"bundle": bd.name, "error": f"placeholder/invalid nixpkgs_rev: {rev[:12]!r}"})
                continue
        if not (bd / "expect.json").is_file():
            dirty.append({"bundle": bd.name, "error": "missing expect.json"})
            continue
        try:
            res = validate_fixture(bd)   # docs + hashes + bundle-schema conditional required-files
        except Exception as exc:  # noqa: BLE001 — report, don't crash the gate
            dirty.append({"bundle": bd.name, "error": f"validate error: {str(exc)[:80]}"})
            continue
        if res.any_errors:
            errs = [f"{k}: {v[0]}" for k, v in res.per_doc_errors.items() if v] + list(res.hash_errors)
            dirty.append({"bundle": bd.name, "error": errs[0] if errs else "schema-invalid"})
    return dirty


def _classify_schema_invalid(dirty: list[dict]) -> dict:
    """Partition the raw schema-invalid list into honest buckets so the readiness
    gate distinguishes a real evidence-bundle defect from two known non-defects:

    - authoring_only: dirs that are authoring-track training pairs mis-enumerated
      as evidence bundles (they carry authoring-example.json and no bundle.json, so
      the 'missing expect.json' flag fires). These were never evidence bundles;
      counting them as corpus pollution is a category error, so they are excluded
      from the block entirely.
    - non_git_provenance: legitimate backports whose upstream-fix provenance is a
      distro/vendor tracker id (debian-bts-*, novell-bugzilla-*, vmware-*,
      nixpkgs-backport-no-sha) rather than a public git sha, so validate_fixture's
      commit_sha regex rejects them. A named known-limitation class (cf.
      authoring-exporter-needs-public-git), surfaced honestly but STILL counted
      toward the block: relaxing that is an eval-gate loosening that needs peer
      sign-off, not a unilateral flip.
    - broken: everything else — the only unqualified evidence-bundle defect.
    """
    authoring_only, non_git_provenance, broken = [], [], []
    for e in dirty:
        err = e.get("error", "")
        bd = REPO / "traces" / "example" / e["bundle"]
        if err == "missing expect.json" and (bd / "authoring-example.json").is_file() \
                and not (bd / "bundle.json").is_file():
            authoring_only.append(e)
        elif "commit_sha" in err and "does not match" in err:
            non_git_provenance.append(e)
        else:
            broken.append(e)
    return {"authoring_only": authoring_only,
            "non_git_provenance": non_git_provenance,
            "broken": broken}


def _uncerted_auto_merge_positives() -> list[dict]:
    """Real-CVE AUTO-MERGE bundles whose Reviewer accepted but which are NOT
    cert-green+signed. An auto-merge positive's accept is only trustworthy if the
    patch actually built and the bundle is signed (codex 2026-06-15: "auto-merge
    positives MUST be cert-green"); review-accept alone is a softer false-green.
    human-review-required positives are exempt — their accept is conditional on human
    review by design. Returns [{bundle, subreason}, ...]. Subreasons: missing-build-json,
    patch-apply-failed, patched-build-failed, non-linux-host, missing-bundle-sig."""
    import re
    out = []
    for bd in sorted((REPO / "traces" / "example").glob("CVE-*")):
        if bd.name.startswith("CVE-0000-"):
            continue
        bjson = bd / "bundle.json"
        review = bd / "review.md"
        if not bjson.is_file() or not review.is_file():
            continue
        try:
            kind = json.loads(bjson.read_text()).get("kind")
        except (OSError, json.JSONDecodeError):
            continue
        if kind != "auto-merge":
            continue
        # only count review-accept bundles (the positives)
        head = review.read_text()[:400].lower()
        if "## verdict" not in head or "accept" not in head.split("## verdict", 1)[1][:40]:
            continue
        sub = None
        bf = bd / "build.json"
        if not bf.is_file():
            sub = "missing-build-json"
        else:
            try:
                b = json.loads(bf.read_text())
            except (OSError, json.JSONDecodeError):
                b = {}
            if b.get("patch_apply", {}).get("applied") is not True:
                sub = "patch-apply-failed"
            elif b.get("patched_build", {}).get("outcome") != "succeeded":
                sub = "patched-build-failed"
            elif b.get("host", {}).get("system") != "x86_64-linux":
                sub = "non-linux-host"
            elif not (bd / "bundle.sig").is_file():
                sub = "missing-bundle-sig"
        if sub:
            out.append({"bundle": bd.name, "subreason": sub})
    return out


def _source_backport_report() -> dict:
    """Behavioral-validation status of the source-backport corpus — the valuable,
    non-version-bump training data (the agent AUTHORS the code fix). A source
    backport only counts as `validated` if the cert behaviorally proved the fix
    addresses the CVE (unpatched-fires / backported-clean); `verified-only` ones
    built + Reviewer-accepted but were not behaviorally proven (codex 2026-06-15).
    Reported separately from the Reviewer-LoRA positives so a 46:4
    version-bump:source-backport split is visible, not hidden (Jason 2026-06-15:
    'don't train on a 46:4 split — source-backports first')."""
    try:
        sys.path.insert(0, str(REPO))
        from eval.backport_validation import scan_source_backports
    except ImportError:
        return {"total": 0, "validated": 0, "verified_only": 0, "validation_failures": []}
    results = scan_source_backports(REPO / "traces" / "example")
    validated = [r for r in results if r.validated]
    verified_only = [r for r in results if not r.validated]
    return {
        "total": len(results),
        "validated": len(validated),
        "verified_only": len(verified_only),
        "validated_bundles": [r.bundle for r in validated],
        "validation_failures": [
            {"bundle": r.bundle, "failed": r.failed_load_bearing()}
            for r in verified_only
        ],
    }


def build_report(pos_threshold: int, neg_threshold: int) -> dict:
    rev = _export("reviewer") or {}
    auth = _export("authoring") or {}
    dirty = _schema_invalid_bundles()
    buckets = _classify_schema_invalid(dirty)
    backports = _source_backport_report()

    labels = rev.get("labels", {})
    pos = labels.get("positive", 0)
    neg = labels.get("negative", 0)
    leakage_ok = bool(rev.get("leakage_check_ok"))

    # cert-green gate: auto-merge positives must be cert-green+signed (codex 2026-06-15).
    # The truly-clean positive count subtracts uncerted auto-merge bundles.
    uncerted = _uncerted_auto_merge_positives()
    pos_certed = max(0, pos - len(uncerted))

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

    # Authoring-only training pairs are not evidence bundles — never block on them.
    # The 6 non-git-provenance backports stay blocking (conservative: relaxing them is
    # an eval-gate loosening that needs peer sign-off, not a unilateral flip).
    schema_blockers = buckets["broken"] + buckets["non_git_provenance"]

    pos_ready = pos_certed >= pos_threshold
    neg_ready = neg >= neg_threshold
    schema_clean = not schema_blockers
    cert_clean = not uncerted
    pilot_ready = pos_ready and neg_ready and leakage_ok and schema_clean and cert_clean

    return {
        "reviewer": {
            "positive": pos, "negative": neg,
            "positive_cert_green": pos_certed,
            "positive_gap": max(0, pos_threshold - pos_certed),
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
        "schema_invalid": {
            "broken": buckets["broken"],                     # genuine evidence-bundle defect (blocks)
            "non_git_provenance": buckets["non_git_provenance"],  # known-limitation backports (blocks, surfaced)
            "authoring_only_excluded": len(buckets["authoring_only"]),  # not evidence bundles; count only
        },
        "uncerted_auto_merge": uncerted,
        "source_backports": backports,
        "thresholds": {"positive": pos_threshold, "negative": neg_threshold},
        "pilot_ready": pilot_ready,
        "blocking": [m for m, ok in (
            (f"need +{max(0, pos_threshold - pos_certed)} cert-green positives", pos_ready),
            (f"need +{max(0, neg_threshold - neg)} negatives", neg_ready),
            (f"{len(buckets['broken'])} broken + {len(buckets['non_git_provenance'])} "
             f"non-git-provenance backports (schema-invalid)", schema_clean),
            (f"{len(uncerted)} uncerted-auto-merge positives (cert-green+signed required)", cert_clean),
            ("family leakage across splits", leakage_ok),
        ) if not ok],
    }


def _emit(r: dict) -> None:
    rv = r["reviewer"]
    print("== Reviewer-LoRA corpus readiness ==")
    print(f"  positives: {rv['positive']}/{r['thresholds']['positive']}"
          f"  (cert-green {rv.get('positive_cert_green', rv['positive'])}; gap {rv['positive_gap']})")
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
    si = r.get("schema_invalid", {})
    broken = si.get("broken", [])
    non_git = si.get("non_git_provenance", [])
    auth_excl = si.get("authoring_only_excluded", 0)
    if broken or non_git:
        print(f"  SCHEMA-INVALID bundles (block readiness): "
              f"{len(broken)} broken + {len(non_git)} non-git-provenance backports")
        for d in broken + non_git:
            print(f"    - {d['bundle']}: {d['error']}")
    if auth_excl:
        print(f"  (excluded {auth_excl} authoring-only training pairs — not evidence "
              f"bundles, tracked on the authoring track)")
    unc = r.get("uncerted_auto_merge", [])
    if unc:
        print(f"  UNCERTED AUTO-MERGE positives (review-accept but not cert-green+signed; "
              f"do NOT count toward the 50): {len(unc)}")
        for u in unc:
            print(f"    - {u['bundle']}: {u['subreason']}")
    sb = r.get("source_backports", {})
    if sb.get("total"):
        print(f"  source-backports (the valuable non-version-bump data): "
              f"{sb['validated']} validated / {sb['total']} total")
        for f in sb.get("validation_failures", []):
            print(f"    - VERIFIED-ONLY {f['bundle']}: failed {', '.join(f['failed'])}")
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
