"""Tests for the five Patcher scorers + the composite runner.

End-to-end approach: copy the synthetic dispatchable fixture into
tmp_path, run the patcher executor with FakeAdapter to produce on-
disk artifacts + replay metadata, then score the resulting (bundle_dir,
invocation) pair.

Each scorer is also exercised in isolation against canned fixtures.
"""

from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator

from agents.patcher import FakeAdapter
from agents.scorers import ScorerRunReport, run_scorers
from agents.scorers.historical_fix_similarity import HistoricalFixSimilarityScorer
from agents.scorers.minimality import MinimalityScorer
from agents.scorers.runner import ScoringRefused
from agents.scorers.schema_valid import SchemaValidScorer
from agents.scorers.unrelated_file_touch_rate import UnrelatedFileTouchRateScorer
from agents.scorers.upstream_ref_compliance import UpstreamRefComplianceScorer
from tools.trace_cli.execute import execute
from tests.schema.validate import REPO_ROOT


FIXTURE_SRC = REPO_ROOT / "traces" / "example" / "CVE-0000-0010--patcher-fixture-dispatchable"
SCORER_SCHEMA_PATH = REPO_ROOT / "policy" / "eval-scorer-result-schema.json"


RATIONALE = """## Upstream reference
Fix lands in v1.4.8 per upstream commit abc1234 at https://example.invalid/libexample.

## Why this version
1.4.8 is the first patch release containing the fix; 1.4.7 does not.

## Why minimal
Only package.nix is touched: version + src.hash bump.

## Alternatives rejected
- Cherry-pick onto 1.4.7: requires maintaining a patch file; no benefit.
- Jump to 2.0.0: pulls in unrelated behaviour changes.

## Downstream risk
impact.json reports reverse_closure_count=42 (<50 bucket); no threshold trigger. Maintainers: alice, bob.
"""


def _patch_response() -> str:
    # Bumps both version and hash. Hash-verifiability requires every hash
    # attribute present in the original package.nix to be touched after a
    # version bump (silent omission is a violation), so a minimal-but-
    # complete synthetic patch must update both.
    return (
        "=== BEGIN patch.diff ===\n"
        "--- a/package.nix\n"
        "+++ b/package.nix\n"
        "@@ -5,5 +5,5 @@\n"
        '-  version = "1.4.7";\n'
        '+  version = "1.4.8";\n'
        ' \n'
        ' src = fetchurl {\n'
        '-    hash = "sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";\n'
        '+    hash = "sha256-NewlyComputedSyntheticHashForTestingPurposes=";\n'
        "=== END patch.diff ===\n"
        "=== BEGIN patch-rationale.md ===\n"
        + RATIONALE
        + "=== END patch-rationale.md ==="
    )


def _refusal_response() -> str:
    return (
        "=== BEGIN refusal ===\n"
        "rule: 3\n"
        "reason: upstream-ref.eligibility.verdict is ineligible-cherry-pick-required\n"
        "=== END refusal ==="
    )


def _factory(text: str):
    def _make(model_id: str) -> FakeAdapter:
        return FakeAdapter(model_id, text)
    return _make


def _copy_fixture(tmp_path: Path) -> Path:
    dst = tmp_path / "bundle"
    shutil.copytree(FIXTURE_SRC, dst)
    return dst


def _fresh(bundle_dir: Path, response: str) -> tuple[Path, dict]:
    """Run patcher against a tmp copy of the fixture; return (dir, invocation)."""
    execute(
        role="patcher",
        bundle_dir=bundle_dir,
        invocation={"invocation_id": None, "inputs": [], "outputs": []},
        verify=False,
        model_id="fake-opus-4-7",
        adapter_factory=_factory(response),
    )
    replay = json.loads((bundle_dir / "replay.json").read_text())
    invocation = [r for r in replay["roles"] if r["role"] == "patcher"][0]["invocations"][-1]
    return bundle_dir, invocation


# ─── happy path: run all five against a real fixture run ───────────────────


def test_run_scorers_happy_path_synthetic_fixture(tmp_path):
    bundle_dir = _copy_fixture(tmp_path)
    bundle_dir, invocation = _fresh(bundle_dir, _patch_response())

    report = run_scorers(bundle_dir=bundle_dir, invocation=invocation)
    assert isinstance(report, ScorerRunReport)
    assert report.patcher_kind == "patch"
    assert report.invocation_id == invocation["invocation_id"]

    by_name = {s.scorer_name: s for s in report.scorers}
    assert set(by_name) == {
        "schema-valid",
        "upstream-ref-compliance",
        "hash-verifiability",
        "unrelated-file-touch-rate",
        "minimality",
        "historical-fix-similarity",
    }

    # schema-valid should be 1.0 — fixture rationale has all five headings
    assert by_name["schema-valid"].score == 1.0
    # upstream-ref-compliance should hit 1.0 — rationale cites 1.4.8 and abc1234
    assert by_name["upstream-ref-compliance"].score == 1.0
    # unrelated-file-touch-rate should hit 1.0 — only package.nix touched
    assert by_name["unrelated-file-touch-rate"].score == 1.0
    # minimality should be high — 2-line patch
    assert by_name["minimality"].score == 1.0
    # historical-fix-similarity is advisory and inapplicable in v0
    hist = by_name["historical-fix-similarity"]
    assert hist.advisory is True
    assert hist.applies is False
    assert hist.score is None

    # Composite excludes advisory + inapplicable
    assert "historical-fix-similarity" not in report.scorers_in_denominator
    assert report.composite_merge_ready_rate == 1.0
    excluded_names = {x["scorer_name"] for x in report.scorers_excluded}
    assert excluded_names == {"historical-fix-similarity"}


def test_scorer_run_report_validates_against_schema(tmp_path):
    bundle_dir = _copy_fixture(tmp_path)
    bundle_dir, invocation = _fresh(bundle_dir, _patch_response())
    report = run_scorers(bundle_dir=bundle_dir, invocation=invocation)

    schema = json.loads(SCORER_SCHEMA_PATH.read_text())
    validator = Draft202012Validator(schema)
    errors = [
        f"{'/'.join(str(p) for p in e.absolute_path)}: {e.message}"
        for e in validator.iter_errors(report.to_dict())
    ]
    assert not errors, f"scoring report failed schema: {errors}"


# ─── refusal path: composite excludes scorers that don't apply ─────────────


def test_run_scorers_refusal_path(tmp_path):
    bundle_dir = _copy_fixture(tmp_path)
    bundle_dir, invocation = _fresh(bundle_dir, _refusal_response())

    report = run_scorers(bundle_dir=bundle_dir, invocation=invocation)
    assert report.patcher_kind == "refusal"

    by_name = {s.scorer_name: s for s in report.scorers}
    # schema-valid still applies and should score 1.0 against the refusal.json
    assert by_name["schema-valid"].applies is True
    assert by_name["schema-valid"].score == 1.0
    # hash-verifiability also applies on refusals (any refusal trivially
    # satisfies it; a rule-8 refusal is the contract-correct outcome).
    assert by_name["hash-verifiability"].applies is True
    assert by_name["hash-verifiability"].score == 1.0
    # The other patch-shape scorers report applies=False on refusal
    for n in ("upstream-ref-compliance", "unrelated-file-touch-rate", "minimality"):
        assert by_name[n].applies is False
    # Advisory scorer also reports applies=False on refusal
    assert by_name["historical-fix-similarity"].applies is False

    # Composite covers schema-valid + hash-verifiability on a refusal
    assert report.scorers_in_denominator == ["schema-valid", "hash-verifiability"]
    assert report.composite_merge_ready_rate == 1.0


# ─── dispatch guard: advisory-only kind is refused outright ────────────────


def test_run_scorers_refuses_advisory_only_bundle(tmp_path):
    bundle_dir = _copy_fixture(tmp_path)
    bundle = json.loads((bundle_dir / "bundle.json").read_text())
    bundle["kind"] = "advisory-only"
    bundle["kind_reason"] = "ineligible-no-fix-available"
    (bundle_dir / "bundle.json").write_text(json.dumps(bundle))

    invocation = {"invocation_id": "00000000-0000-4000-8000-000000000999",
                  "outputs": [{"path": "patch.diff", "sha256": "0" * 64}]}
    with pytest.raises(ScoringRefused, match="advisory-only"):
        run_scorers(bundle_dir=bundle_dir, invocation=invocation)


def test_run_scorers_refuses_ineligible_verdict(tmp_path):
    bundle_dir = _copy_fixture(tmp_path)
    upstream_ref = json.loads((bundle_dir / "upstream-ref.json").read_text())
    upstream_ref["eligibility"] = {
        "verdict": "ineligible-cherry-pick-required",
        "verdict_reason": "test fixture",
    }
    (bundle_dir / "upstream-ref.json").write_text(json.dumps(upstream_ref))

    invocation = {"invocation_id": "00000000-0000-4000-8000-000000000999",
                  "outputs": [{"path": "patch.diff", "sha256": "0" * 64}]}
    with pytest.raises(ScoringRefused, match="ineligible-"):
        run_scorers(bundle_dir=bundle_dir, invocation=invocation)


# ─── per-scorer isolation ──────────────────────────────────────────────────


def _patch_invocation_with(outputs: list[str]) -> dict:
    return {
        "invocation_id": "00000000-0000-4000-8000-000000000010",
        "outputs": [{"path": p, "sha256": "0" * 64} for p in outputs],
    }


def test_schema_valid_scorer_rejects_missing_rationale_heading(tmp_path):
    bundle_dir = _copy_fixture(tmp_path)
    (bundle_dir / "patch.diff").write_text(
        "--- a/package.nix\n+++ b/package.nix\n@@ -1 +1 @@\n-x\n+y\n"
    )
    rationale_missing_heading = RATIONALE.replace("## Why minimal\n", "")
    (bundle_dir / "patch-rationale.md").write_text(rationale_missing_heading)

    s = SchemaValidScorer()
    r = s.score(
        bundle_dir=bundle_dir,
        invocation=_patch_invocation_with(["patch.diff", "patch-rationale.md"]),
    )
    assert r.applies is True and r.advisory is False
    assert r.score == 0.0
    assert "missing required headings" in r.notes


def test_upstream_ref_compliance_partial_credit(tmp_path):
    bundle_dir = _copy_fixture(tmp_path)
    (bundle_dir / "patch.diff").write_text(
        "--- a/package.nix\n+++ b/package.nix\n@@ -1 +1 @@\n-x\n+y\n"
    )
    rationale_missing_sha = RATIONALE.replace("abc1234", "no-sha-cited")
    (bundle_dir / "patch-rationale.md").write_text(rationale_missing_sha)

    s = UpstreamRefComplianceScorer()
    r = s.score(
        bundle_dir=bundle_dir,
        invocation=_patch_invocation_with(["patch.diff", "patch-rationale.md"]),
    )
    assert r.applies is True
    # target_version (1.4.8) and tag (v1.4.8) should still be present;
    # commit_sha abc1234 was scrubbed -> 2 of 3 expected tokens.
    assert r.score is not None
    assert 0 < r.score < 1
    assert r.details["expected_count"] == 3
    assert r.details["present_anywhere_count"] == 2


def test_unrelated_file_touch_rate_flags_off_attr_files(tmp_path):
    bundle_dir = _copy_fixture(tmp_path)
    bad_diff = (
        "--- a/package.nix\n+++ b/package.nix\n@@ -1 +1 @@\n-x\n+y\n"
        "--- a/some/other/file.nix\n+++ b/some/other/file.nix\n@@ -1 +1 @@\n-q\n+r\n"
    )
    (bundle_dir / "patch.diff").write_text(bad_diff)
    (bundle_dir / "patch-rationale.md").write_text(RATIONALE)

    s = UnrelatedFileTouchRateScorer()
    r = s.score(
        bundle_dir=bundle_dir,
        invocation=_patch_invocation_with(["patch.diff", "patch-rationale.md"]),
    )
    assert r.applies is True
    # 1 of 2 touched files is unrelated -> score 0.5
    assert r.score == 0.5
    assert "some/other/file.nix" in r.details["unrelated"]


def test_minimality_decays_with_changed_lines(tmp_path):
    bundle_dir = _copy_fixture(tmp_path)
    big_diff_lines = ["--- a/package.nix", "+++ b/package.nix", "@@ -1,80 +1,80 @@"]
    big_diff_lines += [f"-line{i}" for i in range(80)]
    big_diff_lines += [f"+line{i}-new" for i in range(80)]
    (bundle_dir / "patch.diff").write_text("\n".join(big_diff_lines) + "\n")
    (bundle_dir / "patch-rationale.md").write_text(RATIONALE)

    s = MinimalityScorer()
    r = s.score(
        bundle_dir=bundle_dir,
        invocation=_patch_invocation_with(["patch.diff", "patch-rationale.md"]),
    )
    assert r.applies is True
    # 160 changed lines -> score is well under 1.0
    assert r.score < 0.5
    assert r.details["changed_lines"] == 160
    assert r.details["self_measure_only"] is True


def test_historical_fix_similarity_is_advisory(tmp_path):
    bundle_dir = _copy_fixture(tmp_path)
    (bundle_dir / "patch.diff").write_text(
        "--- a/package.nix\n+++ b/package.nix\n@@ -1 +1 @@\n-x\n+y\n"
    )
    s = HistoricalFixSimilarityScorer()
    assert s.advisory is True
    r = s.score(
        bundle_dir=bundle_dir,
        invocation=_patch_invocation_with(["patch.diff", "patch-rationale.md"]),
    )
    # No historical-fix.diff in the fixture -> not reachable in v0.
    assert r.advisory is True
    assert r.applies is False
    assert r.score is None


def test_historical_fix_similarity_uses_cached_diff_when_present(tmp_path):
    bundle_dir = _copy_fixture(tmp_path)
    patch_diff = "--- a/package.nix\n+++ b/package.nix\n@@ -1 +1 @@\n-version 1.4.7\n+version 1.4.8\n"
    (bundle_dir / "patch.diff").write_text(patch_diff)
    # Identical historical diff -> ratio == 1.0
    (bundle_dir / "historical-fix.diff").write_text(patch_diff)
    s = HistoricalFixSimilarityScorer()
    r = s.score(
        bundle_dir=bundle_dir,
        invocation=_patch_invocation_with(["patch.diff", "patch-rationale.md"]),
    )
    assert r.advisory is True
    assert r.applies is True
    assert r.score == 1.0


# ─── meta: scorer set is the locked six, in canonical order ────────────────


def test_canonical_scorer_names_are_the_locked_six():
    from agents.scorers import canonical_scorer_names
    assert canonical_scorer_names() == (
        "schema-valid",
        "upstream-ref-compliance",
        "hash-verifiability",
        "unrelated-file-touch-rate",
        "minimality",
        "historical-fix-similarity",
    )
