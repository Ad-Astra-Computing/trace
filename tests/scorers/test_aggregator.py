"""Tests for the cohort aggregator + `trace eval patch-rate` CLI.

Anchors on the actual scoring-report.json files committed by today's
live runs (mbedtls run 2, bind run 2, traefik run 4) so the aggregator's
behaviour is validated against real artifacts, not synthetic shapes.

The cohort-1 tally below should match the patch_rate snapshot recorded
in DECISIONS.md: 3 dispatchable bundles, 3 patches at composite >= 0.95,
patch_rate = 1.000.
"""

from __future__ import annotations

import json
from pathlib import Path

from agents.scorers import (
    KNOWN_COHORT_LABELS,
    PATCH_RATE_COMPOSITE_THRESHOLD,
    aggregate_reports,
    expand_glob,
)
from tests.schema.validate import REPO_ROOT


# ─── anchor cases on real cohort-1 reports ─────────────────────────────────


def _scoring_report(name: str) -> Path:
    return REPO_ROOT / "traces" / "example" / name / "scoring-report.json"


def test_cohort_1_three_dispatchable_patch_rate_is_1_000() -> None:
    """The three cohort-1 dispatchable bundles all produced patches with
    composite >= 0.95 under the full prefetch pipeline. Aggregator must
    report patch_rate = 1.000."""
    reports = [
        _scoring_report("CVE-2024-49195--mbedtls"),
        _scoring_report("CVE-2025-13878--bind"),
        _scoring_report("CVE-2026-25949--traefik"),
    ]
    result = aggregate_reports(report_paths=reports, cohort="inner-loop")
    assert result.totals["dispatchable"] == 3
    assert result.totals["patches"] == 3
    assert result.totals["refusals"] == 0
    assert result.totals["patches_at_threshold"] == 3
    assert result.patch_rate == 1.0
    assert result.merge_ready_rate_mean == 1.0


def test_cohort_label_recognised_when_in_known_set() -> None:
    """Sanity: the four documented labels are the recommended baselines."""
    assert "synthetic" in KNOWN_COHORT_LABELS
    assert "real-single" in KNOWN_COHORT_LABELS
    assert "inner-loop" in KNOWN_COHORT_LABELS
    assert "full-corpus" in KNOWN_COHORT_LABELS


def test_provenance_links_back_to_each_input_report() -> None:
    reports = [
        _scoring_report("CVE-2024-49195--mbedtls"),
        _scoring_report("CVE-2025-13878--bind"),
    ]
    result = aggregate_reports(report_paths=reports, cohort="real-single")
    assert len(result.provenance) == 2
    files = {p.file for p in result.provenance}
    assert all(str(r) in files for r in reports)
    # Each entry carries cve / invocation provenance.
    for entry in result.provenance:
        assert entry.bundle_id is not None or entry.invocation_id is not None
        assert entry.composite_merge_ready_rate is not None


def test_provenance_carries_prompt_sha_and_model_id_when_present() -> None:
    """Hand-written reports use rescored_under_prompt_sha; canonical
    reports use prompt_sha. The aggregator falls back gracefully."""
    reports = [_scoring_report("CVE-2026-25949--traefik")]
    result = aggregate_reports(report_paths=reports, cohort="real-single")
    assert len(result.provenance) == 1
    p = result.provenance[0]
    # Traefik scoring-report.json is hand-written; prompt sha is recorded
    # under rescored_under_prompt_sha.
    assert p.prompt_sha is not None
    assert p.model_id == "claude-opus-4-7"


# ─── synthetic / refusal coverage ──────────────────────────────────────────


def _write_synthetic_report(
    tmp_path: Path,
    *,
    name: str,
    composite: float,
    patcher_kind: str = "patch",
    bundle_id: str = "0000000000000001",
) -> Path:
    p = tmp_path / f"{name}.json"
    p.write_text(json.dumps({
        "schema_version": "1.0.0",
        "bundle_dir": str(tmp_path / "bundle"),
        "bundle_id": bundle_id,
        "cve_id": "CVE-0000-0001",
        "invocation_id": "11111111-1111-4111-8111-111111111111",
        "patcher_invocation_id": "11111111-1111-4111-8111-111111111111",
        "patcher_kind": patcher_kind,
        "model_id": "fake-test-model",
        "prompt_sha": "f" * 64,
        "scored_at": "2026-04-27T19:00:00Z",
        "composite_merge_ready_rate": composite,
        "scorer_results": [
            {
                "scorer_name": "schema-valid",
                "scorer_version": "1.0.0",
                "applies": True,
                "advisory": False,
                "score": 1.0,
                "notes": "synthetic",
            },
        ],
    }))
    return p


def test_refusal_only_cohort_yields_patch_rate_zero(tmp_path: Path) -> None:
    """A cohort of N refusals (no patches) has patch_rate = 0.000 even
    when every refusal scored 1.0 composite. patch_rate measures
    productivity, not contract honour."""
    reports = [
        _write_synthetic_report(tmp_path, name="r1", composite=1.0,
                                patcher_kind="refusal", bundle_id="aaaaaaaaaaaaaaaa"),
        _write_synthetic_report(tmp_path, name="r2", composite=1.0,
                                patcher_kind="refusal", bundle_id="bbbbbbbbbbbbbbbb"),
    ]
    result = aggregate_reports(report_paths=reports, cohort="synthetic")
    assert result.totals["dispatchable"] == 2
    assert result.totals["patches"] == 0
    assert result.totals["refusals"] == 2
    assert result.totals["patches_at_threshold"] == 0
    assert result.patch_rate == 0.0
    # Merge-ready rate is the contract-honour metric and stays at 1.0.
    assert result.merge_ready_rate_mean == 1.0


def test_below_threshold_patch_does_not_count(tmp_path: Path) -> None:
    """A patch with composite 0.8 (e.g. traefik run 1's lib.fakeHash)
    does NOT count toward patch_rate. The 0.95 threshold is the SPEC §5
    ship-gate."""
    reports = [
        _write_synthetic_report(tmp_path, name="p1", composite=0.8,
                                bundle_id="cccccccccccccccc"),
        _write_synthetic_report(tmp_path, name="p2", composite=1.0,
                                bundle_id="dddddddddddddddd"),
    ]
    result = aggregate_reports(report_paths=reports, cohort="synthetic")
    assert result.totals["patches"] == 2
    assert result.totals["patches_at_threshold"] == 1
    assert result.patch_rate == 0.5
    assert PATCH_RATE_COMPOSITE_THRESHOLD == 0.95


def test_unparseable_report_is_counted_in_parse_errors(tmp_path: Path) -> None:
    bad = tmp_path / "broken.json"
    bad.write_text("not json{{{")
    good = _write_synthetic_report(tmp_path, name="ok", composite=1.0)
    result = aggregate_reports(report_paths=[bad, good], cohort="synthetic")
    assert result.totals["parse_errors"] == 1
    assert result.totals["scoring_reports"] == 2


def test_scorer_means_aggregate_only_applies_true_entries(tmp_path: Path) -> None:
    p = tmp_path / "sample.json"
    p.write_text(json.dumps({
        "patcher_kind": "patch",
        "composite_merge_ready_rate": 0.8,
        "scorer_results": [
            {"scorer_name": "schema-valid", "applies": True, "advisory": False, "score": 1.0, "notes": ""},
            {"scorer_name": "minimality", "applies": True, "advisory": False, "score": 0.6, "notes": ""},
            {"scorer_name": "historical-fix-similarity", "applies": False, "advisory": True, "score": None, "notes": ""},
            {"scorer_name": "hash-verifiability", "applies": True, "advisory": False, "score": 0.7, "notes": ""},
        ],
    }))
    result = aggregate_reports(report_paths=[p], cohort="synthetic")
    assert result.scorer_means["schema-valid"] == 1.0
    assert result.scorer_means["minimality"] == 0.6
    assert result.scorer_means["hash-verifiability"] == 0.7
    # historical-fix-similarity has applies=False and was filtered out.
    assert "historical-fix-similarity" not in result.scorer_means


def test_expand_glob_returns_sorted_files(tmp_path: Path) -> None:
    (tmp_path / "a").mkdir()
    (tmp_path / "b").mkdir()
    (tmp_path / "a" / "scoring-report.json").write_text("{}")
    (tmp_path / "b" / "scoring-report.json").write_text("{}")
    paths = expand_glob(str(tmp_path / "*" / "scoring-report.json"))
    assert len(paths) == 2
    assert all(p.is_file() for p in paths)
    # Sorted: 'a' before 'b'.
    assert "/a/" in str(paths[0])


# ─── CLI dispatch ──────────────────────────────────────────────────────────


def test_cli_eval_patch_rate_runs_against_cohort_1(capsys) -> None:
    from tools.trace_cli.cli import main as cli_main

    rc = cli_main([
        "eval", "patch-rate",
        "--cohort", "inner-loop",
        "--reports", str(REPO_ROOT / "traces" / "example" / "*" / "scoring-report.json"),
        "--format", "json",
    ])
    assert rc == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["cohort"] == "inner-loop"
    # Cohort-1 has 3 live patches; archives + first-run-archive may add
    # more reports under the glob (mbedtls/_first-run-archive holds the
    # rule-8 refusal). Aggregator must handle the mix correctly.
    assert payload["totals"]["dispatchable"] >= 3
    assert payload["totals"]["patches"] >= 3


def test_cli_eval_patch_rate_empty_glob_returns_invalid(capsys) -> None:
    from tools.trace_cli.cli import main as cli_main
    rc = cli_main([
        "eval", "patch-rate",
        "--cohort", "synthetic",
        "--reports", "/nonexistent/path/that/does/not/exist/*.json",
    ])
    assert rc != 0
    err = capsys.readouterr().err
    assert "no scoring-report.json files matched" in err


def test_cli_human_summary_marks_unknown_cohort_label(tmp_path: Path, capsys) -> None:
    from tools.trace_cli.cli import main as cli_main
    p = _write_synthetic_report(tmp_path, name="x", composite=1.0)
    rc = cli_main([
        "eval", "patch-rate",
        "--cohort", "experimental-cohort-2026q2",
        "--reports", str(p),
    ])
    assert rc == 0
    out = capsys.readouterr().out
    assert "free-form label" in out
