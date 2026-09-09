"""Tests for the reviewer cohort aggregator + `trace eval review-rate` CLI.

Anchors on the two real review-scoring-report.json files written by
the live reviewer runs (traefik run-4 accept + archived run-1 reject)
plus synthetic single-report cases for each derived rate.
"""

from __future__ import annotations

import json
from pathlib import Path

from agents.scorers.reviewer_aggregator import (
    KNOWN_REVIEWER_COHORT_LABELS,
    aggregate_reviewer_reports,
    expand_review_glob,
)
from tests.schema.validate import REPO_ROOT


# ─── anchor cases on real reviewer reports ─────────────────────────────────


def _live_report(name: str) -> Path:
    return REPO_ROOT / "traces" / "example" / name / "review-scoring-report.json"


def _archived_report(name: str) -> Path:
    return (
        REPO_ROOT
        / "traces"
        / "example"
        / name
        / "_first-run-archive"
        / "review-scoring-report.json"
    )


def test_two_live_runs_aggregate_to_expected_rates() -> None:
    """The committed two reviewer scoring reports should aggregate to:
    accept=1, reject=1; attestation_correct_rate=0.0;
    evidence_cited_mean=1.0; disagreement_rate=0.5 (1 of 2 runs
    contradicted Steward)."""
    reports = [
        _live_report("CVE-2026-25949--traefik"),
        _archived_report("CVE-2026-25949--traefik"),
    ]
    result = aggregate_reviewer_reports(report_paths=reports, cohort="real-single")
    assert result.totals["scoring_reports"] == 2
    assert result.totals["verdicts"] == 2
    assert result.totals["accept"] == 1
    assert result.totals["reject"] == 1
    assert result.totals["escalate"] == 0
    assert result.accept_rate == 0.5
    assert result.reject_rate == 0.5
    assert result.escalate_rate == 0.0
    assert result.evidence_cited_mean == 1.0
    assert result.attestation_correct_rate == 0.0  # both runs fabricated
    # disagreement: run-1 aligned with Steward (1.0), run-2 contradicted (0.0)
    # Aligned-fraction = 0.5 → disagreement-rate = 0.5
    assert result.reviewer_steward_disagreement_rate == 0.5


def test_provenance_links_back_to_each_report() -> None:
    reports = [
        _live_report("CVE-2026-25949--traefik"),
        _archived_report("CVE-2026-25949--traefik"),
    ]
    result = aggregate_reviewer_reports(report_paths=reports, cohort="real-single")
    assert len(result.provenance) == 2
    files = {p.file for p in result.provenance}
    assert all(str(r) in files for r in reports)
    verdicts = {p.verdict for p in result.provenance}
    assert verdicts == {"accept", "reject"}
    # Both runs were claude-sonnet-4-6 in our live experiments.
    models = {p.model_id for p in result.provenance}
    assert "claude-sonnet-4-6" in models


# ─── synthetic single-report cases ─────────────────────────────────────────


def _synthetic_report(
    tmp_path: Path,
    *,
    name: str,
    verdict: str,
    evidence_score: float = 1.0,
    attestation_score: float = 1.0,
    disagreement_score: float = 1.0,
) -> Path:
    """Write a minimal review-scoring-report.json with the four-scorer
    canonical shape."""
    p = tmp_path / f"{name}.json"
    p.write_text(
        json.dumps(
            {
                "schema_version": "1.0.0",
                "scope": "reviewer",
                "bundle_dir": str(tmp_path),
                "invocation_id": f"{name:0>8}-0000-4000-8000-000000000000"[-36:],
                "model_id": "claude-sonnet-4-6",
                "prompt_sha": "f" * 64,
                "scored_at": "2026-04-27T00:00:00Z",
                "scorers": [
                    {
                        "scorer_name": "review-schema-valid",
                        "scorer_version": "1.0.0",
                        "applies": True,
                        "advisory": False,
                        "score": 1.0,
                        "notes": "",
                        "details": {"verdict": verdict},
                    },
                    {
                        "scorer_name": "review-evidence-cited",
                        "scorer_version": "1.0.0",
                        "applies": True,
                        "advisory": False,
                        "score": evidence_score,
                        "notes": "",
                    },
                    {
                        "scorer_name": "review-cross-family-attestation",
                        "scorer_version": "1.0.0",
                        "applies": True,
                        "advisory": False,
                        "score": attestation_score,
                        "notes": "",
                    },
                    {
                        "scorer_name": "review-disagreement",
                        "scorer_version": "1.0.0",
                        "applies": True,
                        "advisory": True,
                        "score": disagreement_score,
                        "notes": "",
                    },
                ],
            }
        )
    )
    return p


def test_all_accepts_yields_accept_rate_one(tmp_path: Path) -> None:
    reports = [
        _synthetic_report(tmp_path, name="r1", verdict="accept"),
        _synthetic_report(tmp_path, name="r2", verdict="accept"),
        _synthetic_report(tmp_path, name="r3", verdict="accept"),
    ]
    result = aggregate_reviewer_reports(report_paths=reports, cohort="synthetic")
    assert result.accept_rate == 1.0
    assert result.reject_rate == 0.0
    assert result.escalate_rate == 0.0


def test_attestation_correct_rate_partial(tmp_path: Path) -> None:
    """Two correct attestations + one fabricated → 2/3."""
    reports = [
        _synthetic_report(tmp_path, name="r1", verdict="accept", attestation_score=1.0),
        _synthetic_report(tmp_path, name="r2", verdict="accept", attestation_score=1.0),
        _synthetic_report(tmp_path, name="r3", verdict="accept", attestation_score=0.0),
    ]
    result = aggregate_reviewer_reports(report_paths=reports, cohort="synthetic")
    assert abs(result.attestation_correct_rate - 2 / 3) < 1e-9


def test_disagreement_rate_counts_non_aligned(tmp_path: Path) -> None:
    """Three runs, two aligned with Steward (1.0) and one not (0.5).
    aligned-fraction = 2/3, so disagreement_rate = 1/3."""
    reports = [
        _synthetic_report(
            tmp_path, name="r1", verdict="accept", disagreement_score=1.0
        ),
        _synthetic_report(
            tmp_path, name="r2", verdict="accept", disagreement_score=1.0
        ),
        _synthetic_report(
            tmp_path, name="r3", verdict="escalate", disagreement_score=0.5
        ),
    ]
    result = aggregate_reviewer_reports(report_paths=reports, cohort="synthetic")
    assert abs(result.reviewer_steward_disagreement_rate - 1 / 3) < 1e-9


def _synthetic_report_with_adaptation_equivalence(
    tmp_path: Path,
    *,
    name: str,
    verdict: str,
    adaptation_equivalence_score: float,
) -> Path:
    """Like `_synthetic_report` but also carries a
    `review-adaptation-equivalence` scorer entry, for testing
    `adaptation_equivalence_correct_rate`."""
    p = tmp_path / f"{name}.json"
    p.write_text(
        json.dumps(
            {
                "schema_version": "1.0.0",
                "scope": "reviewer",
                "bundle_dir": str(tmp_path),
                "invocation_id": f"{name:0>8}-0000-4000-8000-000000000000"[-36:],
                "model_id": "claude-sonnet-4-6",
                "prompt_sha": "f" * 64,
                "scored_at": "2026-07-27T00:00:00Z",
                "scorers": [
                    {
                        "scorer_name": "review-schema-valid",
                        "scorer_version": "1.0.0",
                        "applies": True,
                        "advisory": False,
                        "score": 1.0,
                        "notes": "",
                        "details": {"verdict": verdict},
                    },
                    {
                        "scorer_name": "review-evidence-cited",
                        "scorer_version": "1.0.0",
                        "applies": True,
                        "advisory": False,
                        "score": 1.0,
                        "notes": "",
                    },
                    {
                        "scorer_name": "review-cross-family-attestation",
                        "scorer_version": "1.0.0",
                        "applies": True,
                        "advisory": False,
                        "score": 1.0,
                        "notes": "",
                    },
                    {
                        "scorer_name": "review-disagreement",
                        "scorer_version": "1.0.0",
                        "applies": True,
                        "advisory": True,
                        "score": 1.0,
                        "notes": "",
                    },
                    {
                        "scorer_name": "review-adaptation-equivalence",
                        "scorer_version": "1.0.0",
                        "applies": True,
                        "advisory": False,
                        "score": adaptation_equivalence_score,
                        "notes": "",
                    },
                ],
            }
        )
    )
    return p


def test_adaptation_equivalence_correct_rate_partial(tmp_path: Path) -> None:
    """Two matches + one miss → 2/3."""
    reports = [
        _synthetic_report_with_adaptation_equivalence(
            tmp_path, name="a1", verdict="accept", adaptation_equivalence_score=1.0
        ),
        _synthetic_report_with_adaptation_equivalence(
            tmp_path, name="a2", verdict="accept", adaptation_equivalence_score=1.0
        ),
        _synthetic_report_with_adaptation_equivalence(
            tmp_path, name="a3", verdict="reject", adaptation_equivalence_score=0.0
        ),
    ]
    result = aggregate_reviewer_reports(report_paths=reports, cohort="synthetic")
    assert abs(result.adaptation_equivalence_correct_rate - 2 / 3) < 1e-9


def test_adaptation_equivalence_correct_rate_none_when_not_applicable(
    tmp_path: Path,
) -> None:
    """Reports with no `review-adaptation-equivalence` entry (the common
    case — most bundles are not in the adaptation lane) leave the rate
    as None rather than 0.0."""
    reports = [
        _synthetic_report(tmp_path, name="r1", verdict="accept"),
        _synthetic_report(tmp_path, name="r2", verdict="accept"),
    ]
    result = aggregate_reviewer_reports(report_paths=reports, cohort="synthetic")
    assert result.adaptation_equivalence_correct_rate is None


def test_adaptation_equivalence_ignores_non_applying_entries(tmp_path: Path) -> None:
    """A `review-adaptation-equivalence` entry with applies=False (e.g. the
    verbatim lane, or an unregistered CVE) contributes nothing to the rate."""
    p = tmp_path / "not-applicable.json"
    p.write_text(
        json.dumps(
            {
                "schema_version": "1.0.0",
                "scope": "reviewer",
                "bundle_dir": str(tmp_path),
                "invocation_id": "00000000-0000-4000-8000-000000000000",
                "model_id": "claude-sonnet-4-6",
                "prompt_sha": "f" * 64,
                "scored_at": "2026-07-27T00:00:00Z",
                "scorers": [
                    {
                        "scorer_name": "review-schema-valid",
                        "scorer_version": "1.0.0",
                        "applies": True,
                        "advisory": False,
                        "score": 1.0,
                        "notes": "",
                        "details": {"verdict": "accept"},
                    },
                    {
                        "scorer_name": "review-adaptation-equivalence",
                        "scorer_version": "1.0.0",
                        "applies": False,
                        "advisory": False,
                        "score": None,
                        "notes": "not adaptation lane",
                    },
                ],
            }
        )
    )
    result = aggregate_reviewer_reports(report_paths=[p], cohort="synthetic")
    assert result.adaptation_equivalence_correct_rate is None


def test_evidence_cited_mean_partial(tmp_path: Path) -> None:
    reports = [
        _synthetic_report(tmp_path, name="r1", verdict="accept", evidence_score=1.0),
        _synthetic_report(tmp_path, name="r2", verdict="accept", evidence_score=0.5),
    ]
    result = aggregate_reviewer_reports(report_paths=reports, cohort="synthetic")
    assert result.evidence_cited_mean == 0.75


def test_unparseable_report_counted(tmp_path: Path) -> None:
    bad = tmp_path / "broken.json"
    bad.write_text("not json{{")
    good = _synthetic_report(tmp_path, name="ok", verdict="accept")
    result = aggregate_reviewer_reports(report_paths=[bad, good], cohort="synthetic")
    assert result.totals["parse_errors"] == 1
    assert result.totals["scoring_reports"] == 2


def test_known_cohort_labels_are_locked() -> None:
    assert "synthetic" in KNOWN_REVIEWER_COHORT_LABELS
    assert "real-single" in KNOWN_REVIEWER_COHORT_LABELS
    assert "inner-loop" in KNOWN_REVIEWER_COHORT_LABELS
    assert "full-corpus" in KNOWN_REVIEWER_COHORT_LABELS
    assert "real-ci-smoke" in KNOWN_REVIEWER_COHORT_LABELS


# ─── CLI dispatch ──────────────────────────────────────────────────────────


def test_cli_review_rate_runs_against_live_reports(capsys) -> None:
    """Aggregates over every committed live `review-scoring-report.json`
    under `traces/example/**`. As the live-run set grows, the assertions
    track the global state rather than pinning a fixed report count.
    Invariants that should hold for the lifetime of the trace project:
      * `attestation_correct_rate < 1.0` — at least one committed review
        under claude-sonnet-4-6 fabricates `patcher_family_observed`
        (third live observation locked in 2026-04-28; the synthetic
        Steward v1 happy-path fixture has a correct attestation, so the
        cohort rate is non-zero with synthetic fixtures included).
      * `accept_rate + reject_rate + escalate_rate == 1.0` — totals
        consistency.
      * `evidence_cited_mean == 1.0` — every committed review (live and
        synthetic) cited only canonical bundle artifacts.
    """
    from tools.trace_cli.cli import main as cli_main

    rc = cli_main(
        [
            "eval",
            "review-rate",
            "--cohort",
            "real-single",
            "--reports",
            str(REPO_ROOT / "traces" / "example" / "**" / "review-scoring-report.json"),
            "--format",
            "json",
        ]
    )
    assert rc == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["cohort"] == "real-single"
    assert payload["totals"]["verdicts"] >= 2
    rates = (
        payload["accept_rate"] or 0.0,
        payload["reject_rate"] or 0.0,
        payload["escalate_rate"] or 0.0,
    )
    assert abs(sum(rates) - 1.0) < 1e-9, rates
    # Live runs all fabricate; synthetic fixtures may have correct
    # attestation. The invariant: at least one fabrication is recorded
    # in the cohort, so the rate stays strictly below 1.0.
    assert payload["attestation_correct_rate"] < 1.0
    # Every committed live review cites only recognized bundle artifacts,
    # including adaptation-lane reviews whose `source-context/*` and `<cve>.patch`
    # citations the evidence-cited scorer now recognizes (see DECISIONS 2026-07-27).
    assert payload["evidence_cited_mean"] == 1.0


def test_cli_review_rate_empty_glob_returns_invalid(capsys) -> None:
    from tools.trace_cli.cli import main as cli_main

    rc = cli_main(
        [
            "eval",
            "review-rate",
            "--cohort",
            "synthetic",
            "--reports",
            "/nonexistent/path/*.json",
        ]
    )
    assert rc != 0
    err = capsys.readouterr().err
    assert "no review-scoring-report.json files matched" in err


def test_cli_review_rate_unknown_cohort_label_marked(tmp_path: Path, capsys) -> None:
    from tools.trace_cli.cli import main as cli_main

    p = _synthetic_report(tmp_path, name="r1", verdict="accept")
    rc = cli_main(
        [
            "eval",
            "review-rate",
            "--cohort",
            "experimental-cohort",
            "--reports",
            str(p),
        ]
    )
    assert rc == 0
    out = capsys.readouterr().out
    assert "free-form label" in out
