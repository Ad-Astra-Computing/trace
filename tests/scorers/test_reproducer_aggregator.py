"""Tests for the reproducer cohort aggregator + `trace eval repro-rate` CLI.

The locked v0 cohort fields per `docs/REPRODUCER_V1.md` §9.

The aggregator reads scoring reports of the canonical shape (an entry
per scorer with `applies` / `score` / optional `details`). It tolerates
the future runner-aggregated shape AND the inline test-author shape
used here.
"""

from __future__ import annotations

import json
from pathlib import Path

from agents.scorers.reproducer_aggregator import (
    KNOWN_REPRODUCER_COHORT_LABELS,
    aggregate_reproducer_reports,
    expand_reproducer_glob,
)


# ─── synthetic report builders ────────────────────────────────────────────


def _scorer(
    name: str,
    *,
    applies: bool = True,
    advisory: bool = False,
    score: float | None = 1.0,
    details: dict | None = None,
    notes: str = "",
) -> dict:
    e = {
        "scorer_name": name,
        "scorer_version": "1.0.0",
        "applies": applies,
        "advisory": advisory,
        "score": score,
        "notes": notes,
    }
    if details is not None:
        e["details"] = details
    return e


def _write_full_report(
    tmp_path: Path,
    *,
    name: str,
    schema_score: float = 1.0,
    is_proxy: bool = False,
    proxy_reason: str | None = None,
    unpatched_applies: bool = True,
    unpatched_score: float = 1.0,
    patched_applies: bool = True,
    patched_score: float = 1.0,
    passthru_score: float | None = 1.0,
    specificity_score: float | None = 1.0,
    model_id: str = "claude-sonnet-4-6",
    bundle_id: str | None = None,
) -> Path:
    """Write a v1-shape repro-scoring-report.json for one bundle.

    For a full reproducer: schema-valid + unpatched + patched + passthru
    + specificity scorer entries. For a proxy: unpatched applies=False,
    schema-valid carries `is_proxy=True` + `proxy_reason`.
    """
    sv_details: dict = {"is_proxy": is_proxy}
    if is_proxy and proxy_reason:
        sv_details["proxy_reason"] = proxy_reason

    scorers = [
        _scorer("repro-schema-valid", score=schema_score, details=sv_details),
    ]
    if is_proxy:
        scorers.append(
            _scorer(
                "repro-unpatched-fails",
                applies=False,
                score=None,
                notes="proxy reproducer; unpatched-path evidence out of scope",
            )
        )
    else:
        scorers.append(
            _scorer(
                "repro-unpatched-fails",
                applies=unpatched_applies,
                score=unpatched_score if unpatched_applies else None,
            )
        )
    scorers.append(
        _scorer(
            "repro-patched-passes",
            applies=patched_applies,
            score=patched_score if patched_applies else None,
            details={"is_proxy": is_proxy},
        )
    )
    if passthru_score is None:
        scorers.append(_scorer("repro-passthru-recorded", applies=False, score=None))
    else:
        scorers.append(_scorer("repro-passthru-recorded", score=passthru_score))
    if specificity_score is None:
        scorers.append(
            _scorer(
                "repro-signal-specificity", advisory=True, applies=False, score=None
            )
        )
    else:
        scorers.append(
            _scorer("repro-signal-specificity", advisory=True, score=specificity_score)
        )

    p = tmp_path / f"{name}.json"
    p.write_text(
        json.dumps(
            {
                "schema_version": "1.0.0",
                "scope": "reproducer",
                "bundle_id": bundle_id or f"00000000{name:0>8s}",
                "kind": "reproducer",
                "model_id": model_id,
                "prompt_sha": "f" * 64,
                "scored_at": "2026-04-28T03:00:00Z",
                "scorers": scorers,
            }
        )
    )
    return p


def _write_refusal_report(
    tmp_path: Path,
    *,
    name: str,
    rule: int = 3,
    model_id: str = "claude-sonnet-4-6",
) -> Path:
    p = tmp_path / f"{name}.json"
    p.write_text(
        json.dumps(
            {
                "schema_version": "1.0.0",
                "scope": "reproducer",
                "bundle_id": f"00000000{name:0>8s}",
                "kind": "refusal",
                "refusal_rule": rule,
                "model_id": model_id,
                "prompt_sha": "f" * 64,
                "scored_at": "2026-04-28T03:00:00Z",
                "scorers": [
                    _scorer(
                        "repro-schema-valid", score=1.0, details={"refusal_rule": rule}
                    ),
                ],
            }
        )
    )
    return p


# ─── known-labels ─────────────────────────────────────────────────────────


def test_known_cohort_labels_locked() -> None:
    for label in (
        "synthetic",
        "real-single",
        "inner-loop",
        "full-corpus",
        "real-ci-smoke",
    ):
        assert label in KNOWN_REPRODUCER_COHORT_LABELS


# ─── per-field cases ──────────────────────────────────────────────────────


def test_well_formed_rate_full(tmp_path: Path) -> None:
    reports = [
        _write_full_report(tmp_path, name=f"r{i}", schema_score=1.0) for i in range(3)
    ]
    res = aggregate_reproducer_reports(report_paths=reports, cohort="synthetic")
    assert res.reproducer_well_formed_rate == 1.0
    assert res.totals["scoring_reports"] == 3
    assert res.totals["refusals"] == 0
    assert res.totals["proxy"] == 0


def test_well_formed_rate_partial(tmp_path: Path) -> None:
    reports = [
        _write_full_report(tmp_path, name="r1", schema_score=1.0),
        _write_full_report(tmp_path, name="r2", schema_score=0.0),
    ]
    res = aggregate_reproducer_reports(report_paths=reports, cohort="synthetic")
    assert res.reproducer_well_formed_rate == 0.5


def test_vuln_signal_recovered_rate_strict_AND(tmp_path: Path) -> None:
    """Both unpatched-fails AND patched-passes must be 1.0 for the bundle
    to count as recovered. One 1.0 + one 0.0 → not recovered."""
    reports = [
        _write_full_report(
            tmp_path, name="full", unpatched_score=1.0, patched_score=1.0
        ),
        _write_full_report(
            tmp_path, name="partial", unpatched_score=1.0, patched_score=0.0
        ),
        _write_full_report(
            tmp_path, name="other-partial", unpatched_score=0.0, patched_score=1.0
        ),
    ]
    res = aggregate_reproducer_reports(report_paths=reports, cohort="synthetic")
    assert res.totals["vuln_signal_eligible"] == 3
    assert res.vuln_signal_recovered_rate == 1 / 3


def test_vuln_signal_recovered_excludes_proxy(tmp_path: Path) -> None:
    """Proxy bundles MUST NOT contribute to the vuln_signal_recovered_rate
    denominator (their unpatched scorer applies=False by design)."""
    reports = [
        _write_full_report(tmp_path, name="full"),  # eligible, recovered
        _write_full_report(
            tmp_path, name="proxy", is_proxy=True, proxy_reason="sandbox-cannot-trigger"
        ),
    ]
    res = aggregate_reproducer_reports(report_paths=reports, cohort="synthetic")
    assert res.totals["vuln_signal_eligible"] == 1
    assert res.vuln_signal_recovered_rate == 1.0


def test_proxy_patched_passes_rate(tmp_path: Path) -> None:
    """Proxy bundles' repro-patched-passes is the proxy_patched_passes_rate
    numerator. 2 proxies, 1 with score 1.0 → 0.5."""
    reports = [
        _write_full_report(
            tmp_path,
            name="px1",
            is_proxy=True,
            proxy_reason="sandbox-cannot-trigger",
            patched_score=1.0,
        ),
        _write_full_report(
            tmp_path,
            name="px2",
            is_proxy=True,
            proxy_reason="cve-class-needs-fixture-corpus",
            patched_score=0.0,
        ),
    ]
    res = aggregate_reproducer_reports(report_paths=reports, cohort="synthetic")
    assert res.totals["proxy_eligible"] == 2
    assert res.proxy_patched_passes_rate == 0.5


def test_proxy_rate_and_reason_distribution(tmp_path: Path) -> None:
    reports = [
        _write_full_report(tmp_path, name="full"),
        _write_full_report(
            tmp_path, name="px1", is_proxy=True, proxy_reason="sandbox-cannot-trigger"
        ),
        _write_full_report(
            tmp_path, name="px2", is_proxy=True, proxy_reason="sandbox-cannot-trigger"
        ),
        _write_full_report(
            tmp_path,
            name="px3",
            is_proxy=True,
            proxy_reason="cve-class-needs-fixture-corpus",
        ),
    ]
    res = aggregate_reproducer_reports(report_paths=reports, cohort="synthetic")
    assert res.proxy_rate == 0.75
    assert res.proxy_reason_distribution == {
        "sandbox-cannot-trigger": 2,
        "cve-class-needs-fixture-corpus": 1,
    }


def test_refusal_rate(tmp_path: Path) -> None:
    reports = [
        _write_full_report(tmp_path, name="full"),
        _write_refusal_report(tmp_path, name="ref1", rule=3),
        _write_refusal_report(tmp_path, name="ref2", rule=5),
    ]
    res = aggregate_reproducer_reports(report_paths=reports, cohort="synthetic")
    assert res.refusal_rate == 2 / 3
    assert res.totals["refusals"] == 2


def test_passthru_coverage_mean(tmp_path: Path) -> None:
    reports = [
        _write_full_report(tmp_path, name="r1", passthru_score=1.0),
        _write_full_report(tmp_path, name="r2", passthru_score=0.5),
        _write_full_report(tmp_path, name="r3", passthru_score=0.0),
    ]
    res = aggregate_reproducer_reports(report_paths=reports, cohort="synthetic")
    assert res.passthru_coverage_mean == 0.5


def test_signal_specificity_mean_advisory(tmp_path: Path) -> None:
    reports = [
        _write_full_report(tmp_path, name="r1", specificity_score=1.0),
        _write_full_report(tmp_path, name="r2", specificity_score=0.667),
    ]
    res = aggregate_reproducer_reports(report_paths=reports, cohort="synthetic")
    assert res.signal_specificity_mean == 0.8335


def test_provenance_recorded_per_run(tmp_path: Path) -> None:
    reports = [
        _write_full_report(tmp_path, name="r1", model_id="claude-sonnet-4-6"),
        _write_full_report(
            tmp_path,
            name="r2",
            is_proxy=True,
            proxy_reason="sandbox-cannot-trigger",
            model_id="claude-sonnet-4-6",
        ),
        _write_refusal_report(tmp_path, name="r3", rule=3),
    ]
    res = aggregate_reproducer_reports(report_paths=reports, cohort="synthetic")
    assert len(res.provenance) == 3
    refusal_entries = [p for p in res.provenance if p.refused]
    assert len(refusal_entries) == 1
    assert refusal_entries[0].refusal_rule == 3
    proxy_entries = [p for p in res.provenance if p.is_proxy]
    assert len(proxy_entries) == 1
    assert proxy_entries[0].proxy_reason == "sandbox-cannot-trigger"


def test_unparseable_report_counted(tmp_path: Path) -> None:
    bad = tmp_path / "broken.json"
    bad.write_text("not json{{")
    good = _write_full_report(tmp_path, name="ok")
    res = aggregate_reproducer_reports(
        report_paths=[bad, good],
        cohort="synthetic",
    )
    assert res.totals["parse_errors"] == 1
    assert res.totals["scoring_reports"] == 2


# ─── CLI dispatch ────────────────────────────────────────────────────────


def test_cli_repro_rate_runs(tmp_path: Path, capsys) -> None:
    from tools.trace_cli.cli import main as cli_main

    _write_full_report(tmp_path, name="r1")
    _write_full_report(
        tmp_path, name="r2", is_proxy=True, proxy_reason="sandbox-cannot-trigger"
    )
    _write_refusal_report(tmp_path, name="r3", rule=3)
    rc = cli_main(
        [
            "eval",
            "repro-rate",
            "--cohort",
            "synthetic",
            "--reports",
            str(tmp_path / "*.json"),
            "--format",
            "json",
        ]
    )
    assert rc == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["cohort"] == "synthetic"
    assert payload["totals"]["scoring_reports"] == 3
    assert payload["totals"]["refusals"] == 1
    assert payload["totals"]["proxy"] == 1
    assert payload["proxy_rate"] == 1 / 3
    assert payload["refusal_rate"] == 1 / 3


def test_cli_repro_rate_empty_glob_returns_invalid(tmp_path: Path, capsys) -> None:
    from tools.trace_cli.cli import main as cli_main

    rc = cli_main(
        [
            "eval",
            "repro-rate",
            "--cohort",
            "synthetic",
            "--reports",
            "/nonexistent/path/*.json",
        ]
    )
    assert rc != 0
    err = capsys.readouterr().err
    assert "no repro-scoring-report.json files matched" in err


def test_cli_repro_rate_unknown_cohort_label_marked(tmp_path: Path, capsys) -> None:
    from tools.trace_cli.cli import main as cli_main

    _write_full_report(tmp_path, name="r1")
    rc = cli_main(
        [
            "eval",
            "repro-rate",
            "--cohort",
            "experimental-cohort",
            "--reports",
            str(tmp_path / "*.json"),
        ]
    )
    assert rc == 0
    out = capsys.readouterr().out
    assert "free-form label" in out


def test_expand_reproducer_glob_root_relative(tmp_path: Path) -> None:
    _write_full_report(tmp_path, name="a")
    _write_full_report(tmp_path, name="b")
    paths = expand_reproducer_glob(str(tmp_path / "*.json"))
    assert len(paths) == 2
