"""Tests for `trace report throughput`.

The throughput report is a pure roll-up of on-disk artifacts (cron
run records + bundle directories). v0 separates three sections:

  observed:    counts and timestamps directly from JSON files.
  derived:     simple aggregates (kind distribution etc.).
  unobserved:  instrumented fields with no data points and why.

These tests pin the shape so a downstream dashboard or release note
can rely on the JSON. They also pin the "no estimation" rule: a
bundle without patcher-invocation.json must show up as
patcher_invocations_with_usage = 0, not as an inferred value.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any
from unittest.mock import patch

import pytest

from tools.trace_cli import report


# ─── helpers ─────────────────────────────────────────────────────────────────


def _write_json(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2), encoding="utf-8")


def _seed_scout_runs(path: Path, records: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(json.dumps(r) for r in records) + "\n", encoding="utf-8")


def _seed_bundle(
    traces_root: Path,
    cve_id: str,
    *,
    kind: str = "auto-merge",
    kind_reason: str | None = None,
    patcher_family: str | None = "model-attested",
    invocations: list[dict[str, Any]] | None = None,
    reproducer_nix: bool = False,
    reproducer_refusal: bool = False,
    patcher_invocation: dict[str, Any] | None = None,
    bundle_id: str = "deadbeefcafef00d",
) -> Path:
    """Seed a minimal bundle directory under `traces_root`.

    Only the fields the report reader touches are populated. Real
    bundles carry many more keys (impact, scoring-report, etc.); we
    intentionally don't here so a missing field can't accidentally
    sneak into the report.
    """
    bundle_dir = traces_root / cve_id
    bundle_dir.mkdir(parents=True)
    _write_json(bundle_dir / "bundle.json", {
        "schema_version": "1.0.0",
        "cve_id": cve_id,
        "bundle_id": bundle_id,
        "kind": kind,
        "kind_reason": kind_reason,
    })
    roles: list[dict[str, Any]] = []
    if invocations is None:
        invocations = [
            {
                "role": "patcher",
                "started_at": "2026-05-01T00:00:00Z",
                "ended_at": "2026-05-01T00:00:22Z",
                "model": {
                    "family": patcher_family or "model-attested",
                    "model_id": "claude-opus-4-7",
                    "version": "1",
                },
            }
        ] if patcher_family else []
    # Group invocations into roles.
    by_role: dict[str, list[dict[str, Any]]] = {}
    for inv in invocations:
        by_role.setdefault(inv["role"], []).append(inv)
    for role_name, inv_list in by_role.items():
        roles.append({"role": role_name, "invocations": inv_list})
    _write_json(bundle_dir / "replay.json", {"schema_version": "1.0.0", "roles": roles})
    if reproducer_nix:
        (bundle_dir / "reproducer.nix").write_text("# placeholder\n")
    if reproducer_refusal:
        _write_json(bundle_dir / "reproducer-refusal.json", {
            "schema_version": "1.0.0",
            "reason": "sandbox-incompatible",
        })
    if patcher_invocation is not None:
        _write_json(bundle_dir / "patcher-invocation.json", patcher_invocation)
    return bundle_dir


def _provenance(tmp_path: Path) -> report.Provenance:
    return report.Provenance(
        generated_at="2026-05-10T00:00:00Z",
        git_rev="abcdef123456",
        traces_root=str(tmp_path / "traces"),
        scout_runs_path=str(tmp_path / "data" / "scout-runs.jsonl"),
        bundles_scanned=0,
        scout_runs_scanned=0,
    )


# ─── load_scout_runs ─────────────────────────────────────────────────────────


def test_load_scout_runs_missing_file_returns_zeros(tmp_path: Path) -> None:
    """A missing scout-runs.jsonl means the cron never wrote. That's
    informational, not an error: the report should still render with
    every cron counter at zero so downstream consumers can chart the
    series uniformly."""
    s = report.load_scout_runs(tmp_path / "does-not-exist.jsonl")
    assert s.runs == 0
    assert s.earliest_run_at is None
    assert s.latest_run_at is None
    assert s.totals_by_action == {}
    assert s.totals_by_verdict == {}
    assert s.discovered_total == 0
    assert s.processed_total == 0


def test_load_scout_runs_aggregates_actions_and_verdicts(tmp_path: Path) -> None:
    runs_path = tmp_path / "scout-runs.jsonl"
    _seed_scout_runs(runs_path, [
        {
            "run_at": "2026-05-01T00:00:00Z",
            "discovered": 10,
            "processed": 10,
            "actions": {"written": 6, "skipped-irrelevant": 4},
            "resolver_verdicts": {"eligible": 1, "ineligible-no-fix-available": 5},
        },
        {
            "run_at": "2026-05-02T00:00:00Z",
            "discovered": 5,
            "processed": 4,
            "actions": {"written": 3, "skipped-irrelevant": 1},
            "resolver_verdicts": {"ineligible-no-fix-available": 3},
        },
    ])
    s = report.load_scout_runs(runs_path)
    assert s.runs == 2
    assert s.earliest_run_at == "2026-05-01T00:00:00Z"
    assert s.latest_run_at == "2026-05-02T00:00:00Z"
    assert s.discovered_total == 15
    assert s.processed_total == 14
    assert s.totals_by_action == {"written": 9, "skipped-irrelevant": 5}
    assert s.totals_by_verdict == {
        "eligible": 1,
        "ineligible-no-fix-available": 8,
    }


def test_load_scout_runs_tolerates_malformed_lines(tmp_path: Path) -> None:
    """A bad JSONL line should not crash the rollup. v0 silently drops
    them; future iteration could surface a parse-error counter."""
    runs_path = tmp_path / "scout-runs.jsonl"
    runs_path.parent.mkdir(parents=True, exist_ok=True)
    runs_path.write_text(
        '{"run_at": "2026-05-01T00:00:00Z", "discovered": 1, "processed": 1}\n'
        "not valid json at all\n"
        '{"run_at": "2026-05-02T00:00:00Z", "discovered": 2, "processed": 2}\n',
        encoding="utf-8",
    )
    s = report.load_scout_runs(runs_path)
    assert s.runs == 2
    assert s.discovered_total == 3


# ─── scan_bundles ────────────────────────────────────────────────────────────


def test_scan_bundles_skips_synthetic_cves(tmp_path: Path) -> None:
    """Synthetic CVE-0000-* fixtures exercise schema edges, not
    honest pipeline runs. They must not contaminate the throughput
    rollup."""
    traces = tmp_path / "traces"
    _seed_bundle(traces, "CVE-0000-1234")  # synthetic
    _seed_bundle(traces, "CVE-2025-67899")  # real
    bundles = report.scan_bundles(traces)
    assert [b.cve_id for b in bundles] == ["CVE-2025-67899"]


def test_scan_bundles_skips_dir_without_bundle_or_replay(tmp_path: Path) -> None:
    traces = tmp_path / "traces"
    traces.mkdir()
    (traces / "CVE-2025-99999").mkdir()  # empty dir
    _seed_bundle(traces, "CVE-2025-67899")
    bundles = report.scan_bundles(traces)
    assert [b.cve_id for b in bundles] == ["CVE-2025-67899"]


def test_scan_bundles_computes_per_role_wall_time(tmp_path: Path) -> None:
    traces = tmp_path / "traces"
    _seed_bundle(traces, "CVE-2025-67899", invocations=[
        {
            "role": "patcher",
            "started_at": "2026-05-01T00:00:00Z",
            "ended_at": "2026-05-01T00:00:22Z",
            "model": {"family": "model-attested", "model_id": "claude-opus-4-7",
                      "version": "1"},
        },
        {
            "role": "reviewer",
            "started_at": "2026-05-01T00:01:00Z",
            "ended_at": "2026-05-01T00:01:08Z",
            "model": {"family": "model-attested", "model_id": "claude-sonnet-4-6",
                      "version": "1"},
        },
    ])
    bundles = report.scan_bundles(traces)
    assert len(bundles) == 1
    b = bundles[0]
    assert b.per_role["patcher"].duration_seconds == 22.0
    assert b.per_role["patcher"].invocations == 1
    assert b.per_role["reviewer"].duration_seconds == 8.0
    assert b.total_wall_time_seconds == 30.0


def test_scan_bundles_wall_time_unknown_when_timestamps_missing(tmp_path: Path) -> None:
    """If any invocation lacks timestamps the role + bundle total go
    None so downstream consumers can distinguish 'we don't know' from
    'we measured zero'."""
    traces = tmp_path / "traces"
    _seed_bundle(traces, "CVE-2025-67899", invocations=[
        {
            "role": "patcher",
            "started_at": "2026-05-01T00:00:00Z",
            # no ended_at
            "model": {"family": "model-attested", "model_id": "x", "version": "1"},
        },
    ])
    b = report.scan_bundles(traces)[0]
    assert b.per_role["patcher"].duration_seconds is None
    assert b.total_wall_time_seconds is None


def test_scan_bundles_recognises_patcher_family(tmp_path: Path) -> None:
    traces = tmp_path / "traces"
    _seed_bundle(traces, "CVE-2024-11111", patcher_family="model-attested")
    _seed_bundle(traces, "CVE-2024-22222", patcher_family="deterministic-no-model")
    _seed_bundle(traces, "CVE-2024-33333", invocations=[])  # no patcher role
    found = {b.cve_id: b.patcher_provenance for b in report.scan_bundles(traces)}
    assert found == {
        "CVE-2024-11111": "model-attested",
        "CVE-2024-22222": "deterministic-no-model",
        "CVE-2024-33333": "absent",
    }


def test_scan_bundles_reads_patcher_invocation_when_present(tmp_path: Path) -> None:
    """patcher-invocation.json is one of three role sidecars. Reader
    lifts the usage block verbatim — no estimation."""
    traces = tmp_path / "traces"
    _seed_bundle(
        traces, "CVE-2025-67899",
        patcher_invocation={
            "schema_version": "1.0.0",
            "invocation_id": "deadbeef",
            "model_id": "claude-opus-4-7",
            "usage": {"input_tokens": 4321, "output_tokens": 765},
            "budget": {"actual_cost_usd": 0.087, "soft_cap_usd": 1.0},
        },
    )
    b = report.scan_bundles(traces)[0]
    assert b.role_usage["patcher"] == {
        "input_tokens": 4321,
        "output_tokens": 765,
        "actual_cost_usd": 0.087,
        "model_id": "claude-opus-4-7",
        "attempts": None,
        "retry_count": None,
        "first_attempt_conformant": None,
    }


def test_scan_bundles_reads_all_three_role_sidecars(tmp_path: Path) -> None:
    """Slice 2 of cost/throughput: reviewer-invocation.json and
    reproducer-invocation.json land alongside patcher-invocation.json
    with the same shape. The reader must surface all three uniformly
    so per-role cost rollup works."""
    traces = tmp_path / "traces"
    bundle_dir = _seed_bundle(
        traces, "CVE-2025-67899",
        patcher_invocation={
            "usage": {"input_tokens": 4321, "output_tokens": 765},
            "budget": {"actual_cost_usd": 0.087},
            "model_id": "claude-opus-4-7",
        },
    )
    _write_json(bundle_dir / "reviewer-invocation.json", {
        "schema_version": "1.0.0",
        "role": "reviewer",
        "model_id": "claude-sonnet-4-6",
        "usage": {"input_tokens": 2100, "output_tokens": 380},
        "budget": {"actual_cost_usd": 0.012},
    })
    _write_json(bundle_dir / "reproducer-invocation.json", {
        "schema_version": "1.0.0",
        "role": "reproducer",
        "model_id": "claude-sonnet-4-5-20250929",
        "usage": {"input_tokens": 1500, "output_tokens": 200},
        "budget": {"actual_cost_usd": 0.0075},
    })
    b = report.scan_bundles(traces)[0]
    assert set(b.role_usage.keys()) == {"patcher", "reviewer", "reproducer"}
    assert b.role_usage["reviewer"]["model_id"] == "claude-sonnet-4-6"
    assert b.role_usage["reproducer"]["actual_cost_usd"] == 0.0075


def test_scan_bundles_sidecar_reads_cache_token_fields(tmp_path: Path) -> None:
    """Slice 2.1: sidecars now carry cache_creation_input_tokens and
    cache_read_input_tokens. The report reader keeps the existing
    flat usage shape, so the reader's contract doesn't change — but
    it must tolerate sidecars with the extra fields and surface them
    in the lifted usage block."""
    traces = tmp_path / "traces"
    bundle_dir = _seed_bundle(traces, "CVE-2025-67899")
    _write_json(bundle_dir / "patcher-invocation.json", {
        "schema_version": "1.0.0",
        "role": "patcher",
        "model_id": "claude-opus-4-7",
        "usage": {
            "input_tokens": 6,
            "output_tokens": 1310,
            "cache_creation_input_tokens": 8000,
            "cache_read_input_tokens": 0,
        },
        "budget": {"actual_cost_usd": 0.2484},
    })
    b = report.scan_bundles(traces)[0]
    assert "patcher" in b.role_usage
    # The reader's flat shape is unchanged for backwards-compat with
    # earlier sidecars, but the actual_cost_usd reflects cache pricing.
    assert b.role_usage["patcher"]["actual_cost_usd"] == 0.2484
    assert b.role_usage["patcher"]["input_tokens"] == 6


def test_scan_bundles_sidecar_with_null_usage_still_lifted(tmp_path: Path) -> None:
    """FakeAdapter case: usage tokens come back None. The sidecar is
    still written by execute.py with null fields. The reader must
    surface those nulls rather than dropping the entry, so the report
    can distinguish 'role ran, adapter didn't report tokens' from
    'role didn't run'."""
    traces = tmp_path / "traces"
    bundle_dir = _seed_bundle(traces, "CVE-2025-67899")
    _write_json(bundle_dir / "reviewer-invocation.json", {
        "schema_version": "1.0.0",
        "role": "reviewer",
        "model_id": "claude-sonnet-4-6",
        "usage": {"input_tokens": None, "output_tokens": None},
        "budget": {"actual_cost_usd": None},
    })
    b = report.scan_bundles(traces)[0]
    assert "reviewer" in b.role_usage
    assert b.role_usage["reviewer"]["input_tokens"] is None
    assert b.role_usage["reviewer"]["actual_cost_usd"] is None


def test_scan_bundles_sidecar_reads_retry_fields(tmp_path: Path) -> None:
    """A Reviewer sidecar carrying bounded-auto-retry metrics (usage.attempts
    > 1, top-level retry_count + first_attempt_conformant) must surface all
    three through the reader, so the retry_summary aggregate and the
    per-role-usage rows can see the retry-driven extra billed call."""
    traces = tmp_path / "traces"
    bundle_dir = _seed_bundle(traces, "CVE-2025-67899")
    _write_json(bundle_dir / "reviewer-invocation.json", {
        "schema_version": "1.0.0",
        "role": "reviewer",
        "model_id": "claude-sonnet-4-6",
        "usage": {"input_tokens": 2100, "output_tokens": 380, "attempts": 2},
        "budget": {"actual_cost_usd": 0.02},
        "retry_count": 1,
        "first_attempt_conformant": False,
    })
    b = report.scan_bundles(traces)[0]
    assert b.role_usage["reviewer"]["attempts"] == 2
    assert b.role_usage["reviewer"]["retry_count"] == 1
    assert b.role_usage["reviewer"]["first_attempt_conformant"] is False


def test_scan_bundles_sidecar_without_retry_fields_defaults_cleanly(
    tmp_path: Path,
) -> None:
    """Patcher/Reproducer sidecars never carry retry_count or
    first_attempt_conformant (Reviewer-only fields), and pre-bounded-retry
    sidecars may not carry usage.attempts at all. The reader must surface
    None for the absent fields rather than raising."""
    traces = tmp_path / "traces"
    _seed_bundle(
        traces, "CVE-2025-67899",
        patcher_invocation={
            "model_id": "claude-opus-4-7",
            "usage": {"input_tokens": 4321, "output_tokens": 765, "attempts": 1},
            "budget": {"actual_cost_usd": 0.087},
        },
    )
    b = report.scan_bundles(traces)[0]
    assert b.role_usage["patcher"]["attempts"] == 1
    assert b.role_usage["patcher"]["retry_count"] is None
    assert b.role_usage["patcher"]["first_attempt_conformant"] is None


# ─── build_report: observed / derived / unobserved split ─────────────────────


def test_build_report_separates_observed_from_unobserved(tmp_path: Path) -> None:
    """The headline contract: a corpus with NO patcher-invocation.json
    files must show unobserved.per_role_token_cost.data_points = 0,
    not an estimated/imputed number. The reason field must explain
    why so the report is self-documenting."""
    traces = tmp_path / "traces"
    _seed_bundle(traces, "CVE-2024-13978", kind="auto-merge")
    _seed_bundle(
        traces, "CVE-2025-67899",
        kind="human-review-required",
        kind_reason="major-version-jump-requires-review",
        reproducer_refusal=True,
    )
    runs_path = tmp_path / "data" / "scout-runs.jsonl"
    _seed_scout_runs(runs_path, [
        {"run_at": "2026-05-01T00:00:00Z", "discovered": 1, "processed": 1,
         "actions": {"written": 1}, "resolver_verdicts": {"eligible": 1}},
    ])

    scout = report.load_scout_runs(runs_path)
    bundles = report.scan_bundles(traces)
    r = report.build_report(scout, bundles, provenance=_provenance(tmp_path))

    # Observed: cron rolled up, bundle wall times present.
    assert r.observed["cron_throughput"]["runs"] == 1
    assert len(r.observed["bundle_wall_time"]) == 2
    assert r.observed["role_usage"] == []

    # Derived: kind + reproducer + patcher-family distributions.
    assert r.derived["bundle_kind_distribution"] == {
        "auto-merge": 1, "human-review-required": 1,
    }
    assert r.derived["reproducer_status_distribution"]["refusal"] == 1
    assert r.derived["reproducer_status_distribution"]["absent"] == 1

    # Unobserved: explicit zero + reason.
    cost = r.unobserved["per_role_token_cost"]
    assert cost["data_points"] == 0
    assert cost["patcher_invocations_with_usage"] == 0
    assert cost["reviewer_invocations_with_usage"] == 0
    assert cost["reproducer_invocations_with_usage"] == 0
    assert "patcher=0/2" in cost["reason"]
    assert "reviewer=0/2" in cost["reason"]
    assert "reproducer=0/2" in cost["reason"]
    # cost_per_merge_ready lives in derived now (it IS observable when
    # the corpus has at least one auto-merge + patcher sidecar). With
    # zero patcher sidecars present, data_points is 0 but it's a real
    # derived field, not an unobserved one.
    cpb = r.derived["cost_per_merge_ready_bundle"]
    assert cpb["data_points"] == 0
    assert cpb["rows"] == []


def test_build_report_observes_role_usage_when_present(tmp_path: Path) -> None:
    """When role sidecars are on disk, the per-role data shifts from
    unobserved to observed. One row per (bundle, role) sidecar pair."""
    traces = tmp_path / "traces"
    bundle_dir = _seed_bundle(
        traces, "CVE-2025-67899",
        kind="human-review-required",
        patcher_invocation={
            "model_id": "claude-opus-4-7",
            "usage": {"input_tokens": 4321, "output_tokens": 765},
            "budget": {"actual_cost_usd": 0.087},
        },
    )
    _write_json(bundle_dir / "reviewer-invocation.json", {
        "model_id": "claude-sonnet-4-6",
        "usage": {"input_tokens": 2100, "output_tokens": 380},
        "budget": {"actual_cost_usd": 0.012},
    })
    scout = report.load_scout_runs(tmp_path / "missing.jsonl")
    r = report.build_report(scout, report.scan_bundles(traces), provenance=_provenance(tmp_path))
    assert len(r.observed["role_usage"]) == 2
    rows = {(u["cve_id"], u["role"]): u for u in r.observed["role_usage"]}
    assert rows[("CVE-2025-67899", "patcher")]["actual_cost_usd"] == 0.087
    assert rows[("CVE-2025-67899", "reviewer")]["actual_cost_usd"] == 0.012
    # Still no reproducer sidecar; coverage line records that.
    cost = r.unobserved["per_role_token_cost"]
    assert cost["patcher_invocations_with_usage"] == 1
    assert cost["reviewer_invocations_with_usage"] == 1
    assert cost["reproducer_invocations_with_usage"] == 0
    # Not a merge-ready data point: bundle kind is human-review-required.
    assert r.derived["cost_per_merge_ready_bundle"]["data_points"] == 0


def test_build_report_cost_per_merge_ready_counts_auto_merge_with_patcher(
    tmp_path: Path,
) -> None:
    """The v0 cross-family contract is satisfied by Patcher + Reviewer
    OR Patcher + Reproducer, never both. An auto-merge bundle with
    Patcher + one cross-family role is the canonical merge-ready
    shape. Patcher-only auto-merge bundles are also legitimate v0
    (mbedtls) and count too. Human-review never counts regardless
    of how many sidecars are present."""
    traces = tmp_path / "traces"
    inv = {"usage": {"input_tokens": 100, "output_tokens": 50},
           "budget": {"actual_cost_usd": 0.01}, "model_id": "claude-opus-4-7"}
    inv_b = {"usage": {"input_tokens": 50, "output_tokens": 25},
             "budget": {"actual_cost_usd": 0.003}, "model_id": "claude-sonnet-4-6"}
    # Auto-merge with only Patcher: counts.
    _seed_bundle(traces, "CVE-2024-13978", kind="auto-merge",
                 patcher_invocation=inv)
    # Auto-merge with Patcher + Reviewer: counts; total is patcher + reviewer.
    bundle_b = _seed_bundle(traces, "CVE-2024-49195", kind="auto-merge",
                            patcher_invocation=inv)
    _write_json(bundle_b / "reviewer-invocation.json", inv_b)
    # Human-review with all roles: never counts.
    bundle_c = _seed_bundle(traces, "CVE-2025-67899", kind="human-review-required",
                            patcher_invocation=inv)
    _write_json(bundle_c / "reviewer-invocation.json", inv_b)
    scout = report.load_scout_runs(tmp_path / "missing.jsonl")
    r = report.build_report(scout, report.scan_bundles(traces), provenance=_provenance(tmp_path))
    cpb = r.derived["cost_per_merge_ready_bundle"]
    assert cpb["data_points"] == 2
    assert cpb["total_usd"] == pytest.approx(0.01 + 0.01 + 0.003, rel=1e-9)
    rows_by_cve = {row["cve_id"]: row for row in cpb["rows"]}
    assert rows_by_cve["CVE-2024-13978"]["roles_present"] == ["patcher"]
    assert rows_by_cve["CVE-2024-13978"]["total_usd"] == 0.01
    assert rows_by_cve["CVE-2024-49195"]["roles_present"] == ["patcher", "reviewer"]
    assert rows_by_cve["CVE-2024-49195"]["total_usd"] == pytest.approx(0.013, rel=1e-9)


def test_build_report_cost_per_merge_ready_no_patcher_no_data_point(
    tmp_path: Path,
) -> None:
    """An auto-merge bundle without a Patcher sidecar (e.g.
    deterministic-no-model bundles like libtiff) doesn't contribute
    to cost-per-merge-ready: there's no Patcher cost to attribute."""
    traces = tmp_path / "traces"
    _seed_bundle(traces, "CVE-2024-13978", kind="auto-merge",
                 patcher_family="deterministic-no-model")
    scout = report.load_scout_runs(tmp_path / "missing.jsonl")
    r = report.build_report(scout, report.scan_bundles(traces), provenance=_provenance(tmp_path))
    assert r.derived["cost_per_merge_ready_bundle"]["data_points"] == 0


def test_build_report_retry_summary_counts_reviewer_retry(tmp_path: Path) -> None:
    """A Reviewer sidecar with usage.attempts=2 / retry_count=1 /
    first_attempt_conformant=false must (a) surface those fields on the
    observed role_usage row and (b) roll up into derived.retry_summary as
    one retried role + one extra billed call + one nonconformant first
    attempt."""
    traces = tmp_path / "traces"
    bundle_dir = _seed_bundle(
        traces, "CVE-2025-67899",
        patcher_invocation={
            "model_id": "claude-opus-4-7",
            "usage": {"input_tokens": 100, "output_tokens": 50, "attempts": 1},
            "budget": {"actual_cost_usd": 0.01},
        },
    )
    _write_json(bundle_dir / "reviewer-invocation.json", {
        "model_id": "claude-sonnet-4-6",
        "usage": {"input_tokens": 2100, "output_tokens": 380, "attempts": 2},
        "budget": {"actual_cost_usd": 0.02},
        "retry_count": 1,
        "first_attempt_conformant": False,
    })
    scout = report.load_scout_runs(tmp_path / "missing.jsonl")
    r = report.build_report(scout, report.scan_bundles(traces), provenance=_provenance(tmp_path))

    rows = {u["role"]: u for u in r.observed["role_usage"]}
    assert rows["reviewer"]["attempts"] == 2
    assert rows["reviewer"]["retry_count"] == 1
    assert rows["reviewer"]["first_attempt_conformant"] is False

    retry = r.derived["retry_summary"]
    assert retry["roles_with_retry"] == 1
    assert retry["total_extra_calls"] == 1
    assert retry["total_model_call_attempts"] == 3  # patcher attempts=1 + reviewer attempts=2
    assert retry["reviewer_first_attempt_nonconformant"] == 1
    assert retry["reviewer_first_attempt_conformant"] == 0


def test_build_report_retry_summary_zero_for_sidecars_without_retry_fields(
    tmp_path: Path,
) -> None:
    """Patcher/Reproducer sidecars (no retry_count / first_attempt_conformant,
    usage.attempts=1) must contribute 0 extra calls -- the common case for
    the seed corpus, which predates bounded Reviewer auto-retry."""
    traces = tmp_path / "traces"
    _seed_bundle(
        traces, "CVE-2025-67899",
        patcher_invocation={
            "model_id": "claude-opus-4-7",
            "usage": {"input_tokens": 100, "output_tokens": 50, "attempts": 1},
            "budget": {"actual_cost_usd": 0.01},
        },
    )
    scout = report.load_scout_runs(tmp_path / "missing.jsonl")
    r = report.build_report(scout, report.scan_bundles(traces), provenance=_provenance(tmp_path))
    retry = r.derived["retry_summary"]
    assert retry["roles_with_retry"] == 0
    assert retry["total_extra_calls"] == 0
    assert retry["reviewer_first_attempt_conformant"] == 0
    assert retry["reviewer_first_attempt_nonconformant"] == 0


# ─── rendering ───────────────────────────────────────────────────────────────


def test_render_json_is_stable_and_sorted(tmp_path: Path) -> None:
    """The JSON output must be sorted-key + deterministic so diffing
    two reports across runs is meaningful."""
    scout = report.load_scout_runs(tmp_path / "missing.jsonl")
    r = report.build_report(scout, [], provenance=_provenance(tmp_path))
    s = report.render_json(r)
    parsed = json.loads(s)
    assert parsed["schema_version"] == "1.0.0"
    assert parsed["report_kind"] == "throughput"
    # Re-rendering yields identical bytes.
    assert report.render_json(r) == s


def test_render_markdown_keeps_three_sections(tmp_path: Path) -> None:
    """The Markdown is the human-facing surface; the three-section
    contract is load-bearing for release-note + discussion use."""
    traces = tmp_path / "traces"
    _seed_bundle(traces, "CVE-2025-67899", reproducer_refusal=True)
    scout = report.load_scout_runs(tmp_path / "missing.jsonl")
    r = report.build_report(scout, report.scan_bundles(traces), provenance=_provenance(tmp_path))
    md = report.render_markdown(r)
    assert "## Observed" in md
    assert "## Derived" in md
    assert "## Unobserved (instrumented but empty)" in md
    # Provenance line surfaces git rev + bundle/run counts.
    assert "abcdef123456" in md
    assert "bundles scanned: 0" in md  # provenance starts at zero in fixture


# ─── end-to-end run() writes both files ──────────────────────────────────────


def test_parse_scout_runs_ignores_unknown_main_sha_field() -> None:
    # the cron writer added main_sha (schema 1.1.0); the roll-up must ignore
    # unknown fields, not choke on them.
    text = json.dumps({
        "schema_version": "1.1.0", "run_at": "2026-07-20T00:00:00Z",
        "main_sha": "f8c81895e342", "discovered": 3, "processed": 2,
        "actions": {"written": 2}, "resolver_verdicts": {"confirmed": 1},
    }) + "\n"
    s = report.parse_scout_runs(text)
    assert s.runs == 1
    assert s.discovered_total == 3
    assert s.totals_by_action == {"written": 2}


def test_resolve_scout_runs_prefers_telemetry_ref(tmp_path: Path) -> None:
    # when the scout-telemetry ref resolves, its rows win and the source
    # label names the ref (never silently the stale working tree).
    stale = tmp_path / "data" / "scout-runs.jsonl"
    _seed_scout_runs(stale, [{"run_at": "2026-01-01T00:00:00Z", "discovered": 99}])
    live = json.dumps({"run_at": "2026-07-20T00:00:00Z", "discovered": 7}) + "\n"
    args = argparse.Namespace(scout_runs=stale, scout_runs_ref="scout-telemetry")
    with patch.object(report, "_read_scout_runs_ref", return_value=live) as m:
        summary, source = report._resolve_scout_runs(args, repo_root=tmp_path)
    # remote-tracking ref tried first (freshest after `git fetch origin`).
    assert m.call_args_list[0].args[1] == "origin/scout-telemetry"
    assert summary.discovered_total == 7            # live, not the stale 99
    assert source == "origin/scout-telemetry:data/scout-runs.jsonl (as of last fetch)"


def test_resolve_scout_runs_tries_remote_tracking_candidate(tmp_path: Path) -> None:
    # a plain branch name misses on an ordinary checkout (only origin/<name>
    # exists); the resolver must try the remote-tracking ref before falling back.
    live = json.dumps({"run_at": "2026-07-20T00:00:00Z", "discovered": 5}) + "\n"

    def _fake(_repo: Path, ref: str) -> str | None:
        return live if ref == "origin/scout-telemetry" else None

    args = argparse.Namespace(scout_runs=tmp_path / "wt.jsonl", scout_runs_ref="scout-telemetry")
    with patch.object(report, "_read_scout_runs_ref", side_effect=_fake):
        summary, source = report._resolve_scout_runs(args, repo_root=tmp_path)
    assert summary.discovered_total == 5
    assert source == "origin/scout-telemetry:data/scout-runs.jsonl (as of last fetch)"


def test_resolve_scout_runs_falls_back_with_visible_note(tmp_path: Path) -> None:
    # ref unreachable (branch not fetched) -> read the working tree BUT make
    # the staleness explicit in the source label (codex P1: never silent).
    wt = tmp_path / "data" / "scout-runs.jsonl"
    _seed_scout_runs(wt, [{"run_at": "2026-01-01T00:00:00Z", "discovered": 4}])
    args = argparse.Namespace(scout_runs=wt, scout_runs_ref="scout-telemetry")
    with patch.object(report, "_read_scout_runs_ref", return_value=None):
        summary, source = report._resolve_scout_runs(args, repo_root=tmp_path)
    assert summary.discovered_total == 4
    assert "fallback" in source and "unavailable" in source


def test_resolve_scout_runs_empty_ref_reads_working_tree(tmp_path: Path) -> None:
    wt = tmp_path / "data" / "scout-runs.jsonl"
    _seed_scout_runs(wt, [{"run_at": "2026-01-01T00:00:00Z", "discovered": 1}])
    args = argparse.Namespace(scout_runs=wt, scout_runs_ref="")
    # no git call when ref is empty.
    with patch.object(report, "_read_scout_runs_ref",
                      side_effect=AssertionError("must not touch git")):
        summary, source = report._resolve_scout_runs(args, repo_root=tmp_path)
    assert summary.discovered_total == 1
    assert "working tree" in source


def test_run_writes_md_and_json_pair(tmp_path: Path, capsys: pytest.CaptureFixture) -> None:
    """The CLI contract: --out-dir gets a {.md, .json} pair, stdout
    gets the chosen format, exit 0."""
    traces = tmp_path / "traces"
    _seed_bundle(traces, "CVE-2025-67899")
    runs_path = tmp_path / "data" / "scout-runs.jsonl"
    _seed_scout_runs(runs_path, [
        {"run_at": "2026-05-01T00:00:00Z", "discovered": 1, "processed": 1},
    ])
    out_dir = tmp_path / "reports"
    args = argparse.Namespace(
        traces_root=traces,
        scout_runs=runs_path,
        out_dir=out_dir,
        format="json",
    )
    rc = report.run(args, repo_root=tmp_path)
    assert rc == 0
    written = sorted(p.name for p in out_dir.iterdir())
    assert len(written) == 2
    assert any(p.endswith(".json") for p in written)
    assert any(p.endswith(".md") for p in written)
    # stdout carries the JSON when --format json.
    out = capsys.readouterr().out
    assert '"report_kind": "throughput"' in out


# ─── _cost_by_kind: per-kind cost breakdown ──────────────────────────────────

def _bundle(kind: str | None, role_usage: dict[str, Any]) -> report.BundleSummary:
    """Minimal BundleSummary — _cost_by_kind reads only kind + role_usage."""
    return report.BundleSummary(
        cve_id="CVE-0000-0000", bundle_id=None, kind=kind, kind_reason=None,
        per_role={}, total_wall_time_seconds=None, has_reproducer_nix=False,
        has_reproducer_refusal=False, patcher_provenance="absent",
        role_usage=role_usage,
    )


def _usage(cost: float | None) -> dict[str, Any]:
    return {"patcher": {"actual_cost_usd": cost}}


def test_cost_by_kind_groups_and_means() -> None:
    bundles = [
        _bundle("auto-merge", _usage(0.20)),
        _bundle("auto-merge", _usage(0.40)),
        _bundle("human-review-required", _usage(0.10)),
    ]
    out = report._cost_by_kind(bundles)
    assert out["kinds"]["auto-merge"]["data_points"] == 2
    assert out["kinds"]["auto-merge"]["mean_usd"] == 0.30
    assert out["kinds"]["auto-merge"]["total_usd"] == 0.60
    assert out["kinds"]["human-review-required"]["mean_usd"] == 0.10
    assert out["total_usd"] == 0.70


def test_cost_by_kind_skips_bundles_without_patcher_sidecar() -> None:
    # A bundle with no patcher usage has no observed spend -> excluded.
    bundles = [_bundle("auto-merge", _usage(0.20)), _bundle("advisory-only", {})]
    out = report._cost_by_kind(bundles)
    assert set(out["kinds"]) == {"auto-merge"}


def test_cost_by_kind_excludes_bundle_without_patcher_cost() -> None:
    # Only a reviewer sidecar (no Patcher) -> partial, cost-incomplete -> excluded
    # (Patcher dominates spend; both cross-family shapes include it).
    bundles = [
        _bundle("auto-merge", _usage(0.20)),
        _bundle("auto-merge", {"reviewer": {"actual_cost_usd": 0.05}}),
    ]
    out = report._cost_by_kind(bundles)
    assert out["kinds"]["auto-merge"]["data_points"] == 1
    assert out["kinds"]["auto-merge"]["total_usd"] == 0.20


def test_cost_by_kind_sums_all_roles_when_patcher_present() -> None:
    bundles = [_bundle("auto-merge", {
        "patcher": {"actual_cost_usd": 0.20},
        "reviewer": {"actual_cost_usd": 0.05},
    })]
    out = report._cost_by_kind(bundles)
    assert out["kinds"]["auto-merge"]["total_usd"] == 0.25


def test_cost_by_kind_excludes_null_cost_sidecar() -> None:
    # A sidecar present but actual_cost_usd=None (adapter emitted no usage) is
    # cost-UNKNOWN, not $0 -> must not inflate data_points / understate the mean.
    bundles = [_bundle("auto-merge", _usage(0.20)), _bundle("auto-merge", _usage(None))]
    out = report._cost_by_kind(bundles)
    assert out["kinds"]["auto-merge"]["data_points"] == 1
    assert out["kinds"]["auto-merge"]["mean_usd"] == 0.20


def test_cost_by_kind_unclassified_bucket_for_missing_kind() -> None:
    out = report._cost_by_kind([_bundle(None, _usage(0.05))])
    assert out["kinds"]["unclassified"]["total_usd"] == 0.05


def test_cost_by_kind_empty_when_no_costed_bundles() -> None:
    out = report._cost_by_kind([_bundle("auto-merge", {})])
    assert out["kinds"] == {}
    assert out["total_usd"] == 0.0


def test_cost_per_merge_ready_excludes_null_patcher_cost() -> None:
    # An auto-merge bundle with a patcher sidecar but null cost is cost-unknown,
    # not a $0 merge-ready observation (shares _bundle_realized_cost's baseline).
    bundles = [
        _bundle("auto-merge", _usage(0.30)),
        _bundle("auto-merge", _usage(None)),
        _bundle("human-review-required", _usage(0.99)),  # wrong kind, ignored
    ]
    out = report._cost_per_merge_ready(bundles)
    assert out["data_points"] == 1
    assert out["mean_usd"] == 0.30
    assert out["total_usd"] == 0.30
