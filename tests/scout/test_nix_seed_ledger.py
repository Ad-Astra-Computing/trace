"""nix_seed_ledger unit tests: fingerprint stability, read/write round-trip,
the should_emit re-emit predicate (never-seen / retryable / changed / TTL),
and post-run update marking (terminal marks, retryable stays re-emittable,
crash-before-outcome leaves the id untouched)."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path

from agents.scout.nix_seed_ledger import (
    LedgerEntry,
    fingerprint_fields,
    read_ledger,
    should_emit,
    update_ledger,
    write_ledger,
)


_NOW = datetime(2026, 7, 21, 12, 0, 0, tzinfo=timezone.utc)


def _fp(**over) -> str:
    base = dict(
        status="open", fixed_version=None, updated_at=None,
        has_pr=False, has_open_pr=False, has_merged_pr=False,
    )
    base.update(over)
    return fingerprint_fields(**base)


def test_fingerprint_prefers_updated_at():
    fp = _fp(updated_at="2026-07-20T00:00:00Z")
    assert fp == "u:2026-07-20T00:00:00Z"


def test_fingerprint_hashes_state_when_no_updated_at():
    a = _fp(fixed_version=None)
    b = _fp(fixed_version="1.2.3")
    assert a.startswith("h:") and b.startswith("h:")
    assert a != b  # a changed fixed_version must move the fingerprint


def test_fingerprint_moves_on_pr_merge():
    open_pr = _fp(has_pr=True, has_open_pr=True)
    merged = _fp(has_pr=True, has_merged_pr=True)
    assert open_pr != merged


def test_read_write_round_trip(tmp_path: Path):
    path = tmp_path / "nix-seed-seen.jsonl"
    entries = [
        LedgerEntry("CVE-2026-1001", "2026-07-01T00:00:00Z",
                    "2026-07-01T00:00:00Z", "written", "u:x"),
        LedgerEntry("CVE-2026-1002", "2026-07-02T00:00:00Z",
                    "2026-07-02T00:00:00Z", "skipped-irrelevant", "h:abc"),
    ]
    write_ledger(path, entries)
    got = read_ledger(path)
    assert set(got) == {"CVE-2026-1001", "CVE-2026-1002"}
    assert got["CVE-2026-1001"].outcome == "written"


def test_read_ledger_skips_malformed_lines(tmp_path: Path):
    path = tmp_path / "led.jsonl"
    path.write_text(
        '{"cve_id":"CVE-2026-1","first_seen":"a","last_evaluated":"a",'
        '"outcome":"written","fingerprint":"u:x"}\n'
        "not json\n"
        '{"cve_id":"CVE-2026-2"}\n'  # missing fields
    )
    got = read_ledger(path)
    assert set(got) == {"CVE-2026-1"}


def test_should_emit_never_seen():
    assert should_emit(None, current_fingerprint="u:x", now=_NOW) is True


def test_should_emit_retryable_outcome_re_emits():
    e = LedgerEntry("c", "2026-07-21T00:00:00Z", "2026-07-21T00:00:00Z",
                    "fetch-failed", "u:x")
    assert should_emit(e, current_fingerprint="u:x", now=_NOW) is True


def test_should_emit_terminal_same_fp_within_ttl_skips():
    e = LedgerEntry("c", "2026-07-20T00:00:00Z", "2026-07-20T00:00:00Z",
                    "skipped-irrelevant", "u:x")
    assert should_emit(e, current_fingerprint="u:x", now=_NOW) is False


def test_should_emit_fingerprint_change_re_emits():
    e = LedgerEntry("c", "2026-07-20T00:00:00Z", "2026-07-20T00:00:00Z",
                    "written", "u:old")
    assert should_emit(e, current_fingerprint="u:new", now=_NOW) is True


def test_should_emit_ttl_expiry_re_emits():
    old = (_NOW - timedelta(days=31)).isoformat()
    e = LedgerEntry("c", old, old, "skipped-irrelevant", "u:x")
    assert should_emit(e, current_fingerprint="u:x", now=_NOW) is True


def test_should_emit_ttl_boundary_not_yet_expired():
    recent = (_NOW - timedelta(days=29)).isoformat()
    e = LedgerEntry("c", recent, recent, "written", "u:x")
    assert should_emit(e, current_fingerprint="u:x", now=_NOW) is False


def test_update_marks_terminal_outcomes():
    out = update_ledger(
        existing={},
        emitted_fingerprints={"CVE-2026-1001": "u:x", "CVE-2026-1002": "u:y"},
        run_summary=[
            {"cve_id": "CVE-2026-1001", "action": "written"},
            {"cve_id": "CVE-2026-1002", "action": "skipped-irrelevant"},
        ],
        run_at="2026-07-21T12:00:00Z",
    )
    assert out["CVE-2026-1001"].outcome == "written"
    assert out["CVE-2026-1001"].last_evaluated == "2026-07-21T12:00:00Z"
    assert out["CVE-2026-1002"].outcome == "skipped-irrelevant"


def test_update_records_retryable_but_stays_re_emittable():
    out = update_ledger(
        existing={},
        emitted_fingerprints={"CVE-2026-1001": "u:x"},
        run_summary=[{"cve_id": "CVE-2026-1001", "action": "fetch-failed"}],
        run_at="2026-07-21T12:00:00Z",
    )
    e = out["CVE-2026-1001"]
    assert e.outcome == "fetch-failed"
    # retryable outcome => should_emit re-fires next run
    assert should_emit(e, current_fingerprint="u:x", now=_NOW) is True


def test_update_leaves_emitted_but_unprocessed_untouched():
    # Emitted this run but no outcome in the summary (crash before poll) —
    # must NOT be marked, so it re-emits next run.
    out = update_ledger(
        existing={},
        emitted_fingerprints={"CVE-2026-1001": "u:x"},
        run_summary=[],
        run_at="2026-07-21T12:00:00Z",
    )
    assert "CVE-2026-1001" not in out


def test_update_written_with_process_error_stays_re_emittable():
    # batch_cli emits action="written" + finding_status="error"/process_error
    # when process_entry throws after the inbox write. Must NOT be suppressed.
    out = update_ledger(
        existing={},
        emitted_fingerprints={"CVE-2026-1001": "u:x"},
        run_summary=[{
            "cve_id": "CVE-2026-1001", "action": "written",
            "finding_status": "error", "process_error": "process exception: boom",
        }],
        run_at="2026-07-21T12:00:00Z",
    )
    e = out["CVE-2026-1001"]
    assert e.outcome == "error"  # demoted from written
    assert should_emit(e, current_fingerprint="u:x", now=_NOW) is True


def test_update_written_with_steward_error_stays_re_emittable():
    out = update_ledger(
        existing={},
        emitted_fingerprints={"CVE-2026-1001": "u:x"},
        run_summary=[{
            "cve_id": "CVE-2026-1001", "action": "written",
            "steward_error": "opa-unavailable: no binary",
        }],
        run_at="2026-07-21T12:00:00Z",
    )
    e = out["CVE-2026-1001"]
    assert e.outcome == "error"
    assert should_emit(e, current_fingerprint="u:x", now=_NOW) is True


def test_update_clean_written_over_prior_error_becomes_terminal():
    # A prior errored entry that now completes cleanly must go terminal.
    existing = {
        "CVE-2026-1001": LedgerEntry(
            "CVE-2026-1001", "2026-07-20T00:00:00Z", "2026-07-20T00:00:00Z",
            "error", "u:x")
    }
    out = update_ledger(
        existing=existing,
        emitted_fingerprints={"CVE-2026-1001": "u:x"},
        run_summary=[{
            "cve_id": "CVE-2026-1001", "action": "written",
            "finding_status": "finding",
        }],
        run_at="2026-07-21T12:00:00Z",
    )
    e = out["CVE-2026-1001"]
    assert e.outcome == "written"
    assert e.first_seen == "2026-07-20T00:00:00Z"
    assert should_emit(e, current_fingerprint="u:x", now=_NOW) is False


def test_update_preserves_first_seen_on_refresh():
    existing = {
        "CVE-2026-1001": LedgerEntry(
            "CVE-2026-1001", "2026-06-01T00:00:00Z", "2026-06-01T00:00:00Z",
            "skipped-irrelevant", "u:old")
    }
    out = update_ledger(
        existing=existing,
        emitted_fingerprints={"CVE-2026-1001": "u:new"},
        run_summary=[{"cve_id": "CVE-2026-1001", "action": "written"}],
        run_at="2026-07-21T12:00:00Z",
    )
    e = out["CVE-2026-1001"]
    assert e.first_seen == "2026-06-01T00:00:00Z"  # preserved
    assert e.fingerprint == "u:new"  # refreshed
    assert e.outcome == "written"
