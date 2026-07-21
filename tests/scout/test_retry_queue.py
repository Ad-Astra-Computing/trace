"""Retry queue for transient cron failures.

Prevents data loss when discovery advances past a CVE that hit a 503,
rate limit, or other transient error. Each cron:

  1. Reads the persisted queue (state/scout-retry.jsonl).
  2. Prepends queue CVEs to the freshly-discovered window before
     batch_cli runs (deduped, capped at max_cves total).
  3. Updates the queue from the run summary:
       fetch-failed/rate-limited  -> increment attempts
       written/skipped-irrelevant -> remove (handled)
       any CVE >= max_attempts    -> drop with a warning
  4. Persists the queue back to cache.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from agents.scout.retry_queue import (
    RetryEntry,
    cve_ids_for_retry,
    enqueue_ids,
    read_queue,
    update_queue,
    write_queue,
)


def _entry(cve_id: str, attempts: int = 1, last_error: str = "503") -> RetryEntry:
    return RetryEntry(
        cve_id=cve_id,
        attempts=attempts,
        first_seen="2026-04-29T15:00:00Z",
        last_seen="2026-04-29T16:00:00Z",
        last_error=last_error,
    )


def test_read_empty_or_missing_returns_empty(tmp_path: Path) -> None:
    assert read_queue(tmp_path / "absent.jsonl") == []
    f = tmp_path / "empty.jsonl"
    f.write_text("")
    assert read_queue(f) == []


def test_write_then_read_roundtrip(tmp_path: Path) -> None:
    path = tmp_path / "q.jsonl"
    entries = [_entry("CVE-2024-1"), _entry("CVE-2024-2", attempts=2)]
    write_queue(path, entries)
    assert read_queue(path) == entries


def test_enqueue_ids_adds_new_at_zero_attempts() -> None:
    out = enqueue_ids([], ["CVE-2026-1", "CVE-2026-2"], run_at="2026-07-21T12:00:00Z")
    by_id = {e.cve_id: e for e in out}
    assert set(by_id) == {"CVE-2026-1", "CVE-2026-2"}
    # A displacement is not a failure — enters at 0 so it keeps its full budget.
    assert by_id["CVE-2026-1"].attempts == 0
    assert by_id["CVE-2026-1"].first_seen == "2026-07-21T12:00:00Z"
    assert by_id["CVE-2026-1"].last_error == "displaced-by-cap"


def test_enqueue_ids_preserves_existing_entries() -> None:
    existing = [_entry("CVE-2026-1", attempts=2, last_error="503")]
    out = enqueue_ids(existing, ["CVE-2026-1", "CVE-2026-9"], run_at="2026-07-21T12:00:00Z")
    by_id = {e.cve_id: e for e in out}
    # An already-queued id is untouched (attempts/first_seen preserved), not reset.
    assert by_id["CVE-2026-1"].attempts == 2
    assert by_id["CVE-2026-1"].first_seen == "2026-04-29T15:00:00Z"
    assert by_id["CVE-2026-1"].last_error == "503"
    assert by_id["CVE-2026-9"].attempts == 0


def test_enqueue_ids_skips_blank_and_dedupes() -> None:
    out = enqueue_ids([], ["CVE-2026-1", "", "  ", "CVE-2026-1"], run_at="2026-07-21T12:00:00Z")
    assert [e.cve_id for e in out] == ["CVE-2026-1"]


def test_enqueued_displaced_id_gets_full_budget_on_later_failure() -> None:
    # A displaced id (attempts=0) that then fails processing starts its retry
    # count at 1, i.e. it is NOT penalised for having been displaced.
    q = enqueue_ids([], ["CVE-2026-1"], run_at="2026-07-21T12:00:00Z")
    q2 = update_queue(
        existing=q,
        run_summary=[{"cve_id": "CVE-2026-1", "action": "fetch-failed"}],
        run_at="2026-07-21T18:00:00Z",
        max_attempts=3,
    )
    assert {e.cve_id: e.attempts for e in q2}["CVE-2026-1"] == 1


def test_unparseable_line_skipped_with_warning(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    """Defensive: a corrupt entry must not poison the whole queue."""
    path = tmp_path / "q.jsonl"
    path.write_text(
        json.dumps({"cve_id": "CVE-2024-1", "attempts": 1, "first_seen": "x",
                    "last_seen": "y", "last_error": "z"}) + "\n"
        + "not json\n"
        + json.dumps({"cve_id": "CVE-2024-2", "attempts": 2, "first_seen": "x",
                      "last_seen": "y", "last_error": "z"}) + "\n"
    )
    out = read_queue(path)
    assert [e.cve_id for e in out] == ["CVE-2024-1", "CVE-2024-2"]


# ─── update_queue: action -> outcome ────────────────────────────────────────


def test_fetch_failed_added_to_queue() -> None:
    summary = [{"cve_id": "CVE-2024-1", "action": "fetch-failed", "reason": "NVD 503"}]
    new_q = update_queue(
        existing=[],
        run_summary=summary,
        run_at="2026-04-29T17:00:00Z",
        max_attempts=3,
    )
    assert len(new_q) == 1
    assert new_q[0].cve_id == "CVE-2024-1"
    assert new_q[0].attempts == 1
    assert new_q[0].first_seen == "2026-04-29T17:00:00Z"
    assert new_q[0].last_seen == "2026-04-29T17:00:00Z"
    assert "503" in new_q[0].last_error


def test_rate_limited_added_to_queue() -> None:
    summary = [{"cve_id": "CVE-2024-1", "action": "rate-limited", "reason": "60s"}]
    new_q = update_queue(existing=[], run_summary=summary, run_at="2026-04-29T17:00:00Z", max_attempts=3)
    assert new_q[0].cve_id == "CVE-2024-1"


def test_existing_retry_re_failing_increments_attempts() -> None:
    existing = [_entry("CVE-2024-1", attempts=1)]
    summary = [{"cve_id": "CVE-2024-1", "action": "fetch-failed", "reason": "still 503"}]
    new_q = update_queue(existing=existing, run_summary=summary, run_at="2026-04-29T17:00:00Z", max_attempts=3)
    assert new_q[0].attempts == 2
    # first_seen preserved across retries
    assert new_q[0].first_seen == "2026-04-29T15:00:00Z"
    assert new_q[0].last_seen == "2026-04-29T17:00:00Z"
    assert "still 503" in new_q[0].last_error


def test_max_attempts_drops_entry(capsys: pytest.CaptureFixture[str]) -> None:
    """Once a CVE has hit max_attempts and STILL fails, it's dropped
    from the queue with a warning. The data point is lost; better
    that than infinite retry."""
    existing = [_entry("CVE-2024-1", attempts=3)]
    summary = [{"cve_id": "CVE-2024-1", "action": "fetch-failed", "reason": "still 503"}]
    new_q = update_queue(existing=existing, run_summary=summary, run_at="2026-04-29T17:00:00Z", max_attempts=3)
    assert new_q == []
    err = capsys.readouterr().err
    assert "CVE-2024-1" in err
    assert "dropping" in err.lower() or "dropped" in err.lower()


def test_successful_outcome_removes_from_queue() -> None:
    """When a previously-queued CVE finally succeeds, drop it."""
    existing = [_entry("CVE-2024-1", attempts=2)]
    summary = [{"cve_id": "CVE-2024-1", "action": "skipped-irrelevant", "reason": "no-match"}]
    new_q = update_queue(existing=existing, run_summary=summary, run_at="2026-04-29T17:00:00Z", max_attempts=3)
    assert new_q == []


def test_written_outcome_removes_from_queue() -> None:
    existing = [_entry("CVE-2024-1", attempts=2)]
    summary = [{"cve_id": "CVE-2024-1", "action": "written", "reason": "hit",
                "finding_status": "finding", "resolver_status": "eligible"}]
    new_q = update_queue(existing=existing, run_summary=summary, run_at="2026-04-29T17:00:00Z", max_attempts=3)
    assert new_q == []


def test_cve_not_in_summary_kept_in_queue() -> None:
    """If a CVE was queued but the next run didn't process it (capped
    out, or schedule lag), it stays queued for the run after."""
    existing = [_entry("CVE-2024-1", attempts=1), _entry("CVE-2024-2", attempts=1)]
    summary = [{"cve_id": "CVE-2024-1", "action": "fetch-failed", "reason": "x"}]
    new_q = update_queue(existing=existing, run_summary=summary, run_at="2026-04-29T17:00:00Z", max_attempts=3)
    cve_ids = sorted(e.cve_id for e in new_q)
    assert cve_ids == ["CVE-2024-1", "CVE-2024-2"]


def test_error_action_added_to_queue() -> None:
    """batch_cli emits action=error for unexpected exceptions; those
    are also queue-worthy (next run might find a healed upstream)."""
    summary = [{"cve_id": "CVE-2024-1", "action": "error", "reason": "boom"}]
    new_q = update_queue(existing=[], run_summary=summary, run_at="2026-04-29T17:00:00Z", max_attempts=3)
    assert len(new_q) == 1
    assert new_q[0].cve_id == "CVE-2024-1"


# ─── cve_ids_for_retry: emits dedupe-friendly id list ────────────────────────


def test_emit_returns_cve_ids_in_first_seen_order() -> None:
    """Older retries get processed first so they have a chance to
    progress through max_attempts before being dropped."""
    queue = [
        RetryEntry("CVE-2024-2", 1, "2026-04-29T16:00:00Z", "2026-04-29T16:00:00Z", "x"),
        RetryEntry("CVE-2024-1", 2, "2026-04-29T15:00:00Z", "2026-04-29T16:00:00Z", "x"),
        RetryEntry("CVE-2024-3", 1, "2026-04-29T17:00:00Z", "2026-04-29T17:00:00Z", "x"),
    ]
    assert cve_ids_for_retry(queue) == ["CVE-2024-1", "CVE-2024-2", "CVE-2024-3"]


def test_emit_empty_when_queue_empty() -> None:
    assert cve_ids_for_retry([]) == []
