"""retry_cli update --also-enqueue: displaced (discovered-but-unprocessed) ids
carry over into the queue; a missing sidecar file is a no-op."""

from __future__ import annotations

import json
from pathlib import Path

from agents.scout import retry_cli
from agents.scout.retry_queue import read_queue


def _write(path: Path, lines: list[str]) -> None:
    path.write_text("".join(s + "\n" for s in lines))


def _summary(path: Path, rows: list[dict]) -> None:
    path.write_text("".join(json.dumps(r) + "\n" for r in rows))


def test_update_also_enqueue_folds_displaced_ids(tmp_path: Path) -> None:
    queue = tmp_path / "retry.jsonl"
    _write(queue, [])
    summary = tmp_path / "run-summary.jsonl"
    # CVE-1 processed terminally this run; CVE-2 failed (retryable).
    _summary(
        summary,
        [
            {"cve_id": "CVE-2026-1", "action": "written"},
            {"cve_id": "CVE-2026-2", "action": "fetch-failed"},
        ],
    )
    displaced = tmp_path / "displaced.txt"
    # CVE-3 was discovered but never processed (overflowed the cap). By
    # construction the displaced set is disjoint from the processed set, so a
    # terminal id like CVE-1 never appears here.
    _write(displaced, ["CVE-2026-3"])

    rc = retry_cli.main(
        [
            "update",
            "--queue",
            str(queue),
            "--run-summary",
            str(summary),
            "--run-at",
            "2026-07-21T12:00:00Z",
            "--also-enqueue",
            str(displaced),
        ]
    )
    assert rc == 0
    by_id = {e.cve_id: e for e in read_queue(queue)}
    assert set(by_id) == {"CVE-2026-2", "CVE-2026-3"}  # CVE-1 handled, dropped
    assert by_id["CVE-2026-2"].attempts == 1  # genuine failure
    assert by_id["CVE-2026-3"].attempts == 0  # displaced, not a failure


def test_update_also_enqueue_missing_file_is_noop(tmp_path: Path) -> None:
    queue = tmp_path / "retry.jsonl"
    _write(queue, [])
    summary = tmp_path / "run-summary.jsonl"
    _summary(summary, [{"cve_id": "CVE-2026-2", "action": "fetch-failed"}])
    rc = retry_cli.main(
        [
            "update",
            "--queue",
            str(queue),
            "--run-summary",
            str(summary),
            "--run-at",
            "2026-07-21T12:00:00Z",
            "--also-enqueue",
            str(tmp_path / "absent.txt"),
        ]
    )
    assert rc == 0
    assert [e.cve_id for e in read_queue(queue)] == ["CVE-2026-2"]
