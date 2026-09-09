"""Backfill CLI tests.

Backfill is a deliberate, gated catch-up over a wider window than the
hourly cron. It reuses the existing list_recent_cves -> batch_cli
pipeline; this module's value is the wrapper + aggregation summary.

Tests mock both list_recent_cves and the batch processing so the suite
stays offline. Live runs are gated on real NVD/network access.
"""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any
from unittest.mock import patch

import pytest

from agents.scout import backfill_cli


_SNAPSHOT = [
    {
        "attr_path": "libtiff",
        "drv_path": "attr:libtiff",
        "pname": "libtiff",
        "version": "4.7.1",
        "cpes": [],
        "purls": [],
        "src_url": None,
        "src_hash": None,
    }
]


def _write_inputs(tmp_path: Path) -> tuple[Path, Path, Path]:
    snap = tmp_path / "snap.json"
    snap.write_text(json.dumps(_SNAPSHOT))
    inbox = tmp_path / "inbox"
    output_dir = tmp_path / "out"
    return snap, inbox, output_dir


def _stub_batch_cli(
    summary_lines: list[dict[str, Any]],
) -> Any:
    """Replace batch_cli.main with a stub that writes the supplied
    summary lines to the --output-jsonl arg and returns 0."""

    def stub(argv: list[str]) -> int:
        out_jsonl = Path(argv[argv.index("--output-jsonl") + 1])
        out_jsonl.parent.mkdir(parents=True, exist_ok=True)
        with out_jsonl.open("w") as f:
            for r in summary_lines:
                f.write(json.dumps(r) + "\n")
        return 0

    return stub


def test_requires_explicit_window(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """Backfill must be opted into; no --since-days default catches all
    history. Per user constraint: gated behind explicit args."""
    snap, inbox, out_dir = _write_inputs(tmp_path)
    rc = backfill_cli.main(
        [
            "--graph-snapshot",
            str(snap),
            "--inbox",
            str(inbox),
            "--output-dir",
            str(out_dir),
        ]
    )
    assert rc == 64
    err = capsys.readouterr().err.lower()
    assert "since-days" in err or "since" in err


def test_discover_to_aggregate_writes_run_summary_and_counts(tmp_path: Path) -> None:
    snap, inbox, out_dir = _write_inputs(tmp_path)
    discovered = ["CVE-2024-1", "CVE-2024-2", "CVE-2024-3", "CVE-2024-4", "CVE-2024-5"]
    summary = [
        {"cve_id": "CVE-2024-1", "action": "skipped-irrelevant"},
        {"cve_id": "CVE-2024-2", "action": "skipped-irrelevant"},
        {
            "cve_id": "CVE-2024-3",
            "action": "written",
            "finding_status": "finding",
            "resolver_status": "eligible",
            "steward_state": "auto-merge-eligible",
            "steward_reasons": ["eligible-high-confidence"],
        },
        {
            "cve_id": "CVE-2024-4",
            "action": "written",
            "finding_status": "finding",
            "resolver_status": "eligible-requires-human-review",
            "steward_state": "human-review-required",
            "steward_reasons": [
                "upstream-ref-requires-human-review:major-version-jump"
            ],
        },
        {
            "cve_id": "CVE-2024-5",
            "action": "written",
            "finding_status": "finding",
            "resolver_status": "ineligible-no-fix-available",
            "steward_state": "advisory-only",
            "steward_reasons": ["upstream-ref-ineligible:no-fix-available"],
        },
    ]
    with (
        patch.object(backfill_cli, "list_recent_cves", return_value=discovered),
        patch.object(backfill_cli, "_run_batch", side_effect=_stub_batch_cli(summary)),
    ):
        rc = backfill_cli.main(
            [
                "--since-days",
                "7",
                "--graph-snapshot",
                str(snap),
                "--inbox",
                str(inbox),
                "--output-dir",
                str(out_dir),
            ]
        )
    assert rc == 0
    assert (out_dir / "run-summary.jsonl").is_file()
    assert (out_dir / "aggregate-counts.json").is_file()
    counts = json.loads((out_dir / "aggregate-counts.json").read_text())
    assert counts["discovered"] == 5
    assert counts["actions"] == {"skipped-irrelevant": 2, "written": 3}
    assert counts["steward_states"] == {
        "auto-merge-eligible": 1,
        "human-review-required": 1,
        "advisory-only": 1,
    }
    assert (
        counts["reason_codes"]["upstream-ref-requires-human-review:major-version-jump"]
        == 1
    )
    assert counts["reason_codes"]["upstream-ref-ineligible:no-fix-available"] == 1
    assert counts["reason_codes"]["eligible-high-confidence"] == 1
    assert counts["resolver_verdicts"] == {
        "eligible": 1,
        "eligible-requires-human-review": 1,
        "ineligible-no-fix-available": 1,
    }
    assert counts["window"]["since"].endswith("Z")
    assert counts["window"]["until"].endswith("Z")
    assert counts["window"]["days"] == 7


def test_cap_limits_processed_count(tmp_path: Path) -> None:
    """Cap is enforced AFTER discovery: the discovered total reflects
    what NVD returned, but only the first --cap CVEs are processed."""
    snap, inbox, out_dir = _write_inputs(tmp_path)
    discovered = [f"CVE-2024-{i}" for i in range(20)]
    captured_argv: list[list[str]] = []

    def stub(argv: list[str]) -> int:
        captured_argv.append(list(argv))
        ids_file = Path(argv[argv.index("--cve-ids-file") + 1])
        cap_count = len(ids_file.read_text().splitlines())
        out_jsonl = Path(argv[argv.index("--output-jsonl") + 1])
        out_jsonl.parent.mkdir(parents=True, exist_ok=True)
        with out_jsonl.open("w") as f:
            for i in range(cap_count):
                f.write(
                    json.dumps(
                        {"cve_id": f"CVE-2024-{i}", "action": "skipped-irrelevant"}
                    )
                    + "\n"
                )
        return 0

    with (
        patch.object(backfill_cli, "list_recent_cves", return_value=discovered),
        patch.object(backfill_cli, "_run_batch", side_effect=stub),
    ):
        backfill_cli.main(
            [
                "--since-days",
                "7",
                "--graph-snapshot",
                str(snap),
                "--inbox",
                str(inbox),
                "--output-dir",
                str(out_dir),
                "--cap",
                "5",
            ]
        )
    counts = json.loads((out_dir / "aggregate-counts.json").read_text())
    assert counts["discovered"] == 20
    assert counts["processed"] == 5
    assert counts["cap_applied"] is True


def test_no_cap_processes_all(tmp_path: Path) -> None:
    snap, inbox, out_dir = _write_inputs(tmp_path)
    discovered = [f"CVE-2024-{i}" for i in range(3)]
    summary = [{"cve_id": cid, "action": "skipped-irrelevant"} for cid in discovered]
    with (
        patch.object(backfill_cli, "list_recent_cves", return_value=discovered),
        patch.object(backfill_cli, "_run_batch", side_effect=_stub_batch_cli(summary)),
    ):
        backfill_cli.main(
            [
                "--since-days",
                "7",
                "--graph-snapshot",
                str(snap),
                "--inbox",
                str(inbox),
                "--output-dir",
                str(out_dir),
            ]
        )
    counts = json.loads((out_dir / "aggregate-counts.json").read_text())
    assert counts["discovered"] == 3
    assert counts["processed"] == 3
    assert counts["cap_applied"] is False


def test_cpe_index_threaded_when_provided(tmp_path: Path) -> None:
    snap, inbox, out_dir = _write_inputs(tmp_path)
    cpe_index = tmp_path / "cpe-index.json"
    cpe_index.write_text(json.dumps({"libtiff": []}))
    discovered = ["CVE-2024-1"]
    captured: list[list[str]] = []

    def stub(argv: list[str]) -> int:
        captured.append(list(argv))
        return _stub_batch_cli(
            [{"cve_id": "CVE-2024-1", "action": "skipped-irrelevant"}]
        )(argv)

    with (
        patch.object(backfill_cli, "list_recent_cves", return_value=discovered),
        patch.object(backfill_cli, "_run_batch", side_effect=stub),
    ):
        backfill_cli.main(
            [
                "--since-days",
                "7",
                "--graph-snapshot",
                str(snap),
                "--inbox",
                str(inbox),
                "--output-dir",
                str(out_dir),
                "--cpe-index",
                str(cpe_index),
            ]
        )
    assert "--cpe-index" in captured[0]
    assert str(cpe_index) in captured[0]


def test_zero_discovered_emits_zero_counts(tmp_path: Path) -> None:
    snap, inbox, out_dir = _write_inputs(tmp_path)
    with (
        patch.object(backfill_cli, "list_recent_cves", return_value=[]),
        patch.object(backfill_cli, "_run_batch", side_effect=_stub_batch_cli([])),
    ):
        rc = backfill_cli.main(
            [
                "--since-days",
                "1",
                "--graph-snapshot",
                str(snap),
                "--inbox",
                str(inbox),
                "--output-dir",
                str(out_dir),
            ]
        )
    assert rc == 0
    counts = json.loads((out_dir / "aggregate-counts.json").read_text())
    assert counts["discovered"] == 0
    assert counts["processed"] == 0
    assert counts["actions"] == {}
    assert counts["steward_states"] == {}
    assert counts["reason_codes"] == {}


def test_window_is_capped_at_120_days(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """NVD's pubStartDate/pubEndDate API has a 120-day max-range
    constraint. Backfill rejects larger windows up front."""
    snap, inbox, out_dir = _write_inputs(tmp_path)
    rc = backfill_cli.main(
        [
            "--since-days",
            "121",
            "--graph-snapshot",
            str(snap),
            "--inbox",
            str(inbox),
            "--output-dir",
            str(out_dir),
        ]
    )
    assert rc == 64
    err = capsys.readouterr().err.lower()
    assert "120" in err
