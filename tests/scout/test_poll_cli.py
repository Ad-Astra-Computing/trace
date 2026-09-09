"""Scout poll CLI smoke tests.

The orchestrator (poll_one) is already covered by tests/scout/test_poller.py.
This file exercises the argv parsing, snapshot loader, exit-code mapping,
and the JSON record printed to stdout.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any
from unittest.mock import patch, MagicMock

import pytest

from agents.scout import poll_cli
from agents.scout.poller import PollOutcome


_SNAPSHOT = [
    {
        "attr_path": "libtiff",
        "drv_path": "/nix/store/aaa-libtiff.drv",
        "pname": "libtiff",
        "version": "4.7.0",
        "cpes": ["cpe:2.3:a:libtiff:libtiff:*:*:*:*:*:*:*:*"],
        "purls": [],
        "src_url": None,
        "src_hash": None,
    }
]


def _write_snapshot(tmp_path: Path, records: Any = None) -> Path:
    path = tmp_path / "snapshot.json"
    path.write_text(json.dumps(_SNAPSHOT if records is None else records))
    return path


def test_missing_snapshot_returns_usage_exit(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    rc = poll_cli.main(
        [
            "CVE-2024-13978",
            "--graph-snapshot",
            str(tmp_path / "absent.json"),
            "--inbox",
            str(tmp_path / "inbox"),
        ]
    )
    assert rc == 64
    err = capsys.readouterr().err
    assert "graph snapshot not found" in err


def test_malformed_snapshot_returns_usage_exit(tmp_path: Path) -> None:
    path = tmp_path / "snap.json"
    path.write_text('{"not": "an array"}')
    rc = poll_cli.main(
        [
            "CVE-2024-13978",
            "--graph-snapshot",
            str(path),
            "--inbox",
            str(tmp_path / "inbox"),
        ]
    )
    assert rc == 64


def test_invalid_cve_id_returns_usage_exit(tmp_path: Path) -> None:
    snap = _write_snapshot(tmp_path)
    rc = poll_cli.main(
        [
            "not-a-cve",
            "--graph-snapshot",
            str(snap),
            "--inbox",
            str(tmp_path / "inbox"),
        ]
    )
    assert rc == 64


def _patched(action: str, **outcome_kw: Any) -> Any:
    return PollOutcome(
        cve_id="CVE-2024-13978",
        action=action,
        reason=outcome_kw.get("reason", "x"),
        feed_used=outcome_kw.get("feed_used"),
        entry_path=outcome_kw.get("entry_path"),
        retry_after_seconds=outcome_kw.get("retry_after_seconds"),
    )


def test_written_outcome_returns_zero_and_prints_record(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    snap = _write_snapshot(tmp_path)
    entry = tmp_path / "inbox" / "CVE-2024-13978"
    fake = _patched("written", feed_used="dossier", entry_path=entry)
    with patch.object(poll_cli, "poll_one", return_value=fake) as mock_poll:
        rc = poll_cli.main(
            [
                "CVE-2024-13978",
                "--graph-snapshot",
                str(snap),
                "--inbox",
                str(tmp_path / "inbox"),
            ]
        )
    assert rc == 0
    record = json.loads(capsys.readouterr().out)
    assert record["action"] == "written"
    assert record["feed_used"] == "dossier"
    assert record["entry_path"].endswith("CVE-2024-13978")
    mock_poll.assert_called_once()


def test_skipped_irrelevant_returns_zero(tmp_path: Path) -> None:
    snap = _write_snapshot(tmp_path)
    fake = _patched("skipped-irrelevant", reason="no-match")
    with patch.object(poll_cli, "poll_one", return_value=fake):
        rc = poll_cli.main(
            [
                "CVE-2024-13978",
                "--graph-snapshot",
                str(snap),
                "--inbox",
                str(tmp_path / "inbox"),
            ]
        )
    assert rc == 0


def test_fetch_failed_returns_ten(tmp_path: Path) -> None:
    snap = _write_snapshot(tmp_path)
    fake = _patched("fetch-failed", reason="404")
    with patch.object(poll_cli, "poll_one", return_value=fake):
        rc = poll_cli.main(
            [
                "CVE-2024-13978",
                "--graph-snapshot",
                str(snap),
                "--inbox",
                str(tmp_path / "inbox"),
            ]
        )
    assert rc == 10


def test_rate_limited_returns_twenty(tmp_path: Path) -> None:
    snap = _write_snapshot(tmp_path)
    fake = _patched("rate-limited", retry_after_seconds=120)
    with patch.object(poll_cli, "poll_one", return_value=fake):
        rc = poll_cli.main(
            [
                "CVE-2024-13978",
                "--graph-snapshot",
                str(snap),
                "--inbox",
                str(tmp_path / "inbox"),
            ]
        )
    assert rc == 20


def test_nvd_api_key_lifted_from_env(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    snap = _write_snapshot(tmp_path)
    monkeypatch.setenv("NVD_API_KEY", "abc-123")
    fake = _patched("written", feed_used="dossier", entry_path=tmp_path / "x")
    with patch.object(poll_cli, "poll_one", return_value=fake) as mock_poll:
        poll_cli.main(
            [
                "CVE-2024-13978",
                "--graph-snapshot",
                str(snap),
                "--inbox",
                str(tmp_path / "inbox"),
            ]
        )
    assert mock_poll.call_args.kwargs["nvd_api_key"] == "abc-123"


def test_no_nvd_api_key_passes_none(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    snap = _write_snapshot(tmp_path)
    monkeypatch.delenv("NVD_API_KEY", raising=False)
    fake = _patched("written", feed_used="dossier", entry_path=tmp_path / "x")
    with patch.object(poll_cli, "poll_one", return_value=fake) as mock_poll:
        poll_cli.main(
            [
                "CVE-2024-13978",
                "--graph-snapshot",
                str(snap),
                "--inbox",
                str(tmp_path / "inbox"),
            ]
        )
    assert mock_poll.call_args.kwargs["nvd_api_key"] is None
