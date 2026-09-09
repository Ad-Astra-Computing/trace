"""Snapshot CLI smoke tests.

The builder is covered by test_snapshot_builder. This exercises argv
parsing, exit-code mapping, and the JSON written to --out.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any
from unittest.mock import patch

import pytest

from agents.scout import snapshot_cli
from agents.scout.graph_lookup import GraphMatch
from agents.scout.snapshot_builder import SnapshotBuildError


def _records() -> list[GraphMatch]:
    return [
        GraphMatch(
            attr_path="libtiff",
            drv_path="attr:libtiff",
            pname="libtiff",
            version="4.7.1",
        )
    ]


def test_writes_snapshot_to_out_path(tmp_path: Path) -> None:
    out = tmp_path / "snap.json"
    with patch.object(snapshot_cli, "build_snapshot", return_value=_records()):
        rc = snapshot_cli.main(["--out", str(out)])
    assert rc == 0
    assert out.is_file()
    parsed = json.loads(out.read_text())
    assert isinstance(parsed, list)
    assert parsed[0]["attr_path"] == "libtiff"


def test_creates_parent_dirs(tmp_path: Path) -> None:
    out = tmp_path / "deep" / "dir" / "snap.json"
    with patch.object(snapshot_cli, "build_snapshot", return_value=_records()):
        rc = snapshot_cli.main(["--out", str(out)])
    assert rc == 0
    assert out.is_file()


def test_build_failure_exits_ten(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    with patch.object(
        snapshot_cli, "build_snapshot", side_effect=SnapshotBuildError("nope")
    ):
        rc = snapshot_cli.main(["--out", str(tmp_path / "snap.json")])
    assert rc == 10
    assert "nope" in capsys.readouterr().err


def test_nixpkgs_arg_threaded_to_builder(tmp_path: Path) -> None:
    with patch.object(snapshot_cli, "build_snapshot", return_value=[]) as mock_build:
        snapshot_cli.main(
            [
                "--nixpkgs",
                "/path/to/nixpkgs",
                "--out",
                str(tmp_path / "snap.json"),
            ]
        )
    assert mock_build.call_args.kwargs["nixpkgs"] == "/path/to/nixpkgs"


def test_default_nixpkgs_is_angle_bracket(tmp_path: Path) -> None:
    with patch.object(snapshot_cli, "build_snapshot", return_value=[]) as mock_build:
        snapshot_cli.main(["--out", str(tmp_path / "snap.json")])
    assert mock_build.call_args.kwargs["nixpkgs"] == "<nixpkgs>"


def test_timeout_arg_threaded(tmp_path: Path) -> None:
    with patch.object(snapshot_cli, "build_snapshot", return_value=[]) as mock_build:
        snapshot_cli.main(["--out", str(tmp_path / "snap.json"), "--timeout-s", "60"])
    assert mock_build.call_args.kwargs["timeout_s"] == 60


def test_summary_printed_to_stderr(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    with patch.object(snapshot_cli, "build_snapshot", return_value=_records()):
        snapshot_cli.main(["--out", str(tmp_path / "snap.json")])
    err = capsys.readouterr().err
    assert "1 records" in err or "1 record" in err
