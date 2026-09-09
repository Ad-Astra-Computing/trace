"""batch_cli smoke tests. The poll/process units already have full
coverage; this exercises the loop, the JSONL output, the per-CVE
exception isolation, and the env-var threading."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any
from unittest.mock import patch

import pytest

from agents.scout import batch_cli
from agents.scout.poller import PollOutcome
from agents.scout.processor import ProcessOutcome


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


def _write_inputs(tmp_path: Path, cve_ids: list[str]) -> tuple[Path, Path, Path, Path]:
    snap = tmp_path / "snap.json"
    snap.write_text(json.dumps(_SNAPSHOT))
    cve_ids_file = tmp_path / "ids.txt"
    cve_ids_file.write_text("\n".join(cve_ids) + "\n")
    inbox = tmp_path / "inbox"
    out = tmp_path / "out.jsonl"
    return snap, cve_ids_file, inbox, out


def _poll(cve_id: str, action: str, **kw: Any) -> PollOutcome:
    return PollOutcome(
        cve_id=cve_id,
        action=action,
        reason=kw.get("reason", "x"),
        feed_used=kw.get("feed_used"),
        entry_path=kw.get("entry_path"),
        retry_after_seconds=kw.get("retry_after_seconds"),
    )


def _proc(
    cve_id: str, finding: str = "finding", verdict: str = "eligible"
) -> ProcessOutcome:
    return ProcessOutcome(
        cve_id=cve_id,
        entry_path=Path("/dev/null"),
        finding_status=finding,
        resolver_status=verdict,
    )


def test_each_cve_emits_one_jsonl_record(tmp_path: Path) -> None:
    snap, ids, inbox, out = _write_inputs(
        tmp_path, ["CVE-2024-1", "CVE-2024-2", "CVE-2024-3"]
    )
    polls = {
        "CVE-2024-1": _poll("CVE-2024-1", "skipped-irrelevant", reason="no-match"),
        "CVE-2024-2": _poll("CVE-2024-2", "fetch-failed", reason="404"),
        "CVE-2024-3": _poll(
            "CVE-2024-3",
            "written",
            entry_path=tmp_path / "inbox" / "CVE-2024-3",
            feed_used="dossier",
        ),
    }
    with (
        patch.object(
            batch_cli, "poll_one", side_effect=lambda cve_id, **_: polls[cve_id]
        ) as p,
        patch.object(batch_cli, "process_entry", return_value=_proc("CVE-2024-3")) as q,
    ):
        rc = batch_cli.main(
            [
                "--cve-ids-file",
                str(ids),
                "--graph-snapshot",
                str(snap),
                "--inbox",
                str(inbox),
                "--output-jsonl",
                str(out),
            ]
        )

    assert rc == 0
    rows = [json.loads(line) for line in out.read_text().splitlines()]
    assert len(rows) == 3
    assert rows[0]["action"] == "skipped-irrelevant"
    assert rows[1]["action"] == "fetch-failed"
    assert rows[2]["action"] == "written"
    assert rows[2]["finding_status"] == "finding"
    assert rows[2]["resolver_status"] == "eligible"
    # process_entry only called for the `written` CVE
    assert q.call_count == 1


def test_per_cve_exception_does_not_stop_batch(tmp_path: Path) -> None:
    snap, ids, inbox, out = _write_inputs(tmp_path, ["CVE-2024-1", "CVE-2024-2"])

    def poll_side_effect(cve_id: str, **_: Any) -> PollOutcome:
        if cve_id == "CVE-2024-1":
            raise RuntimeError("boom")
        return _poll(cve_id, "skipped-irrelevant")

    with patch.object(batch_cli, "poll_one", side_effect=poll_side_effect):
        rc = batch_cli.main(
            [
                "--cve-ids-file",
                str(ids),
                "--graph-snapshot",
                str(snap),
                "--inbox",
                str(inbox),
                "--output-jsonl",
                str(out),
            ]
        )

    assert rc == 0
    rows = [json.loads(line) for line in out.read_text().splitlines()]
    assert len(rows) == 2
    assert rows[0]["action"] == "error"
    assert "boom" in rows[0]["reason"]
    assert rows[1]["action"] == "skipped-irrelevant"


def test_blank_lines_in_cve_ids_file_skipped(tmp_path: Path) -> None:
    snap, _, inbox, out = _write_inputs(tmp_path, [])
    ids_file = tmp_path / "ids2.txt"
    ids_file.write_text("CVE-2024-1\n\n\nCVE-2024-2\n   \n")
    with patch.object(
        batch_cli,
        "poll_one",
        side_effect=lambda cve_id, **_: _poll(cve_id, "skipped-irrelevant"),
    ):
        batch_cli.main(
            [
                "--cve-ids-file",
                str(ids_file),
                "--graph-snapshot",
                str(snap),
                "--inbox",
                str(inbox),
                "--output-jsonl",
                str(out),
            ]
        )
    rows = [json.loads(line) for line in out.read_text().splitlines()]
    assert [r["cve_id"] for r in rows] == ["CVE-2024-1", "CVE-2024-2"]


def test_missing_cve_ids_file_returns_usage(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    snap, _, inbox, out = _write_inputs(tmp_path, [])
    rc = batch_cli.main(
        [
            "--cve-ids-file",
            str(tmp_path / "absent.txt"),
            "--graph-snapshot",
            str(snap),
            "--inbox",
            str(inbox),
            "--output-jsonl",
            str(out),
        ]
    )
    assert rc == 64
    assert "not found" in capsys.readouterr().err


def test_missing_snapshot_returns_usage(tmp_path: Path) -> None:
    _, ids, inbox, out = _write_inputs(tmp_path, ["CVE-2024-1"])
    rc = batch_cli.main(
        [
            "--cve-ids-file",
            str(ids),
            "--graph-snapshot",
            str(tmp_path / "absent-snap.json"),
            "--inbox",
            str(inbox),
            "--output-jsonl",
            str(out),
        ]
    )
    assert rc == 64


def test_nvd_api_key_threaded(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    snap, ids, inbox, out = _write_inputs(tmp_path, ["CVE-2024-1"])
    monkeypatch.setenv("NVD_API_KEY", "key-abc")
    with patch.object(
        batch_cli, "poll_one", return_value=_poll("CVE-2024-1", "skipped-irrelevant")
    ) as p:
        batch_cli.main(
            [
                "--cve-ids-file",
                str(ids),
                "--graph-snapshot",
                str(snap),
                "--inbox",
                str(inbox),
                "--output-jsonl",
                str(out),
            ]
        )
    assert p.call_args.kwargs["nvd_api_key"] == "key-abc"


def test_cpe_index_enriches_records_before_graph_built(tmp_path: Path) -> None:
    """When --cpe-index is passed, snapshot records are enriched with
    real CPEs before the GraphLookup is built. The enriched record is
    what poll_one's graph parameter sees."""
    snap, ids, inbox, out = _write_inputs(tmp_path, ["CVE-2024-1"])
    cpe_index_path = tmp_path / "cpe-index.json"
    cpe_index_path.write_text(
        json.dumps(
            {
                "libtiff": [
                    "cpe:2.3:a:libtiff:libtiff:4.7.0:*:*:*:*:*:*:*",
                    "cpe:2.3:a:libtiff:libtiff:4.6.0:*:*:*:*:*:*:*",
                ]
            }
        )
    )
    captured: dict[str, Any] = {}

    def poll_capturing(cve_id: str, **kwargs: Any) -> PollOutcome:
        captured["graph"] = kwargs["graph"]
        return _poll(cve_id, "skipped-irrelevant")

    with patch.object(batch_cli, "poll_one", side_effect=poll_capturing):
        batch_cli.main(
            [
                "--cve-ids-file",
                str(ids),
                "--graph-snapshot",
                str(snap),
                "--inbox",
                str(inbox),
                "--output-jsonl",
                str(out),
                "--cpe-index",
                str(cpe_index_path),
            ]
        )

    graph = captured["graph"]
    assert graph.find_by_cpe("cpe:2.3:a:libtiff:libtiff:4.7.0:*:*:*:*:*:*:*"), (
        "enrichment should have indexed the libtiff CPE"
    )


def test_missing_cpe_index_returns_usage(tmp_path: Path) -> None:
    snap, ids, inbox, out = _write_inputs(tmp_path, ["CVE-2024-1"])
    rc = batch_cli.main(
        [
            "--cve-ids-file",
            str(ids),
            "--graph-snapshot",
            str(snap),
            "--inbox",
            str(inbox),
            "--output-jsonl",
            str(out),
            "--cpe-index",
            str(tmp_path / "absent-cpe-index.json"),
        ]
    )
    assert rc == 64


def test_output_jsonl_parent_created(tmp_path: Path) -> None:
    snap, ids, inbox, _ = _write_inputs(tmp_path, ["CVE-2024-1"])
    nested = tmp_path / "nested" / "deep" / "out.jsonl"
    with patch.object(
        batch_cli, "poll_one", return_value=_poll("CVE-2024-1", "skipped-irrelevant")
    ):
        rc = batch_cli.main(
            [
                "--cve-ids-file",
                str(ids),
                "--graph-snapshot",
                str(snap),
                "--inbox",
                str(inbox),
                "--output-jsonl",
                str(nested),
            ]
        )
    assert rc == 0
    assert nested.is_file()
