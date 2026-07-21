"""nix_seed_ledger_cli update: end-to-end fold of a run summary + emit sidecar
into the persisted ledger."""

from __future__ import annotations

import json
from pathlib import Path

from agents.scout import nix_seed_ledger_cli
from agents.scout.nix_seed_ledger import read_ledger


def _write_jsonl(path: Path, rows: list[dict]) -> None:
    path.write_text("".join(json.dumps(r, sort_keys=True) + "\n" for r in rows))


def test_update_folds_terminal_outcomes(tmp_path: Path) -> None:
    ledger = tmp_path / "seen.jsonl"
    sidecar = tmp_path / "emitted.jsonl"
    summary = tmp_path / "run-summary.jsonl"
    _write_jsonl(sidecar, [
        {"cve_id": "CVE-2026-1001", "fingerprint": "u:x"},
        {"cve_id": "CVE-2026-1002", "fingerprint": "u:y"},
    ])
    _write_jsonl(summary, [
        {"cve_id": "CVE-2026-1001", "action": "written"},
        {"cve_id": "CVE-2026-1002", "action": "skipped-irrelevant"},
    ])
    rc = nix_seed_ledger_cli.main([
        "update", "--ledger", str(ledger), "--sidecar", str(sidecar),
        "--run-summary", str(summary), "--run-at", "2026-07-21T12:00:00Z",
    ])
    assert rc == 0
    got = read_ledger(ledger)
    assert got["CVE-2026-1001"].outcome == "written"
    assert got["CVE-2026-1001"].last_evaluated == "2026-07-21T12:00:00Z"
    assert got["CVE-2026-1002"].outcome == "skipped-irrelevant"


def test_update_missing_sidecar_is_noop(tmp_path: Path) -> None:
    ledger = tmp_path / "seen.jsonl"
    summary = tmp_path / "run-summary.jsonl"
    _write_jsonl(summary, [{"cve_id": "CVE-2026-1001", "action": "written"}])
    rc = nix_seed_ledger_cli.main([
        "update", "--ledger", str(ledger), "--sidecar", str(tmp_path / "absent.jsonl"),
        "--run-summary", str(summary), "--run-at", "2026-07-21T12:00:00Z",
    ])
    assert rc == 0
    assert not ledger.exists()  # nothing written


def test_update_missing_run_summary_is_usage_error(tmp_path: Path) -> None:
    ledger = tmp_path / "seen.jsonl"
    sidecar = tmp_path / "emitted.jsonl"
    _write_jsonl(sidecar, [{"cve_id": "CVE-2026-1001", "fingerprint": "u:x"}])
    rc = nix_seed_ledger_cli.main([
        "update", "--ledger", str(ledger), "--sidecar", str(sidecar),
        "--run-summary", str(tmp_path / "absent.jsonl"), "--run-at", "t",
    ])
    assert rc == 64
