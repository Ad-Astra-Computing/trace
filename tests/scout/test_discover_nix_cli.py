"""discover_nix_cli smoke tests. The snapshot client is covered by
test_nix_discovery; this exercises argv parsing, exit-code mapping,
CVE-id fan-out (an entry may carry several cve ids), dedup, and the
optional client-side published-at window filter."""

from __future__ import annotations

from typing import Any
from unittest.mock import patch

import pytest

from agents.scout import discover_nix_cli
from agents.scout.feed_client import FeedRateLimit, FeedTransientError
from agents.scout.nix_discovery import NixCvesSnapshot, NixpkgsCve

# Ledger TTL is measured against the real clock (discover_nix_cli uses
# datetime.now()), so a hardcoded last_evaluated date silently ages past the
# default 30-day TTL and flips skip tests to re-emit. Compute it relative to
# now so these tests stay stable over time.
from datetime import datetime, timedelta, timezone

_RECENT_EVAL = (datetime.now(timezone.utc) - timedelta(days=1)).strftime(
    "%Y-%m-%dT%H:%M:%SZ"
)


def _cve(
    cid: str, published: str = "2026-07-20T00:00:00Z", cve_ids: list[str] | None = None
) -> NixpkgsCve:
    return NixpkgsCve(
        nixpkgs_id=f"NIXPKGS-{cid}",
        cve_id=cid,
        cve_ids=cve_ids or [cid],
        status="open",
        published_at=published,
    )


def _snap(entries: list[NixpkgsCve]) -> NixCvesSnapshot:
    return NixCvesSnapshot(
        entries=entries,
        count=len(entries),
        source="github",
        request_url="x",
        fetched_at="t",
        response_sha256="0" * 64,
        capped=False,
    )


def test_emits_all_cve_ids_one_per_line(capsys: pytest.CaptureFixture[str]) -> None:
    with patch.object(
        discover_nix_cli,
        "list_nixpkgs_cves",
        return_value=_snap([_cve("CVE-2026-1001"), _cve("CVE-2026-1002")]),
    ):
        rc = discover_nix_cli.main([])
    assert rc == 0
    assert capsys.readouterr().out.strip().splitlines() == [
        "CVE-2026-1001",
        "CVE-2026-1002",
    ]


def test_multi_cve_entry_fans_out_all_ids(capsys: pytest.CaptureFixture[str]) -> None:
    # one entry covering two CVEs emits both ids.
    with patch.object(
        discover_nix_cli,
        "list_nixpkgs_cves",
        return_value=_snap(
            [_cve("CVE-2026-1001", cve_ids=["CVE-2026-1001", "CVE-2026-1002"])]
        ),
    ):
        rc = discover_nix_cli.main([])
    assert rc == 0
    assert capsys.readouterr().out.strip().splitlines() == [
        "CVE-2026-1001",
        "CVE-2026-1002",
    ]


def test_dedup_preserves_first_seen_order(capsys: pytest.CaptureFixture[str]) -> None:
    with patch.object(
        discover_nix_cli,
        "list_nixpkgs_cves",
        return_value=_snap(
            [
                _cve("CVE-2026-1001"),
                _cve("CVE-2026-1009", cve_ids=["CVE-2026-1009", "CVE-2026-1001"]),
            ]
        ),
    ):
        discover_nix_cli.main([])
    assert capsys.readouterr().out.strip().splitlines() == [
        "CVE-2026-1001",
        "CVE-2026-1009",
    ]


def test_non_cve_primary_id_is_dropped(capsys: pytest.CaptureFixture[str]) -> None:
    # a malformed cve_id ("" or a non-CVE token) must not reach the poll loop.
    with patch.object(
        discover_nix_cli,
        "list_nixpkgs_cves",
        return_value=_snap([_cve("GHSA-xxxx"), _cve("CVE-2026-1003")]),
    ):
        discover_nix_cli.main([])
    assert capsys.readouterr().out.strip().splitlines() == ["CVE-2026-1003"]


def test_window_filters_by_published_at() -> None:
    snap = _snap(
        [
            _cve("CVE-2026-1001", published="2026-07-05T00:00:00Z"),
            _cve("CVE-2026-1002", published="2026-07-18T00:00:00Z"),
        ]
    )
    with patch.object(discover_nix_cli, "list_nixpkgs_cves", return_value=snap):
        import io
        import contextlib

        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            rc = discover_nix_cli.main(
                ["--since", "2026-07-10T00:00:00Z", "--until", "2026-07-20T00:00:00Z"]
            )
    assert rc == 0
    assert buf.getvalue().strip().splitlines() == ["CVE-2026-1002"]


def test_window_keeps_unparseable_published_at() -> None:
    # a bad published_at must not silently drop a real candidate; fail open
    # into the window (the poll loop then confirms or drops it on its own).
    snap = _snap([_cve("CVE-2026-1001", published="garbage")])
    with patch.object(discover_nix_cli, "list_nixpkgs_cves", return_value=snap):
        import io
        import contextlib

        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            rc = discover_nix_cli.main(["--since", "2026-07-10T00:00:00Z"])
    assert rc == 0
    assert buf.getvalue().strip().splitlines() == ["CVE-2026-1001"]


def test_lookback_hours_and_since_mutually_exclusive(
    capsys: pytest.CaptureFixture[str],
) -> None:
    rc = discover_nix_cli.main(
        ["--since", "2026-07-01T00:00:00Z", "--lookback-hours", "24"]
    )
    assert rc == 64
    assert "mutually exclusive" in capsys.readouterr().err


def test_naive_since_rejected(capsys: pytest.CaptureFixture[str]) -> None:
    rc = discover_nix_cli.main(["--since", "2026-07-01T00:00:00"])
    assert rc == 64
    assert "timezone" in capsys.readouterr().err.lower()


def test_rate_limit_exits_twenty(capsys: pytest.CaptureFixture[str]) -> None:
    with patch.object(
        discover_nix_cli, "list_nixpkgs_cves", side_effect=FeedRateLimit(30)
    ):
        rc = discover_nix_cli.main([])
    assert rc == 20
    assert "30s" in capsys.readouterr().err


def test_transient_error_exits_ten() -> None:
    with patch.object(
        discover_nix_cli, "list_nixpkgs_cves", side_effect=FeedTransientError("nope")
    ):
        rc = discover_nix_cli.main([])
    assert rc == 10


def _write_ledger(path, rows):
    import json

    path.write_text("".join(json.dumps(r, sort_keys=True) + "\n" for r in rows))


def test_ledger_skips_terminally_seen_unchanged(tmp_path, capsys):
    # A CVE terminally evaluated at the same fingerprint, within TTL, is not re-emitted.
    ledger = tmp_path / "seen.jsonl"
    fp = (
        "h:" + "0" * 16
    )  # matches an all-default entry only if state matches; use updated_at instead
    _write_ledger(
        ledger,
        [
            {
                "cve_id": "CVE-2026-1001",
                "first_seen": "2026-07-20T00:00:00Z",
                "last_evaluated": _RECENT_EVAL,
                "outcome": "skipped-irrelevant",
                "fingerprint": "u:2026-07-19T00:00:00Z",
            }
        ],
    )
    entry = NixpkgsCve(
        nixpkgs_id="N",
        cve_id="CVE-2026-1001",
        cve_ids=["CVE-2026-1001"],
        status="open",
        published_at="2026-07-19T00:00:00Z",
        updated_at="2026-07-19T00:00:00Z",
    )
    new = NixpkgsCve(
        nixpkgs_id="N2",
        cve_id="CVE-2026-1002",
        cve_ids=["CVE-2026-1002"],
        status="open",
        published_at="2026-07-19T00:00:00Z",
        updated_at="2026-07-19T00:00:00Z",
    )
    with patch.object(
        discover_nix_cli, "list_nixpkgs_cves", return_value=_snap([entry, new])
    ):
        rc = discover_nix_cli.main(["--seen-ledger", str(ledger)])
    assert rc == 0
    # 1001 skipped (seen, unchanged), 1002 emitted (new)
    assert capsys.readouterr().out.strip().splitlines() == ["CVE-2026-1002"]


def test_ledger_re_emits_on_fingerprint_change(tmp_path, capsys):
    ledger = tmp_path / "seen.jsonl"
    _write_ledger(
        ledger,
        [
            {
                "cve_id": "CVE-2026-1001",
                "first_seen": "2026-07-20T00:00:00Z",
                "last_evaluated": _RECENT_EVAL,
                "outcome": "written",
                "fingerprint": "u:OLD",
            }
        ],
    )
    entry = NixpkgsCve(
        nixpkgs_id="N",
        cve_id="CVE-2026-1001",
        cve_ids=["CVE-2026-1001"],
        status="open",
        published_at="2026-07-19T00:00:00Z",
        updated_at="NEW",
    )
    with patch.object(
        discover_nix_cli, "list_nixpkgs_cves", return_value=_snap([entry])
    ):
        rc = discover_nix_cli.main(["--seen-ledger", str(ledger)])
    assert rc == 0
    assert capsys.readouterr().out.strip().splitlines() == ["CVE-2026-1001"]


def test_ledger_re_emits_when_second_record_changed(tmp_path, capsys):
    # A CVE spans two snapshot records (separate attrs). The ledger holds a
    # terminal entry matching the FIRST record's fingerprint. A change on the
    # SECOND record must still re-emit — the change signal aggregates all
    # records, not just the first seen (codex audit 2026-07-21).
    ledger = tmp_path / "seen.jsonl"
    _write_ledger(
        ledger,
        [
            {
                "cve_id": "CVE-2026-1001",
                "first_seen": "2026-07-20T00:00:00Z",
                "last_evaluated": _RECENT_EVAL,
                "outcome": "written",
                "fingerprint": "u:A",  # matches record #1 only
            }
        ],
    )
    rec1 = NixpkgsCve(
        nixpkgs_id="attr-a",
        cve_id="CVE-2026-1001",
        cve_ids=["CVE-2026-1001"],
        status="open",
        published_at="2026-07-19T00:00:00Z",
        updated_at="A",
    )
    rec2 = NixpkgsCve(
        nixpkgs_id="attr-b",
        cve_id="CVE-2026-1001",
        cve_ids=["CVE-2026-1001"],
        status="open",
        published_at="2026-07-19T00:00:00Z",
        updated_at="B",
    )
    with patch.object(
        discover_nix_cli, "list_nixpkgs_cves", return_value=_snap([rec1, rec2])
    ):
        rc = discover_nix_cli.main(["--seen-ledger", str(ledger)])
    assert rc == 0
    assert capsys.readouterr().out.strip().splitlines() == ["CVE-2026-1001"]


def test_ledger_skips_multi_record_when_aggregate_unchanged(tmp_path, capsys):
    # Same two-record CVE, but the ledger holds the AGGREGATE fingerprint and
    # nothing changed -> suppressed. Proves the aggregate is stable across runs.
    from agents.scout.nix_seed_ledger import aggregate_fingerprint

    agg = aggregate_fingerprint(["u:A", "u:B"])
    ledger = tmp_path / "seen.jsonl"
    _write_ledger(
        ledger,
        [
            {
                "cve_id": "CVE-2026-1001",
                "first_seen": "2026-07-20T00:00:00Z",
                "last_evaluated": _RECENT_EVAL,
                "outcome": "written",
                "fingerprint": agg,
            }
        ],
    )
    rec1 = NixpkgsCve(
        nixpkgs_id="attr-a",
        cve_id="CVE-2026-1001",
        cve_ids=["CVE-2026-1001"],
        status="open",
        published_at="2026-07-19T00:00:00Z",
        updated_at="A",
    )
    rec2 = NixpkgsCve(
        nixpkgs_id="attr-b",
        cve_id="CVE-2026-1001",
        cve_ids=["CVE-2026-1001"],
        status="open",
        published_at="2026-07-19T00:00:00Z",
        updated_at="B",
    )
    with patch.object(
        discover_nix_cli, "list_nixpkgs_cves", return_value=_snap([rec1, rec2])
    ):
        rc = discover_nix_cli.main(["--seen-ledger", str(ledger)])
    assert rc == 0
    assert capsys.readouterr().out.strip() == ""


def test_emit_sidecar_records_fingerprints(tmp_path, capsys):
    import json

    sidecar = tmp_path / "emitted.jsonl"
    entry = NixpkgsCve(
        nixpkgs_id="N",
        cve_id="CVE-2026-1001",
        cve_ids=["CVE-2026-1001"],
        status="open",
        published_at="2026-07-19T00:00:00Z",
        updated_at="2026-07-19T00:00:00Z",
    )
    with patch.object(
        discover_nix_cli, "list_nixpkgs_cves", return_value=_snap([entry])
    ):
        rc = discover_nix_cli.main(["--emit-sidecar", str(sidecar)])
    assert rc == 0
    rows = [json.loads(x) for x in sidecar.read_text().splitlines() if x.strip()]
    assert rows == [
        {"cve_id": "CVE-2026-1001", "fingerprint": "u:2026-07-19T00:00:00Z"}
    ]
