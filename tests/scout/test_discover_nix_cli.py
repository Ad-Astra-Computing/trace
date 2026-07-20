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


def _cve(cid: str, published: str = "2026-07-20T00:00:00Z",
         cve_ids: list[str] | None = None) -> NixpkgsCve:
    return NixpkgsCve(
        nixpkgs_id=f"NIXPKGS-{cid}", cve_id=cid, cve_ids=cve_ids or [cid],
        status="open", published_at=published,
    )


def _snap(entries: list[NixpkgsCve]) -> NixCvesSnapshot:
    return NixCvesSnapshot(entries=entries, count=len(entries), source="github",
                           request_url="x", fetched_at="t", response_sha256="0" * 64,
                           capped=False)


def test_emits_all_cve_ids_one_per_line(capsys: pytest.CaptureFixture[str]) -> None:
    with patch.object(discover_nix_cli, "list_nixpkgs_cves",
                      return_value=_snap([_cve("CVE-2026-1001"), _cve("CVE-2026-1002")])):
        rc = discover_nix_cli.main([])
    assert rc == 0
    assert capsys.readouterr().out.strip().splitlines() == ["CVE-2026-1001", "CVE-2026-1002"]


def test_multi_cve_entry_fans_out_all_ids(capsys: pytest.CaptureFixture[str]) -> None:
    # one entry covering two CVEs emits both ids.
    with patch.object(discover_nix_cli, "list_nixpkgs_cves",
                      return_value=_snap([_cve("CVE-2026-1001", cve_ids=["CVE-2026-1001", "CVE-2026-1002"])])):
        rc = discover_nix_cli.main([])
    assert rc == 0
    assert capsys.readouterr().out.strip().splitlines() == ["CVE-2026-1001", "CVE-2026-1002"]


def test_dedup_preserves_first_seen_order(capsys: pytest.CaptureFixture[str]) -> None:
    with patch.object(discover_nix_cli, "list_nixpkgs_cves",
                      return_value=_snap([_cve("CVE-2026-1001"),
                                          _cve("CVE-2026-1009", cve_ids=["CVE-2026-1009", "CVE-2026-1001"])])):
        discover_nix_cli.main([])
    assert capsys.readouterr().out.strip().splitlines() == ["CVE-2026-1001", "CVE-2026-1009"]


def test_non_cve_primary_id_is_dropped(capsys: pytest.CaptureFixture[str]) -> None:
    # a malformed cve_id ("" or a non-CVE token) must not reach the poll loop.
    with patch.object(discover_nix_cli, "list_nixpkgs_cves",
                      return_value=_snap([_cve("GHSA-xxxx"), _cve("CVE-2026-1003")])):
        discover_nix_cli.main([])
    assert capsys.readouterr().out.strip().splitlines() == ["CVE-2026-1003"]


def test_window_filters_by_published_at() -> None:
    snap = _snap([
        _cve("CVE-2026-1001", published="2026-07-05T00:00:00Z"),
        _cve("CVE-2026-1002", published="2026-07-18T00:00:00Z"),
    ])
    with patch.object(discover_nix_cli, "list_nixpkgs_cves", return_value=snap):
        import io
        import contextlib
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            rc = discover_nix_cli.main(["--since", "2026-07-10T00:00:00Z",
                                        "--until", "2026-07-20T00:00:00Z"])
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


def test_lookback_hours_and_since_mutually_exclusive(capsys: pytest.CaptureFixture[str]) -> None:
    rc = discover_nix_cli.main(["--since", "2026-07-01T00:00:00Z", "--lookback-hours", "24"])
    assert rc == 64
    assert "mutually exclusive" in capsys.readouterr().err


def test_naive_since_rejected(capsys: pytest.CaptureFixture[str]) -> None:
    rc = discover_nix_cli.main(["--since", "2026-07-01T00:00:00"])
    assert rc == 64
    assert "timezone" in capsys.readouterr().err.lower()


def test_rate_limit_exits_twenty(capsys: pytest.CaptureFixture[str]) -> None:
    with patch.object(discover_nix_cli, "list_nixpkgs_cves", side_effect=FeedRateLimit(30)):
        rc = discover_nix_cli.main([])
    assert rc == 20
    assert "30s" in capsys.readouterr().err


def test_transient_error_exits_ten() -> None:
    with patch.object(discover_nix_cli, "list_nixpkgs_cves", side_effect=FeedTransientError("nope")):
        rc = discover_nix_cli.main([])
    assert rc == 10
