"""compute_comparison() — pure metric function, offline."""

from __future__ import annotations

from datetime import datetime, timezone

from agents.scout.nix_discovery import NixCvesSnapshot, NixpkgsCve
from eval.compare_sources import _parse_day, compute_comparison


def test_parse_day_normalizes_to_utc() -> None:
    # naive → UTC; offset-aware → converted to UTC (not left on its own clock,
    # which would query the wrong NVD interval).
    assert _parse_day("2026-07-01").isoformat() == "2026-07-01T00:00:00+00:00"
    assert (
        _parse_day("2026-07-01T01:00:00+02:00").isoformat()
        == "2026-06-30T23:00:00+00:00"
    )


def _cve(
    cid: str,
    published: str,
    *,
    attr: str | None = "pkgs.x",
    fixed: str = "",
    status: str = "open",
    has_pr: bool = False,
    cve_ids: list[str] | None = None,
) -> NixpkgsCve:
    return NixpkgsCve(
        nixpkgs_id=f"NIXPKGS-{cid}",
        cve_id=cid,
        cve_ids=cve_ids or [cid],
        status=status,
        published_at=published,
        nixpkgs_attribute=attr,
        fixed_version=(fixed or None),
        has_pr=has_pr,
    )


def _snapshot(entries: list[NixpkgsCve], *, capped: bool = False) -> NixCvesSnapshot:
    return NixCvesSnapshot(
        entries=entries,
        count=len(entries),
        source="github",
        request_url="x",
        fetched_at="t",
        response_sha256="0" * 64,
        capped=capped,
    )


SINCE = datetime(2026, 7, 1, tzinfo=timezone.utc)
UNTIL = datetime(2026, 7, 20, tzinfo=timezone.utc)


def test_overlap_and_outside_yield() -> None:
    nvd = ["CVE-2026-1", "CVE-2026-2", "CVE-2026-3"]
    snap = _snapshot(
        [
            _cve("CVE-2026-2", "2026-07-05T00:00:00Z"),  # in NVD window
            _cve("CVE-2026-9", "2026-07-06T00:00:00Z"),  # not in NVD window
        ]
    )
    c = compute_comparison(nvd, snap, SINCE, UNTIL)
    assert c.nvd_window_count == 3
    assert c.vulnpatch_total == 2
    assert c.overlap_in_nvd_window == 1
    assert c.vulnpatch_outside_nvd_window == 1
    assert "CVE-2026-9" in c.vulnpatch_outside_sample


def test_full_snapshot_used_regardless_of_tracker_publish_date() -> None:
    # tracker publishedAt spans well outside [SINCE, UNTIL]; the whole snapshot
    # is still counted (we don't window vulnpatch by its own clock).
    snap = _snapshot(
        [
            _cve("CVE-2026-5", "2026-06-01T00:00:00Z"),
            _cve("CVE-2026-6", "2026-07-10T00:00:00Z"),
            _cve("CVE-2026-7", "2026-08-01T00:00:00Z"),
        ]
    )
    c = compute_comparison([], snap, SINCE, UNTIL)
    assert c.vulnpatch_total == 3


def test_prejoin_and_backport_and_nopr_signals() -> None:
    snap = _snapshot(
        [
            _cve(
                "CVE-2026-1",
                "2026-07-05T00:00:00Z",
                attr="pkgs.a",
                fixed="1.1",
                has_pr=False,
            ),
            _cve(
                "CVE-2026-2", "2026-07-06T00:00:00Z", attr=None, fixed="", has_pr=True
            ),
            _cve(
                "CVE-2026-3",
                "2026-07-07T00:00:00Z",
                attr="pkgs.c",
                fixed="2.0",
                has_pr=False,
            ),
        ]
    )
    c = compute_comparison([], snap, SINCE, UNTIL)
    assert c.vulnpatch_prejoined_nixpkgs == 2  # a and c have attributes
    assert c.vulnpatch_fixed_version_present == 2  # 1.1 and 2.0
    assert c.vulnpatch_open_no_pr == 2  # 1 and 3 open with no PR


def test_multi_cve_entry_counts_all_ids() -> None:
    snap = _snapshot(
        [
            _cve(
                "CVE-2026-1",
                "2026-07-05T00:00:00Z",
                cve_ids=["CVE-2026-1", "CVE-2026-2"],
            )
        ]
    )
    c = compute_comparison(["CVE-2026-2"], snap, SINCE, UNTIL)
    assert c.overlap_in_nvd_window == 1  # matched via the secondary id
    assert c.vulnpatch_total == 2


def test_capped_flag_passthrough() -> None:
    snap = _snapshot([_cve("CVE-2026-1", "2026-07-10T00:00:00Z")], capped=True)
    c = compute_comparison([], snap, SINCE, UNTIL)
    assert c.vulnpatch_snapshot_capped is True
    assert c.vulnpatch_published_range == [
        "2026-07-10T00:00:00Z",
        "2026-07-10T00:00:00Z",
    ]
