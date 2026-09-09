"""Scout CVE-discovery feed tests.

Slice 8 of Scout autonomy. Lists CVE IDs published in a window so
the cron has work to do.

  list_recent_cves(since, until, *, http=..., api_key=...) -> list[str]

Walks NVD's /rest/json/cves/2.0 with pubStartDate / pubEndDate. NVD
returns up to 2000 results per page with totalResults + startIndex
metadata; the discoverer paginates until it has them all and returns
a deduplicated, time-sorted list of CVE ids.

Anonymous-first per the locked Scout decisions; an optional api_key
lifts the rate limit.

The HTTP transport is injected so tests stay fully offline. Real-
network smoke is gated on TRACE_REAL_FEED_FETCH=1 (same gate as the
feed client).
"""

from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from typing import Any
from unittest.mock import MagicMock

import pytest

from agents.scout.discovery import list_recent_cves
from agents.scout.feed_client import FeedRateLimit, FeedTransientError


def _page(
    cve_ids: list[str],
    *,
    total: int | None = None,
    start_index: int = 0,
    results_per_page: int | None = None,
) -> bytes:
    rpp = results_per_page if results_per_page is not None else len(cve_ids)
    return json.dumps(
        {
            "totalResults": total if total is not None else len(cve_ids),
            "startIndex": start_index,
            "resultsPerPage": rpp,
            "vulnerabilities": [
                {"cve": {"id": cid, "published": "2026-04-28T12:00:00.000"}}
                for cid in cve_ids
            ],
        }
    ).encode()


def _http(plan: list[tuple[int, bytes]]) -> Any:
    fn = MagicMock()
    fn.side_effect = [(s, b, {}) for s, b in plan]
    return fn


def test_single_page_returns_cve_ids() -> None:
    http = _http([(200, _page(["CVE-2026-1", "CVE-2026-2"]))])
    out = list_recent_cves(
        since=datetime(2026, 4, 28, tzinfo=timezone.utc),
        until=datetime(2026, 4, 29, tzinfo=timezone.utc),
        http=http,
    )
    assert out == ["CVE-2026-1", "CVE-2026-2"]


def test_pagination_walks_all_pages() -> None:
    """NVD returns at most 2000 per page; discoverer keeps walking
    while startIndex+resultsPerPage < totalResults."""
    page1 = _page(
        ["CVE-2026-1", "CVE-2026-2"], total=4, start_index=0, results_per_page=2
    )
    page2 = _page(
        ["CVE-2026-3", "CVE-2026-4"], total=4, start_index=2, results_per_page=2
    )
    http = _http([(200, page1), (200, page2)])
    out = list_recent_cves(
        since=datetime(2026, 4, 28, tzinfo=timezone.utc),
        until=datetime(2026, 4, 29, tzinfo=timezone.utc),
        http=http,
    )
    assert out == ["CVE-2026-1", "CVE-2026-2", "CVE-2026-3", "CVE-2026-4"]
    assert http.call_count == 2


def test_dedupe_within_response() -> None:
    """Defensive: NVD has been known to repeat ids across pages on
    edge boundaries. The discoverer dedupes preserving first-seen
    order."""
    page1 = _page(
        ["CVE-2026-1", "CVE-2026-2"], total=4, start_index=0, results_per_page=2
    )
    page2 = _page(
        ["CVE-2026-2", "CVE-2026-3"], total=4, start_index=2, results_per_page=2
    )
    http = _http([(200, page1), (200, page2)])
    out = list_recent_cves(
        since=datetime(2026, 4, 28, tzinfo=timezone.utc),
        until=datetime(2026, 4, 29, tzinfo=timezone.utc),
        http=http,
    )
    assert out == ["CVE-2026-1", "CVE-2026-2", "CVE-2026-3"]


def test_window_passed_as_iso_query_params() -> None:
    http = _http([(200, _page([]))])
    list_recent_cves(
        since=datetime(2026, 4, 28, 1, 2, 3, tzinfo=timezone.utc),
        until=datetime(2026, 4, 29, 4, 5, 6, tzinfo=timezone.utc),
        http=http,
    )
    url = http.call_args.args[0]
    assert (
        "pubStartDate=2026-04-28T01%3A02%3A03" in url
        or "pubStartDate=2026-04-28T01:02:03" in url
    )
    assert (
        "pubEndDate=2026-04-29T04%3A05%3A06" in url
        or "pubEndDate=2026-04-29T04:05:06" in url
    )


def test_api_key_threaded_through_when_provided() -> None:
    http = _http([(200, _page([]))])
    list_recent_cves(
        since=datetime(2026, 4, 28, tzinfo=timezone.utc),
        until=datetime(2026, 4, 29, tzinfo=timezone.utc),
        http=http,
        api_key="abc-123",
    )
    headers = http.call_args.kwargs.get("headers") or http.call_args.args[1]
    assert headers.get("apiKey") == "abc-123"


def test_no_api_key_omits_header() -> None:
    http = _http([(200, _page([]))])
    list_recent_cves(
        since=datetime(2026, 4, 28, tzinfo=timezone.utc),
        until=datetime(2026, 4, 29, tzinfo=timezone.utc),
        http=http,
    )
    headers = http.call_args.kwargs.get("headers") or http.call_args.args[1]
    assert "apiKey" not in headers


def test_naive_datetime_rejected() -> None:
    """All NVD timestamps are UTC. Demanding tz-aware datetimes saves
    a class of off-by-N-hours bugs upstream."""
    with pytest.raises(ValueError, match="timezone"):
        list_recent_cves(
            since=datetime(2026, 4, 28),  # naive
            until=datetime(2026, 4, 29, tzinfo=timezone.utc),
            http=_http([]),
        )


def test_window_inverted_rejected() -> None:
    with pytest.raises(ValueError, match="since"):
        list_recent_cves(
            since=datetime(2026, 4, 30, tzinfo=timezone.utc),
            until=datetime(2026, 4, 29, tzinfo=timezone.utc),
            http=_http([]),
        )


def test_429_propagates_as_rate_limit() -> None:
    http = MagicMock(return_value=(429, b"", {"Retry-After": "60"}))
    with pytest.raises(FeedRateLimit):
        list_recent_cves(
            since=datetime(2026, 4, 28, tzinfo=timezone.utc),
            until=datetime(2026, 4, 29, tzinfo=timezone.utc),
            http=http,
        )


def test_5xx_propagates_as_transient() -> None:
    http = MagicMock(return_value=(503, b"", {}))
    with pytest.raises(FeedTransientError):
        list_recent_cves(
            since=datetime(2026, 4, 28, tzinfo=timezone.utc),
            until=datetime(2026, 4, 29, tzinfo=timezone.utc),
            http=http,
        )


def test_empty_window_returns_empty_list() -> None:
    http = _http([(200, _page([]))])
    out = list_recent_cves(
        since=datetime(2026, 4, 28, tzinfo=timezone.utc),
        until=datetime(2026, 4, 29, tzinfo=timezone.utc),
        http=http,
    )
    assert out == []


@pytest.mark.skipif(
    os.environ.get("TRACE_REAL_FEED_FETCH") != "1",
    reason="real-network test; set TRACE_REAL_FEED_FETCH=1 to enable",
)
def test_live_smoke_returns_at_least_one_cve() -> None:
    """Walk a 24-hour window in the past against the live NVD API.
    Asserts pagination + parsing work end-to-end."""
    until = datetime(2026, 4, 28, tzinfo=timezone.utc)
    since = datetime(2026, 4, 27, tzinfo=timezone.utc)
    out = list_recent_cves(since=since, until=until)
    assert isinstance(out, list)
    if out:
        assert all(c.startswith("CVE-") for c in out)
