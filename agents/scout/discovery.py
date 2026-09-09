"""CVE-discovery feed: list CVEs published in a window.

  list_recent_cves(since, until, *, http=..., api_key=...) -> list[str]

Walks NVD /rest/json/cves/2.0 with pubStartDate / pubEndDate;
paginates through resultsPerPage chunks until totalResults is
exhausted. Returns a deduplicated list of CVE ids in first-seen
order.

Anonymous-first per the locked Scout decisions; an optional
api_key lifts the rate limit.

The HTTP transport is injected so tests stay offline. The default
transport is the same `_default_http` shim as feed_client (urllib).
"""

from __future__ import annotations

import json
import urllib.parse
from datetime import datetime
from typing import Any

from agents.scout.feed_client import (
    FeedDecodeError,
    FeedNotFound,
    FeedRateLimit,
    FeedTransientError,
    HttpFn,
    _call,
)


_NVD_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"
_USER_AGENT = "trace-scout/0.1 (+https://github.com/Ad-Astra-Computing/trace)"


def list_recent_cves(
    since: datetime,
    until: datetime,
    *,
    http: HttpFn | None = None,
    api_key: str | None = None,
) -> list[str]:
    if since.tzinfo is None or until.tzinfo is None:
        raise ValueError(
            "list_recent_cves requires tz-aware (timezone-aware) datetimes; NVD timestamps are UTC"
        )
    if since >= until:
        raise ValueError(
            f"since ({since.isoformat()}) must be before until ({until.isoformat()})"
        )

    headers = {"Accept": "application/json", "User-Agent": _USER_AGENT}
    if api_key:
        headers["apiKey"] = api_key

    seen: set[str] = set()
    ordered: list[str] = []
    start_index = 0

    while True:
        url = _build_url(since, until, start_index=start_index)
        status, body, _resp_headers = _call(http, url, headers)

        if status == 429:
            from agents.scout.feed_client import _parse_retry_after

            raise FeedRateLimit(_parse_retry_after(_resp_headers))
        if status >= 500:
            raise FeedTransientError(f"NVD list returned {status}")
        if status == 404:
            raise FeedNotFound("NVD list endpoint returned 404")
        if status != 200:
            raise FeedDecodeError(f"NVD list returned unexpected status {status}")

        try:
            payload = json.loads(body)
        except json.JSONDecodeError as e:
            raise FeedDecodeError(f"NVD list body is not valid JSON: {e}") from e

        if not isinstance(payload, dict):
            raise FeedDecodeError("NVD list payload is not an object")

        vulns = payload.get("vulnerabilities") or []
        for entry in vulns:
            cve = entry.get("cve") if isinstance(entry, dict) else None
            cid = cve.get("id") if isinstance(cve, dict) else None
            if cid and cid not in seen:
                seen.add(cid)
                ordered.append(cid)

        results_per_page = payload.get("resultsPerPage", len(vulns))
        total = payload.get("totalResults", len(vulns))
        start_index += results_per_page
        if start_index >= total or not vulns:
            return ordered


def _build_url(since: datetime, until: datetime, *, start_index: int) -> str:
    params: dict[str, Any] = {
        "pubStartDate": _nvd_iso(since),
        "pubEndDate": _nvd_iso(until),
        "startIndex": start_index,
    }
    return f"{_NVD_BASE}?{urllib.parse.urlencode(params)}"


def _nvd_iso(dt: datetime) -> str:
    """NVD wants no trailing Z and millisecond precision optional. We
    emit second-precision local-style (YYYY-MM-DDTHH:MM:SS) which the
    API accepts under either UTC or explicit offset interpretation."""
    return dt.astimezone(dt.tzinfo).strftime("%Y-%m-%dT%H:%M:%S")
