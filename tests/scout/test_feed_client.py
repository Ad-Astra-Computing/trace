"""Scout feed client (HTTP transport) tests.

Slice 3 of the Scout autonomy arc. Two fetchers:

  * `fetch_dossier(cve_id, http=...)`        → cve.vulnpatch.dev/api/v1/cve/:id/dossier
  * `fetch_nvd_direct(cve_id, http=..., api_key=...)`
                                             → services.nvd.nist.gov/rest/json/cves/2.0

Both share an injectable HTTP transport so tests stay fully offline.
Real-network smoke is gated on `TRACE_REAL_FEED_FETCH=1`.

Per locked design (user direction, 28 April 2026):
  * Anonymous-first NVD; an optional NVD_API_KEY enables the higher
    rate-limit path but is never required.
  * Dossier-primary; direct NVD is the fallback when dossier 404s or
    the dossier service is unavailable. Per-call selection is the
    caller's responsibility (slice 5/6); this slice just provides the
    transports.
  * Raw response bytes are returned unmodified so the caller can
    record sha256 for replay.

Errors are explicit and typed so the orchestrator can decide whether
to backoff (transient), fall back (not-found), or refuse (decode).
"""

from __future__ import annotations

import json
import os
import re
import urllib.error
from typing import Any
from unittest.mock import MagicMock

import pytest

from agents.scout.feed_client import (
    FeedDecodeError,
    FeedNotFound,
    FeedRateLimit,
    FeedTransientError,
    FetchResult,
    fetch_dossier,
    fetch_nvd_direct,
)


_DOSSIER_BODY = json.dumps({
    "success": True,
    "data": {
        "cveId": "CVE-2024-13978",
        "canonical": {
            "id": "CVE-2024-13978",
            "publishedAt": "2025-01-01T00:00:00Z",
            "description": "x",
        },
        "provenance": [],
    },
    "timestamp": "2026-04-29T00:00:00Z",
}).encode()


_NVD_BODY = json.dumps({
    "vulnerabilities": [{
        "cve": {
            "id": "CVE-2024-13978",
            "published": "2025-01-01T00:00:00.000",
            "descriptions": [{"lang": "en", "value": "x"}],
            "references": [],
        },
    }],
    "totalResults": 1,
}).encode()


def _ok_http(body: bytes, status: int = 200, headers: dict[str, str] | None = None) -> Any:
    """Build a fake `http(url, headers, timeout) -> (status, body, headers)` callable."""
    return MagicMock(return_value=(status, body, headers or {}))


# ─── fetch_dossier ──────────────────────────────────────────────────────────


def test_dossier_returns_parsed_data_and_raw_bytes() -> None:
    http = _ok_http(_DOSSIER_BODY)
    result = fetch_dossier("CVE-2024-13978", http=http)

    assert isinstance(result, FetchResult)
    assert result.data["cveId"] == "CVE-2024-13978"
    assert result.raw_bytes == _DOSSIER_BODY
    assert result.request_url.endswith("/api/v1/cve/CVE-2024-13978/dossier")
    assert result.status_code == 200
    # ISO-8601 with trailing 'Z'
    assert re.match(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$", result.fetched_at)


def test_dossier_unwraps_envelope_to_data() -> None:
    """The vulnpatch API wraps every response in {success, data, timestamp};
    the dossier normalizer expects to be handed `.data`, so the client
    unwraps for it."""
    http = _ok_http(_DOSSIER_BODY)
    result = fetch_dossier("CVE-2024-13978", http=http)
    assert "canonical" in result.data
    assert "success" not in result.data


def test_dossier_404_raises_feed_not_found() -> None:
    http = _ok_http(b'{"error": "not found"}', status=404)
    with pytest.raises(FeedNotFound) as exc_info:
        fetch_dossier("CVE-9999-99999", http=http)
    assert "CVE-9999-99999" in str(exc_info.value)


def test_dossier_429_raises_rate_limit() -> None:
    http = _ok_http(b"", status=429, headers={"Retry-After": "60"})
    with pytest.raises(FeedRateLimit) as exc_info:
        fetch_dossier("CVE-2024-13978", http=http)
    assert exc_info.value.retry_after == 60


def test_dossier_5xx_raises_transient() -> None:
    http = _ok_http(b"", status=503)
    with pytest.raises(FeedTransientError):
        fetch_dossier("CVE-2024-13978", http=http)


def test_dossier_invalid_json_raises_decode() -> None:
    http = _ok_http(b"not json")
    with pytest.raises(FeedDecodeError):
        fetch_dossier("CVE-2024-13978", http=http)


def test_dossier_envelope_without_data_raises_decode() -> None:
    http = _ok_http(b'{"success": false, "error": "x"}')
    with pytest.raises(FeedDecodeError, match="data"):
        fetch_dossier("CVE-2024-13978", http=http)


def test_dossier_rejects_non_cve_id() -> None:
    http = _ok_http(_DOSSIER_BODY)
    with pytest.raises(ValueError, match="CVE"):
        fetch_dossier("GHSA-abcd-efgh-ijkl", http=http)
    http.assert_not_called()


# ─── fetch_nvd_direct ───────────────────────────────────────────────────────


def test_nvd_returns_first_vulnerability_cve() -> None:
    """NVD's response is a list under `vulnerabilities[].cve`; the
    client returns the inner `.cve` ready for `nvd.normalize` to
    consume."""
    http = _ok_http(_NVD_BODY)
    result = fetch_nvd_direct("CVE-2024-13978", http=http)
    assert result.data["id"] == "CVE-2024-13978"
    assert "?cveId=CVE-2024-13978" in result.request_url


def test_nvd_zero_results_raises_not_found() -> None:
    body = json.dumps({"vulnerabilities": [], "totalResults": 0}).encode()
    http = _ok_http(body)
    with pytest.raises(FeedNotFound):
        fetch_nvd_direct("CVE-9999-99999", http=http)


def test_nvd_api_key_added_to_headers_when_present() -> None:
    """Anonymous-first; with NVD_API_KEY the apiKey header lifts the
    rate limit. The client never requires the key."""
    http = _ok_http(_NVD_BODY)
    fetch_nvd_direct("CVE-2024-13978", http=http, api_key="abc-123")
    sent_headers = http.call_args.kwargs.get("headers") or http.call_args.args[1]
    assert sent_headers.get("apiKey") == "abc-123"


def test_nvd_no_api_key_omits_header() -> None:
    http = _ok_http(_NVD_BODY)
    fetch_nvd_direct("CVE-2024-13978", http=http, api_key=None)
    sent_headers = http.call_args.kwargs.get("headers") or http.call_args.args[1]
    assert "apiKey" not in sent_headers


def test_nvd_429_raises_rate_limit() -> None:
    http = _ok_http(b"", status=429, headers={"Retry-After": "30"})
    with pytest.raises(FeedRateLimit) as exc_info:
        fetch_nvd_direct("CVE-2024-13978", http=http)
    assert exc_info.value.retry_after == 30


def test_nvd_rejects_non_cve_id() -> None:
    http = _ok_http(_NVD_BODY)
    with pytest.raises(ValueError, match="CVE"):
        fetch_nvd_direct("not-a-cve", http=http)


# ─── transport-layer error mapping ──────────────────────────────────────────


def test_url_error_maps_to_transient() -> None:
    http = MagicMock(side_effect=urllib.error.URLError("connection reset"))
    with pytest.raises(FeedTransientError):
        fetch_dossier("CVE-2024-13978", http=http)


# ─── live smoke (network-gated) ─────────────────────────────────────────────


@pytest.mark.skipif(
    os.environ.get("TRACE_REAL_FEED_FETCH") != "1",
    reason="real-network test; set TRACE_REAL_FEED_FETCH=1 to enable",
)
def test_dossier_live_smoke() -> None:
    result = fetch_dossier("CVE-2024-13978")
    assert result.data["cveId"] == "CVE-2024-13978"
    assert result.status_code == 200
    assert len(result.raw_bytes) > 100


@pytest.mark.skipif(
    os.environ.get("TRACE_REAL_FEED_FETCH") != "1",
    reason="real-network test; set TRACE_REAL_FEED_FETCH=1 to enable",
)
def test_nvd_live_smoke() -> None:
    result = fetch_nvd_direct("CVE-2024-13978")
    assert result.data["id"] == "CVE-2024-13978"
