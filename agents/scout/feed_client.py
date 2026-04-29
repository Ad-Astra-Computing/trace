"""Scout HTTP feed client: dossier-primary, NVD-direct fallback.

Two fetchers, each returning a `FetchResult` carrying the parsed
inner record + the raw response bytes (for sha256 provenance):

  * `fetch_dossier(cve_id, *, http=...)`
        GET https://api.vulnpatch.dev/api/v1/cve/<id>/dossier
        Unwraps the {success, data, timestamp} envelope; downstream
        normalizer (agents.feed_normalizers.dossier) consumes `.data`.

  * `fetch_nvd_direct(cve_id, *, http=..., api_key=...)`
        GET https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=<id>
        Anonymous-first; NVD_API_KEY (when set) lifts the rate limit
        but is never required. Returns the first vulnerabilities[].cve.

The HTTP transport is injected so tests stay fully offline. The
default transport is a thin wrapper around urllib.request.urlopen
to avoid pulling a third-party HTTP dep into the runtime path.

Errors are typed so the caller (slice 5/6 orchestrator) can decide:
  * FeedNotFound       → 404 / zero results: try the next source
  * FeedRateLimit      → 429: backoff using `retry_after`
  * FeedTransientError → 5xx / network: retry with jitter
  * FeedDecodeError    → JSON parse / shape: refuse, replay-blocking
  * ValueError         → caller bug (non-CVE id passed in)
"""

from __future__ import annotations

import json
import urllib.error
import urllib.request
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Callable


HttpResponse = tuple[int, bytes, dict[str, str]]
HttpFn = Callable[..., HttpResponse]


_DOSSIER_BASE = "https://api.vulnpatch.dev/api/v1/cve"
_NVD_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"
_DEFAULT_TIMEOUT_S = 30
_USER_AGENT = "trace-scout/0.1 (+https://github.com/Ad-Astra-Computing/trace)"


class FeedNotFound(Exception):
    """The remote returned 404 or zero results for the queried CVE."""


class FeedRateLimit(Exception):
    """The remote returned 429. Exposes the server-suggested Retry-After."""

    def __init__(self, retry_after: int):
        super().__init__(f"rate-limited; retry after {retry_after}s")
        self.retry_after = retry_after


class FeedTransientError(Exception):
    """Network error or 5xx; safe to retry with backoff."""


class FeedDecodeError(Exception):
    """The response body did not match the expected JSON shape."""


@dataclass(frozen=True)
class FetchResult:
    data: dict[str, Any]
    raw_bytes: bytes
    request_url: str
    fetched_at: str
    status_code: int


def fetch_dossier(cve_id: str, *, http: HttpFn | None = None) -> FetchResult:
    _require_cve_id(cve_id)
    url = f"{_DOSSIER_BASE}/{cve_id}/dossier"
    headers = {"Accept": "application/json", "User-Agent": _USER_AGENT}

    status, body, _resp_headers = _call(http, url, headers)
    fetched_at = _now_iso()

    if status == 404:
        raise FeedNotFound(f"dossier not found for {cve_id}")
    if status == 429:
        raise FeedRateLimit(_parse_retry_after(_resp_headers))
    if status >= 500:
        raise FeedTransientError(f"dossier returned {status}")
    if status != 200:
        raise FeedDecodeError(f"dossier returned unexpected status {status}")

    try:
        envelope = json.loads(body)
    except json.JSONDecodeError as e:
        raise FeedDecodeError(f"dossier body is not valid JSON: {e}") from e

    data = envelope.get("data") if isinstance(envelope, dict) else None
    if not isinstance(data, dict):
        raise FeedDecodeError("dossier envelope missing 'data' object")

    return FetchResult(
        data=data,
        raw_bytes=body,
        request_url=url,
        fetched_at=fetched_at,
        status_code=status,
    )


def fetch_nvd_direct(
    cve_id: str,
    *,
    http: HttpFn | None = None,
    api_key: str | None = None,
) -> FetchResult:
    _require_cve_id(cve_id)
    url = f"{_NVD_BASE}?cveId={cve_id}"
    headers = {"Accept": "application/json", "User-Agent": _USER_AGENT}
    if api_key:
        headers["apiKey"] = api_key

    status, body, _resp_headers = _call(http, url, headers)
    fetched_at = _now_iso()

    if status == 404:
        raise FeedNotFound(f"NVD returned 404 for {cve_id}")
    if status == 429:
        raise FeedRateLimit(_parse_retry_after(_resp_headers))
    if status >= 500:
        raise FeedTransientError(f"NVD returned {status}")
    if status != 200:
        raise FeedDecodeError(f"NVD returned unexpected status {status}")

    try:
        payload = json.loads(body)
    except json.JSONDecodeError as e:
        raise FeedDecodeError(f"NVD body is not valid JSON: {e}") from e

    vulns = payload.get("vulnerabilities") if isinstance(payload, dict) else None
    if not isinstance(vulns, list) or not vulns:
        raise FeedNotFound(f"NVD returned zero results for {cve_id}")

    cve = vulns[0].get("cve") if isinstance(vulns[0], dict) else None
    if not isinstance(cve, dict):
        raise FeedDecodeError("NVD vulnerabilities[0].cve missing or malformed")

    return FetchResult(
        data=cve,
        raw_bytes=body,
        request_url=url,
        fetched_at=fetched_at,
        status_code=status,
    )


def _require_cve_id(cve_id: str) -> None:
    if not isinstance(cve_id, str) or not cve_id.startswith("CVE-"):
        raise ValueError(f"not a CVE id: {cve_id!r}")


def _call(http: HttpFn | None, url: str, headers: dict[str, str]) -> HttpResponse:
    fn = http or _default_http
    try:
        return fn(url, headers=headers, timeout=_DEFAULT_TIMEOUT_S)
    except urllib.error.URLError as e:
        raise FeedTransientError(f"transport error: {e}") from e
    except TimeoutError as e:
        raise FeedTransientError(f"timeout: {e}") from e


def _default_http(url: str, *, headers: dict[str, str], timeout: int) -> HttpResponse:
    req = urllib.request.Request(url, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            body = resp.read()
            resp_headers = {k: v for k, v in resp.headers.items()}
            return resp.getcode(), body, resp_headers
    except urllib.error.HTTPError as e:
        body = e.read() if hasattr(e, "read") else b""
        resp_headers = {k: v for k, v in (e.headers or {}).items()}
        return e.code, body, resp_headers


def _parse_retry_after(headers: dict[str, str]) -> int:
    raw = headers.get("Retry-After") or headers.get("retry-after") or "60"
    try:
        return int(raw)
    except (TypeError, ValueError):
        return 60


def _now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
