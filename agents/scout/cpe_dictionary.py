"""NVD CPE dictionary integration.

Walks https://services.nvd.nist.gov/rest/json/cpes/2.0 (paginated),
builds a product-keyed CPE index, and enriches GraphMatch snapshots
with real CPE strings so Scout's relevance + scan paths can hit
cpe-exact (high confidence) instead of the cpe-product (vendor-
agnostic) fallback.

  fetch_all_cpe_pages   yields each page dict (totalResults, products[])
  parse_cpe_page        extracts non-deprecated cpeName strings
  build_product_index   product (lowercased) -> list[cpe], deduped
  enrich_records_with_cpes  attach matching CPEs to each record by pname
  write_index / read_index  JSON persistence

The HTTP transport is injected so tests stay fully offline. Live
smoke is gated on TRACE_REAL_CPE_DICT=1.

Anonymous-first; an optional NVD_API_KEY lifts the per-30s quota
from 5 -> 50 requests, cutting full-walk time from ~16 min to ~1 min.
"""

from __future__ import annotations

import json
import re
import urllib.parse
from pathlib import Path
from typing import Any, Iterable, Iterator

from agents.scout.feed_client import (
    FeedDecodeError,
    FeedRateLimit,
    FeedTransientError,
    HttpFn,
    _call,
    _parse_retry_after,
)
from agents.scout.graph_lookup import GraphMatch


_NVD_BASE = "https://services.nvd.nist.gov/rest/json/cpes/2.0"
_USER_AGENT = "trace-scout/0.1 (+https://github.com/Ad-Astra-Computing/trace)"
_PAGE_SIZE = 10000
_CPE_PRODUCT_RE = re.compile(r"^cpe:2\.3:[^:]+:[^:]+:([^:]+):")


def fetch_all_cpe_pages(
    *,
    http: HttpFn | None = None,
    api_key: str | None = None,
) -> Iterator[dict[str, Any]]:
    """Yield each /cpes/2.0 response page until totalResults is exhausted.

    Caller is responsible for parsing each page (parse_cpe_page) and
    aggregating into an index (build_product_index)."""
    headers = {"Accept": "application/json", "User-Agent": _USER_AGENT}
    if api_key:
        headers["apiKey"] = api_key

    start_index = 0
    while True:
        url = _build_url(start_index)
        status, body, resp_headers = _call(http, url, headers)

        if status == 429:
            raise FeedRateLimit(_parse_retry_after(resp_headers))
        if status >= 500:
            raise FeedTransientError(f"CPE dictionary returned {status}")
        if status != 200:
            raise FeedDecodeError(f"CPE dictionary returned unexpected status {status}")

        try:
            payload = json.loads(body)
        except json.JSONDecodeError as e:
            raise FeedDecodeError(f"CPE page is not valid JSON: {e}") from e

        if not isinstance(payload, dict):
            raise FeedDecodeError("CPE page payload is not an object")

        yield payload

        total = payload.get("totalResults", 0)
        results_per_page = payload.get("resultsPerPage", 0) or _PAGE_SIZE
        start_index += results_per_page
        if start_index >= total:
            return


def parse_cpe_page(payload: dict[str, Any]) -> list[str]:
    """Extract non-deprecated cpeName strings from one /cpes/2.0 page."""
    out: list[str] = []
    for entry in payload.get("products") or []:
        cpe = entry.get("cpe") if isinstance(entry, dict) else None
        if not isinstance(cpe, dict):
            continue
        if cpe.get("deprecated"):
            continue
        name = cpe.get("cpeName")
        if isinstance(name, str) and name.startswith("cpe:2.3:"):
            out.append(name)
    return out


def build_product_index(cpes: Iterable[str]) -> dict[str, list[str]]:
    """Group CPE strings by lowercased product (4th colon field).

    Output is sorted-deduped per product so the JSON is reproducible
    across runs and easy to diff."""
    raw: dict[str, set[str]] = {}
    for cpe in cpes:
        m = _CPE_PRODUCT_RE.match(cpe)
        if not m:
            continue
        raw.setdefault(m.group(1).lower(), set()).add(cpe)
    return {k: sorted(v) for k, v in sorted(raw.items())}


def enrich_records_with_cpes(
    records: Iterable[GraphMatch],
    product_index: dict[str, list[str]],
) -> list[GraphMatch]:
    """Attach matching CPEs to each record by lowercased pname.

    Existing CPEs are unioned (not replaced), preserving any future
    nixpkgs-meta-derived CPEs. Ordering is stable and deduped."""
    out: list[GraphMatch] = []
    for r in records:
        key = (r.pname or "").lower()
        matches = product_index.get(key, [])
        if not matches and not r.cpes:
            out.append(r)
            continue
        merged: list[str] = []
        seen: set[str] = set()
        for c in tuple(r.cpes) + tuple(matches):
            if c not in seen:
                seen.add(c)
                merged.append(c)
        out.append(GraphMatch(
            attr_path=r.attr_path,
            drv_path=r.drv_path,
            pname=r.pname,
            version=r.version,
            cpes=tuple(merged),
            purls=r.purls,
            src_url=r.src_url,
            src_hash=r.src_hash,
        ))
    return out


def write_index(index: dict[str, list[str]], path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(index, indent=2, sort_keys=True) + "\n")


def read_index(path: Path) -> dict[str, list[str]]:
    if not path.is_file():
        raise FileNotFoundError(f"CPE index not found: {path}")
    return json.loads(path.read_text())


def _build_url(start_index: int) -> str:
    params = {"resultsPerPage": _PAGE_SIZE, "startIndex": start_index}
    return f"{_NVD_BASE}?{urllib.parse.urlencode(params)}"
