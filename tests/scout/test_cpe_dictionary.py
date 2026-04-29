"""Real CPE dictionary integration.

Walks NVD's /rest/json/cpes/2.0 endpoint, builds a product-keyed
index, and enriches GraphMatch snapshots with real CPE strings so
Scout's relevance + scan paths can hit cpe-exact (high confidence)
instead of bouncing through the cpe-product (vendor-agnostic)
fallback.

Tests stay offline by injecting an HTTP transport that returns
captured fixtures. A live smoke is gated on TRACE_REAL_CPE_DICT=1.
"""

from __future__ import annotations

import json
import os
import urllib.error
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock

import pytest

from agents.scout.cpe_dictionary import (
    build_product_index,
    enrich_records_with_cpes,
    fetch_all_cpe_pages,
    parse_cpe_page,
    read_index,
    write_index,
)
from agents.scout.feed_client import FeedRateLimit, FeedTransientError
from agents.scout.graph_lookup import GraphMatch


_FIXTURE = Path(__file__).parent / "fixtures" / "cpe-page-libtiff.json"


def _ok_http(body: bytes, status: int = 200, headers: dict[str, str] | None = None) -> Any:
    return MagicMock(return_value=(status, body, headers or {}))


# ─── parse_cpe_page ─────────────────────────────────────────────────────────


def test_parse_extracts_cpe_strings_from_real_fixture() -> None:
    payload = json.loads(_FIXTURE.read_text())
    cpes = parse_cpe_page(payload)
    assert all(c.startswith("cpe:2.3:") for c in cpes)
    assert any("libtiff:libtiff" in c for c in cpes)


def test_parse_skips_deprecated_entries() -> None:
    payload = {
        "products": [
            {"cpe": {"cpeName": "cpe:2.3:a:x:active:1.0:*:*:*:*:*:*:*", "deprecated": False}},
            {"cpe": {"cpeName": "cpe:2.3:a:x:gone:1.0:*:*:*:*:*:*:*", "deprecated": True}},
        ]
    }
    cpes = parse_cpe_page(payload)
    assert any("active" in c for c in cpes)
    assert not any("gone" in c for c in cpes)


def test_parse_tolerates_missing_products_key() -> None:
    assert parse_cpe_page({"products": []}) == []
    assert parse_cpe_page({}) == []


# ─── fetch_all_cpe_pages: pagination + rate-limit/transient ────────────────


def _build_page(cpes: list[str], total: int, start: int, per_page: int) -> bytes:
    return json.dumps({
        "totalResults": total,
        "startIndex": start,
        "resultsPerPage": per_page,
        "products": [{"cpe": {"cpeName": c, "deprecated": False}} for c in cpes],
    }).encode()


def test_fetch_walks_all_pages() -> None:
    page1 = _build_page(["cpe:2.3:a:x:a:1:*:*:*:*:*:*:*",
                         "cpe:2.3:a:x:b:1:*:*:*:*:*:*:*"], total=4, start=0, per_page=2)
    page2 = _build_page(["cpe:2.3:a:x:c:1:*:*:*:*:*:*:*",
                         "cpe:2.3:a:x:d:1:*:*:*:*:*:*:*"], total=4, start=2, per_page=2)
    fn = MagicMock()
    fn.side_effect = [(200, page1, {}), (200, page2, {})]
    pages = list(fetch_all_cpe_pages(http=fn))
    assert len(pages) == 2
    assert fn.call_count == 2


def test_fetch_includes_api_key_when_provided() -> None:
    fn = _ok_http(_build_page([], total=0, start=0, per_page=10000))
    list(fetch_all_cpe_pages(http=fn, api_key="abc-123"))
    headers = fn.call_args.kwargs.get("headers") or fn.call_args.args[1]
    assert headers.get("apiKey") == "abc-123"


def test_fetch_rate_limit_propagates() -> None:
    fn = MagicMock(return_value=(429, b"", {"Retry-After": "60"}))
    with pytest.raises(FeedRateLimit):
        list(fetch_all_cpe_pages(http=fn))


def test_fetch_5xx_propagates_as_transient() -> None:
    fn = MagicMock(return_value=(503, b"", {}))
    with pytest.raises(FeedTransientError):
        list(fetch_all_cpe_pages(http=fn))


def test_fetch_url_error_maps_to_transient() -> None:
    fn = MagicMock(side_effect=urllib.error.URLError("connection reset"))
    with pytest.raises(FeedTransientError):
        list(fetch_all_cpe_pages(http=fn))


# ─── build_product_index ────────────────────────────────────────────────────


def test_build_product_index_groups_by_lowercased_product() -> None:
    cpes = [
        "cpe:2.3:a:libtiff:libtiff:4.7.0:*:*:*:*:*:*:*",
        "cpe:2.3:a:libtiff:LibTIFF:4.6.0:*:*:*:*:*:*:*",  # mixed-case
        "cpe:2.3:a:apache:httpd:2.4:*:*:*:*:*:*:*",
    ]
    idx = build_product_index(cpes)
    assert "libtiff" in idx
    assert len(idx["libtiff"]) == 2  # both libtiff cases collapse
    assert "httpd" in idx


def test_build_product_index_dedupes() -> None:
    cpes = [
        "cpe:2.3:a:libtiff:libtiff:4.7.0:*:*:*:*:*:*:*",
        "cpe:2.3:a:libtiff:libtiff:4.7.0:*:*:*:*:*:*:*",
    ]
    idx = build_product_index(cpes)
    assert len(idx["libtiff"]) == 1


def test_build_product_index_skips_unparseable_cpes() -> None:
    """Defensive: a malformed CPE string in the upstream feed must
    not break the whole dictionary build."""
    cpes = [
        "cpe:2.3:a:libtiff:libtiff:4.7.0:*:*:*:*:*:*:*",
        "not-a-cpe-string",
        "",
        "cpe:2.3:a:apache:httpd:2.4:*:*:*:*:*:*:*",
    ]
    idx = build_product_index(cpes)
    assert "libtiff" in idx
    assert "httpd" in idx


# ─── enrich_records_with_cpes ───────────────────────────────────────────────


def test_enrich_attaches_matching_cpes_to_record() -> None:
    records = [
        GraphMatch(attr_path="libtiff", drv_path="attr:libtiff",
                   pname="libtiff", version="4.7.1"),
    ]
    index = {"libtiff": [
        "cpe:2.3:a:libtiff:libtiff:4.7.0:*:*:*:*:*:*:*",
        "cpe:2.3:a:libtiff:libtiff:4.6.0:*:*:*:*:*:*:*",
    ]}
    enriched = enrich_records_with_cpes(records, index)
    assert len(enriched) == 1
    assert len(enriched[0].cpes) == 2
    assert all("libtiff:libtiff" in c for c in enriched[0].cpes)


def test_enrich_preserves_records_without_match() -> None:
    records = [
        GraphMatch(attr_path="weirdlib", drv_path="attr:weirdlib",
                   pname="weirdlib", version="1.0"),
    ]
    enriched = enrich_records_with_cpes(records, {"libtiff": ["cpe:2.3:a:x:libtiff:*"]})
    assert enriched[0].cpes == ()


def test_enrich_does_not_clobber_existing_cpes() -> None:
    """A snapshot may already carry a CPE (e.g. from meta.cpe in a
    future iteration). Enrichment unions, doesn't replace."""
    records = [
        GraphMatch(
            attr_path="libtiff", drv_path="attr:libtiff",
            pname="libtiff", version="4.7.1",
            cpes=("cpe:2.3:a:libtiff:libtiff:4.7.1:*:*:*:*:*:*:*",),
        ),
    ]
    index = {"libtiff": ["cpe:2.3:a:libtiff:libtiff:4.6.0:*:*:*:*:*:*:*"]}
    enriched = enrich_records_with_cpes(records, index)
    cpes = enriched[0].cpes
    assert any("4.7.1" in c for c in cpes)  # original kept
    assert any("4.6.0" in c for c in cpes)  # enrichment added
    # No duplicates
    assert len(cpes) == len(set(cpes))


def test_enrich_is_case_insensitive_on_pname() -> None:
    records = [
        GraphMatch(attr_path="LibreSSL", drv_path="attr:LibreSSL",
                   pname="libressl", version="3.9.2"),
    ]
    # Index built from lowercased products; enrichment lowercases lookup key.
    index = {"libressl": ["cpe:2.3:a:libressl:libressl:3.9.2:*:*:*:*:*:*:*"]}
    enriched = enrich_records_with_cpes(records, index)
    assert len(enriched[0].cpes) == 1


# ─── persistence ────────────────────────────────────────────────────────────


def test_write_then_read_index_roundtrip(tmp_path: Path) -> None:
    idx = {"libtiff": ["cpe:2.3:a:libtiff:libtiff:4.7.0:*:*:*:*:*:*:*"]}
    path = tmp_path / "cpe-index.json"
    write_index(idx, path)
    assert read_index(path) == idx


def test_read_missing_index_raises(tmp_path: Path) -> None:
    with pytest.raises(FileNotFoundError):
        read_index(tmp_path / "absent.json")


# ─── live smoke ─────────────────────────────────────────────────────────────


@pytest.mark.skipif(
    os.environ.get("TRACE_REAL_CPE_DICT") != "1",
    reason="real-network CPE dictionary fetch; set TRACE_REAL_CPE_DICT=1",
)
def test_live_keyword_search_libtiff() -> None:
    from agents.scout.cpe_dictionary import _NVD_BASE
    import urllib.parse, urllib.request, json as _json
    url = f"{_NVD_BASE}?keywordSearch=libtiff&resultsPerPage=5"
    with urllib.request.urlopen(url, timeout=30) as resp:
        body = resp.read()
    cpes = parse_cpe_page(_json.loads(body))
    idx = build_product_index(cpes)
    assert "libtiff" in idx
