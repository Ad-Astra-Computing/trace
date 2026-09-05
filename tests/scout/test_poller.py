"""Scout cron poller tests.

Slice 6a of Scout autonomy. The poller orchestrates one CVE end-to-end:

  fetch (dossier-primary, NVD-direct fallback)
       ↓
  normalize (dossier or nvd normalizer)
       ↓
  relevance filter (graph lookup, short-circuits)
       ↓
  inbox write (atomic, schema-validated, idempotent)

Returns a `PollOutcome` recording exactly what happened so the cron
workflow can log structured progress + a per-run summary. No
networking inside tests; the HTTP transport is injected.

Decisions encoded here (locked, user direction 28 April 2026):
  * Anonymous-first NVD; NVD_API_KEY is optional (passed through).
  * Dossier-primary; NVD-direct only when the dossier 404s or
    transient-errors out repeatedly (poller retries are out of
    scope for slice 6: the cron itself reschedules).
  * Both feeds are tried when dossier is decode-broken so a partial
    outage upstream does not block the inbox.
  * Irrelevant CVEs are NOT persisted (saves disk + downstream noise);
    the decision is logged in the PollOutcome instead.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock

import pytest

from agents.scout.graph_lookup import CannedGraphLookup, GraphMatch
from agents.scout.poller import PollOutcome, poll_one


_LIBTIFF = GraphMatch(
    attr_path="libtiff",
    drv_path="/nix/store/aaa-libtiff.drv",
    pname="libtiff",
    version="4.7.0",
    cpes=("cpe:2.3:a:libtiff:libtiff:*:*:*:*:*:*:*:*",),
)


_DOSSIER_BODY = json.dumps({
    "success": True,
    "data": {
        "cveId": "CVE-2024-13978",
        "canonical": {
            "id": "CVE-2024-13978",
            "publishedAt": "2025-08-01T21:32:07Z",
            "description": "LibTIFF null deref",
            "severity": "low",
        },
        "sources": {
            "nvd": {
                "cpeMatches": [
                    {"cpe": "cpe:2.3:a:libtiff:libtiff:*:*:*:*:*:*:*:*",
                     "versionEnd": "4.7.0"}
                ]
            }
        },
        "provenance": [],
    },
    "timestamp": "2026-04-29T00:00:00Z",
}).encode()


_NVD_BODY = json.dumps({
    "vulnerabilities": [{
        "cve": {
            "id": "CVE-2024-13978",
            "published": "2025-08-01T21:32:07.000",
            "descriptions": [{"lang": "en", "value": "LibTIFF null deref"}],
            "configurations": [{
                "nodes": [{
                    "operator": "OR",
                    "negate": False,
                    "cpeMatch": [{
                        "vulnerable": True,
                        "criteria": "cpe:2.3:a:libtiff:libtiff:*:*:*:*:*:*:*:*",
                    }],
                }],
            }],
            "references": [],
        },
    }],
    "totalResults": 1,
}).encode()


def _http_returning(status: int, body: bytes) -> Any:
    return MagicMock(return_value=(status, body, {}))


def _multi_http(plan: list[tuple[int, bytes]]) -> Any:
    """Sequential responses by call order; useful for dossier-then-nvd flows."""
    fn = MagicMock()
    fn.side_effect = [(s, b, {}) for s, b in plan]
    return fn


def test_dossier_path_writes_inbox_when_relevant(tmp_path: Path) -> None:
    http = _http_returning(200, _DOSSIER_BODY)
    graph = CannedGraphLookup([_LIBTIFF])
    out = poll_one(
        "CVE-2024-13978",
        graph=graph,
        root=tmp_path,
        http=http,
    )

    assert isinstance(out, PollOutcome)
    assert out.action == "written"
    assert out.feed_used == "dossier"
    assert out.entry_path == tmp_path / "CVE-2024-13978"
    assert (out.entry_path / "scout-input.json").exists()
    assert (out.entry_path / "raw-dossier.json").exists()


def test_dossier_404_falls_back_to_nvd_direct(tmp_path: Path) -> None:
    http = _multi_http([(404, b'{"error":"not found"}'), (200, _NVD_BODY)])
    graph = CannedGraphLookup([_LIBTIFF])

    out = poll_one("CVE-2024-13978", graph=graph, root=tmp_path, http=http)

    assert out.action == "written"
    assert out.feed_used == "nvd"
    assert (out.entry_path / "raw-nvd.json").exists()
    assert not (out.entry_path / "raw-dossier.json").exists()
    assert http.call_count == 2


def test_relevant_filter_skips_irrelevant_cve(tmp_path: Path) -> None:
    """Empty graph → no nixpkgs match → poller declines to write."""
    http = _http_returning(200, _DOSSIER_BODY)
    graph = CannedGraphLookup([])

    out = poll_one("CVE-2024-13978", graph=graph, root=tmp_path, http=http)

    assert out.action == "skipped-irrelevant"
    assert "no-match" in out.reason
    assert not (tmp_path / "CVE-2024-13978").exists()


def test_idempotent_repeat_run_is_noop(tmp_path: Path) -> None:
    http = _http_returning(200, _DOSSIER_BODY)
    graph = CannedGraphLookup([_LIBTIFF])

    out1 = poll_one("CVE-2024-13978", graph=graph, root=tmp_path, http=http)
    out2 = poll_one("CVE-2024-13978", graph=graph, root=tmp_path, http=http)

    assert out1.action == "written"
    assert out2.action == "written"
    assert out1.entry_path == out2.entry_path


def test_both_feeds_404_returns_fetch_failed(tmp_path: Path) -> None:
    http = _multi_http([(404, b""), (404, b"")])
    graph = CannedGraphLookup([_LIBTIFF])

    out = poll_one("CVE-2999-99999", graph=graph, root=tmp_path, http=http)

    assert out.action == "fetch-failed"
    assert out.feed_used is None
    assert "not found" in out.reason.lower() or "404" in out.reason


def test_dossier_decode_error_falls_back_to_nvd(tmp_path: Path) -> None:
    """Per locked decision: a partial outage upstream (broken dossier
    response) does not block the inbox; NVD-direct is tried."""
    http = _multi_http([(200, b"<html>maintenance</html>"), (200, _NVD_BODY)])
    graph = CannedGraphLookup([_LIBTIFF])

    out = poll_one("CVE-2024-13978", graph=graph, root=tmp_path, http=http)

    assert out.action == "written"
    assert out.feed_used == "nvd"


def test_rate_limit_propagates_with_retry_after(tmp_path: Path) -> None:
    """If both feeds rate-limit, the poller surfaces the longer retry
    so the cron can sleep before the next CVE."""
    fn = MagicMock()
    fn.side_effect = [
        (429, b"", {"Retry-After": "60"}),
        (429, b"", {"Retry-After": "120"}),
    ]
    graph = CannedGraphLookup([_LIBTIFF])
    out = poll_one("CVE-2024-13978", graph=graph, root=tmp_path, http=fn)
    assert out.action == "rate-limited"
    assert out.retry_after_seconds == 120


def test_nvd_api_key_threaded_through(tmp_path: Path) -> None:
    """When the dossier 404s and NVD is queried, the api_key (if any)
    must flow into the apiKey header. The poller does not invent or
    read env keys; it forwards what the caller passes."""
    http = _multi_http([(404, b""), (200, _NVD_BODY)])
    graph = CannedGraphLookup([_LIBTIFF])
    poll_one(
        "CVE-2024-13978",
        graph=graph,
        root=tmp_path,
        http=http,
        nvd_api_key="abc-123",
    )
    nvd_call = http.call_args_list[1]
    headers = nvd_call.kwargs.get("headers") or nvd_call.args[1]
    assert headers.get("apiKey") == "abc-123"


def test_invalid_cve_id_raises(tmp_path: Path) -> None:
    http = _http_returning(200, _DOSSIER_BODY)
    graph = CannedGraphLookup([_LIBTIFF])
    with pytest.raises(ValueError, match="CVE"):
        poll_one("not-a-cve", graph=graph, root=tmp_path, http=http)


def test_outcome_carries_cve_id_for_logging(tmp_path: Path) -> None:
    """Every outcome (written, skipped, failed) carries the CVE id
    so a structured log line can be emitted without separate state."""
    http = _http_returning(200, _DOSSIER_BODY)
    graph = CannedGraphLookup([])
    out = poll_one("CVE-2024-13978", graph=graph, root=tmp_path, http=http)
    assert out.cve_id == "CVE-2024-13978"


_NVD_BODY_WITH_PATCH = json.dumps({
    "vulnerabilities": [{
        "cve": {
            "id": "CVE-2024-13978",
            "published": "2025-08-01T21:32:07.000",
            "descriptions": [{"lang": "en", "value": "LibTIFF null deref"}],
            "configurations": [{
                "nodes": [{
                    "operator": "OR",
                    "negate": False,
                    "cpeMatch": [{
                        "vulnerable": True,
                        "criteria": "cpe:2.3:a:libtiff:libtiff:*:*:*:*:*:*:*:*",
                    }],
                }],
            }],
            "references": [
                {"url": "https://gitlab.com/libtiff/libtiff/-/commit/" + "c" * 40,
                 "tags": ["Patch"]},
            ],
        },
    }],
    "totalResults": 1,
}).encode()


def _dossier_with_refs(refs: list[dict[str, str]]) -> bytes:
    body = json.loads(_DOSSIER_BODY)
    body["data"]["provenance"] = [{"url": r["url"]} for r in refs]
    return json.dumps(body).encode()


def test_dossier_without_fix_commit_is_enriched_from_nvd(tmp_path: Path) -> None:
    """The aggregator dropped its embedded reference list, so the fix commit must
    come from the authoritative record or nothing is ever source-backport tier."""
    http = _multi_http([(200, _DOSSIER_BODY), (200, _NVD_BODY_WITH_PATCH)])
    graph = CannedGraphLookup([_LIBTIFF])

    out = poll_one("CVE-2024-13978", graph=graph, root=tmp_path, http=http)

    assert out.action == "written"
    assert out.feed_used == "dossier"
    written = json.loads((out.entry_path / "scout-input.json").read_text())
    kinds = [r["kind"] for r in written["references"]]
    assert "upstream-commit" in kinds
    enriched = written["aggregator"]["enriched_from"]
    assert enriched["feed"] == "nvd"
    assert "references" in enriched["fields_merged"]
    assert len(enriched["response_sha256"]) == 64
    # the merged fields must be reconstructible from stored bytes, not a hash alone
    import hashlib
    stored = (out.entry_path / "raw-nvd-enrichment.json").read_bytes()
    assert hashlib.sha256(stored).hexdigest() == enriched["response_sha256"]
    meta = json.loads((out.entry_path / "fetch-meta.json").read_text())
    assert meta["extra_raw"]["raw_filename"] == "raw-nvd-enrichment.json"


def test_dossier_carrying_fix_commit_skips_the_second_fetch(tmp_path: Path) -> None:
    body = json.loads(_DOSSIER_BODY)
    body["data"]["sources"]["nvd"]["nvdReferences"] = [
        {"url": "https://github.com/o/libtiff/commit/" + "d" * 40, "tags": ["Patch"]},
    ]
    http = _http_returning(200, json.dumps(body).encode())
    graph = CannedGraphLookup([_LIBTIFF])

    out = poll_one("CVE-2024-13978", graph=graph, root=tmp_path, http=http)

    assert out.action == "written"
    assert http.call_count == 1
    written = json.loads((out.entry_path / "scout-input.json").read_text())
    assert "enriched_from" not in written["aggregator"]


def test_failed_enrichment_still_writes_the_dossier_record(tmp_path: Path) -> None:
    http = _multi_http([(200, _DOSSIER_BODY), (404, b"{}")])
    graph = CannedGraphLookup([_LIBTIFF])

    out = poll_one("CVE-2024-13978", graph=graph, root=tmp_path, http=http)

    assert out.action == "written"
    written = json.loads((out.entry_path / "scout-input.json").read_text())
    assert "enriched_from" not in written["aggregator"]


def test_untagged_commit_url_counts_as_a_fix_reference(tmp_path: Path) -> None:
    """NVD adds the Patch tag days after disclosure; the URL shape is the signal."""
    body = json.loads(_DOSSIER_BODY)
    body["data"]["provenance"] = [
        {"url": "https://gitlab.com/gnuwget/wget/-/commit/" + "e" * 40},
    ]
    http = _http_returning(200, json.dumps(body).encode())
    graph = CannedGraphLookup([_LIBTIFF])

    out = poll_one("CVE-2024-13978", graph=graph, root=tmp_path, http=http)

    assert out.action == "written"
    assert http.call_count == 1
    assert not (out.entry_path / "raw-nvd-enrichment.json").exists()
