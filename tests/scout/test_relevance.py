"""Upfront nixpkgs-relevance filter for scout-input records.

Slice 4 of Scout autonomy. Before invoking the full Scout match
pipeline (which builds a finding-or-mapping-failure record per
input), the orchestrator asks: does this scout-input even plausibly
touch nixpkgs?

The filter walks identifiers in the same priority Scout uses
(cpe → purl → pname) and short-circuits on the first hit. A miss
returns relevant=False so the orchestrator skips writing an inbox
file, saves a cron cycle, and avoids generating mapping-failure noise
for CVEs that obviously do not touch the nixpkgs surface.

Conservative by design: any single graph hit at any layer keeps the
record. False positives are cheap (Scout produces a low-confidence
finding); false negatives are expensive (a real CVE silently dropped)
so we tilt towards inclusion.
"""

from __future__ import annotations

from typing import Any

from agents.scout.graph_lookup import CannedGraphLookup, GraphMatch
from agents.scout.relevance import RelevanceDecision, is_relevant_to_nixpkgs


_LIBTIFF = GraphMatch(
    attr_path="libtiff",
    drv_path="/nix/store/aaa-libtiff.drv",
    pname="libtiff",
    version="4.7.0",
    cpes=("cpe:2.3:a:libtiff:libtiff:*:*:*:*:*:*:*:*",),
)


def _input(**overrides: Any) -> dict[str, Any]:
    base: dict[str, Any] = {
        "feed": "nvd",
        "cve_id": "CVE-2024-13978",
        "published_at": "2025-01-01T00:00:00Z",
    }
    base.update(overrides)
    return base


def test_cpe_hit_marks_relevant() -> None:
    graph = CannedGraphLookup([_LIBTIFF])
    record = _input(cpe_matches=[{"cpe": _LIBTIFF.cpes[0]}])
    decision = is_relevant_to_nixpkgs(record, graph)
    assert decision.relevant is True
    assert decision.matched_identifier == _LIBTIFF.cpes[0]
    assert decision.layer == "cpe"


def test_pname_hint_hit_marks_relevant() -> None:
    graph = CannedGraphLookup([_LIBTIFF])
    record = _input(pname_hints=["libtiff"])
    decision = is_relevant_to_nixpkgs(record, graph)
    assert decision.relevant is True
    assert decision.matched_identifier == "libtiff"
    assert decision.layer == "pname"


def test_purl_hit_marks_relevant() -> None:
    purl = "pkg:generic/libtiff@4.6.0"
    graph_record = GraphMatch(
        attr_path="libtiff",
        drv_path="/nix/store/aaa-libtiff.drv",
        pname="libtiff",
        version="4.6.0",
        purls=(purl,),
    )
    graph = CannedGraphLookup([graph_record])
    record = _input(purl_matches=[purl])
    decision = is_relevant_to_nixpkgs(record, graph)
    assert decision.relevant is True
    assert decision.matched_identifier == purl
    assert decision.layer == "purl"


def test_no_match_anywhere_marks_irrelevant() -> None:
    graph = CannedGraphLookup([_LIBTIFF])
    record = _input(
        cpe_matches=[{"cpe": "cpe:2.3:a:contoso:windows-only-thing:*:*:*:*:*:*:*:*"}],
        pname_hints=["windows-only-thing"],
    )
    decision = is_relevant_to_nixpkgs(record, graph)
    assert decision.relevant is False
    assert decision.matched_identifier is None
    assert decision.layer is None
    assert "no-match" in decision.reason


def test_empty_identifier_set_marks_irrelevant() -> None:
    """A scout-input with no cpe/purl/pname can't be matched at all;
    Scout would return mapping-failure(reason=empty-identifier-set).
    Filter declines upfront."""
    graph = CannedGraphLookup([_LIBTIFF])
    decision = is_relevant_to_nixpkgs(_input(), graph)
    assert decision.relevant is False
    assert "no-identifiers" in decision.reason


def test_decision_short_circuits_on_first_hit() -> None:
    """Once a layer hits, the filter does not need to walk further
    layers. Verified by checking the decision exposes the layer that
    matched (cpe before pname when both could match)."""
    graph = CannedGraphLookup([_LIBTIFF])
    record = _input(
        cpe_matches=[{"cpe": _LIBTIFF.cpes[0]}],
        pname_hints=["libtiff"],
    )
    decision = is_relevant_to_nixpkgs(record, graph)
    assert decision.layer == "cpe"


def test_pname_match_is_case_insensitive_for_filter() -> None:
    """Dossier sometimes returns mixed-case package names (LibTIFF);
    pname hints from canonical.affectedPackages already get lowercased
    by the normalizer, but the filter is defensive."""
    graph = CannedGraphLookup([_LIBTIFF])
    record = _input(pname_hints=["LibTIFF"])
    decision = is_relevant_to_nixpkgs(record, graph)
    assert decision.relevant is True


def test_cpe_product_fallback_hits_when_full_cpe_misses() -> None:
    """A snapshot built without a CPE dictionary indexes records by pname
    only. When a CVE quotes `cpe:2.3:a:libtiff:libtiff:...` and the snapshot
    has a record with pname=libtiff, the relevance filter must still hit
    via the cpe-product fallback (vendor-agnostic). This is what unblocks
    the cron loop on real nixpkgs surfaces without a paid NVD dictionary."""
    snapshot_record = GraphMatch(
        attr_path="libtiff",
        drv_path="attr:libtiff",
        pname="libtiff",
        version="4.7.1",
        cpes=(),
    )
    graph = CannedGraphLookup([snapshot_record])
    record = _input(cpe_matches=[{"cpe": "cpe:2.3:a:libtiff:libtiff:*:*:*:*:*:*:*:*"}])
    decision = is_relevant_to_nixpkgs(record, graph)
    assert decision.relevant is True
    assert decision.layer == "cpe-product"
    assert "vendor-agnostic" in decision.reason


def test_decision_is_a_relevance_decision() -> None:
    graph = CannedGraphLookup([_LIBTIFF])
    decision = is_relevant_to_nixpkgs(_input(), graph)
    assert isinstance(decision, RelevanceDecision)
    # Conformant frozen dataclass: serializable for inbox metadata.
    assert decision.relevant is False
    assert isinstance(decision.reason, str)
