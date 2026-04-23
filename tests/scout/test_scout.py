"""Scout stub tests.

Covers:
  * exact CPE/PURL match, 1 derivation       → high
  * exact CPE/PURL match, multiple           → low (ambiguous-multi)
  * pname heuristic, 1 derivation            → medium
  * pname heuristic, multiple                → low
  * no match                                 → mapping-failure (no finding)
  * empty identifier set                     → mapping-failure (reason=empty-identifier-set)

Every emitted finding is schema-validated against `policy/finding-schema.json`
and every mapping-failure against `policy/mapping-failure-schema.json`.
Every scout-input used by a test is schema-validated against
`policy/scout-input-schema.json` so the test inputs themselves remain honest.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
from jsonschema import Draft202012Validator

from agents.scout import CannedGraphLookup, scan
from agents.scout.graph_lookup import GraphMatch
from tests.schema.validate import REPO_ROOT


@pytest.fixture(scope="module")
def scout_input_validator() -> Draft202012Validator:
    schema = json.loads((REPO_ROOT / "policy" / "scout-input-schema.json").read_text())
    return Draft202012Validator(schema)


@pytest.fixture(scope="module")
def finding_validator() -> Draft202012Validator:
    schema = json.loads((REPO_ROOT / "policy" / "finding-schema.json").read_text())
    return Draft202012Validator(schema)


@pytest.fixture(scope="module")
def mapping_failure_validator() -> Draft202012Validator:
    schema = json.loads((REPO_ROOT / "policy" / "mapping-failure-schema.json").read_text())
    return Draft202012Validator(schema)


def _validate(validator: Draft202012Validator, doc: Any, label: str) -> None:
    errors = [
        f"{'/'.join(str(p) for p in e.absolute_path)}: {e.message}"
        for e in validator.iter_errors(doc)
    ]
    assert not errors, f"{label} failed schema validation: {errors}"


# Two canned derivations used across fixtures.
MATCH_LIBEXAMPLE = GraphMatch(
    attr_path="libexample",
    drv_path="/nix/store/00000000000000000000000000000001-libexample-1.4.7.drv",
    pname="libexample",
    version="1.4.7",
    cpes=("cpe:2.3:a:example:libexample:1.4.7:*:*:*:*:*:*:*",),
    purls=("pkg:generic/libexample@1.4.7",),
    src_url="https://example.invalid/libexample-1.4.7.tar.gz",
    src_hash="sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
)

MATCH_LIBEXAMPLE_ALT = GraphMatch(
    attr_path="libexampleAlt",
    drv_path="/nix/store/00000000000000000000000000000002-libexample-alt-1.4.7.drv",
    pname="libexample",
    version="1.4.7",
    cpes=("cpe:2.3:a:example:libexample:1.4.7:*:*:*:*:*:*:*",),
    purls=("pkg:generic/libexample@1.4.7",),
)


def _base_feed(cve: str, **overrides: Any) -> dict[str, Any]:
    rec = {
        "feed": "nvd",
        "cve_id": cve,
        "published_at": "2026-04-01T00:00:00Z",
        "severity": {"rating": "high", "cvss_v3_score": 7.5},
    }
    rec.update(overrides)
    return rec


# ─── path 1: exact match, single hit → high ─────────────────────────────────


def test_cpe_exact_single_hit_high(scout_input_validator, finding_validator):
    feed = _base_feed(
        "CVE-0000-2001",
        cpe_matches=[{"cpe": "cpe:2.3:a:example:libexample:1.4.7:*:*:*:*:*:*:*"}],
    )
    _validate(scout_input_validator, feed, "scout input")
    graph = CannedGraphLookup([MATCH_LIBEXAMPLE])

    result = scan(feed, graph)
    assert result["status"] == "finding"
    finding = result["finding"]
    _validate(finding_validator, finding, "finding")

    assert finding["mapping"]["method"] == "cpe-exact"
    assert finding["mapping"]["cpe"] == ["cpe:2.3:a:example:libexample:1.4.7:*:*:*:*:*:*:*"]
    assert len(finding["affected"]) == 1
    affected = finding["affected"][0]
    assert affected["confidence"] == "high"
    assert "confidence_reason" not in affected


def test_purl_exact_single_hit_high(scout_input_validator, finding_validator):
    feed = _base_feed(
        "CVE-0000-2002",
        purl_matches=["pkg:generic/libexample@1.4.7"],
    )
    _validate(scout_input_validator, feed, "scout input")
    graph = CannedGraphLookup([MATCH_LIBEXAMPLE])

    result = scan(feed, graph)
    assert result["status"] == "finding"
    finding = result["finding"]
    _validate(finding_validator, finding, "finding")

    assert finding["mapping"]["method"] == "purl-exact"
    assert finding["affected"][0]["confidence"] == "high"


# ─── path 2: exact match, multiple hits → low (ambiguous) ───────────────────


def test_exact_match_multi_hit_low(scout_input_validator, finding_validator):
    feed = _base_feed(
        "CVE-0000-2003",
        cpe_matches=[{"cpe": "cpe:2.3:a:example:libexample:1.4.7:*:*:*:*:*:*:*"}],
    )
    _validate(scout_input_validator, feed, "scout input")
    graph = CannedGraphLookup([MATCH_LIBEXAMPLE, MATCH_LIBEXAMPLE_ALT])

    result = scan(feed, graph)
    assert result["status"] == "finding"
    finding = result["finding"]
    _validate(finding_validator, finding, "finding")

    assert finding["mapping"]["method"] == "cpe-exact"
    assert finding["mapping"]["mapping_notes"].startswith("ambiguous 2-way")
    assert len(finding["affected"]) == 2
    for aff in finding["affected"]:
        assert aff["confidence"] == "low"
        assert "confidence_reason" in aff


# ─── path 3: pname heuristic, single hit → medium ───────────────────────────


def test_pname_heuristic_single_hit_medium(scout_input_validator, finding_validator):
    # Neither CPE nor PURL hits the graph; pname hint falls back to libexample.
    feed = _base_feed(
        "CVE-0000-2004",
        cpe_matches=[{"cpe": "cpe:2.3:a:example:libexample-core:1.4.7:*:*:*:*:*:*:*"}],
        pname_hints=["libexample"],
    )
    _validate(scout_input_validator, feed, "scout input")
    # Graph record has a different CPE so CPE-exact won't fire; pname=libexample matches.
    graph = CannedGraphLookup([
        GraphMatch(
            attr_path="libexample",
            drv_path="/nix/store/00000000000000000000000000000003-libexample-1.4.7.drv",
            pname="libexample",
            version="1.4.7",
            cpes=("cpe:2.3:a:example:libexample:1.4.7:*:*:*:*:*:*:*",),
        )
    ])

    result = scan(feed, graph)
    assert result["status"] == "finding"
    finding = result["finding"]
    _validate(finding_validator, finding, "finding")

    assert finding["mapping"]["method"] == "pname-heuristic"
    assert finding["affected"][0]["confidence"] == "medium"
    assert "confidence_reason" in finding["affected"][0]


def test_pname_derived_from_cpe_when_no_hint_given(scout_input_validator, finding_validator):
    # Scout should derive pname="libexample" from the cpe product component.
    feed = _base_feed(
        "CVE-0000-2005",
        cpe_matches=[{"cpe": "cpe:2.3:a:example:libexample:9.9.9:*:*:*:*:*:*:*"}],
    )
    _validate(scout_input_validator, feed, "scout input")
    graph = CannedGraphLookup([
        GraphMatch(
            attr_path="libexample",
            drv_path="/nix/store/00000000000000000000000000000004-libexample-1.4.7.drv",
            pname="libexample",
            version="1.4.7",
            # Note: no CPE on this graph record (different from feed cpe), so exact
            # lookup misses; pname extraction from the feed cpe must rescue it.
        )
    ])
    result = scan(feed, graph)
    assert result["status"] == "finding"
    _validate(finding_validator, result["finding"], "finding")
    assert result["finding"]["mapping"]["method"] == "pname-heuristic"
    assert result["finding"]["affected"][0]["confidence"] == "medium"


# ─── path 4: pname heuristic, multiple hits → low ───────────────────────────


def test_pname_heuristic_multi_hit_low(scout_input_validator, finding_validator):
    feed = _base_feed(
        "CVE-0000-2006",
        pname_hints=["libexample"],
    )
    _validate(scout_input_validator, feed, "scout input")
    graph = CannedGraphLookup([
        GraphMatch(
            attr_path="libexample",
            drv_path="/nix/store/00000000000000000000000000000005-libexample-1.4.7.drv",
            pname="libexample",
            version="1.4.7",
        ),
        GraphMatch(
            attr_path="libexampleAlt",
            drv_path="/nix/store/00000000000000000000000000000006-libexample-alt-1.4.7.drv",
            pname="libexample",
            version="1.4.7",
        ),
    ])

    result = scan(feed, graph)
    assert result["status"] == "finding"
    finding = result["finding"]
    _validate(finding_validator, finding, "finding")

    assert finding["mapping"]["method"] == "pname-heuristic"
    assert len(finding["affected"]) == 2
    for aff in finding["affected"]:
        assert aff["confidence"] == "low"


# ─── path 5: no match → mapping-failure ─────────────────────────────────────


def test_no_match_emits_mapping_failure(scout_input_validator, mapping_failure_validator):
    feed = _base_feed(
        "CVE-0000-2007",
        cpe_matches=[{"cpe": "cpe:2.3:a:unknownvendor:nothing-here:1.0.0:*:*:*:*:*:*:*"}],
        purl_matches=["pkg:generic/nothing-here@1.0.0"],
    )
    _validate(scout_input_validator, feed, "scout input")
    graph = CannedGraphLookup([MATCH_LIBEXAMPLE])  # different product

    result = scan(feed, graph)
    assert result["status"] == "mapping-failure"
    mf = result["mapping_failure"]
    _validate(mapping_failure_validator, mf, "mapping-failure")

    assert mf["cve_id"] == "CVE-0000-2007"
    assert mf["reason"] == "no-match"
    methods_tried = {m["method"] for m in mf["attempted_methods"]}
    assert "cpe-exact" in methods_tried
    assert "purl-exact" in methods_tried
    assert "pname-heuristic" in methods_tried
    for m in mf["attempted_methods"]:
        assert m["hits"] == 0


def test_empty_identifier_set_emits_mapping_failure(scout_input_validator, mapping_failure_validator):
    feed = _base_feed("CVE-0000-2008")  # no cpes, no purls, no pname hints
    _validate(scout_input_validator, feed, "scout input")
    graph = CannedGraphLookup([MATCH_LIBEXAMPLE])

    result = scan(feed, graph)
    assert result["status"] == "mapping-failure"
    mf = result["mapping_failure"]
    _validate(mapping_failure_validator, mf, "mapping-failure")

    assert mf["reason"] == "empty-identifier-set"


# ─── meta ───────────────────────────────────────────────────────────────────


def test_scout_never_advances_to_patcher(scout_input_validator, finding_validator):
    """Scout emits finding/mapping-failure only. It does not carry any Patcher-advancement verdict, and does not short-circuit to auto-merge on high confidence. That decision belongs to UpstreamRefResolver + Steward."""
    feed = _base_feed(
        "CVE-0000-2009",
        cpe_matches=[{"cpe": "cpe:2.3:a:example:libexample:1.4.7:*:*:*:*:*:*:*"}],
    )
    graph = CannedGraphLookup([MATCH_LIBEXAMPLE])
    result = scan(feed, graph)
    assert result["status"] == "finding"
    finding = result["finding"]
    # No bundle.kind / eligibility / verdict fields anywhere in the finding.
    assert "kind" not in finding
    assert "eligibility" not in finding
    assert "verdict" not in finding
