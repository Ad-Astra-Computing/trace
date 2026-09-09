"""GHSA-direct → scout-input normalizer tests.

Two fixtures, both captured from api.github.com on 2026-04-23:
  * GHSA-rxwq-x6h5-x525 — unreviewed, no vulnerabilities[] package info (xz backdoor; GitHub classed it unreviewed so no package mapping).
  * GHSA-c57f-mm3j-27q9 — reviewed npm advisory with package info (@astrojs/node).

Asserts:
  * Source fixtures validate against ghsa-source-schema.json.
  * Normalizer output validates against scout-input-schema.json.
  * feed is always "ghsa"; aggregator block is absent (direct-source path).
  * Scoped npm packages emit PURLs per PURL spec (namespace-encoded @).
  * Advisories without CVE are refused (trace findings are CVE-keyed).
  * Reviewed advisory with package info produces purl_matches + pname_hints.
  * Unreviewed advisory with no package info produces a scout-input that
    routes to mapping-failure at Scout layer (no identifiers).
  * No policy verdict leakage.
"""

from __future__ import annotations

import copy
import json
from pathlib import Path
from typing import Any

import pytest
from jsonschema import Draft202012Validator

from agents.feed_normalizers import normalize_ghsa
from tests.schema.validate import REPO_ROOT


FIXTURES = Path(__file__).parent / "fixtures"
GHSA_UNREVIEWED = FIXTURES / "ghsa-GHSA-rxwq-x6h5-x525.json"  # xz, CVE-2024-3094
GHSA_REVIEWED = FIXTURES / "ghsa-GHSA-c57f-mm3j-27q9.json"  # @astrojs/node


@pytest.fixture(scope="module")
def source_validator() -> Draft202012Validator:
    return Draft202012Validator(
        json.loads((REPO_ROOT / "policy" / "ghsa-source-schema.json").read_text())
    )


@pytest.fixture(scope="module")
def scout_input_validator() -> Draft202012Validator:
    return Draft202012Validator(
        json.loads((REPO_ROOT / "policy" / "scout-input-schema.json").read_text())
    )


def _errors(v: Draft202012Validator, doc: Any) -> list[str]:
    return [
        f"{'/'.join(str(p) for p in e.absolute_path)}: {e.message}"
        for e in v.iter_errors(doc)
    ]


# ─── shape ─────────────────────────────────────────────────────────────────


@pytest.mark.parametrize("path", [GHSA_UNREVIEWED, GHSA_REVIEWED])
def test_ghsa_source_fixtures_validate(source_validator, path):
    doc = json.loads(path.read_text())
    errs = _errors(source_validator, doc)
    assert not errs, f"{path.name} failed source schema: {errs}"


# ─── unreviewed advisory (xz) ──────────────────────────────────────────────


def test_unreviewed_advisory_normalizes(scout_input_validator):
    raw = json.loads(GHSA_UNREVIEWED.read_text())
    out = normalize_ghsa(raw)
    errs = _errors(scout_input_validator, out)
    assert not errs, f"output failed scout-input schema: {errs}"

    assert out["feed"] == "ghsa"
    assert out["cve_id"] == "CVE-2024-3094"
    assert out["severity"]["rating"] == "critical"
    assert out["severity"]["cvss_v3_score"] == 10.0
    assert (
        out["severity"]["cvss_v3_vector"]
        == "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"
    )
    # No vulnerabilities[] with package info in this unreviewed record.
    assert "purl_matches" not in out
    assert "pname_hints" not in out
    # Aliases include the GHSA id (primary) plus any in identifiers[].
    assert "GHSA-rxwq-x6h5-x525" in out["aliases"]


def test_unreviewed_advisory_scout_input_routes_to_mapping_failure():
    """An advisory with no package identifiers must produce a scout-input whose Scout result is mapping-failure — trace does not auto-advance a finding when there is no way to pin it to a derivation."""
    from agents.scout import CannedGraphLookup, scan

    raw = json.loads(GHSA_UNREVIEWED.read_text())
    out = normalize_ghsa(raw)

    graph = CannedGraphLookup([])
    result = scan(out, graph)
    assert result["status"] == "mapping-failure"
    assert result["mapping_failure"]["reason"] == "empty-identifier-set"


# ─── reviewed advisory (npm @astrojs/node) ─────────────────────────────────


def test_reviewed_advisory_normalizes(scout_input_validator):
    raw = json.loads(GHSA_REVIEWED.read_text())
    out = normalize_ghsa(raw)
    errs = _errors(scout_input_validator, out)
    assert not errs, f"output failed scout-input schema: {errs}"

    assert out["feed"] == "ghsa"
    assert out["cve_id"] == "CVE-2026-41322"
    assert out["pname_hints"] == ["@astrojs/node"]
    # Scoped npm → pkg:npm/%40<scope>/<name>
    assert out["purl_matches"] == ["pkg:npm/%40astrojs/node"]


def test_reviewed_advisory_pipes_to_scout_as_purl_match(scout_input_validator):
    """The normalized record should feed Scout cleanly and produce a finding when the graph has the matching PURL."""
    from agents.scout import CannedGraphLookup, scan
    from agents.scout.graph_lookup import GraphMatch

    raw = json.loads(GHSA_REVIEWED.read_text())
    out = normalize_ghsa(raw)

    graph = CannedGraphLookup(
        [
            GraphMatch(
                attr_path="nodePackages.astrojs-node",
                drv_path="/nix/store/00000000000000000000000000000009-astrojs-node-10.0.4.drv",
                pname="@astrojs/node",
                version="10.0.4",
                purls=("pkg:npm/%40astrojs/node",),
            )
        ]
    )
    result = scan(out, graph)
    assert result["status"] == "finding"
    finding = result["finding"]
    assert finding["source_feeds"] == ["ghsa"]
    assert finding["mapping"]["method"] == "purl-exact"
    assert finding["affected"][0]["confidence"] == "high"
    # No aggregator leakage anywhere downstream.
    assert "aggregator" not in finding


# ─── refusals + edge cases ─────────────────────────────────────────────────


def test_ghsa_without_cve_refused():
    raw = json.loads(GHSA_REVIEWED.read_text())
    raw["cve_id"] = None
    with pytest.raises(ValueError):
        normalize_ghsa(raw)


def test_normalizer_does_not_mutate_input():
    raw = json.loads(GHSA_REVIEWED.read_text())
    clone = copy.deepcopy(raw)
    normalize_ghsa(raw)
    assert raw == clone, "normalizer must not mutate its input"


def test_no_aggregator_block_on_direct_source():
    """GHSA-direct is not an aggregator. Provenance for the fetch belongs in replay.json, not on the scout-input."""
    raw = json.loads(GHSA_REVIEWED.read_text())
    out = normalize_ghsa(raw)
    assert "aggregator" not in out


def test_no_policy_verdict_leaks():
    raw = json.loads(GHSA_REVIEWED.read_text())
    out = normalize_ghsa(raw)
    forbidden = {"kind", "eligibility", "verdict", "bundle_kind", "confidence"}
    assert not (set(out.keys()) & forbidden)


def test_maven_package_splits_group_artifact():
    """GHSA uses `groupId:artifactId` for Maven; PURL splits into namespace/name with `/`."""
    synthetic = {
        "ghsa_id": "GHSA-aaaa-bbbb-cccc",
        "cve_id": "CVE-2099-0001",
        "severity": "high",
        "published_at": "2026-04-23T00:00:00Z",
        "vulnerabilities": [
            {"package": {"ecosystem": "maven", "name": "org.example:libexample"}},
        ],
        "references": [],
        "cvss": {
            "vector_string": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
            "score": 7.5,
        },
    }
    out = normalize_ghsa(synthetic)
    assert out["purl_matches"] == ["pkg:maven/org.example/libexample"]
    assert out["pname_hints"] == ["org.example:libexample"]


def test_unknown_ecosystem_falls_back_to_pname_hint_only():
    synthetic = {
        "ghsa_id": "GHSA-aaaa-bbbb-dddd",
        "cve_id": "CVE-2099-0002",
        "severity": "medium",
        "published_at": "2026-04-23T00:00:00Z",
        "vulnerabilities": [
            {"package": {"ecosystem": "something-new", "name": "foo"}},
        ],
        "references": [],
    }
    out = normalize_ghsa(synthetic)
    assert out["pname_hints"] == ["foo"]
    assert "purl_matches" not in out


def test_reference_kind_inference():
    synthetic = {
        "ghsa_id": "GHSA-aaaa-bbbb-eeee",
        "cve_id": "CVE-2099-0003",
        "severity": "low",
        "published_at": "2026-04-23T00:00:00Z",
        "vulnerabilities": [],
        "references": [
            "https://github.com/example/repo/commit/abc1234",
            "https://github.com/example/repo/releases/tag/v1.4.8",
            "https://github.com/advisories/GHSA-aaaa-bbbb-eeee",
            "https://bugs.example.invalid/show_bug.cgi?id=1",
            "https://openwall.com/lists/oss-security/2024/03/29/4",
            "https://random.example.invalid/something",
        ],
    }
    out = normalize_ghsa(synthetic)
    kinds = [r["kind"] for r in out["references"]]
    assert kinds == [
        "upstream-commit",
        "release-notes",
        "advisory",
        "bug-tracker",
        "blog",
        "advisory",
    ]
