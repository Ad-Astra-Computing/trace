"""Vulnpatch dossier → scout-input normalizer tests.

Fixture captured from https://api.vulnpatch.dev/api/v1/cve/CVE-2024-13978/dossier
on 28 April 2026.

The dossier is an aggregator (cve.vulnpatch.dev) that bundles raw NVD,
GHSA, OSV, MITRE, EPSS, KEV payloads into a single response with quality
metrics and agent-tailored hints. Per the existing trust boundary
(vulnpatch_cve.py + DECISIONS 2026-04-23), aggregator metadata lives in
the optional aggregator block on scout-input; `feed` reflects the
underlying authoritative source so Scout's mapping method and finding
source_feeds keep their existing meaning.

Asserts:
  * Source fixture validates against dossier-source-schema.json.
  * Normalizer output validates against scout-input-schema.json.
  * feed='nvd' when sources.nvd is present (the canonical authoritative
    feed for nixpkgs-relevant CVEs).
  * aggregator block carries name='vulnpatch-dossier' + request_url +
    fetched_at + response_sha256 (for "raw payload provenance" per
    user note 28 April 2026).
  * cve_id, published_at preserved.
  * CPE matches lifted from data.sources.nvd via the existing nvd
    normalizer's CPE extraction logic (no duplication).
  * pname_hints derived from CPE products (lowercase).
  * Severity rating from canonical.severity (already lowercased by dossier).
  * References include the canonical advisory URL (links.html).
  * Bundles without sources.nvd fall back to feed=ghsa or osv.
  * Records without a CVE id refused.
"""

from __future__ import annotations

import copy
import json
from pathlib import Path
from typing import Any

import pytest
from jsonschema import Draft202012Validator

from agents.feed_normalizers.dossier import normalize as normalize_dossier
from tests.schema.validate import REPO_ROOT


FIXTURE = Path(__file__).parent / "fixtures" / "dossier-CVE-2024-13978.json"


@pytest.fixture(scope="module")
def source_validator() -> Draft202012Validator:
    return Draft202012Validator(
        json.loads((REPO_ROOT / "policy" / "dossier-source-schema.json").read_text())
    )


@pytest.fixture(scope="module")
def scout_input_validator() -> Draft202012Validator:
    return Draft202012Validator(
        json.loads((REPO_ROOT / "policy" / "scout-input-schema.json").read_text())
    )


def _data() -> dict[str, Any]:
    raw = json.loads(FIXTURE.read_text())
    return raw["data"]


def _normalize_call() -> dict[str, Any]:
    raw_bytes = FIXTURE.read_bytes()
    return normalize_dossier(
        _data(),
        request_url="https://api.vulnpatch.dev/api/v1/cve/CVE-2024-13978/dossier",
        fetched_at="2026-04-29T01:39:42Z",
        raw_response_bytes=raw_bytes,
    )


def test_source_fixture_validates(source_validator: Draft202012Validator) -> None:
    errors = sorted(source_validator.iter_errors(_data()), key=lambda e: e.path)
    assert not errors, [str(e) for e in errors[:3]]


def test_normalizer_output_validates(scout_input_validator: Draft202012Validator) -> None:
    out = _normalize_call()
    errors = sorted(scout_input_validator.iter_errors(out), key=lambda e: e.path)
    assert not errors, [str(e) for e in errors[:3]]


def test_feed_is_nvd_when_nvd_source_present() -> None:
    out = _normalize_call()
    assert out["feed"] == "nvd"


def test_aggregator_block_records_provenance() -> None:
    out = _normalize_call()
    agg = out.get("aggregator")
    assert agg is not None, "dossier output MUST carry aggregator block"
    assert agg["name"] == "vulnpatch-dossier"
    assert agg["request_url"].endswith("/CVE-2024-13978/dossier")
    assert agg["fetched_at"] == "2026-04-29T01:39:42Z"
    assert len(agg["response_sha256"]) == 64
    assert all(c in "0123456789abcdef" for c in agg["response_sha256"])


def test_cve_id_and_published_at_preserved() -> None:
    out = _normalize_call()
    assert out["cve_id"] == "CVE-2024-13978"
    # Dossier publishedAt may end in 'Z' or have ms; either way scout-input
    # accepts ISO-8601.
    assert out["published_at"].startswith("2025") or out["published_at"].startswith("2024")


def test_severity_lowercased_from_canonical() -> None:
    out = _normalize_call()
    sev = out.get("severity", {})
    assert sev.get("rating") in {"critical", "high", "medium", "low", "none", "unknown"}
    if sev.get("cvss_v3_score") is not None:
        assert 0.0 <= sev["cvss_v3_score"] <= 10.0


def test_cpe_matches_lifted_from_nvd_source() -> None:
    out = _normalize_call()
    cpes = out.get("cpe_matches", [])
    assert cpes, "dossier embeds NVD source; CPE matches must be lifted"
    for entry in cpes:
        assert entry["cpe"].startswith("cpe:2.3:")


def test_pname_hints_derived_from_cpes_lowercase() -> None:
    out = _normalize_call()
    hints = set(out.get("pname_hints", []))
    assert "libtiff" in hints, f"expected 'libtiff' in pname_hints, got {hints!r}"


def test_references_include_canonical_link() -> None:
    out = _normalize_call()
    refs = out.get("references", [])
    assert refs
    urls = [r["url"] for r in refs]
    # The dossier's HTML view OR the upstream CVE.org URL should be present.
    assert any("cve.vulnpatch.dev" in u or "cve.org" in u or "nvd.nist.gov" in u for u in urls)


def test_nvd_patch_tag_lifts_commit_url_as_upstream_commit() -> None:
    """sources.nvd.nvdReferences[] entries tagged 'Patch' MUST surface
    as kind='upstream-commit' so the Scout processor can extract them
    as candidate fix commits. Regression: dossier normalizer was
    previously only walking top-level links/provenance and silently
    dropping NVD's per-source references."""
    out = _normalize_call()
    refs = out.get("references", [])
    upstream_commits = [r for r in refs if r["kind"] == "upstream-commit"]
    gitlab_commits = [r for r in upstream_commits if "gitlab.com" in r["url"] and "/commit/" in r["url"]]
    assert gitlab_commits, f"expected gitlab.com /commit/ URL with kind=upstream-commit, got {refs!r}"


def test_falls_back_to_ghsa_when_nvd_absent() -> None:
    """If a dossier has no sources.nvd but does have sources.github, the
    feed flips to 'ghsa' to keep authoritative-source attribution
    accurate."""
    data = copy.deepcopy(_data())
    data.setdefault("sources", {})["nvd"] = None
    raw_bytes = json.dumps({"data": data}).encode()
    out = normalize_dossier(
        data,
        request_url="https://api.vulnpatch.dev/api/v1/cve/CVE-2024-13978/dossier",
        fetched_at="2026-04-29T01:39:42Z",
        raw_response_bytes=raw_bytes,
    )
    assert out["feed"] in {"ghsa", "osv"}


def _dossier_with_cve_list_v5_affected(affected: list[dict[str, Any]]) -> dict[str, Any]:
    """Minimal dossier shape carrying only the fields the normalizer
    needs to test version_bounds extraction."""
    return {
        "cveId": "CVE-2026-42615",
        "canonical": {
            "id": "CVE-2026-42615",
            "publishedAt": "2026-04-29T02:55:53.171Z",
            "description": "test",
            "severity": "high",
        },
        "sources": {
            "cve_list_v5": {
                "id": "CVE-2026-42615",
                "datePublished": "2026-04-29T02:55:53.171Z",
                "affected": affected,
            },
        },
    }


def _normalize(data: dict[str, Any]) -> dict[str, Any]:
    raw = json.dumps({"data": data}).encode()
    return normalize_dossier(
        data,
        request_url="https://api.vulnpatch.dev/api/v1/cve/x/dossier",
        fetched_at="2026-04-29T00:00:00Z",
        raw_response_bytes=raw,
    )


def test_version_bounds_extracted_from_cve_list_v5_lessThan() -> None:
    """The CyberChef regression case: cve_list_v5 affected[].versions[]
    carries lessThan=11.0.0 meaning the fix landed at v11.0.0. The
    normalizer must lift this to scout-input so the resolver doesn't
    fall back to the bare-commit placeholder."""
    data = _dossier_with_cve_list_v5_affected([{
        "vendor": "GCHQ",
        "product": "CyberChef",
        "versions": [{
            "version": "0",
            "status": "affected",
            "lessThan": "11.0.0",
            "versionType": "semver",
        }],
        "cpes": [],
    }])
    out = _normalize(data)
    bounds = out.get("version_bounds", [])
    assert bounds, "version_bounds must be lifted from cve_list_v5"
    b = bounds[0]
    assert b["product"] == "cyberchef"  # lowercased to align with pname
    assert b["fixed"] == "11.0.0"
    assert b["fixed_kind"] == "lessThan"
    assert b["version_type"] == "semver"
    assert b["source"] == "cve_list_v5"
    assert b.get("introduced") == "0"


def test_version_bounds_lessThanOrEqual_preserved_distinctly() -> None:
    """lessThanOrEqual is NOT the same as lessThan. The processor needs
    to know which was given so it can decide whether to synthesize a
    candidate target_version (lessThan: yes) or fall back (lessThanOrEqual:
    needs next-semver math we don't have yet)."""
    data = _dossier_with_cve_list_v5_affected([{
        "vendor": "x", "product": "Foo",
        "versions": [{"version": "1.0.0", "status": "affected",
                      "lessThanOrEqual": "1.4.5", "versionType": "semver"}],
        "cpes": [],
    }])
    out = _normalize(data)
    bounds = out["version_bounds"]
    assert bounds[0]["fixed_kind"] == "lessThanOrEqual"
    assert bounds[0]["fixed"] == "1.4.5"


def test_version_bounds_skips_unaffected_status() -> None:
    """Only status=affected entries are bounds for fix-version derivation."""
    data = _dossier_with_cve_list_v5_affected([{
        "vendor": "x", "product": "Foo",
        "versions": [
            {"version": "0", "status": "affected", "lessThan": "2.0.0",
             "versionType": "semver"},
            {"version": "2.0.0", "status": "unaffected",
             "versionType": "semver"},
        ],
        "cpes": [],
    }])
    out = _normalize(data)
    bounds = out["version_bounds"]
    assert len(bounds) == 1
    assert bounds[0]["fixed"] == "2.0.0"


def test_version_bounds_skips_non_semver_version_types() -> None:
    """v0 only handles semver. Custom/git/rpm types pass through with no
    bound emitted; the placeholder path takes over."""
    data = _dossier_with_cve_list_v5_affected([{
        "vendor": "x", "product": "Foo",
        "versions": [{"version": "0", "status": "affected",
                      "lessThan": "abc-1.2", "versionType": "custom"}],
        "cpes": [],
    }])
    out = _normalize(data)
    assert "version_bounds" not in out or out["version_bounds"] == []


def test_version_bounds_multiple_products_each_carry_their_bound() -> None:
    """Multi-product CVEs: each affected product gets its own bound;
    processor filters by matched pname."""
    data = _dossier_with_cve_list_v5_affected([
        {"vendor": "x", "product": "Foo",
         "versions": [{"version": "0", "status": "affected",
                       "lessThan": "1.2.0", "versionType": "semver"}],
         "cpes": []},
        {"vendor": "y", "product": "Bar",
         "versions": [{"version": "0", "status": "affected",
                       "lessThan": "3.0.0", "versionType": "semver"}],
         "cpes": []},
    ])
    out = _normalize(data)
    bounds = out["version_bounds"]
    products = {b["product"]: b["fixed"] for b in bounds}
    assert products == {"foo": "1.2.0", "bar": "3.0.0"}


def test_version_bounds_omitted_when_no_cve_list_v5() -> None:
    data = {
        "cveId": "CVE-2024-13978",
        "canonical": {
            "id": "CVE-2024-13978",
            "publishedAt": "2024-09-01T00:00:00Z",
            "description": "x",
        },
        "sources": {},
    }
    out = _normalize(data)
    assert "version_bounds" not in out


def test_version_bounds_output_validates(scout_input_validator: Draft202012Validator) -> None:
    data = _dossier_with_cve_list_v5_affected([{
        "vendor": "GCHQ", "product": "CyberChef",
        "versions": [{"version": "0", "status": "affected",
                      "lessThan": "11.0.0", "versionType": "semver"}],
        "cpes": [],
    }])
    out = _normalize(data)
    errors = sorted(scout_input_validator.iter_errors(out), key=lambda e: e.path)
    assert not errors, [str(e) for e in errors[:3]]


def test_no_cve_id_rejected() -> None:
    bad = {
        "cveId": "GHSA-xyz",
        "canonical": {
            "id": "GHSA-xyz",
            "publishedAt": "2026-01-01T00:00:00Z",
            "description": "x",
        },
        "provenance": [],
    }
    with pytest.raises(ValueError, match="CVE"):
        normalize_dossier(
            bad,
            request_url="https://api.vulnpatch.dev/api/v1/cve/X/dossier",
            fetched_at="2026-04-29T01:39:42Z",
            raw_response_bytes=b"{}",
        )
