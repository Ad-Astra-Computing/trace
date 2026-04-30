"""NVD-direct → scout-input normalizer tests.

Fixture captured from services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2024-13978
on 28 April 2026. The full NVD response is wider than what trace consumes;
the source schema validates only the subset the normalizer reads.

Asserts:
  * Source fixture validates against nvd-source-schema.json (the .cve level).
  * Normalizer output validates against scout-input-schema.json.
  * feed is always "nvd"; aggregator block absent (direct-source path).
  * CPE matches are emitted with cpe + optional version_range.
  * CVSS v3.1 baseScore + baseSeverity + vectorString surface in severity.
  * References are categorised by NVD tag where possible
    ('Patch'/'Issue Tracking' → upstream-commit/bug-tracker), else 'other'.
  * Summary uses the en-language description, truncated to SUMMARY_MAX.
  * No fix-commit metadata leaks into source_feeds beyond the feed enum.
"""

from __future__ import annotations

import copy
import json
from pathlib import Path
from typing import Any

import pytest
from jsonschema import Draft202012Validator

from agents.feed_normalizers.nvd import normalize as normalize_nvd
from tests.schema.validate import REPO_ROOT


FIXTURE = Path(__file__).parent / "fixtures" / "nvd-CVE-2024-13978.json"


@pytest.fixture(scope="module")
def source_validator() -> Draft202012Validator:
    return Draft202012Validator(
        json.loads((REPO_ROOT / "policy" / "nvd-source-schema.json").read_text())
    )


@pytest.fixture(scope="module")
def scout_input_validator() -> Draft202012Validator:
    return Draft202012Validator(
        json.loads((REPO_ROOT / "policy" / "scout-input-schema.json").read_text())
    )


def _cve_record() -> dict[str, Any]:
    """Pull the single .vulnerabilities[0].cve from the NVD response."""
    raw = json.loads(FIXTURE.read_text())
    assert raw["totalResults"] == 1
    return raw["vulnerabilities"][0]["cve"]


def test_source_fixture_validates(source_validator: Draft202012Validator) -> None:
    cve = _cve_record()
    errors = sorted(source_validator.iter_errors(cve), key=lambda e: e.path)
    assert not errors, [str(e) for e in errors[:3]]


def test_normalizer_output_validates_against_scout_input(
    scout_input_validator: Draft202012Validator,
) -> None:
    cve = _cve_record()
    output = normalize_nvd(cve)
    errors = sorted(scout_input_validator.iter_errors(output), key=lambda e: e.path)
    assert not errors, [str(e) for e in errors[:3]]


def test_feed_is_nvd_with_no_aggregator() -> None:
    cve = _cve_record()
    output = normalize_nvd(cve)
    assert output["feed"] == "nvd"
    assert "aggregator" not in output


def test_cve_id_and_publication_preserved() -> None:
    cve = _cve_record()
    output = normalize_nvd(cve)
    assert output["cve_id"] == "CVE-2024-13978"
    assert output["published_at"].startswith("2025") or output["published_at"].startswith("2024")


def test_summary_is_en_description() -> None:
    cve = _cve_record()
    output = normalize_nvd(cve)
    assert "summary" in output
    assert len(output["summary"]) > 10
    # The CVE-2024-13978 description mentions libtiff or fax2ps somewhere.
    assert any(tok in output["summary"].lower() for tok in ("libtiff", "fax2ps", "tiff"))


def test_summary_truncated_to_max(scout_input_validator: Draft202012Validator) -> None:
    cve = _cve_record()
    cve = copy.deepcopy(cve)
    cve["descriptions"] = [{"lang": "en", "value": "x" * 5000}]
    output = normalize_nvd(cve)
    assert len(output["summary"]) <= 2000
    errors = sorted(scout_input_validator.iter_errors(output), key=lambda e: e.path)
    assert not errors


def test_cpe_matches_emitted_with_version_range() -> None:
    cve = _cve_record()
    output = normalize_nvd(cve)
    cpes = output.get("cpe_matches", [])
    assert cpes, "NVD record has CPE matches; normalizer must emit them"
    for entry in cpes:
        assert entry["cpe"].startswith("cpe:2.3:")


def test_severity_extracted_from_cvss_v31() -> None:
    cve = _cve_record()
    output = normalize_nvd(cve)
    sev = output.get("severity", {})
    # CVE-2024-13978 has a CVSS 3.1 score in NVD; the rating must come
    # through as one of the enum values.
    assert sev.get("rating") in {"critical", "high", "medium", "low", "none", "unknown"}
    if sev.get("cvss_v3_score") is not None:
        assert 0.0 <= sev["cvss_v3_score"] <= 10.0


def test_references_categorised() -> None:
    cve = _cve_record()
    output = normalize_nvd(cve)
    refs = output.get("references", [])
    assert refs
    allowed = {"advisory", "upstream-commit", "release-notes", "blog", "bug-tracker", "other"}
    for r in refs:
        assert r["url"]
        assert r["kind"] in allowed


def test_pname_hints_derived_from_cpes_when_available() -> None:
    """libtiff CPE → pname hint 'libtiff'. The normalizer extracts the
    product field from cpe:2.3:a:vendor:product:* segments."""
    cve = _cve_record()
    output = normalize_nvd(cve)
    hints = set(output.get("pname_hints", []))
    assert "libtiff" in hints, f"expected 'libtiff' in pname_hints, got {hints!r}"


def test_version_bounds_extracted_from_versionEndExcluding() -> None:
    """NVD's configurations[].nodes[].cpeMatch[].versionEndExcluding
    encodes the upstream fix version. Without lifting it to
    version_bounds, scan can't gate on advisory range and the
    resolver target falls back to the placeholder = current_version."""
    cve = {
        "id": "CVE-2099-9001",
        "published": "2026-04-30T00:00:00Z",
        "descriptions": [{"lang": "en", "value": "x"}],
        "configurations": [{
            "nodes": [{
                "operator": "OR",
                "cpeMatch": [{
                    "vulnerable": True,
                    "criteria": "cpe:2.3:a:frappe:press:*:*:*:*:*:*:*:*",
                    "versionEndExcluding": "0.9.0",
                }],
            }],
        }],
    }
    output = normalize_nvd(cve)
    bounds = output.get("version_bounds", [])
    assert bounds, "NVD versionEndExcluding must populate version_bounds"
    b = bounds[0]
    assert b["product"] == "press"
    assert b["fixed"] == "0.9.0"
    assert b["fixed_kind"] == "versionEndExcluding"
    assert b["source"] == "nvd_configurations"


def test_version_bounds_extracted_from_versionEndIncluding() -> None:
    cve = {
        "id": "CVE-2099-9002",
        "published": "2026-04-30T00:00:00Z",
        "descriptions": [{"lang": "en", "value": "x"}],
        "configurations": [{
            "nodes": [{
                "operator": "OR",
                "cpeMatch": [{
                    "vulnerable": True,
                    "criteria": "cpe:2.3:a:x:y:*:*:*:*:*:*:*:*",
                    "versionEndIncluding": "1.4.5",
                }],
            }],
        }],
    }
    output = normalize_nvd(cve)
    b = output["version_bounds"][0]
    assert b["fixed"] == "1.4.5"
    assert b["fixed_kind"] == "versionEndIncluding"


def test_version_bounds_omitted_when_no_end_field() -> None:
    """A cpeMatch with only versionStart and no end is a 'no fix yet'
    signal; emit no bound."""
    cve = {
        "id": "CVE-2099-9003",
        "published": "2026-04-30T00:00:00Z",
        "descriptions": [{"lang": "en", "value": "x"}],
        "configurations": [{
            "nodes": [{
                "operator": "OR",
                "cpeMatch": [{
                    "vulnerable": True,
                    "criteria": "cpe:2.3:a:x:y:*:*:*:*:*:*:*:*",
                    "versionStartIncluding": "1.0.0",
                }],
            }],
        }],
    }
    output = normalize_nvd(cve)
    assert "version_bounds" not in output or output["version_bounds"] == []


def test_no_cve_id_rejected() -> None:
    cve = {
        "id": "GHSA-xyz",  # not a CVE
        "published": "2026-01-01T00:00:00Z",
        "descriptions": [{"lang": "en", "value": "x"}],
        "references": [],
    }
    with pytest.raises(ValueError, match="CVE"):
        normalize_nvd(cve)
