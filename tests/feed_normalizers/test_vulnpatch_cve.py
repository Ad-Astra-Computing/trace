"""Vulnpatch → scout-input normalizer tests.

Fixture: a real response captured from `https://api.vulnpatch.dev/api/v1/cve/CVE-2024-3094`
on 2026-04-23. Driving tests against real bytes (rather than a hand-rolled
mock) keeps the normalizer honest when the upstream shape drifts.

Trust boundary tests:
  * Vulnpatch response validates against vulnpatch-cve-source-schema.json.
  * Normalizer output validates against scout-input-schema.json.
  * Aggregator metadata is populated with request URL, fetched timestamp,
    raw-response sha256, per-source sha256s, and EPSS signals.
  * Scout is never told the record is authoritative — feed/source_feeds
    reflect the underlying feed (nvd for cve-list-v5 primary), not 'vulnpatch'.
  * Steward would not read aggregator (asserted structurally: the finding
    produced downstream by Scout carries no aggregator reference).
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator

from agents.feed_normalizers import normalize_vulnpatch
from agents.feed_normalizers.vulnpatch_cve import sha256_hex
from tests.schema.validate import REPO_ROOT


FIXTURES = Path(__file__).parent / "fixtures"
FIXTURE_CVE_2024_3094 = FIXTURES / "vulnpatch-CVE-2024-3094.json"


# ─── shared validators ─────────────────────────────────────────────────────


@pytest.fixture(scope="module")
def source_validator() -> Draft202012Validator:
    schema = json.loads(
        (REPO_ROOT / "policy" / "vulnpatch-cve-source-schema.json").read_text()
    )
    return Draft202012Validator(schema)


@pytest.fixture(scope="module")
def scout_input_validator() -> Draft202012Validator:
    schema = json.loads((REPO_ROOT / "policy" / "scout-input-schema.json").read_text())
    return Draft202012Validator(schema)


def _errors(v: Draft202012Validator, doc: dict) -> list[str]:
    return [
        f"{'/'.join(str(p) for p in e.absolute_path)}: {e.message}"
        for e in v.iter_errors(doc)
    ]


# ─── source shape ──────────────────────────────────────────────────────────


def test_vulnpatch_source_fixture_validates(source_validator):
    doc = json.loads(FIXTURE_CVE_2024_3094.read_text())
    errs = _errors(source_validator, doc)
    assert not errs, f"real Vulnpatch response failed source schema: {errs}"


def test_source_schema_requires_top_level_fields(source_validator):
    # success / data / integrity / sourceUrl / timestamp are all required.
    doc = json.loads(FIXTURE_CVE_2024_3094.read_text())
    for key in ("success", "data", "integrity", "sourceUrl", "timestamp"):
        without = {k: v for k, v in doc.items() if k != key}
        errs = _errors(source_validator, without)
        assert any(key in m for m in errs), f"schema should require top-level {key!r}"


# ─── normalizer output ─────────────────────────────────────────────────────


@pytest.fixture(scope="module")
def normalized() -> dict:
    raw_bytes = FIXTURE_CVE_2024_3094.read_bytes()
    response = json.loads(raw_bytes)
    return normalize_vulnpatch(
        response,
        request_url="https://api.vulnpatch.dev/api/v1/cve/CVE-2024-3094",
        fetched_at="2026-04-23T15:37:05Z",
        raw_response_bytes=raw_bytes,
        api_version="v1",
    )


def test_normalized_validates_against_scout_input_schema(
    scout_input_validator, normalized
):
    errs = _errors(scout_input_validator, normalized)
    assert not errs, f"normalized output failed scout-input schema: {errs}"


def test_normalized_cve_id_and_feed(normalized):
    assert normalized["cve_id"] == "CVE-2024-3094"
    # cve_list_v5 is the primary source for this fixture → underlying feed is nvd.
    # Feed must be one of the scout-input enum values (nvd/ghsa/osv), never "vulnpatch".
    assert normalized["feed"] == "nvd"


def test_normalized_cpes_collected_deduped_and_converted_to_2_3(normalized):
    cpes = [m["cpe"] for m in normalized.get("cpe_matches", [])]
    # Real fixture contains CPE 2.2-shaped Red Hat identifiers. Normalizer converts to 2.3.
    assert all(c.startswith("cpe:2.3:") for c in cpes), (
        f"all CPEs must be in 2.3 form; got: {cpes}"
    )
    assert any("cpe:2.3:o:redhat:enterprise_linux:8:" in c for c in cpes)
    assert len(set(cpes)) == len(cpes), "cpes must be deduplicated"


def test_normalized_severity_preserves_score_and_vector(normalized):
    sev = normalized["severity"]
    assert sev["rating"] == "critical"
    assert sev["cvss_v3_score"] == 10
    assert sev["cvss_v3_vector"] == "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"


def test_normalized_references_deduped_and_tagged(normalized):
    refs = normalized.get("references", [])
    urls = [r["url"] for r in refs]
    assert len(urls) == len(set(urls))
    assert all(
        r["kind"]
        in {
            "advisory",
            "upstream-commit",
            "release-notes",
            "blog",
            "bug-tracker",
            "other",
        }
        for r in refs
    )
    # Real fixture has Red Hat bugzilla reference tagged issue-tracking.
    bugzilla = [r for r in refs if "bugzilla.redhat.com" in r["url"]]
    assert bugzilla, "expected Red Hat bugzilla reference in fixture"
    assert bugzilla[0]["kind"] == "bug-tracker"


def test_normalized_pname_hints_exclude_unknown(normalized):
    hints = normalized.get("pname_hints", [])
    assert "unknown" not in hints
    # fixture vendor=Red Hat, product="Red Hat Enterprise Linux 10" etc. — real products should appear.
    assert any("Red Hat Enterprise Linux" in h for h in hints)


# ─── aggregator provenance block ───────────────────────────────────────────


def test_aggregator_records_request_url_and_response_hash(normalized):
    agg = normalized["aggregator"]
    assert agg["name"] == "vulnpatch"
    assert agg["request_url"] == "https://api.vulnpatch.dev/api/v1/cve/CVE-2024-3094"
    expected = sha256_hex(FIXTURE_CVE_2024_3094.read_bytes())
    assert agg["response_sha256"] == expected
    assert agg["api_version"] == "v1"


def test_aggregator_uses_vulnpatch_fetched_at_when_present(normalized):
    agg = normalized["aggregator"]
    # integrity.fetchedAt should win over caller-supplied fallback.
    assert agg["fetched_at"] == "2026-04-23T15:37:05.173Z"


def test_aggregator_preserves_underlying_source_hashes(normalized):
    agg = normalized["aggregator"]
    hashes = {h["source"]: h["sha256"] for h in agg.get("underlying_source_hashes", [])}
    # Real fixture has cve_list_v5, github, osv integrity hashes.
    for key in ("cve_list_v5", "github", "osv"):
        assert key in hashes, f"missing underlying source hash for {key}"
        assert len(hashes[key]) == 64


def test_aggregator_epss_recorded_when_present(normalized):
    agg = normalized["aggregator"]
    assert "epss" in agg
    assert 0.0 <= agg["epss"]["score"] <= 1.0
    assert 0.0 <= agg["epss"]["percentile"] <= 1.0


# ─── trust-boundary tests ──────────────────────────────────────────────────


def test_normalizer_does_not_mutate_input():
    raw_bytes = FIXTURE_CVE_2024_3094.read_bytes()
    response_before = json.loads(raw_bytes)
    import copy

    clone = copy.deepcopy(response_before)
    normalize_vulnpatch(
        response_before,
        request_url="https://api.vulnpatch.dev/api/v1/cve/CVE-2024-3094",
        fetched_at="2026-04-23T15:37:05Z",
        raw_response_bytes=raw_bytes,
    )
    assert response_before == clone, "normalizer must not mutate its input"


def test_feed_field_never_vulnpatch(normalized):
    """`feed` records the underlying authoritative source. Vulnpatch is NOT authoritative; it is a convenience aggregator. The aggregator block carries vulnpatch provenance; `feed` does not."""
    assert normalized["feed"] != "vulnpatch"


def test_no_policy_verdict_leaks_into_normalizer_output(normalized):
    """Scout will decide confidence; UpstreamRefResolver will decide eligibility; Steward will decide bundle.kind. The normalizer must not pre-empt any of that."""
    forbidden = {"kind", "eligibility", "verdict", "bundle_kind", "confidence"}
    assert not (set(normalized.keys()) & forbidden)


def test_feeding_output_through_scout_produces_finding(normalized):
    """End-to-end smoke: the normalized doc is a valid Scout input and produces a finding with a real graph match (stubbed)."""
    from agents.scout import CannedGraphLookup, scan
    from agents.scout.graph_lookup import GraphMatch

    # A graph that knows one of the Red Hat CPEs from the fixture, pinned in
    # the 2.3 form the normalizer emits.
    graph = CannedGraphLookup(
        [
            GraphMatch(
                attr_path="redhat-enterprise-linux-8",
                drv_path="/nix/store/00000000000000000000000000000001-rhel-8.drv",
                pname="rhel",
                version="8",
                cpes=("cpe:2.3:o:redhat:enterprise_linux:8:*:*:*:*:*:*:*",),
            )
        ]
    )
    result = scan(normalized, graph)
    assert result["status"] == "finding"
    finding = result["finding"]
    # Scout's source_feeds reflects the `feed` we set, NOT 'vulnpatch'.
    assert finding["source_feeds"] == [normalized["feed"]]
    # Finding carries no aggregator pass-through — Steward never sees it.
    assert "aggregator" not in finding


# ─── edge cases ────────────────────────────────────────────────────────────


def test_normalizer_rejects_response_with_no_payload():
    response = {
        "success": True,
        "data": {"cve_id": "CVE-2026-0001", "sources": {}},
        "integrity": {
            "sources": {},
            "primaryHash": "0" * 64,
            "fetchedAt": "2026-04-23T00:00:00Z",
        },
        "sourceUrl": "https://example.invalid",
        "timestamp": "2026-04-23T00:00:00Z",
    }
    with pytest.raises(ValueError):
        normalize_vulnpatch(
            response,
            request_url="https://api.vulnpatch.dev/api/v1/cve/CVE-2026-0001",
            fetched_at="2026-04-23T00:00:00Z",
            raw_response_bytes=json.dumps(response).encode(),
        )


def test_normalizer_handles_kev_block(scout_input_validator):
    """When Vulnpatch includes a KEV block, the aggregator preserves it."""
    raw = json.loads(FIXTURE_CVE_2024_3094.read_text())
    raw["data"]["kev"] = {
        "vendorProject": "Example",
        "product": "thing",
        "vulnerabilityName": "Example vuln",
        "dateAdded": "2026-04-01",
        "dueDate": "2026-04-22",
        "requiredAction": "patch",
        "knownRansomwareCampaignUse": "Known",
    }
    raw_bytes = json.dumps(raw).encode()
    normalized = normalize_vulnpatch(
        raw,
        request_url="https://api.vulnpatch.dev/api/v1/cve/CVE-2024-3094",
        fetched_at="2026-04-23T00:00:00Z",
        raw_response_bytes=raw_bytes,
    )
    errs = _errors(scout_input_validator, normalized)
    assert not errs, f"kev-augmented output failed scout-input schema: {errs}"
    kev = normalized["aggregator"]["cisa_kev"]
    assert kev["in_catalog"] is True
    assert kev["added_date"] == "2026-04-01"
    assert kev["required_action"] == "patch"
