"""CPE 2.3 wildcard / version-range matching at scan time.

Diagnosed 2026-04-30 (backfill 7-day window): advisory CPEs commonly
carry wildcard values (`cpe:2.3:a:apache:activemq:*:*:*:*:*:*:*:*`)
while snapshot CPEs (post NVD-dictionary enrichment) carry concrete
versions. The exact-string graph index never matched the two, so
Scout fell through to pname-heuristic and confidence stayed at medium
even on identifier-rich advisories. Auto-merge eligibility was
unreachable as a result.

This module pins the fix:

  * find_by_cpe_uri_match(cpe) honours CPE 2.3 wildcards in
    part / vendor / product / version fields. `*` and `-` match any
    concrete value at the same field position.
  * Scan promotes a wildcard match to cpe-exact + confidence:high
    iff the snapshot version is actually in the advisory's affected
    range (cpe_matches[].version_range OR version_bounds for the
    matched product).
  * Out-of-scope wildcard matches are skipped entirely (the snapshot
    is not affected; emitting a finding would be a false positive).
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from agents.scout.graph_lookup import CannedGraphLookup, GraphMatch
from agents.scout.scout import scan
from agents.scout.processor import process_entry


_ACTIVEMQ_REAL = GraphMatch(
    attr_path="activemq",
    drv_path="attr:activemq",
    pname="activemq",
    version="6.2.4",
    cpes=(
        "cpe:2.3:a:apache:activemq:6.2.4:*:*:*:*:*:*:*",
        "cpe:2.3:a:apache:activemq:6.2.0:*:*:*:*:*:*:*",
    ),
)


def _scout_input(
    *,
    cpe_matches: list[dict[str, Any]] | None = None,
    version_bounds: list[dict[str, Any]] | None = None,
    pname_hints: list[str] | None = None,
) -> dict[str, Any]:
    out: dict[str, Any] = {
        "feed": "nvd",
        "cve_id": "CVE-2099-9000",
        "published_at": "2026-04-30T00:00:00Z",
    }
    if cpe_matches is not None:
        out["cpe_matches"] = cpe_matches
    if pname_hints is not None:
        out["pname_hints"] = pname_hints
    if version_bounds is not None:
        out["version_bounds"] = version_bounds
    return out


# ─── graph_lookup wildcard semantics ────────────────────────────────────────


def test_find_by_cpe_uri_match_promotes_wildcard_advisory_to_real_record() -> None:
    from agents.scout.graph_lookup import CannedGraphLookup

    g = CannedGraphLookup([_ACTIVEMQ_REAL])
    matches = g.find_by_cpe_uri_match("cpe:2.3:a:apache:activemq:*:*:*:*:*:*:*:*")
    assert len(matches) == 1
    assert matches[0].attr_path == "activemq"


def test_find_by_cpe_uri_match_concrete_advisory_uses_exact_index() -> None:
    g = CannedGraphLookup([_ACTIVEMQ_REAL])
    matches = g.find_by_cpe_uri_match("cpe:2.3:a:apache:activemq:6.2.4:*:*:*:*:*:*:*")
    assert len(matches) == 1
    assert matches[0].attr_path == "activemq"


def test_find_by_cpe_uri_match_does_not_cross_vendor() -> None:
    """Wildcard expansion must NOT widen across vendors. apache:activemq
    must not match jboss:activemq. Vendor specificity is the whole
    point of using the dictionary."""
    g = CannedGraphLookup([_ACTIVEMQ_REAL])
    matches = g.find_by_cpe_uri_match("cpe:2.3:a:jboss:activemq:*:*:*:*:*:*:*:*")
    assert matches == []


def test_find_by_cpe_uri_match_handles_dash_wildcard() -> None:
    """CPE 2.3 reserves `-` for 'not applicable' / wildcard. Treat it
    the same as `*` for matching purposes."""
    g = CannedGraphLookup([_ACTIVEMQ_REAL])
    matches = g.find_by_cpe_uri_match("cpe:2.3:a:apache:activemq:-:*:*:*:*:*:*:*")
    assert len(matches) == 1


def test_find_by_cpe_uri_match_returns_empty_on_unknown_vendor() -> None:
    g = CannedGraphLookup([_ACTIVEMQ_REAL])
    assert g.find_by_cpe_uri_match("cpe:2.3:a:nope:nope:*:*:*:*:*:*:*:*") == []


# ─── scan() integration: version-range gating ───────────────────────────────


def test_in_scope_wildcard_advisory_yields_cpe_exact_high_confidence() -> None:
    """activemq 6.2.4 against advisory 'apache:activemq:* (>=6.0.0,<6.2.5)'
    is in scope: snapshot version satisfies the advisory range. The
    finding must be cpe-exact with confidence:high so Steward can
    classify it as auto-merge-eligible."""
    scout_in = _scout_input(
        cpe_matches=[
            {
                "cpe": "cpe:2.3:a:apache:activemq:*:*:*:*:*:*:*:*",
                "version_range": ">=6.0.0,<6.2.5",
            }
        ],
    )
    result = scan(scout_in, graph=CannedGraphLookup([_ACTIVEMQ_REAL]))
    assert result["status"] == "finding"
    affected = result["finding"]["affected"]
    assert len(affected) == 1
    assert affected[0]["confidence"] == "high"
    assert result["finding"]["mapping"]["method"] == "cpe-exact"


def test_out_of_scope_wildcard_advisory_is_skipped() -> None:
    """activemq 6.2.4 against advisory 'apache:activemq:* (<5.0.0)'
    is OUT of scope: snapshot version is not affected. Scan must NOT
    emit a finding (false positive that would auto-merge an unrelated
    CVE onto the package). Mapping-failure is the right outcome when
    no other identifier hits."""
    scout_in = _scout_input(
        cpe_matches=[
            {
                "cpe": "cpe:2.3:a:apache:activemq:*:*:*:*:*:*:*:*",
                "version_range": "<5.0.0",
            }
        ],
    )
    result = scan(scout_in, graph=CannedGraphLookup([_ACTIVEMQ_REAL]))
    assert result["status"] == "mapping-failure"


def test_version_bounds_used_when_no_explicit_range_on_cpe_match() -> None:
    """If cpe_matches[].version_range is absent but version_bounds carry
    a lessThan bound for the matched product, the bound supplies the
    in-scope check. activemq 6.2.4 vs lessThan=6.2.5 -> in scope."""
    scout_in = _scout_input(
        cpe_matches=[{"cpe": "cpe:2.3:a:apache:activemq:*:*:*:*:*:*:*:*"}],
        version_bounds=[
            {
                "product": "activemq",
                "fixed": "6.2.5",
                "fixed_kind": "lessThan",
                "version_type": "semver",
                "source": "cve_list_v5",
            }
        ],
    )
    result = scan(scout_in, graph=CannedGraphLookup([_ACTIVEMQ_REAL]))
    assert result["status"] == "finding"
    assert result["finding"]["affected"][0]["confidence"] == "high"


def test_no_version_constraint_drops_to_medium_confidence() -> None:
    """If the advisory has neither version_range on the cpe_match nor
    version_bounds for the product, we cannot prove the snapshot is in
    scope. Match still hits (vendor+product) but confidence is medium
    so Steward routes to human review, not auto-merge."""
    scout_in = _scout_input(
        cpe_matches=[{"cpe": "cpe:2.3:a:apache:activemq:*:*:*:*:*:*:*:*"}],
    )
    result = scan(scout_in, graph=CannedGraphLookup([_ACTIVEMQ_REAL]))
    assert result["status"] == "finding"
    affected = result["finding"]["affected"]
    assert affected[0]["confidence"] == "medium"
    assert result["finding"]["mapping"]["method"] == "cpe-vendor-product"


def test_concrete_cpe_still_uses_exact_index_unchanged() -> None:
    """Backwards-compat: a fully-concrete CPE that matches the snapshot
    via the exact index keeps its existing behaviour (cpe-exact, high)."""
    scout_in = _scout_input(
        cpe_matches=[{"cpe": "cpe:2.3:a:apache:activemq:6.2.4:*:*:*:*:*:*:*"}],
    )
    result = scan(scout_in, graph=CannedGraphLookup([_ACTIVEMQ_REAL]))
    assert result["status"] == "finding"
    assert result["finding"]["affected"][0]["confidence"] == "high"
    assert result["finding"]["mapping"]["method"] == "cpe-exact"


def test_processor_end_to_end_yields_auto_merge_eligible_inputs(tmp_path: Path) -> None:
    """End-to-end: an in-scope wildcard advisory writes finding.json
    with confidence:high. Combined with version_bounds shipping a
    point-release target (eligible verdict) and Steward checking
    confidence_high_only=True, the steward-decision should be
    auto-merge-eligible. (We assert through the resolver-input shape
    here; the live cron path runs Steward via batch_cli.)"""
    entry = tmp_path / "CVE-2099-9000"
    entry.mkdir()
    scout_in = _scout_input(
        cpe_matches=[
            {
                "cpe": "cpe:2.3:a:apache:activemq:*:*:*:*:*:*:*:*",
                "version_range": ">=6.0.0,<6.2.5",
            }
        ],
        version_bounds=[
            {
                "product": "activemq",
                "fixed": "6.2.5",
                "fixed_kind": "lessThan",
                "version_type": "semver",
                "source": "cve_list_v5",
            }
        ],
    )
    (entry / "scout-input.json").write_text(json.dumps(scout_in))
    process_entry(entry, graph=CannedGraphLookup([_ACTIVEMQ_REAL]))

    finding = json.loads((entry / "finding.json").read_text())
    assert finding["affected"][0]["confidence"] == "high"
    assert finding["affected"][0]["pname"] == "activemq"

    resolver_input = json.loads((entry / "resolver-input.json").read_text())
    refs = resolver_input["candidate_refs"]
    if refs:
        assert refs[0]["version"] == "6.2.5"  # synthesized from version_bounds
