"""Steward routing-classifier tests.

Exercises agents.steward.agent.route_inbox_entry against synthetic
inbox entries. The agent is a thin runtime over policy/steward_route.rego;
these tests pin the contract:

  * states: auto-merge-eligible, human-review-required, advisory-only, reject
  * reason_codes are machine-readable, stable, structured (prefix:detail)
  * decision artifact (steward-decision.json) is written atomically
  * inputs_summary records what the policy actually saw

Skips when opa is not on PATH (matches the existing test_steward.py pattern).
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
from pathlib import Path
from typing import Any

import pytest


@pytest.fixture(scope="session")
def opa_available() -> bool:
    try:
        subprocess.run(["opa", "version"], check=True, capture_output=True)
    except (FileNotFoundError, subprocess.CalledProcessError):
        if os.environ.get("TRACE_REQUIRE_OPA") == "1":
            pytest.fail("TRACE_REQUIRE_OPA=1 but opa not available")
        pytest.skip("opa not on PATH")
    return True


def _seed(
    tmp_path: Path,
    *,
    cve_id: str = "CVE-2099-0001",
    finding: dict[str, Any] | None = None,
    upstream_ref: dict[str, Any] | None = None,
    mapping_failure: dict[str, Any] | None = None,
) -> Path:
    entry = tmp_path / cve_id
    entry.mkdir()
    if finding is not None:
        (entry / "finding.json").write_text(json.dumps(finding))
    if upstream_ref is not None:
        (entry / "upstream-ref.json").write_text(json.dumps(upstream_ref))
    if mapping_failure is not None:
        (entry / "mapping-failure.json").write_text(json.dumps(mapping_failure))
    return entry


def _eligible_upstream(
    verdict: str = "eligible",
    *,
    with_prefetch: bool = True,
    **extra: Any,
) -> dict[str, Any]:
    """Build an upstream-ref fixture. `with_prefetch=True` (default)
    populates prefetch_hashes so auto-merge-eligible cases pass the
    patcher-readiness gate. Tests that exercise the missing-prefetch
    path pass with_prefetch=False explicitly."""
    out: dict[str, Any] = {
        "schema_version": "1.0.0",
        "cve_id": "CVE-2099-0001",
        "current_version": "1.0.0",
        "target_version": "1.1.0",
        "fix_tier": "security-patch-release",
        "release_url": "https://example.test/r",
        "delta": {
            "transitive_package_changes": 0,
            "new_direct_deps": [],
            "removed_direct_deps": [],
            "crosses_large_delta_threshold": False,
            "threshold_policy": "v0-default",
        },
        "replay_critical": True,
        "eligibility": {"verdict": verdict},
    }
    if with_prefetch:
        out["prefetch_hashes"] = [{
            "name": "src",
            "algorithm": "sha256",
            "value": "0" * 64,
            "source": "nix-prefetch-url",
            "prefetch_kind": "release-archive",
            "replay_critical": True,
        }]
    out["eligibility"].update(extra)
    return out


def _finding(confidence: str = "high") -> dict[str, Any]:
    return {
        "cve_id": "CVE-2099-0001",
        "affected": [{
            "attr_path": "foo",
            "drv_path": "attr:foo",
            "pname": "foo",
            "version": "1.0.0",
            "confidence": confidence,
            "confidence_reason": "test",
        }],
        "mapping": {"method": "cpe-exact", "mapping_notes": "test"},
        "published_at": "2026-04-29T00:00:00Z",
        "references": [],
    }


def test_auto_merge_eligible_when_eligible_and_high_confidence(tmp_path: Path, opa_available: bool) -> None:
    from agents.steward.agent import route_inbox_entry
    entry = _seed(
        tmp_path,
        finding=_finding(confidence="high"),
        upstream_ref=_eligible_upstream(verdict="eligible"),
    )
    decision = route_inbox_entry(entry)
    assert decision["state"] == "auto-merge-eligible"
    assert "eligible-high-confidence" in decision["reason_codes"]
    out = json.loads((entry / "steward-decision.json").read_text())
    assert out["state"] == "auto-merge-eligible"
    assert out["cve_id"] == "CVE-2099-0001"


def test_human_review_when_resolver_routes_to_review(tmp_path: Path, opa_available: bool) -> None:
    from agents.steward.agent import route_inbox_entry
    entry = _seed(
        tmp_path,
        finding=_finding(),
        upstream_ref=_eligible_upstream(
            verdict="eligible-requires-human-review",
            verdict_reason="test",
            human_review_trigger="major-version-jump",
        ),
    )
    decision = route_inbox_entry(entry)
    assert decision["state"] == "human-review-required"
    assert "upstream-ref-requires-human-review:major-version-jump" in decision["reason_codes"]


def test_human_review_when_confidence_below_high(tmp_path: Path, opa_available: bool) -> None:
    """Even with verdict=eligible, medium-confidence pname-heuristic
    findings can never auto-merge per rule-1 of the merge-gate policy.
    Steward routes them to review instead of letting them slip through."""
    from agents.steward.agent import route_inbox_entry
    entry = _seed(
        tmp_path,
        finding=_finding(confidence="medium"),
        upstream_ref=_eligible_upstream(verdict="eligible"),
    )
    decision = route_inbox_entry(entry)
    assert decision["state"] == "human-review-required"
    assert "confidence-not-high:medium" in decision["reason_codes"]


def test_advisory_only_when_resolver_ineligible(tmp_path: Path, opa_available: bool) -> None:
    from agents.steward.agent import route_inbox_entry
    entry = _seed(
        tmp_path,
        finding=_finding(),
        upstream_ref=_eligible_upstream(
            verdict="ineligible-no-fix-available",
            verdict_reason="test",
        ),
    )
    decision = route_inbox_entry(entry)
    assert decision["state"] == "advisory-only"
    assert "upstream-ref-ineligible:no-fix-available" in decision["reason_codes"]


def test_reject_when_only_mapping_failure(tmp_path: Path, opa_available: bool) -> None:
    from agents.steward.agent import route_inbox_entry
    entry = _seed(
        tmp_path,
        mapping_failure={"cve_id": "CVE-2099-0001", "reason": "no-match"},
    )
    decision = route_inbox_entry(entry)
    assert decision["state"] == "reject"
    assert "mapping-failure" in decision["reason_codes"]


def test_reject_when_no_actionable_input(tmp_path: Path, opa_available: bool) -> None:
    from agents.steward.agent import route_inbox_entry
    entry = _seed(tmp_path)  # nothing
    decision = route_inbox_entry(entry)
    assert decision["state"] == "reject"
    assert "no-actionable-input" in decision["reason_codes"]


def test_decision_records_inputs_summary(tmp_path: Path, opa_available: bool) -> None:
    """The decision artifact must record what the policy actually saw,
    so downstream metrics can group by resolver_verdict / trigger."""
    from agents.steward.agent import route_inbox_entry
    entry = _seed(
        tmp_path,
        finding=_finding(),
        upstream_ref=_eligible_upstream(
            verdict="eligible-requires-human-review",
            verdict_reason="test",
            human_review_trigger="ambiguous-fixed-version",
        ),
    )
    route_inbox_entry(entry)
    out = json.loads((entry / "steward-decision.json").read_text())
    summary = out["inputs_summary"]
    assert summary["resolver_verdict"] == "eligible-requires-human-review"
    assert summary["resolver_trigger"] == "ambiguous-fixed-version"
    assert summary["finding_status"] == "finding"
    assert summary["confidence_high_only"] is True


def test_decision_records_policy_provenance(tmp_path: Path, opa_available: bool) -> None:
    from agents.steward.agent import route_inbox_entry
    entry = _seed(
        tmp_path,
        finding=_finding(),
        upstream_ref=_eligible_upstream(verdict="eligible"),
    )
    route_inbox_entry(entry)
    out = json.loads((entry / "steward-decision.json").read_text())
    assert out["evaluator"].startswith("opa-rego/")
    assert "data.trace.steward.route" in out["evaluator"]
    assert len(out["policy_sha256"]) == 64
    assert out["schema_version"] == "1.0.0"
    assert out["decided_at"].endswith("Z")


def test_atomic_write(tmp_path: Path, opa_available: bool) -> None:
    """A reprocess overwrites cleanly; no partial files remain."""
    from agents.steward.agent import route_inbox_entry
    entry = _seed(
        tmp_path,
        finding=_finding(),
        upstream_ref=_eligible_upstream(verdict="eligible"),
    )
    route_inbox_entry(entry)
    route_inbox_entry(entry)
    leftovers = [p for p in entry.iterdir() if p.name.startswith("steward-decision.json.")]
    assert leftovers == [], f"temp files leaked: {leftovers}"


def test_unanalyzed_impact_routes_to_human_review(tmp_path: Path, opa_available: bool) -> None:
    """When impact.json is present with analysis_status != 'complete',
    Steward routes to human-review-required regardless of the resolver
    verdict. Auto-merge cannot happen on partial impact data."""
    from agents.steward.agent import route_inbox_entry
    entry = _seed(
        tmp_path,
        finding=_finding(),
        upstream_ref=_eligible_upstream(verdict="eligible"),
    )
    (entry / "impact.json").write_text(json.dumps({
        "schema_version": "1.0.0",
        "cve_id": "CVE-2099-0001",
        "nixpkgs_rev": "0" * 40,
        "blast_radius_threshold": 500,
        "threshold_policy": "v0-default",
        "affected_attr_paths": ["foo"],
        "reverse_closure_count": 0,
        "reverse_closure_bucket": "<50",
        "exceeds_threshold": False,
        "per_attr": [],
        "replay_critical": True,
        "analysis_status": "skipped-v0",
        "analysis_reason": "snapshot-backend-unimplemented",
    }))
    decision = route_inbox_entry(entry)
    assert decision["state"] == "human-review-required"
    assert "impact-unanalyzed:skipped-v0" in decision["reason_codes"]


def test_impact_without_analysis_status_forces_review(tmp_path: Path, opa_available: bool) -> None:
    """analysis_status is optional in impact-schema.json, so absence is reachable.
    `analysis_status != "complete"` is UNDEFINED when the field is missing, which
    used to let such an impact stay auto-merge eligible. Absence means nobody
    asserted the analysis ran: fail closed."""
    from agents.steward.agent import route_inbox_entry
    entry = _seed(
        tmp_path,
        finding=_finding(),
        upstream_ref=_eligible_upstream(verdict="eligible"),
    )
    (entry / "impact.json").write_text(json.dumps({
        "schema_version": "1.0.0",
        "cve_id": "CVE-2099-0001",
        "nixpkgs_rev": "0" * 40,
        "blast_radius_threshold": 500,
        "threshold_policy": "v0-default",
        "affected_attr_paths": ["foo"],
        "reverse_closure_count": 42,
        "reverse_closure_bucket": "<50",
        "exceeds_threshold": False,
        "per_attr": [],
        "replay_critical": True,
    }))
    decision = route_inbox_entry(entry)
    assert decision["state"] == "human-review-required"
    assert "impact-unanalyzed:absent" in decision["reason_codes"]


def test_complete_impact_does_not_force_review(tmp_path: Path, opa_available: bool) -> None:
    """Backwards-compat: impact.json with analysis_status='complete'
    behaves exactly like before (no impact.json)."""
    from agents.steward.agent import route_inbox_entry
    entry = _seed(
        tmp_path,
        finding=_finding(),
        upstream_ref=_eligible_upstream(verdict="eligible"),
    )
    (entry / "impact.json").write_text(json.dumps({
        "schema_version": "1.0.0",
        "cve_id": "CVE-2099-0001",
        "nixpkgs_rev": "0" * 40,
        "blast_radius_threshold": 500,
        "threshold_policy": "v0-default",
        "affected_attr_paths": ["foo"],
        "reverse_closure_count": 0,
        "reverse_closure_bucket": "<50",
        "exceeds_threshold": False,
        "per_attr": [],
        "replay_critical": True,
        "analysis_status": "complete",
    }))
    decision = route_inbox_entry(entry)
    assert decision["state"] == "auto-merge-eligible"


def test_decision_validates_against_schema(tmp_path: Path, opa_available: bool) -> None:
    from jsonschema import Draft202012Validator
    from agents.steward.agent import route_inbox_entry

    schema_path = Path(__file__).resolve().parents[2] / "policy" / "steward-decision-schema.json"
    validator = Draft202012Validator(json.loads(schema_path.read_text()))

    cases = [
        ("CVE-2099-1001", {"finding": _finding(), "upstream_ref": _eligible_upstream(verdict="eligible")}),
        ("CVE-2099-1002", {"finding": _finding(), "upstream_ref": _eligible_upstream(
            verdict="eligible-requires-human-review",
            verdict_reason="t", human_review_trigger="major-version-jump")}),
        ("CVE-2099-1003", {"mapping_failure": {"cve_id": "CVE-2099-1003", "reason": "x"}}),
    ]
    for cve_id, kwargs in cases:
        e = _seed(tmp_path, cve_id=cve_id, **kwargs)
        route_inbox_entry(e)
        out = json.loads((e / "steward-decision.json").read_text())
        errors = sorted(validator.iter_errors(out), key=lambda x: x.path)
        assert not errors, [str(x) for x in errors[:3]]


def test_missing_prefetch_routes_to_human_review(tmp_path: Path, opa_available: bool) -> None:
    """Without prefetch_hashes, Patcher's rule 8 would refuse downstream.
    Steward must surface that as a routing decision pre-flight, not
    pretend the bundle is auto-merge-ready."""
    from agents.steward.agent import route_inbox_entry
    entry = _seed(
        tmp_path,
        finding=_finding(),
        upstream_ref=_eligible_upstream(verdict="eligible", with_prefetch=False),
    )
    decision = route_inbox_entry(entry)
    assert decision["state"] == "human-review-required"
    assert "patcher-not-ready:missing-prefetch-hashes" in decision["reason_codes"]


def test_prefetch_skip_required_routes_to_human_review(tmp_path: Path, opa_available: bool) -> None:
    """A prefetch_skips[] entry with required_for_patch=true is an
    auditable refusal trigger downstream; route to review now."""
    from agents.steward.agent import route_inbox_entry
    upstream = _eligible_upstream(verdict="eligible")
    upstream["prefetch_skips"] = [{
        "name": "src",
        "reason": "v0-no-fetcher-handler",
        "required_for_patch": True,
    }]
    entry = _seed(tmp_path, finding=_finding(), upstream_ref=upstream)
    decision = route_inbox_entry(entry)
    assert decision["state"] == "human-review-required"
    assert "patcher-not-ready:prefetch-skipped:src" in decision["reason_codes"]


def test_prefetch_failure_required_routes_to_human_review(tmp_path: Path, opa_available: bool) -> None:
    """A prefetch_failures[] entry with required_for_patch=true is the
    other auditable refusal trigger; route to review."""
    from agents.steward.agent import route_inbox_entry
    upstream = _eligible_upstream(verdict="eligible")
    upstream["prefetch_failures"] = [{
        "name": "src",
        "reason": "404 from upstream",
        "required_for_patch": True,
    }]
    entry = _seed(tmp_path, finding=_finding(), upstream_ref=upstream)
    decision = route_inbox_entry(entry)
    assert decision["state"] == "human-review-required"
    assert "patcher-not-ready:prefetch-failed:src" in decision["reason_codes"]


def test_optional_prefetch_skip_does_not_block(tmp_path: Path, opa_available: bool) -> None:
    """A prefetch_skips[] entry with required_for_patch=false is informational;
    auto-merge still rides as long as prefetch_hashes are present."""
    from agents.steward.agent import route_inbox_entry
    upstream = _eligible_upstream(verdict="eligible")
    upstream["prefetch_skips"] = [{
        "name": "vendored-cargo-deps",
        "reason": "no-rust-vendoring-in-this-package",
        "required_for_patch": False,
    }]
    entry = _seed(tmp_path, finding=_finding(), upstream_ref=upstream)
    decision = route_inbox_entry(entry)
    assert decision["state"] == "auto-merge-eligible"


def test_missing_opa_raises(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """If opa isn't on PATH, the agent must fail loudly rather than
    silently producing no decision."""
    from agents.steward.agent import route_inbox_entry, OpaUnavailable
    monkeypatch.setenv("PATH", "/nonexistent")
    entry = _seed(tmp_path, mapping_failure={"cve_id": "x", "reason": "y"})
    with pytest.raises(OpaUnavailable):
        route_inbox_entry(entry)
