"""Patcher inbox bridge: assemble run_patcher inputs from a Scout inbox entry.

Bridges the Scout side (finding.json + upstream-ref.json + steward-decision.json
in inbox/<CVE>/) and the Patcher side (run_patcher's required inputs:
finding, upstream_ref, impact, maintainers, package_source). Calls
Cartographer.analyze for impact + maintainers and the path resolver
for package_source.

Slice 2 of the Patcher pipeline. Slice 3 will replace the
CannedCartographerGraph with a real graph adapter; this slice
takes a graph as input so callers can pick.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from agents.cartographer.graph import CannedCartographerGraph, CannedNode, Maintainer
from agents.patcher.inbox_bridge import (
    BridgeRefused,
    InboxBundleNotReady,
    assemble_inputs_from_inbox,
)


_RADARE2 = CannedNode(
    attr_path="radare2",
    drv_path="/nix/store/aaa-radare2.drv",
    pname="radare2",
    version="6.1.2",
    reverse_closure=("radare2-cutter",),
    critical_downstreams=(),
    maintainers=(Maintainer(github="lassulus", email="x@y", name="Lassulus"),),
)


def _seed_inbox(
    tmp_path: Path,
    *,
    cve_id: str = "CVE-2026-6941",
    state: str = "auto-merge-eligible",
    finding: dict[str, Any] | None = None,
    upstream_ref: dict[str, Any] | None = None,
) -> Path:
    entry = tmp_path / "inbox" / cve_id
    entry.mkdir(parents=True)
    finding = finding or {
        "schema_version": "1.0.0",
        "cve_id": cve_id,
        "affected": [{
            "attr_path": "radare2",
            "drv_path": "/nix/store/aaa-radare2.drv",
            "pname": "radare2",
            "version": "6.1.2",
            "confidence": "high",
        }],
        "mapping": {"method": "cpe-exact", "mapping_notes": "test"},
        "published_at": "2026-04-30T00:00:00Z",
        "references": [],
    }
    upstream_ref = upstream_ref or {
        "schema_version": "1.0.0",
        "cve_id": cve_id,
        "current_version": "6.1.2",
        "target_version": "6.1.4",
        "fix_tier": "security-patch-release",
        "release_url": "https://github.com/radareorg/radare2/releases/6.1.4",
        "delta": {
            "transitive_package_changes": 0,
            "new_direct_deps": [],
            "removed_direct_deps": [],
            "crosses_large_delta_threshold": False,
            "threshold_policy": "v0-default",
        },
        "replay_critical": True,
        "eligibility": {"verdict": "eligible"},
    }
    (entry / "finding.json").write_text(json.dumps(finding))
    (entry / "upstream-ref.json").write_text(json.dumps(upstream_ref))
    (entry / "steward-decision.json").write_text(json.dumps({
        "schema_version": "1.0.0",
        "cve_id": cve_id,
        "decided_at": "2026-04-30T00:00:00Z",
        "state": state,
        "reason_codes": ["eligible-high-confidence"],
        "evaluator": "opa-rego/data.trace.steward.route",
        "policy_sha256": "0" * 64,
        "inputs_summary": {"finding_status": "finding"},
    }))
    return entry


def _mk_nixpkgs(root: Path) -> Path:
    (root / "pkgs" / "by-name" / "ra" / "radare2").mkdir(parents=True)
    (root / "pkgs" / "by-name" / "ra" / "radare2" / "package.nix").write_text(
        '{ ... }: { version = "6.1.2"; }'
    )
    return root


def test_assembles_complete_inputs_for_auto_merge_entry(tmp_path: Path) -> None:
    entry = _seed_inbox(tmp_path)
    nixpkgs = _mk_nixpkgs(tmp_path / "nixpkgs")
    graph = CannedCartographerGraph([_RADARE2])

    out = assemble_inputs_from_inbox(
        entry, nixpkgs_root=nixpkgs, graph=graph, nixpkgs_rev="abc123",
    )

    assert set(out.inputs.keys()) >= {
        "finding", "upstream_ref", "impact", "maintainers",
        "package_source", "package_source_path",
    }
    assert out.inputs["upstream_ref"]["target_version"] == "6.1.4"
    assert out.inputs["impact"]["affected_attr_paths"] == ["radare2"]
    assert "lassulus" in json.dumps(out.inputs["maintainers"])
    assert "version = \"6.1.2\"" in out.inputs["package_source"]
    assert out.inputs["package_source_path"] == "pkgs/by-name/ra/radare2/package.nix"
    assert out.steward_state == "auto-merge-eligible"


def test_refuses_non_auto_merge_state(tmp_path: Path) -> None:
    entry = _seed_inbox(tmp_path, state="human-review-required")
    graph = CannedCartographerGraph([_RADARE2])
    nixpkgs = _mk_nixpkgs(tmp_path / "nixpkgs")
    with pytest.raises(BridgeRefused, match="human-review-required"):
        assemble_inputs_from_inbox(
            entry, nixpkgs_root=nixpkgs, graph=graph, nixpkgs_rev="abc123",
        )


def test_refuses_when_steward_decision_missing(tmp_path: Path) -> None:
    entry = _seed_inbox(tmp_path)
    (entry / "steward-decision.json").unlink()
    graph = CannedCartographerGraph([_RADARE2])
    nixpkgs = _mk_nixpkgs(tmp_path / "nixpkgs")
    with pytest.raises(InboxBundleNotReady, match="steward-decision.json"):
        assemble_inputs_from_inbox(
            entry, nixpkgs_root=nixpkgs, graph=graph, nixpkgs_rev="abc123",
        )


def test_refuses_when_finding_missing(tmp_path: Path) -> None:
    entry = _seed_inbox(tmp_path)
    (entry / "finding.json").unlink()
    graph = CannedCartographerGraph([_RADARE2])
    nixpkgs = _mk_nixpkgs(tmp_path / "nixpkgs")
    with pytest.raises(InboxBundleNotReady, match="finding.json"):
        assemble_inputs_from_inbox(
            entry, nixpkgs_root=nixpkgs, graph=graph, nixpkgs_rev="abc123",
        )


def test_refuses_when_package_source_unresolvable(tmp_path: Path) -> None:
    """If the resolver can't find package.nix, the bridge surfaces the
    error rather than producing partial inputs that would crash
    run_patcher later."""
    entry = _seed_inbox(tmp_path)
    nixpkgs = tmp_path / "empty-nixpkgs"
    nixpkgs.mkdir()
    graph = CannedCartographerGraph([_RADARE2])
    with pytest.raises(InboxBundleNotReady, match="package source"):
        assemble_inputs_from_inbox(
            entry, nixpkgs_root=nixpkgs, graph=graph, nixpkgs_rev="abc",
        )


def test_writes_assembled_inputs_to_disk_when_dest_provided(tmp_path: Path) -> None:
    """For replay/auditability, the bridge can persist the assembled
    inputs (impact.json + maintainers.json side-by-side with the
    Scout artefacts in the inbox entry)."""
    entry = _seed_inbox(tmp_path)
    nixpkgs = _mk_nixpkgs(tmp_path / "nixpkgs")
    graph = CannedCartographerGraph([_RADARE2])
    assemble_inputs_from_inbox(
        entry, nixpkgs_root=nixpkgs, graph=graph, nixpkgs_rev="abc",
        write_to_inbox=True,
    )
    impact = json.loads((entry / "impact.json").read_text())
    maint = json.loads((entry / "maintainers.json").read_text())
    assert impact["cve_id"] == "CVE-2026-6941"
    assert "radare2" in maint["attr_paths"]


def test_does_not_write_when_dest_omitted(tmp_path: Path) -> None:
    entry = _seed_inbox(tmp_path)
    nixpkgs = _mk_nixpkgs(tmp_path / "nixpkgs")
    graph = CannedCartographerGraph([_RADARE2])
    assemble_inputs_from_inbox(
        entry, nixpkgs_root=nixpkgs, graph=graph, nixpkgs_rev="abc",
    )
    assert not (entry / "impact.json").exists()
    assert not (entry / "maintainers.json").exists()


def test_propagates_analysis_status_to_impact(tmp_path: Path) -> None:
    """When the caller declares the graph backend can't compute
    reverse-closure, the bridge must stamp impact.analysis_status
    accordingly so Steward routes to human-review-required."""
    entry = _seed_inbox(tmp_path)
    nixpkgs = _mk_nixpkgs(tmp_path / "nixpkgs")
    graph = CannedCartographerGraph([_RADARE2])
    out = assemble_inputs_from_inbox(
        entry,
        nixpkgs_root=nixpkgs,
        graph=graph,
        nixpkgs_rev="abc",
        analysis_status="skipped-v0",
        analysis_reason="snapshot-backend-unimplemented",
    )
    assert out.inputs["impact"]["analysis_status"] == "skipped-v0"
    assert out.inputs["impact"]["analysis_reason"] == "snapshot-backend-unimplemented"
