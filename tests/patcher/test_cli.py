"""Patcher CLI tests.

Exercises agents.patcher.cli.main against synthetic inbox entries
using the FakeAdapter via dependency injection. No real API calls.

Pins the v0 contract:
  * default model is claude-opus-4-7
  * $1.00 soft cap, $3.00 hard cap per CVE
  * --force-budget required to exceed soft cap
  * hard cap refuses unconditionally
  * env gate refuses without TRACE_REAL_PATCHER=1 (production path)
  * Steward dispatch refusal stops the CLI before any model spend
  * malformed output writes nothing
  * happy path emits patch.diff + patch-rationale.md + patcher-invocation.json
  * refusal path emits refusal.json + patcher-invocation.json
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from agents.cartographer.graph import CannedCartographerGraph, CannedNode, Maintainer
from agents.patcher import FakeAdapter
from agents.patcher.cli import main


REPO_ROOT = Path(__file__).resolve().parents[2]
PROMPT_PATH = REPO_ROOT / "prompts" / "patcher.v1.md"


_RATIONALE = """## Upstream reference
Fix lands in v6.1.4 per upstream release.

## Why this version
6.1.4 is the smallest patch release containing the fix.

## Why minimal
Only pkgs/by-name/ra/radare2/package.nix is touched.

## Alternatives rejected
- Cherry-pick: no benefit over patch-release bump.

## Downstream risk
reverse_closure_count=1; under threshold.
"""


def _fake_patch_response() -> str:
    return (
        "=== BEGIN patch.diff ===\n"
        "--- a/pkgs/by-name/ra/radare2/package.nix\n"
        "+++ b/pkgs/by-name/ra/radare2/package.nix\n"
        "@@ -1 +1 @@\n"
        "-version = \"6.1.2\";\n"
        "+version = \"6.1.4\";\n"
        "=== END patch.diff ===\n"
        "=== BEGIN patch-rationale.md ===\n"
        + _RATIONALE
        + "=== END patch-rationale.md ==="
    )


def _fake_refusal_response() -> str:
    return (
        "=== BEGIN refusal ===\n"
        "rule: 1\n"
        "reason: confidence is medium for at least one affected attr\n"
        "=== END refusal ==="
    )


_RADARE2_NODE = CannedNode(
    attr_path="radare2",
    drv_path="/nix/store/aaa-radare2.drv",
    pname="radare2",
    version="6.1.2",
    reverse_closure=("radare2-cutter",),
    critical_downstreams=(),
    maintainers=(Maintainer(github="lassulus", email="x@y", name="Lassulus"),),
)


def _seed(
    tmp_path: Path,
    *,
    cve_id: str = "CVE-2026-6941",
    state: str = "auto-merge-eligible",
) -> Path:
    entry = tmp_path / "inbox" / cve_id
    entry.mkdir(parents=True)
    finding = {
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
    upstream_ref = {
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


def _argv(entry: Path, nixpkgs: Path, *extra: str) -> list[str]:
    return [
        str(entry),
        "--nixpkgs-root", str(nixpkgs),
        "--nixpkgs-rev", "0" * 40,
        "--analysis-status", "complete",  # canned graph IS complete
        *extra,
    ]


def _patch_factory(model_id: str) -> FakeAdapter:
    return FakeAdapter(model_id, _fake_patch_response())


def _refusal_factory(model_id: str) -> FakeAdapter:
    return FakeAdapter(model_id, _fake_refusal_response())


def _graph_factory(_attrs: list[str]):
    return CannedCartographerGraph([_RADARE2_NODE])


def test_happy_path_writes_patch_and_invocation(tmp_path: Path) -> None:
    entry = _seed(tmp_path)
    nixpkgs = _mk_nixpkgs(tmp_path / "nixpkgs")
    rc = main(
        _argv(entry, nixpkgs),
        adapter_factory=_patch_factory,
        graph_factory=_graph_factory,
    )
    assert rc == 0
    assert (entry / "patch.diff").is_file()
    assert (entry / "patch-rationale.md").is_file()
    inv = json.loads((entry / "patcher-invocation.json").read_text())
    assert inv["kind"] == "patch"
    assert inv["model_id"] == "claude-opus-4-7"  # default model
    assert inv["steward_state"] == "auto-merge-eligible"
    assert inv["budget"]["soft_cap_usd"] == 1.00
    assert inv["budget"]["hard_cap_usd"] == 3.00
    assert inv["budget"]["force_budget"] is False
    # FakeAdapter does not report token usage; actual cost is None.
    assert inv["budget"]["actual_cost_usd"] is None


def test_refusal_path_writes_refusal_json(tmp_path: Path) -> None:
    entry = _seed(tmp_path)
    nixpkgs = _mk_nixpkgs(tmp_path / "nixpkgs")
    rc = main(
        _argv(entry, nixpkgs),
        adapter_factory=_refusal_factory,
        graph_factory=_graph_factory,
    )
    assert rc == 0
    assert (entry / "refusal.json").is_file()
    assert not (entry / "patch.diff").exists()
    inv = json.loads((entry / "patcher-invocation.json").read_text())
    assert inv["kind"] == "refusal"


def test_refuses_when_steward_state_is_not_auto_merge(tmp_path: Path) -> None:
    entry = _seed(tmp_path, state="human-review-required")
    nixpkgs = _mk_nixpkgs(tmp_path / "nixpkgs")
    rc = main(
        _argv(entry, nixpkgs),
        adapter_factory=_patch_factory,
        graph_factory=_graph_factory,
    )
    assert rc == 12  # _EXIT_REFUSED_BY_STEWARD
    assert not (entry / "patch.diff").exists()
    assert not (entry / "patcher-invocation.json").exists()


def test_refuses_when_inbox_artefact_missing(tmp_path: Path) -> None:
    entry = _seed(tmp_path)
    (entry / "upstream-ref.json").unlink()
    nixpkgs = _mk_nixpkgs(tmp_path / "nixpkgs")
    rc = main(
        _argv(entry, nixpkgs),
        adapter_factory=_patch_factory,
        graph_factory=_graph_factory,
    )
    assert rc == 13  # _EXIT_BUNDLE_NOT_READY


def test_default_model_is_opus_4_7(tmp_path: Path) -> None:
    """Locks the qualified default. Override goes through --model."""
    entry = _seed(tmp_path)
    nixpkgs = _mk_nixpkgs(tmp_path / "nixpkgs")
    seen: dict[str, Any] = {}

    def factory(model_id: str) -> FakeAdapter:
        seen["model_id"] = model_id
        return FakeAdapter(model_id, _fake_patch_response())

    main(_argv(entry, nixpkgs), adapter_factory=factory, graph_factory=_graph_factory)
    assert seen["model_id"] == "claude-opus-4-7"


def test_model_override_for_experiments(tmp_path: Path) -> None:
    entry = _seed(tmp_path)
    nixpkgs = _mk_nixpkgs(tmp_path / "nixpkgs")
    seen: dict[str, Any] = {}

    def factory(model_id: str) -> FakeAdapter:
        seen["model_id"] = model_id
        return FakeAdapter(model_id, _fake_patch_response())

    main(
        _argv(entry, nixpkgs, "--model", "claude-sonnet-4-6"),
        adapter_factory=factory,
        graph_factory=_graph_factory,
    )
    assert seen["model_id"] == "claude-sonnet-4-6"


def test_soft_cap_blocks_without_force(tmp_path: Path) -> None:
    """Soft cap defaults to $1; setting it to $0 forces a soft-cap trip
    on any non-trivial prompt without --force-budget."""
    entry = _seed(tmp_path)
    nixpkgs = _mk_nixpkgs(tmp_path / "nixpkgs")
    rc = main(
        _argv(entry, nixpkgs, "--soft-budget", "0.0001"),
        adapter_factory=_patch_factory,
        graph_factory=_graph_factory,
    )
    assert rc == 10  # _EXIT_BUDGET
    assert not (entry / "patcher-invocation.json").exists()


def test_force_budget_allows_exceeding_soft_cap(tmp_path: Path) -> None:
    entry = _seed(tmp_path)
    nixpkgs = _mk_nixpkgs(tmp_path / "nixpkgs")
    rc = main(
        _argv(entry, nixpkgs, "--soft-budget", "0.0001", "--force-budget"),
        adapter_factory=_patch_factory,
        graph_factory=_graph_factory,
    )
    assert rc == 0
    inv = json.loads((entry / "patcher-invocation.json").read_text())
    assert inv["budget"]["force_budget"] is True


def test_hard_cap_refuses_unconditionally(tmp_path: Path) -> None:
    """Hard cap cannot be bypassed by --force-budget."""
    entry = _seed(tmp_path)
    nixpkgs = _mk_nixpkgs(tmp_path / "nixpkgs")
    rc = main(
        _argv(
            entry, nixpkgs,
            "--soft-budget", "0.0001",
            "--hard-budget", "0.0002",
            "--force-budget",
        ),
        adapter_factory=_patch_factory,
        graph_factory=_graph_factory,
    )
    assert rc == 10


def test_hard_below_soft_is_usage_error(tmp_path: Path) -> None:
    entry = _seed(tmp_path)
    nixpkgs = _mk_nixpkgs(tmp_path / "nixpkgs")
    rc = main(
        _argv(entry, nixpkgs, "--soft-budget", "2.0", "--hard-budget", "1.0"),
        adapter_factory=_patch_factory,
        graph_factory=_graph_factory,
    )
    assert rc == 64


def test_dry_run_does_not_invoke_adapter(tmp_path: Path) -> None:
    entry = _seed(tmp_path)
    nixpkgs = _mk_nixpkgs(tmp_path / "nixpkgs")
    invoked: list[str] = []

    def factory(model_id: str) -> FakeAdapter:
        adapter = FakeAdapter(model_id, _fake_patch_response())
        # Wrap to record calls.
        original = adapter.invoke
        def spy(**kw):  # type: ignore[no-untyped-def]
            invoked.append(model_id)
            return original(**kw)
        adapter.invoke = spy  # type: ignore[method-assign]
        return adapter

    rc = main(
        _argv(entry, nixpkgs, "--dry-run"),
        adapter_factory=factory,
        graph_factory=_graph_factory,
    )
    assert rc == 0
    assert invoked == []
    assert not (entry / "patch.diff").exists()
    assert not (entry / "patcher-invocation.json").exists()


def test_env_gate_blocks_when_no_adapter_factory(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Production path: without TRACE_REAL_PATCHER=1, refuse before
    constructing a real adapter. The adapter_factory test path bypasses
    the gate, so we drop the factory here to exercise the production
    code path while still avoiding any real API call (the
    AnthropicAdapter constructor refuses without ANTHROPIC_API_KEY)."""
    entry = _seed(tmp_path)
    nixpkgs = _mk_nixpkgs(tmp_path / "nixpkgs")
    monkeypatch.delenv("TRACE_REAL_PATCHER", raising=False)
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    rc = main(_argv(entry, nixpkgs), graph_factory=_graph_factory)
    assert rc == 11  # _EXIT_GATING


def test_malformed_output_exits_without_writing(tmp_path: Path) -> None:
    entry = _seed(tmp_path)
    nixpkgs = _mk_nixpkgs(tmp_path / "nixpkgs")

    def factory(model_id: str) -> FakeAdapter:
        return FakeAdapter(model_id, "not a valid patcher output at all")

    rc = main(
        _argv(entry, nixpkgs),
        adapter_factory=factory,
        graph_factory=_graph_factory,
    )
    assert rc == 14  # _EXIT_MALFORMED
    assert not (entry / "patch.diff").exists()
    assert not (entry / "refusal.json").exists()
    assert not (entry / "patcher-invocation.json").exists()


def test_invocation_records_full_provenance(tmp_path: Path) -> None:
    entry = _seed(tmp_path)
    nixpkgs = _mk_nixpkgs(tmp_path / "nixpkgs")
    main(
        _argv(entry, nixpkgs),
        adapter_factory=_patch_factory,
        graph_factory=_graph_factory,
    )
    inv = json.loads((entry / "patcher-invocation.json").read_text())
    assert inv["schema_version"] == "1.0.0"
    assert inv["cve_id"] == "CVE-2026-6941"
    assert len(inv["prompt_sha256"]) == 64
    assert len(inv["user_content_sha256"]) == 64
    assert len(inv["raw_response_sha256"]) == 64
    assert inv["nixpkgs_rev"] == "0" * 40
    assert inv["package_source_path"] == "pkgs/by-name/ra/radare2/package.nix"
    assert inv["budget"]["estimate"]["total_cost_est"] >= 0
    assert inv["started_at"].endswith("Z")
    assert inv["ended_at"].endswith("Z")
