"""Replay --execute tests.

Builds synthetic replay fixtures programmatically so input and output sha256
values are computed, not hand-crafted. That forces replay.json's input-snapshot
semantics to be real.

Scope (per the execute-integration brief):
  * execute Scout, Cartographer, UpstreamRefResolver against canned input
  * plan-only behavior unchanged when --execute is absent
  * --execute requires --role
  * --execute refuses Patcher/Reviewer/Reproducer
  * input-hash mismatch → nonzero
  * output-hash mismatch → nonzero
  * --no-verify lets a hash mismatch pass
"""

from __future__ import annotations

import json
import uuid
from pathlib import Path
from typing import Any

import pytest

from tools.trace_cli.cli import (
    EXIT_HASH_MISMATCH,
    EXIT_INVALID,
    EXIT_NOT_FOUND,
    EXIT_OK,
    EXIT_USAGE,
    main,
)
from tools.trace_cli.execute import canonical_json_bytes, sha256_hex


# ─── fixture builders ───────────────────────────────────────────────────────


def _write_json(path: Path, obj: Any) -> tuple[str, str]:
    """Write obj as canonical JSON, return (relative-filename, sha256)."""
    body = canonical_json_bytes(obj)
    path.write_bytes(body)
    return path.name, sha256_hex(body)


def _bundle_skeleton(cve: str, bundle_id: str) -> dict[str, Any]:
    return {
        "schema_version": "1.0.0",
        "bundle_id": bundle_id,
        "cve_id": cve,
        "nixpkgs_rev": "0" * 40,
        "kind": "advisory-only",
        "kind_reason": "ineligible-no-fix-available",
        "created_at": "2026-04-23T00:00:00Z",
        "policy_version": "0" * 64,
        "bundle_schema_version": "1" * 64,
        "files": {
            "bundle.json": {"sha256": "a" * 64, "bytes": 1, "producer_role": "steward", "replay_critical": True},
            "finding.json": {"sha256": "b" * 64, "bytes": 1, "producer_role": "scout", "replay_critical": True},
            "impact.json": {"sha256": "d" * 64, "bytes": 1, "producer_role": "cartographer", "replay_critical": True},
            "maintainers.json": {"sha256": "e" * 64, "bytes": 1, "producer_role": "cartographer", "replay_critical": True},
            "upstream-ref.json": {"sha256": "c" * 64, "bytes": 1, "producer_role": "upstream-ref-resolver", "replay_critical": True},
            "replay.json": {"sha256": "f" * 64, "bytes": 1, "producer_role": "steward", "replay_critical": True},
            "provenance.jsonl": {"sha256": "0" * 64, "bytes": 1, "producer_role": "steward", "replay_critical": False},
            "bundle.sig": {"sha256": "9" * 64, "bytes": 1, "producer_role": "steward", "replay_critical": False},
        },
        "signed_manifest": {
            "algorithm": "sigstore-cosign-v1",
            "signer": "fixture@example.invalid",
            "signed_files": [{"path": "bundle.json", "sha256": "a" * 64}],
        },
    }


def _replay_skeleton(cve: str, bundle_id: str, role_entries: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        "schema_version": "1.0.0",
        "bundle_id": bundle_id,
        "cve_id": cve,
        "nixpkgs_rev": "0" * 40,
        "policy_version": "0" * 64,
        "bundle_schema_sha256": "1" * 64,
        "routing_config_sha256": "2" * 64,
        "tool_manifest": {
            "flake_lock_sha256": "3" * 64,
            "tools": [{"name": "python", "version": "3.13"}],
        },
        "cross_family_rule_honored": True,
        "roles": role_entries,
    }


def _make_invocation(role: str, inputs: list[dict], outputs: list[dict]) -> dict[str, Any]:
    return {
        "invocation_id": str(uuid.uuid4()),
        "role": role,
        "started_at": "2026-04-23T00:00:00Z",
        "ended_at": "2026-04-23T00:00:01Z",
        "model": {
            "family": "deterministic-no-model",
            "vendor": "internal",
            "model_id": f"{role}-deterministic",
            "version": "1.0.0",
            "sampling": {"temperature": 0, "top_p": 1, "max_tokens": 1},
        },
        "prompt": {"path": f"prompts/{role}.v1.md", "sha256": "7" * 64},
        "inputs": inputs,
        "outputs": outputs,
        "rng_seed": None,
        "validators_passed": [],
        "network_policy_applied": "none",
    }


def _build_bundle(tmp_path: Path, cve: str, bundle_id: str, role_entries: list[dict]) -> Path:
    bundle_dir = tmp_path / cve
    bundle_dir.mkdir(parents=True)
    bundle = _bundle_skeleton(cve, bundle_id)
    replay = _replay_skeleton(cve, bundle_id, role_entries)
    (bundle_dir / "bundle.json").write_text(json.dumps(bundle, indent=2))
    (bundle_dir / "replay.json").write_text(json.dumps(replay, indent=2))
    return bundle_dir


# ─── per-role fixtures ──────────────────────────────────────────────────────


def _build_scout_fixture(tmp_path: Path) -> tuple[Path, dict[str, Any]]:
    from agents.scout import CannedGraphLookup, scan
    from agents.scout.graph_lookup import GraphMatch

    bundle_dir = tmp_path / "scout-bundle"
    bundle_dir.mkdir()

    feed = {
        "feed": "nvd",
        "cve_id": "CVE-0000-7001",
        "published_at": "2026-04-01T00:00:00Z",
        "severity": {"rating": "high", "cvss_v3_score": 7.5},
        "cpe_matches": [{"cpe": "cpe:2.3:a:example:libexample:1.4.7:*:*:*:*:*:*:*"}],
    }
    graph_src = {
        "schema_version": "1.0.0",
        "nixpkgs_rev": "0" * 40,
        "nodes": [
            {
                "attr_path": "libexample",
                "drv_path": "/nix/store/00000000000000000000000000000001-libexample-1.4.7.drv",
                "pname": "libexample",
                "version": "1.4.7",
                "cpes": ["cpe:2.3:a:example:libexample:1.4.7:*:*:*:*:*:*:*"],
                "purls": [],
            }
        ]
    }
    feed_name, feed_sha = _write_json(bundle_dir / "feed.json", feed)
    graph_name, graph_sha = _write_json(bundle_dir / "graph.json", graph_src)

    # Compute expected output by running the stub directly.
    graph = CannedGraphLookup([GraphMatch(**m) for m in graph_src["nodes"]])
    result = scan(feed, graph)
    assert result["status"] == "finding"
    finding = result["finding"]
    finding_name = "finding.json"
    finding_sha = sha256_hex(canonical_json_bytes(finding))

    invocation = _make_invocation(
        "scout",
        inputs=[
            {"path": feed_name, "sha256": feed_sha},
            {"path": graph_name, "sha256": graph_sha},
        ],
        outputs=[{"path": finding_name, "sha256": finding_sha}],
    )

    replay = _replay_skeleton("CVE-0000-7001", "0000000000007001",
                              [{"role": "scout", "invocations": [invocation]}])
    bundle = _bundle_skeleton("CVE-0000-7001", "0000000000007001")
    (bundle_dir / "bundle.json").write_text(json.dumps(bundle, indent=2))
    (bundle_dir / "replay.json").write_text(json.dumps(replay, indent=2))
    return bundle_dir, {"expected_output_sha256": finding_sha}


def _build_cartographer_fixture(tmp_path: Path) -> tuple[Path, dict[str, Any]]:
    from agents.cartographer import (
        CannedCartographerGraph, CannedNode, Maintainer, analyze,
    )

    bundle_dir = tmp_path / "cartographer-bundle"
    bundle_dir.mkdir()

    finding = {
        "schema_version": "1.0.0",
        "cve_id": "CVE-0000-7002",
        "source_feeds": ["nvd"],
        "severity": {"rating": "high", "cvss_v3_score": 7.5},
        "published_at": "2026-04-01T00:00:00Z",
        "affected": [
            {
                "attr_path": "libexample",
                "drv_path": "/nix/store/00000000000000000000000000000002-libexample-1.4.7.drv",
                "pname": "libexample",
                "version": "1.4.7",
                "confidence": "high",
            }
        ],
        "mapping": {"method": "cpe-exact"},
        "replay_critical": True,
    }
    graph_src = {
        "schema_version": "1.0.0",
        "nixpkgs_rev": "0" * 40,
        "nodes": [
            {
                "attr_path": "libexample",
                "drv_path": "/nix/store/00000000000000000000000000000002-libexample-1.4.7.drv",
                "pname": "libexample",
                "version": "1.4.7",
                "reverse_closure": ["exampleApp", "exampleServer"],
                "critical_downstreams": [],
                "maintainers": [{"github": "alice"}],
            }
        ],
    }
    f_name, f_sha = _write_json(bundle_dir / "finding.json", finding)
    g_name, g_sha = _write_json(bundle_dir / "graph.json", graph_src)

    nodes = [CannedNode(
        attr_path=graph_src["nodes"][0]["attr_path"],
        drv_path=graph_src["nodes"][0]["drv_path"],
        pname=graph_src["nodes"][0]["pname"],
        version=graph_src["nodes"][0]["version"],
        reverse_closure=tuple(graph_src["nodes"][0]["reverse_closure"]),
        critical_downstreams=tuple(graph_src["nodes"][0]["critical_downstreams"]),
        maintainers=(Maintainer(github="alice"),),
    )]
    out = analyze(finding, CannedCartographerGraph(nodes), nixpkgs_rev="0" * 40)
    impact_sha = sha256_hex(canonical_json_bytes(out["impact"]))
    maint_sha = sha256_hex(canonical_json_bytes(out["maintainers"]))

    invocation = _make_invocation(
        "cartographer",
        inputs=[
            {"path": f_name, "sha256": f_sha},
            {"path": g_name, "sha256": g_sha},
        ],
        outputs=[
            {"path": "impact.json", "sha256": impact_sha},
            {"path": "maintainers.json", "sha256": maint_sha},
        ],
    )
    replay = _replay_skeleton("CVE-0000-7002", "0000000000007002",
                              [{"role": "cartographer", "invocations": [invocation]}])
    bundle = _bundle_skeleton("CVE-0000-7002", "0000000000007002")
    (bundle_dir / "bundle.json").write_text(json.dumps(bundle, indent=2))
    (bundle_dir / "replay.json").write_text(json.dumps(replay, indent=2))
    return bundle_dir, {}


def _build_resolver_fixture(tmp_path: Path) -> tuple[Path, dict[str, Any]]:
    from agents.upstream_ref_resolver import resolve

    bundle_dir = tmp_path / "resolver-bundle"
    bundle_dir.mkdir()

    doc = {
        "cve_id": "CVE-0000-7003",
        "current_version": "1.4.7",
        "candidate_refs": [
            {
                "version": "1.4.8",
                "tag": "v1.4.8",
                "release_url": "https://example.invalid/libexample/releases/1.4.8",
                "changelog_url": "https://example.invalid/libexample/CHANGELOG#v1.4.8",
                "advisory_urls": ["https://example.invalid/advisory/LIBEXAMPLE"],
                "upstream_fix_commits": [{"repo_url": "https://example.invalid/libexample", "commit_sha": "abc1234"}],
                "delta": {"transitive_package_changes": 0, "new_direct_deps": [], "removed_direct_deps": [], "crosses_large_delta_threshold": False, "threshold_policy": "v0-default"},
                "tier_hint": "security-patch-release",
            }
        ],
    }
    in_name, in_sha = _write_json(bundle_dir / "resolver-input.json", doc)
    out = resolve(doc)
    out_sha = sha256_hex(canonical_json_bytes(out))

    invocation = _make_invocation(
        "upstream-ref-resolver",
        inputs=[{"path": in_name, "sha256": in_sha}],
        outputs=[{"path": "upstream-ref.json", "sha256": out_sha}],
    )
    replay = _replay_skeleton("CVE-0000-7003", "0000000000007003",
                              [{"role": "upstream-ref-resolver", "invocations": [invocation]}])
    bundle = _bundle_skeleton("CVE-0000-7003", "0000000000007003")
    (bundle_dir / "bundle.json").write_text(json.dumps(bundle, indent=2))
    (bundle_dir / "replay.json").write_text(json.dumps(replay, indent=2))
    return bundle_dir, {}


# ─── test helpers ───────────────────────────────────────────────────────────


def _run(argv: list[str], capsys: pytest.CaptureFixture[str]) -> tuple[int, str, str]:
    try:
        rc = main(argv)
    except SystemExit as exc:
        rc = int(exc.code) if isinstance(exc.code, int) else EXIT_USAGE
    captured = capsys.readouterr()
    return rc, captured.out, captured.err


# ─── execute: per-role happy paths ─────────────────────────────────────────


def test_execute_scout(tmp_path, capsys):
    bundle_dir, _ = _build_scout_fixture(tmp_path)
    rc, out, err = _run(
        ["replay", str(bundle_dir), "--execute", "--role", "scout", "--format", "json"],
        capsys,
    )
    assert rc == EXIT_OK, f"stderr: {err}"
    report = json.loads(out)
    assert report["role"] == "scout"
    assert report["verified"] is True
    assert len(report["results"]) == 1
    result_outputs = report["results"][0]["outputs"]
    assert len(result_outputs) == 1
    assert result_outputs[0]["match"] is True


def test_execute_cartographer(tmp_path, capsys):
    bundle_dir, _ = _build_cartographer_fixture(tmp_path)
    rc, out, err = _run(
        ["replay", str(bundle_dir), "--execute", "--role", "cartographer", "--format", "json"],
        capsys,
    )
    assert rc == EXIT_OK, f"stderr: {err}"
    report = json.loads(out)
    paths = {o["path"] for o in report["results"][0]["outputs"]}
    assert paths == {"impact.json", "maintainers.json"}
    for o in report["results"][0]["outputs"]:
        assert o["match"] is True


def test_execute_upstream_ref_resolver(tmp_path, capsys):
    bundle_dir, _ = _build_resolver_fixture(tmp_path)
    rc, out, err = _run(
        ["replay", str(bundle_dir), "--execute", "--role", "upstream-ref-resolver", "--format", "json"],
        capsys,
    )
    assert rc == EXIT_OK, f"stderr: {err}"
    report = json.loads(out)
    outs = report["results"][0]["outputs"]
    assert outs[0]["path"] == "upstream-ref.json"
    assert outs[0]["match"] is True


# ─── execute: refusals ─────────────────────────────────────────────────────


@pytest.mark.parametrize("role", ["reviewer", "reproducer"])
def test_execute_refuses_reviewer_reproducer_until_wired(tmp_path, capsys, role):
    """Reviewer + Reproducer stay in the 'not yet wired' bucket. Patcher was
    in this bucket historically but now has its own wiring (see
    tests/patcher/test_execute_wiring.py); removed from this parametrize."""
    bundle_dir, _ = _build_resolver_fixture(tmp_path)
    replay_path = bundle_dir / "replay.json"
    replay = json.loads(replay_path.read_text())
    replay["roles"][0]["role"] = role
    replay["roles"][0]["invocations"][0]["role"] = role
    replay_path.write_text(json.dumps(replay, indent=2))

    rc, _out, err = _run(
        ["replay", str(bundle_dir), "--execute", "--role", role],
        capsys,
    )
    assert rc == EXIT_INVALID
    assert "not yet wired" in err


def test_execute_patcher_without_model_rejected(tmp_path, capsys):
    """Patcher is the first model-backed role wired for --execute. Without
    --model it must reject at the CLI layer — no default live model."""
    bundle_dir, _ = _build_resolver_fixture(tmp_path)
    replay_path = bundle_dir / "replay.json"
    replay = json.loads(replay_path.read_text())
    replay["roles"][0]["role"] = "patcher"
    replay["roles"][0]["invocations"][0]["role"] = "patcher"
    replay_path.write_text(json.dumps(replay, indent=2))

    rc, _out, err = _run(
        ["replay", str(bundle_dir), "--execute", "--role", "patcher"],
        capsys,
    )
    assert rc != EXIT_OK
    assert "requires --model" in err


def test_execute_refuses_builder(tmp_path, capsys):
    bundle_dir, _ = _build_resolver_fixture(tmp_path)
    replay_path = bundle_dir / "replay.json"
    replay = json.loads(replay_path.read_text())
    replay["roles"][0]["role"] = "builder"
    replay["roles"][0]["invocations"][0]["role"] = "builder"
    replay_path.write_text(json.dumps(replay, indent=2))

    rc, _out, err = _run(
        ["replay", str(bundle_dir), "--execute", "--role", "builder"],
        capsys,
    )
    assert rc == EXIT_INVALID
    assert "not supported" in err


def test_execute_requires_role_flag(tmp_path, capsys):
    bundle_dir, _ = _build_resolver_fixture(tmp_path)
    rc, _out, err = _run(
        ["replay", str(bundle_dir), "--execute"],
        capsys,
    )
    assert rc == EXIT_USAGE
    assert "--execute requires --role" in err


def test_execute_rejects_role_not_in_replay(tmp_path, capsys):
    bundle_dir, _ = _build_resolver_fixture(tmp_path)
    rc, _out, err = _run(
        ["replay", str(bundle_dir), "--execute", "--role", "cartographer"],
        capsys,
    )
    assert rc == EXIT_NOT_FOUND
    assert "no invocations for role 'cartographer'" in err


# ─── execute: hash mismatches ──────────────────────────────────────────────


def test_input_hash_mismatch_fails(tmp_path, capsys):
    bundle_dir, _ = _build_resolver_fixture(tmp_path)
    # Mutate the input file so its bytes no longer match the recorded sha.
    (bundle_dir / "resolver-input.json").write_bytes(b"{\"cve_id\":\"CVE-0000-9999\",\"current_version\":\"0\",\"candidate_refs\":[]}")

    rc, _out, err = _run(
        ["replay", str(bundle_dir), "--execute", "--role", "upstream-ref-resolver"],
        capsys,
    )
    assert rc == EXIT_HASH_MISMATCH
    assert "input hash mismatch" in err


def test_output_hash_mismatch_fails(tmp_path, capsys):
    bundle_dir, _ = _build_resolver_fixture(tmp_path)
    # Corrupt the recorded output sha in replay.json.
    replay_path = bundle_dir / "replay.json"
    replay = json.loads(replay_path.read_text())
    replay["roles"][0]["invocations"][0]["outputs"][0]["sha256"] = "f" * 64
    replay_path.write_text(json.dumps(replay, indent=2))

    rc, _out, err = _run(
        ["replay", str(bundle_dir), "--execute", "--role", "upstream-ref-resolver"],
        capsys,
    )
    assert rc == EXIT_HASH_MISMATCH
    assert "output hash mismatch" in err


def test_no_verify_skips_hash_check(tmp_path, capsys):
    bundle_dir, _ = _build_resolver_fixture(tmp_path)
    # Break both input and output hashes in replay.json.
    replay_path = bundle_dir / "replay.json"
    replay = json.loads(replay_path.read_text())
    replay["roles"][0]["invocations"][0]["inputs"][0]["sha256"] = "a" * 64
    replay["roles"][0]["invocations"][0]["outputs"][0]["sha256"] = "b" * 64
    replay_path.write_text(json.dumps(replay, indent=2))

    rc, out, err = _run(
        ["replay", str(bundle_dir), "--execute", "--role", "upstream-ref-resolver",
         "--no-verify", "--format", "json"],
        capsys,
    )
    assert rc == EXIT_OK, f"stderr: {err}"
    report = json.loads(out)
    assert report["verified"] is False
    # The computed hash is still reported; it just isn't compared.
    assert report["results"][0]["outputs"][0]["match"] is False


# ─── no-execute keeps plan-only behavior ───────────────────────────────────


def test_no_execute_yields_plan_only(tmp_path, capsys):
    bundle_dir, _ = _build_resolver_fixture(tmp_path)
    rc, out, err = _run(
        ["replay", str(bundle_dir), "--format", "json"],
        capsys,
    )
    assert rc == EXIT_OK, f"stderr: {err}"
    plan = json.loads(out)
    assert plan["executor"] == "stub"
    for inv in plan["invocations"]:
        assert inv["status"] == "stub"
        assert "computed_sha256" not in inv
