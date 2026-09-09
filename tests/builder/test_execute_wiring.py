"""End-to-end wiring of `trace replay --execute --role builder`.

Builder is RUNNER_BACKED (deterministic, subprocess-driven). Tests
inject a FakeBuildRunner via build_runner_factory; production path
uses LocalNixBuildRunner. Mirrors the patcher / reviewer / reproducer
executor-test shape but without an LLM model dimension.

Covers:
  * Happy path on a finalized bundle: writes build.json + appends
    a builder replay invocation.
  * refused-no-patch: bundle has no patch.diff; build.json records
    refused-no-patch; no BuildRunner calls made.
  * refused-no-reproducer: bundle has patch.diff but no reproducer.nix;
    only patched-build phase runs; build.json records refused-no-
    reproducer with two reproducer phases marked applied=False.
  * Cross-references in replay invocation: patcher_invocation_id and
    reproducer_invocation_id are populated when those roles already
    have invocations in replay.json.
  * Oversize log spills to build.log sidecar.
"""

from __future__ import annotations

import json
from pathlib import Path

from agents.builder import BuildOutcome, FakeBuildRunner
from tools.trace_cli.execute import (
    RUNNER_BACKED_ROLES,
    execute,
)


# ─── bundle fixture ───────────────────────────────────────────────────────


def _build_post_reproducer_bundle(
    tmp_path: Path,
    *,
    include_patch: bool = True,
    include_reproducer: bool = True,
    include_patcher_invocation: bool = True,
    include_reproducer_invocation: bool = True,
) -> Path:
    bundle_dir = tmp_path / "bundle"
    bundle_dir.mkdir()
    (bundle_dir / "bundle.json").write_text(
        json.dumps(
            {
                "schema_version": "1.0.0",
                "bundle_id": "0000000000000001",
                "cve_id": "CVE-0000-0001",
                "nixpkgs_rev": "0" * 40,
                "kind": "auto-merge",
            }
        )
    )
    (bundle_dir / "finding.json").write_text(
        json.dumps(
            {
                "cve_id": "CVE-0000-0001",
                "affected": [{"attr_path": "demo", "version": "1.0.0"}],
            }
        )
    )
    (bundle_dir / "package.nix").write_text('version = "1.0.0";\n')
    if include_patch:
        (bundle_dir / "patch.diff").write_text(
            "--- a/package.nix\n+++ b/package.nix\n@@ -1 +1 @@\n"
            '-version = "1.0.0";\n+version = "1.0.1";\n'
        )
    if include_reproducer:
        (bundle_dir / "reproducer.nix").write_text(
            "{ pkgs ? import <nixpkgs> { } }: {\n"
            "  unpatched = pkgs.demo;\n"
            "  patched = pkgs.demo;\n"
            "  test = pkgs.runCommand \"r\" { } ''true'';\n"
            "}\n"
        )

    roles = []
    if include_patcher_invocation:
        roles.append(
            {
                "role": "patcher",
                "invocations": [
                    {
                        "invocation_id": "11111111-1111-4111-8111-111111111111",
                        "role": "patcher",
                        "started_at": "2026-04-27T00:00:00Z",
                        "ended_at": "2026-04-27T00:00:05Z",
                        "model": {
                            "family": "anthropic",
                            "vendor": "anthropic",
                            "model_id": "claude-opus-4-7",
                            "version": "test",
                            "sampling": {
                                "temperature": 0,
                                "top_p": 1,
                                "max_tokens": 8192,
                            },
                        },
                        "prompt": {"path": "prompts/patcher.v2.md", "sha256": "a" * 64},
                        "inputs": [],
                        "outputs": [],
                        "rng_seed": None,
                        "validators_passed": ["schema-valid-output"],
                        "network_policy_applied": "none",
                    }
                ],
            }
        )
    if include_reproducer_invocation:
        roles.append(
            {
                "role": "reproducer",
                "invocations": [
                    {
                        "invocation_id": "22222222-2222-4222-8222-222222222222",
                        "role": "reproducer",
                        "started_at": "2026-04-28T00:00:00Z",
                        "ended_at": "2026-04-28T00:00:05Z",
                        "model": {
                            "family": "anthropic",
                            "vendor": "anthropic",
                            "model_id": "claude-sonnet-4-6",
                            "version": "test",
                            "sampling": {
                                "temperature": 0,
                                "top_p": 1,
                                "max_tokens": 8192,
                            },
                        },
                        "prompt": {
                            "path": "prompts/reproducer.v1.md",
                            "sha256": "b" * 64,
                        },
                        "inputs": [],
                        "outputs": [],
                        "patcher_invocation_id": "11111111-1111-4111-8111-111111111111",
                        "patcher_family_recorded": "anthropic-opus",
                        "cross_family_rule_honored": True,
                        "rng_seed": None,
                        "validators_passed": ["schema-valid-output"],
                        "network_policy_applied": "none",
                    }
                ],
            }
        )
    replay = {
        "schema_version": "1.0.0",
        "bundle_id": "0000000000000001",
        "cve_id": "CVE-0000-0001",
        "nixpkgs_rev": "0" * 40,
        "policy_version": "0" * 64,
        "bundle_schema_sha256": "1" * 64,
        "routing_config_sha256": "2" * 64,
        "tool_manifest": {
            "flake_lock_sha256": "3" * 64,
            "tools": [{"name": "python", "version": "3.13"}],
        },
        "cross_family_rule_honored": True,
        "roles": roles,
    }
    (bundle_dir / "replay.json").write_text(json.dumps(replay))
    return bundle_dir


def _ok(stdout: str = "+ ok\n") -> BuildOutcome:
    return BuildOutcome(
        exit_code=0,
        drv_path=None,
        out_path="/nix/store/x-result",
        stdout_stderr=stdout,
        elapsed_seconds=1.0,
    )


def _factory_for(*outcomes: BuildOutcome):
    def make() -> FakeBuildRunner:
        return FakeBuildRunner(responses=list(outcomes))

    return make


def _factory_single(outcome: BuildOutcome):
    def make() -> FakeBuildRunner:
        return FakeBuildRunner(response=outcome)

    return make


# ─── happy path ──────────────────────────────────────────────────────────


def test_builder_happy_path_writes_build_json(tmp_path: Path) -> None:
    bundle = _build_post_reproducer_bundle(tmp_path)
    factory = _factory_for(
        _ok("patched-build ok\n"),
        _ok("vuln-triggered: out-of-bounds-read in deserialise()\n"),
        _ok("rejected-malformed-length-prefix-as-expected-from-CVE-0000-0001\n"),
    )
    result = execute(
        role="builder",
        bundle_dir=bundle,
        invocation={"invocation_id": None, "inputs": [], "outputs": []},
        verify=False,
        build_runner_factory=factory,
        nixpkgs_checkout=None,
    )
    assert result["dispatch_outcome"] == "ok"
    assert (bundle / "build.json").is_file()
    bj = json.loads((bundle / "build.json").read_text())
    assert bj["schema_version"] == "1.0.0"
    assert bj["dispatch_outcome"] == "ok"
    assert bj["patched_build"]["outcome"] == "succeeded"
    assert bj["unpatched"]["outcome"] == "succeeded"
    assert bj["patched"]["outcome"] == "succeeded"


def test_builder_appends_replay_invocation_with_cross_references(
    tmp_path: Path,
) -> None:
    bundle = _build_post_reproducer_bundle(tmp_path)
    factory = _factory_for(_ok(), _ok(), _ok())
    result = execute(
        role="builder",
        bundle_dir=bundle,
        invocation={"invocation_id": None, "inputs": [], "outputs": []},
        verify=False,
        build_runner_factory=factory,
        nixpkgs_checkout=None,
    )
    inv = result["replay_invocation"]
    assert inv["role"] == "builder"
    assert inv["model"]["family"] == "deterministic-no-model"
    assert inv["prompt"] is None
    assert inv["network_policy_applied"] == "substituter-only"
    # Cross-references populated from the existing patcher + reproducer
    # invocations in the bundle's replay.json.
    assert inv["patcher_invocation_id"] == "11111111-1111-4111-8111-111111111111"
    assert inv["reproducer_invocation_id"] == "22222222-2222-4222-8222-222222222222"
    # And replay.json on disk now has a builder role entry.
    replay = json.loads((bundle / "replay.json").read_text())
    builder_roles = [r for r in replay["roles"] if r["role"] == "builder"]
    assert len(builder_roles) == 1
    assert builder_roles[0]["invocations"][-1]["invocation_id"] == inv["invocation_id"]


def test_builder_invocation_validators_passed(tmp_path: Path) -> None:
    bundle = _build_post_reproducer_bundle(tmp_path)
    factory = _factory_for(_ok(), _ok(), _ok())
    result = execute(
        role="builder",
        bundle_dir=bundle,
        invocation={"invocation_id": None, "inputs": [], "outputs": []},
        verify=False,
        build_runner_factory=factory,
        nixpkgs_checkout=None,
    )
    assert result["replay_invocation"]["validators_passed"] == [
        "build-json-shape-valid",
    ]


# ─── refused paths ───────────────────────────────────────────────────────


def test_builder_refused_no_patch(tmp_path: Path) -> None:
    bundle = _build_post_reproducer_bundle(tmp_path, include_patch=False)
    factory = _factory_single(_ok())
    runner_holder = {}

    def make() -> FakeBuildRunner:
        runner_holder["runner"] = FakeBuildRunner(response=_ok())
        return runner_holder["runner"]

    result = execute(
        role="builder",
        bundle_dir=bundle,
        invocation={"invocation_id": None, "inputs": [], "outputs": []},
        verify=False,
        build_runner_factory=make,
        nixpkgs_checkout=None,
    )
    assert result["dispatch_outcome"] == "refused-no-patch"
    bj = json.loads((bundle / "build.json").read_text())
    assert bj["dispatch_outcome"] == "refused-no-patch"
    assert bj["patched_build"]["outcome"] == "skipped"
    # FakeBuildRunner created but never invoked.
    assert "runner" in runner_holder
    assert runner_holder["runner"].calls == []


def test_builder_refused_no_reproducer(tmp_path: Path) -> None:
    bundle = _build_post_reproducer_bundle(tmp_path, include_reproducer=False)
    factory = _factory_for(_ok("patched build ok\n"))
    result = execute(
        role="builder",
        bundle_dir=bundle,
        invocation={"invocation_id": None, "inputs": [], "outputs": []},
        verify=False,
        build_runner_factory=factory,
        nixpkgs_checkout=None,
    )
    assert result["dispatch_outcome"] == "refused-no-reproducer"
    bj = json.loads((bundle / "build.json").read_text())
    assert bj["dispatch_outcome"] == "refused-no-reproducer"
    assert bj["patched_build"]["outcome"] == "succeeded"
    assert bj["unpatched"]["outcome"] == "skipped"
    assert bj["patched"]["outcome"] == "skipped"


# ─── oversize log spillover ──────────────────────────────────────────────


def test_builder_writes_build_log_sidecar_on_oversize(tmp_path: Path) -> None:
    bundle = _build_post_reproducer_bundle(tmp_path)
    huge = "z" * 80000  # > 64 KiB
    factory = _factory_for(
        BuildOutcome(
            exit_code=0,
            drv_path=None,
            out_path=None,
            stdout_stderr=huge,
            elapsed_seconds=1.0,
        ),
        _ok(),
        _ok(),
    )
    result = execute(
        role="builder",
        bundle_dir=bundle,
        invocation={"invocation_id": None, "inputs": [], "outputs": []},
        verify=False,
        build_runner_factory=factory,
        nixpkgs_checkout=None,
    )
    out_paths = {o["path"] for o in result["outputs"]}
    assert "build.log" in out_paths
    assert (bundle / "build.log").is_file()
    log_text = (bundle / "build.log").read_text()
    assert "=== patched_build ===" in log_text
    assert "z" * 80000 in log_text


# ─── structural assertions ──────────────────────────────────────────────


def test_builder_in_runner_backed_roles_set() -> None:
    assert "builder" in RUNNER_BACKED_ROLES
