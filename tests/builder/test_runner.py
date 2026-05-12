"""Tests for `agents.builder.runner.run_builder`.

Covers each dispatch_outcome path:

  * ok                        — happy path, all 4 operations succeed
  * refused-no-patch          — patch.diff missing
  * refused-no-reproducer     — reproducer.nix missing
  * patch-apply-failed        — git apply fails (real git, fake patch
                                that doesn't match working tree)
  * infra-failure             — BuildRunner returns exit_code=None

Plus shape checks: build.json validates against
policy/build-output-schema.json on every path.
"""

from __future__ import annotations

import json
import subprocess
from pathlib import Path
from typing import Any

import pytest
from jsonschema import Draft202012Validator

from agents.builder import (
    BuildOutcome,
    BuilderRunResult,
    FakeBuildRunner,
    run_builder,
)


# ─── schema validator ─────────────────────────────────────────────────────


def _build_output_validator() -> Draft202012Validator:
    repo_root = Path(__file__).resolve().parents[2]
    schema = json.loads((repo_root / "policy" / "build-output-schema.json").read_text())
    return Draft202012Validator(schema)


_VALIDATOR = _build_output_validator()


def _assert_valid(build_json: dict[str, Any]) -> None:
    errors = sorted(_VALIDATOR.iter_errors(build_json), key=lambda e: e.path)
    if errors:
        msg = "\n".join(f"  {list(e.absolute_path)}: {e.message}" for e in errors)
        raise AssertionError(f"build.json fails schema:\n{msg}")


# ─── bundle fixtures ──────────────────────────────────────────────────────


def _scaffold_bundle(
    tmp_path: Path,
    *,
    cve_id: str = "CVE-0000-0001",
    bundle_id: str = "0000000000000001",
    nixpkgs_rev: str = "0" * 40,
    attr: str = "demo",
    include_patch: bool = True,
    include_reproducer: bool = True,
    include_patcher_refusal: bool = False,
    include_reproducer_refusal: bool = False,
) -> Path:
    b = tmp_path / "bundle"
    b.mkdir()
    (b / "bundle.json").write_text(json.dumps({
        "schema_version": "1.0.0",
        "bundle_id": bundle_id,
        "cve_id": cve_id,
        "nixpkgs_rev": nixpkgs_rev,
        "kind": "auto-merge",
    }))
    (b / "finding.json").write_text(json.dumps({
        "cve_id": cve_id,
        "affected": [{"attr_path": attr, "version": "1.0.0"}],
    }))
    (b / "package.nix").write_text('version = "1.0.0";\n')
    if include_patch:
        (b / "patch.diff").write_text(
            "--- a/package.nix\n"
            "+++ b/package.nix\n"
            "@@ -1 +1 @@\n"
            '-version = "1.0.0";\n'
            '+version = "1.0.1";\n'
        )
    if include_patcher_refusal:
        (b / "refusal.json").write_text(json.dumps({"rule": 3, "reason": "x"}))
    if include_reproducer:
        (b / "reproducer.nix").write_text(
            "{ pkgs ? import <nixpkgs> { } }: {\n"
            "  unpatched = pkgs.demo;\n"
            "  patched = pkgs.demo;\n"
            "  test = pkgs.runCommand \"r\" { } ''true'';\n"
            "}\n"
        )
    if include_reproducer_refusal:
        (b / "reproducer-refusal.json").write_text(
            json.dumps({"rule": 3, "reason": "y"})
        )
    return b


def _ok_outcome(stdout: str = "+ ok\n") -> BuildOutcome:
    return BuildOutcome(
        exit_code=0, drv_path="/nix/store/abc.drv",
        out_path="/nix/store/abc-result", stdout_stderr=stdout,
        elapsed_seconds=1.0,
    )


def _failure_outcome(stdout: str = "+ fail\nerror!\n") -> BuildOutcome:
    return BuildOutcome(
        exit_code=1, drv_path="/nix/store/abc.drv", out_path=None,
        stdout_stderr=stdout, elapsed_seconds=2.0,
    )


def _infra_outcome() -> BuildOutcome:
    return BuildOutcome(
        exit_code=None, drv_path=None, out_path=None,
        stdout_stderr="nix-build not on PATH",
        elapsed_seconds=0.0,
        extras={"reason": "nix-build-not-available"},
    )


# ─── happy path: ok ───────────────────────────────────────────────────────


def test_happy_path_dispatch_outcome_ok(tmp_path: Path) -> None:
    bundle = _scaffold_bundle(tmp_path)
    # Without nixpkgs_checkout, patch-apply is skipped (`apply_patch=True
    # but checkout=None` → skipped reason). For the happy-path test we
    # explicitly pass apply_patch=False so patch_apply is recorded as
    # skipped-by-orchestrator.
    runner = FakeBuildRunner(responses=[
        _ok_outcome("patched-build ok\n"),
        _ok_outcome("vuln-triggered: out-of-bounds-read in deserialise()\n"),
        _ok_outcome("rejected-malformed-length-prefix-as-expected-from-CVE-0000-0001\n"),
        # passthru-tests enumeration: returns 0 because we don't have a
        # real nixpkgs checkout for the test runner to enumerate against
        # — and run_builder skips enumeration when nixpkgs_checkout=None.
    ])
    result = run_builder(
        bundle_dir=bundle,
        build_runner=runner,
        nixpkgs_checkout=None,  # skip patch-apply + passthru enumeration
        apply_patch=False,
    )
    assert isinstance(result, BuilderRunResult)
    assert result.dispatch_outcome == "ok"
    bj = result.build_json
    assert bj["schema_version"] == "1.0.0"
    assert bj["cve_id"] == "CVE-0000-0001"
    assert bj["dispatch_outcome"] == "ok"
    assert bj["patch_apply"]["applied"] is False
    assert bj["patch_apply"]["reason"] == "skipped-by-orchestrator"
    assert bj["patched_build"]["outcome"] == "succeeded"
    assert bj["unpatched"]["outcome"] == "succeeded"
    assert "vuln-triggered" in bj["unpatched"]["stdout_stderr"]
    assert bj["patched"]["outcome"] == "succeeded"
    assert "rejected-malformed-length-prefix" in bj["patched"]["stdout_stderr"]
    assert bj["passthru_tests_ground_truth"] == []
    assert bj["sbom_delta_attempted"] is False
    _assert_valid(bj)


def test_happy_path_records_three_full_logs(tmp_path: Path) -> None:
    bundle = _scaffold_bundle(tmp_path)
    runner = FakeBuildRunner(responses=[
        _ok_outcome("patched-build ok\n"),
        _ok_outcome("unpatched run\n"),
        _ok_outcome("patched run\n"),
    ])
    result = run_builder(
        bundle_dir=bundle, build_runner=runner,
        nixpkgs_checkout=None, apply_patch=False,
    )
    # full_logs records the untruncated stdout per phase. For inputs
    # under the inline cap, the value matches stdout_stderr verbatim.
    assert "patched-build ok" in result.full_logs["patched_build"]
    assert "unpatched run" in result.full_logs["unpatched"]
    assert "patched run" in result.full_logs["patched"]


# ─── refused-no-patch ─────────────────────────────────────────────────────


def test_refused_when_patch_diff_missing(tmp_path: Path) -> None:
    bundle = _scaffold_bundle(tmp_path, include_patch=False)
    runner = FakeBuildRunner(response=_ok_outcome())
    result = run_builder(
        bundle_dir=bundle, build_runner=runner,
        nixpkgs_checkout=None, apply_patch=True,
    )
    assert result.dispatch_outcome == "refused-no-patch"
    bj = result.build_json
    assert bj["patch_apply"]["applied"] is False
    assert bj["patched_build"]["outcome"] == "skipped"
    assert bj["unpatched"]["outcome"] == "skipped"
    assert bj["patched"]["outcome"] == "skipped"
    assert bj["passthru_tests_ground_truth"] == []
    _assert_valid(bj)
    # And the FakeBuildRunner was not consulted at all.
    assert runner.calls == []


def test_refused_when_patcher_refused(tmp_path: Path) -> None:
    bundle = _scaffold_bundle(
        tmp_path, include_patch=False, include_patcher_refusal=True,
    )
    runner = FakeBuildRunner(response=_ok_outcome())
    result = run_builder(
        bundle_dir=bundle, build_runner=runner,
        nixpkgs_checkout=None, apply_patch=True,
    )
    assert result.dispatch_outcome == "refused-no-patch"


# ─── refused-no-reproducer ────────────────────────────────────────────────


def test_refused_no_reproducer_runs_patched_build_only(tmp_path: Path) -> None:
    bundle = _scaffold_bundle(tmp_path, include_reproducer=False)
    runner = FakeBuildRunner(responses=[_ok_outcome("patched build ok\n")])
    result = run_builder(
        bundle_dir=bundle, build_runner=runner,
        nixpkgs_checkout=None, apply_patch=False,
    )
    assert result.dispatch_outcome == "refused-no-reproducer"
    bj = result.build_json
    assert bj["patched_build"]["outcome"] == "succeeded"
    assert bj["unpatched"]["outcome"] == "skipped"
    assert bj["patched"]["outcome"] == "skipped"
    assert bj["unpatched"]["reason"] == "no-reproducer-or-reproducer-refused"
    assert bj["patched"]["reason"] == "no-reproducer-or-reproducer-refused"
    _assert_valid(bj)
    # Only one BuildRunner call: the patched-build sanity check.
    assert len(runner.calls) == 1


def test_refused_no_reproducer_when_reproducer_refused(tmp_path: Path) -> None:
    bundle = _scaffold_bundle(
        tmp_path, include_reproducer=False, include_reproducer_refusal=True,
    )
    runner = FakeBuildRunner(responses=[_ok_outcome()])
    result = run_builder(
        bundle_dir=bundle, build_runner=runner,
        nixpkgs_checkout=None, apply_patch=False,
    )
    assert result.dispatch_outcome == "refused-no-reproducer"


# ─── patch-apply-failed ───────────────────────────────────────────────────


def _init_git_checkout(checkout: Path) -> None:
    subprocess.run(["git", "init", "-q"], cwd=str(checkout), check=True)
    subprocess.run(["git", "add", "-A"], cwd=str(checkout), check=True)
    subprocess.run(
        ["git",
         "-c", "user.email=t@example.com",
         "-c", "user.name=t",
         "-c", "commit.gpgsign=false",
         "commit", "-q", "-m", "init"],
        cwd=str(checkout), check=True,
    )


def test_patch_apply_failed_when_package_dir_unresolvable(tmp_path: Path) -> None:
    """When neither pkgs/by-name/<aa>/<attr>/package.nix nor a nix-eval
    fallback can locate the affected attr's package directory in the
    nixpkgs checkout, _apply_patch returns 'could not resolve' before
    invoking `git apply`. dispatch_outcome=patch-apply-failed."""
    if not _git_on_path():
        pytest.skip("git not on PATH")
    checkout = tmp_path / "checkout"
    checkout.mkdir()
    # No pkgs/by-name/de/demo structure here.
    (checkout / "README.md").write_text("# unrelated\n")
    _init_git_checkout(checkout)

    bundle = _scaffold_bundle(tmp_path)
    runner = FakeBuildRunner(response=_ok_outcome())
    result = run_builder(
        bundle_dir=bundle, build_runner=runner,
        nixpkgs_checkout=checkout, apply_patch=True,
    )
    assert result.dispatch_outcome == "patch-apply-failed"
    bj = result.build_json
    assert bj["patch_apply"]["applied"] is False
    assert bj["patch_apply"]["git_apply_exit_code"] is None
    assert "could not resolve package directory" in bj["patch_apply"]["reason"]
    assert bj["patched_build"]["outcome"] == "skipped"
    _assert_valid(bj)
    assert runner.calls == []


def test_patch_apply_failed_when_diff_mismatches_real_git(tmp_path: Path) -> None:
    """Resolution succeeds (pkgs/by-name/de/demo/package.nix exists) but
    the file's content doesn't match the patch's expected pre-image.
    `git apply --check --directory=pkgs/by-name/de/demo` refuses; the
    dispatcher records patch-apply-failed with a non-zero exit code."""
    if not _git_on_path():
        pytest.skip("git not on PATH")
    checkout = tmp_path / "checkout"
    pkg_dir = checkout / "pkgs" / "by-name" / "de" / "demo"
    pkg_dir.mkdir(parents=True)
    # Working-tree content does NOT match the patch's pre-image.
    (pkg_dir / "package.nix").write_text("# something completely different\n")
    _init_git_checkout(checkout)

    bundle = _scaffold_bundle(tmp_path)
    runner = FakeBuildRunner(response=_ok_outcome())
    result = run_builder(
        bundle_dir=bundle, build_runner=runner,
        nixpkgs_checkout=checkout, apply_patch=True,
    )
    assert result.dispatch_outcome == "patch-apply-failed"
    bj = result.build_json
    assert bj["patch_apply"]["applied"] is False
    # git apply exited non-zero (real git failure, not a resolution miss).
    assert isinstance(bj["patch_apply"]["git_apply_exit_code"], int)
    assert bj["patch_apply"]["git_apply_exit_code"] != 0
    assert "git apply --check --directory=pkgs/by-name/de/demo" in bj["patch_apply"]["reason"]
    _assert_valid(bj)
    assert runner.calls == []


def test_patch_apply_succeeds_against_pkgs_by_name_structure(tmp_path: Path) -> None:
    """Resolution succeeds AND the file's content matches the patch's
    pre-image. The Builder's --directory=pkgs/by-name/de/demo invocation
    applies cleanly. patch_apply.applied=True; files_changed records
    the nixpkgs-rooted path."""
    if not _git_on_path():
        pytest.skip("git not on PATH")
    checkout = tmp_path / "checkout"
    pkg_dir = checkout / "pkgs" / "by-name" / "de" / "demo"
    pkg_dir.mkdir(parents=True)
    # Working-tree content DOES match the patch's pre-image
    # ("version = \"1.0.0\";\n") so `git apply` succeeds.
    (pkg_dir / "package.nix").write_text('version = "1.0.0";\n')
    _init_git_checkout(checkout)

    bundle = _scaffold_bundle(tmp_path)
    runner = FakeBuildRunner(responses=[
        _ok_outcome(),  # patched_build
        _ok_outcome(),  # unpatched reproducer run
        _ok_outcome(),  # patched reproducer run
        _ok_outcome(),  # passthru-tests enumeration
    ])
    result = run_builder(
        bundle_dir=bundle, build_runner=runner,
        nixpkgs_checkout=checkout, apply_patch=True,
    )
    bj = result.build_json
    assert bj["patch_apply"]["applied"] is True, bj["patch_apply"]
    assert bj["patch_apply"]["git_apply_exit_code"] == 0
    assert bj["patch_apply"]["files_changed"] == ["pkgs/by-name/de/demo/package.nix"]
    # Confirm the patch actually mutated the working tree.
    actual_post = (pkg_dir / "package.nix").read_text()
    assert actual_post == 'version = "1.0.1";\n'
    _assert_valid(bj)


def test_resolve_attr_package_dir_returns_none_for_missing_attr(tmp_path: Path) -> None:
    """Direct unit test of the resolver helper: missing attr → None."""
    from agents.builder.runner import _resolve_attr_package_dir
    checkout = tmp_path / "checkout"
    checkout.mkdir()
    # No nix on PATH guaranteed in this scenario, but even if there is,
    # an empty checkout has no nix flake to evaluate.
    assert _resolve_attr_package_dir(checkout, None) is None
    assert _resolve_attr_package_dir(checkout, "") is None


def test_resolve_attr_package_dir_finds_pkgs_by_name(tmp_path: Path) -> None:
    """Direct unit test: pkgs/by-name/<aa>/<attr>/package.nix → returns
    the relative directory path."""
    from agents.builder.runner import _resolve_attr_package_dir
    checkout = tmp_path / "checkout"
    pkg_dir = checkout / "pkgs" / "by-name" / "tr" / "traefik"
    pkg_dir.mkdir(parents=True)
    (pkg_dir / "package.nix").write_text("dummy")
    assert _resolve_attr_package_dir(checkout, "traefik") == "pkgs/by-name/tr/traefik"


def _git_on_path() -> bool:
    try:
        subprocess.run(["git", "--version"], check=True, capture_output=True)
        return True
    except (OSError, subprocess.CalledProcessError):
        return False


# ─── infra-failure ────────────────────────────────────────────────────────


def test_infra_failure_records_patched_build_skipped_outcome(tmp_path: Path) -> None:
    """When the BuildRunner returns exit_code=None (e.g. nix-build not
    on PATH), the patched_build phase records outcome=None (the dispatcher
    still treats `applied=True` because the orchestrator DID try; the
    reason field surfaces the runner's diagnostic)."""
    bundle = _scaffold_bundle(tmp_path)
    runner = FakeBuildRunner(responses=[
        _infra_outcome(),
        _infra_outcome(),
        _infra_outcome(),
    ])
    result = run_builder(
        bundle_dir=bundle, build_runner=runner,
        nixpkgs_checkout=None, apply_patch=False,
    )
    # We don't bubble infra failure to dispatch_outcome at this layer
    # (the orchestrator can't tell the difference between a slow
    # builder, a failing one, and a missing nix-build); the executor
    # may downgrade based on the per-phase records. v0 records the
    # phase as outcome=null with a reason, dispatch stays "ok".
    bj = result.build_json
    assert bj["patched_build"]["exit_code"] is None
    assert bj["patched_build"]["reason"] == "nix-build-not-available"
    _assert_valid(bj)


# ─── reproducer-instrumentation.json ─────────────────────────────────────


def test_instrumentation_absent_records_null_and_no_asan_flag(
    tmp_path: Path,
) -> None:
    """No reproducer-instrumentation.json present → current behavior:
    build.json.instrumentation == None, BuildRunner.calls show
    instrumentation=None on every invocation."""
    bundle = _scaffold_bundle(tmp_path)
    runner = FakeBuildRunner(responses=[_ok_outcome(), _ok_outcome(), _ok_outcome()])
    result = run_builder(
        bundle_dir=bundle, build_runner=runner,
        nixpkgs_checkout=None, apply_patch=False,
    )
    assert result.build_json["instrumentation"] is None
    _assert_valid(result.build_json)
    for call in runner.calls:
        assert call["instrumentation"] is None


def test_instrumentation_asan_true_propagates_to_reproducer_phases(
    tmp_path: Path,
) -> None:
    """When reproducer-instrumentation.json has asan: true, the
    unpatched + patched reproducer-run phases receive
    instrumentation='asan'. build.json records the active mode."""
    bundle = _scaffold_bundle(tmp_path)
    (bundle / "reproducer-instrumentation.json").write_text(
        json.dumps({"schema_version": "1.0.0", "asan": True})
    )
    runner = FakeBuildRunner(responses=[
        _ok_outcome("patched-build ok\n"),
        _ok_outcome("unpatched repro\n"),
        _ok_outcome("patched repro\n"),
    ])
    result = run_builder(
        bundle_dir=bundle, build_runner=runner,
        nixpkgs_checkout=None, apply_patch=False,
    )
    assert result.dispatch_outcome == "ok"
    assert result.build_json["instrumentation"] == "asan"
    _assert_valid(result.build_json)
    # Three calls: patched_build sanity, unpatched repro, patched repro.
    # User contract: "apply to both unpatched and patched builds" — those
    # are the two reproducer phases. The patched_build sanity check is
    # intentionally NOT instrumented.
    assert len(runner.calls) == 3
    assert runner.calls[0]["instrumentation"] is None  # patched_build
    assert runner.calls[1]["instrumentation"] == "asan"  # unpatched repro
    assert runner.calls[2]["instrumentation"] == "asan"  # patched repro


def test_instrumentation_asan_false_records_null(tmp_path: Path) -> None:
    """asan: false is an explicit opt-out; identical to absent — no
    BuildRunner instrumentation, build.json.instrumentation == None.
    Crucially NOT a refusal."""
    bundle = _scaffold_bundle(tmp_path)
    (bundle / "reproducer-instrumentation.json").write_text(
        json.dumps({"schema_version": "1.0.0", "asan": False})
    )
    runner = FakeBuildRunner(responses=[_ok_outcome(), _ok_outcome(), _ok_outcome()])
    result = run_builder(
        bundle_dir=bundle, build_runner=runner,
        nixpkgs_checkout=None, apply_patch=False,
    )
    assert result.dispatch_outcome == "ok"
    assert result.build_json["instrumentation"] is None
    for call in runner.calls:
        assert call["instrumentation"] is None


def test_instrumentation_invalid_json_is_structured_refusal(
    tmp_path: Path,
) -> None:
    bundle = _scaffold_bundle(tmp_path)
    (bundle / "reproducer-instrumentation.json").write_text("{ this is not json")
    runner = FakeBuildRunner(response=_ok_outcome())
    result = run_builder(
        bundle_dir=bundle, build_runner=runner,
        nixpkgs_checkout=None, apply_patch=False,
    )
    assert result.dispatch_outcome == "instrumentation-malformed"
    bj = result.build_json
    assert bj["instrumentation"] is None
    assert "not valid JSON" in bj["patch_apply"]["reason"]
    _assert_valid(bj)
    # No BuildRunner invocations on the refusal path.
    assert runner.calls == []


def test_instrumentation_wrong_schema_version_is_refusal(
    tmp_path: Path,
) -> None:
    bundle = _scaffold_bundle(tmp_path)
    (bundle / "reproducer-instrumentation.json").write_text(
        json.dumps({"schema_version": "2.0.0", "asan": True})
    )
    runner = FakeBuildRunner(response=_ok_outcome())
    result = run_builder(
        bundle_dir=bundle, build_runner=runner,
        nixpkgs_checkout=None, apply_patch=False,
    )
    assert result.dispatch_outcome == "instrumentation-malformed"
    assert "schema_version" in result.build_json["patch_apply"]["reason"]
    _assert_valid(result.build_json)
    assert runner.calls == []


def test_instrumentation_asan_not_bool_is_refusal(tmp_path: Path) -> None:
    bundle = _scaffold_bundle(tmp_path)
    (bundle / "reproducer-instrumentation.json").write_text(
        json.dumps({"schema_version": "1.0.0", "asan": "yes"})
    )
    runner = FakeBuildRunner(response=_ok_outcome())
    result = run_builder(
        bundle_dir=bundle, build_runner=runner,
        nixpkgs_checkout=None, apply_patch=False,
    )
    assert result.dispatch_outcome == "instrumentation-malformed"
    assert "asan" in result.build_json["patch_apply"]["reason"]
    assert "boolean" in result.build_json["patch_apply"]["reason"]
    _assert_valid(result.build_json)
    assert runner.calls == []


def test_instrumentation_unknown_keys_is_refusal(tmp_path: Path) -> None:
    """v0 is strictly asan-only. UBSAN/MSAN/TSAN keys must refuse rather
    than silently ignore — they signal a user who expects something we
    don't support yet."""
    bundle = _scaffold_bundle(tmp_path)
    (bundle / "reproducer-instrumentation.json").write_text(
        json.dumps({"schema_version": "1.0.0", "asan": True, "ubsan": True})
    )
    runner = FakeBuildRunner(response=_ok_outcome())
    result = run_builder(
        bundle_dir=bundle, build_runner=runner,
        nixpkgs_checkout=None, apply_patch=False,
    )
    assert result.dispatch_outcome == "instrumentation-malformed"
    assert "unknown keys" in result.build_json["patch_apply"]["reason"]
    assert "ubsan" in result.build_json["patch_apply"]["reason"]
    _assert_valid(result.build_json)


def test_instrumentation_missing_asan_key_is_refusal(tmp_path: Path) -> None:
    bundle = _scaffold_bundle(tmp_path)
    (bundle / "reproducer-instrumentation.json").write_text(
        json.dumps({"schema_version": "1.0.0"})
    )
    runner = FakeBuildRunner(response=_ok_outcome())
    result = run_builder(
        bundle_dir=bundle, build_runner=runner,
        nixpkgs_checkout=None, apply_patch=False,
    )
    assert result.dispatch_outcome == "instrumentation-malformed"


# ─── 64 KiB truncation ───────────────────────────────────────────────────


def test_oversize_log_truncated_with_sha256_recorded(tmp_path: Path) -> None:
    huge_log = "x" * 80000  # > 64 KiB
    runner = FakeBuildRunner(responses=[
        BuildOutcome(exit_code=0, drv_path=None, out_path=None,
                     stdout_stderr=huge_log, elapsed_seconds=1.0),
        _ok_outcome(),
        _ok_outcome(),
    ])
    bundle = _scaffold_bundle(tmp_path)
    result = run_builder(
        bundle_dir=bundle, build_runner=runner,
        nixpkgs_checkout=None, apply_patch=False,
    )
    pb = result.build_json["patched_build"]
    assert len(pb["stdout_stderr"].encode("utf-8")) <= 65536
    assert pb["stdout_stderr_log_sha256"] is not None
    assert len(pb["stdout_stderr_log_sha256"]) == 64
    # full_logs preserves the untruncated text.
    assert len(result.full_logs["patched_build"]) == 80000
