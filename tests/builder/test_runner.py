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
        # Builder runs phases in this order: unpatched.test (pre-patch),
        # then patched-build (post-patch), then patched.test (post-patch).
        # See DECISIONS 2026-05-17 (F7) for why unpatched.test runs before
        # patch-apply.
        _ok_outcome("vuln-triggered: out-of-bounds-read in deserialise()\n"),
        _ok_outcome("patched-build ok\n"),
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
        # Order: unpatched, patched-build, patched. See DECISIONS F7.
        _ok_outcome("unpatched run\n"),
        _ok_outcome("patched-build ok\n"),
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
    invoking `git apply`. dispatch_outcome=patch-apply-failed.

    Per F7, unpatched.test runs BEFORE patch-apply, so the runner
    receives one call (the unpatched-side reproducer) before the
    patch-apply failure short-circuits."""
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
    # unpatched.test ran first against the pre-patch tree and succeeded.
    assert bj["unpatched"]["outcome"] == "succeeded"
    assert bj["patched"]["outcome"] == "skipped"
    _assert_valid(bj)
    assert len(runner.calls) == 1


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
    # unpatched.test ran first against the pre-patch tree and succeeded (per F7).
    assert bj["unpatched"]["outcome"] == "succeeded"
    assert bj["patched_build"]["outcome"] == "skipped"
    assert bj["patched"]["outcome"] == "skipped"
    _assert_valid(bj)
    assert len(runner.calls) == 1


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
        # Order (per F7): unpatched, patched_build, patched, then
        # passthru-tests enumeration.
        _ok_outcome(),  # unpatched reproducer (pre-patch)
        _ok_outcome(),  # patched_build (post-patch)
        _ok_outcome(),  # patched reproducer (post-patch)
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


# ─── filename remap: package.nix → default.nix (codex 2026-06-15) ────────────

_PKG_DIFF = (
    "diff --git a/package.nix b/package.nix\n"
    "--- a/package.nix\n"
    "+++ b/package.nix\n"
    "@@ -1 +1 @@\n"
    '-version = "10.0p2"; # see package.nix notes\n'
    '+version = "10.1p1"; # see package.nix notes\n'
)


def test_paths_contained_in_guard() -> None:
    """The path-traversal guard for direct-package-dir apply: contained paths pass;
    absolute, '..', '.', empty, backslash, and outside-dir paths are rejected."""
    from agents.builder.runner import _paths_contained_in
    d = "pkgs/development/python-modules/requests"
    assert _paths_contained_in([f"{d}/default.nix", f"{d}/CVE-2024-47081.patch"], d)
    assert _paths_contained_in([d], d)  # the dir itself
    assert not _paths_contained_in([f"{d}/../evil.nix"], d)
    assert not _paths_contained_in(["/etc/passwd"], d)
    assert not _paths_contained_in([f"{d}/sub/../../escape.nix"], d)
    assert not _paths_contained_in(["pkgs/development/python-modules/requests-evil/x"], d)
    assert not _paths_contained_in([""], d)
    assert not _paths_contained_in([f"{d}/a\\b"], d)


def test_apply_patch_direct_package_dir_multifile_source_backport(tmp_path: Path, monkeypatch) -> None:
    """A non-by-name source-backport: full nixpkgs paths contained in the package
    dir (a new CVE.patch + a default.nix edit) apply at the repo root with NO remap
    and NO --directory. This is the legacy-package source-backport path that the
    canonical-remap refactor regressed (codex 2026-06-15)."""
    if not _git_on_path():
        pytest.skip("git not on PATH")
    from agents.builder import runner as R
    checkout = tmp_path / "checkout"
    pkg = checkout / "pkgs" / "development" / "python-modules" / "demo"
    pkg.mkdir(parents=True)
    (pkg / "default.nix").write_text('  patches = [\n    ./old.patch\n  ];\n')
    (pkg / "old.patch").write_text("# pre-existing\n")
    _init_git_checkout(checkout)
    monkeypatch.setattr(R, "_resolve_attr_package_dir",
                        lambda co, attr: "pkgs/development/python-modules/demo")
    patch = tmp_path / "patch.diff"
    rel = "pkgs/development/python-modules/demo"
    patch.write_text(
        f"diff --git a/{rel}/CVE-2099-1.patch b/{rel}/CVE-2099-1.patch\n"
        "new file mode 100644\n"
        "--- /dev/null\n"
        f"+++ b/{rel}/CVE-2099-1.patch\n"
        "@@ -0,0 +1 @@\n"
        "+the authored upstream fix\n"
        f"diff --git a/{rel}/default.nix b/{rel}/default.nix\n"
        f"--- a/{rel}/default.nix\n"
        f"+++ b/{rel}/default.nix\n"
        "@@ -1,3 +1,4 @@\n"
        "   patches = [\n"
        "     ./old.patch\n"
        "+    ./CVE-2099-1.patch\n"
        "   ];\n"
    )
    res = R._apply_patch(patch_diff_path=patch, nixpkgs_checkout=checkout, attr="python3Packages.demo")
    assert res["applied"] is True, res
    assert res["apply_mode"] == "direct-package-dir"
    assert "package_file_remap" not in res
    assert set(res["files_changed"]) == {f"{rel}/CVE-2099-1.patch", f"{rel}/default.nix"}
    assert (pkg / "CVE-2099-1.patch").read_text() == "the authored upstream fix\n"
    assert "./CVE-2099-1.patch" in (pkg / "default.nix").read_text()
    assert patch.read_text().startswith("diff --git")  # committed patch untouched


def test_apply_patch_direct_mode_rejects_path_escape(tmp_path: Path, monkeypatch) -> None:
    """Security: a non-by-name patch that touches a file OUTSIDE the resolved package
    dir (path traversal) must NOT take the direct-package-dir mode — it falls through
    to the canonical remap, which refuses the multi-file shape. The outside file is
    never mutated."""
    if not _git_on_path():
        pytest.skip("git not on PATH")
    from agents.builder import runner as R
    checkout = tmp_path / "checkout"
    pkg = checkout / "pkgs" / "development" / "python-modules" / "demo"
    pkg.mkdir(parents=True)
    (pkg / "default.nix").write_text('version = "1";\n')
    victim_dir = checkout / "pkgs" / "stdenv"
    victim_dir.mkdir(parents=True)
    (victim_dir / "secret.nix").write_text("# do not touch\n")
    _init_git_checkout(checkout)
    monkeypatch.setattr(R, "_resolve_attr_package_dir",
                        lambda co, attr: "pkgs/development/python-modules/demo")
    rel = "pkgs/development/python-modules/demo"
    patch = tmp_path / "patch.diff"
    patch.write_text(
        f"diff --git a/{rel}/default.nix b/{rel}/default.nix\n"
        f"--- a/{rel}/default.nix\n+++ b/{rel}/default.nix\n"
        '@@ -1 +1 @@\n-version = "1";\n+version = "2";\n'
        "diff --git a/pkgs/stdenv/secret.nix b/pkgs/stdenv/secret.nix\n"
        "--- a/pkgs/stdenv/secret.nix\n+++ b/pkgs/stdenv/secret.nix\n"
        "@@ -1 +1 @@\n-# do not touch\n+# pwned\n"
    )
    res = R._apply_patch(patch_diff_path=patch, nixpkgs_checkout=checkout, attr="python3Packages.demo")
    assert res["applied"] is False, res
    assert res.get("apply_mode") != "direct-package-dir"
    assert (victim_dir / "secret.nix").read_text() == "# do not touch\n"  # untouched


def test_remap_diff_basename_rewrites_only_headers() -> None:
    """The remap helper rewrites exactly the three git path headers and leaves
    hunk bodies untouched — even context lines that mention 'package.nix'."""
    from agents.builder.runner import _remap_diff_basename
    out = _remap_diff_basename(_PKG_DIFF, "package.nix", "default.nix")
    assert "diff --git a/default.nix b/default.nix\n" in out
    assert "--- a/default.nix\n" in out
    assert "+++ b/default.nix\n" in out
    # hunk body (the version line, which also contains the word package.nix) is intact
    assert '-version = "10.0p2"; # see package.nix notes\n' in out
    assert '+version = "10.1p1"; # see package.nix notes\n' in out
    assert "a/package.nix" not in out and "b/package.nix" not in out


def _multivariant_checkout(tmp_path: Path):
    """A checkout whose openssh dir has default.nix + common.nix (no package.nix),
    mimicking the real multi-variant layout where meta.position points at common.nix
    but the patched per-variant content lives in default.nix."""
    checkout = tmp_path / "checkout"
    pkg_dir = checkout / "pkgs" / "tools" / "networking" / "openssh"
    pkg_dir.mkdir(parents=True)
    (pkg_dir / "default.nix").write_text('version = "10.0p2"; # see package.nix notes\n')
    # a sibling .nix the patch must NOT match (the `common` helper)
    (pkg_dir / "common.nix").write_text("{ lib }: { }\n")
    return checkout, pkg_dir


def test_apply_patch_remaps_via_content_match(tmp_path: Path, monkeypatch) -> None:
    """Non-by-name multi-variant package: the Builder picks the target file by BYTE
    match to the bundled package.nix (primary signal), remaps package.nix->default.nix,
    applies, mutates the real file, records method=content-match. patch.diff untouched."""
    if not _git_on_path():
        pytest.skip("git not on PATH")
    from agents.builder import runner as R
    checkout, pkg_dir = _multivariant_checkout(tmp_path)
    _init_git_checkout(checkout)
    patch = tmp_path / "patch.diff"
    patch.write_text(_PKG_DIFF)
    # bundled package.nix == default.nix bytes => unique content-match
    (tmp_path / "package.nix").write_text('version = "10.0p2"; # see package.nix notes\n')
    monkeypatch.setattr(
        R, "_resolve_attr_package_file",
        lambda co, attr: "pkgs/tools/networking/openssh/common.nix",  # meta.position lies
    )
    res = R._apply_patch(patch_diff_path=patch, nixpkgs_checkout=checkout, attr="openssh_gssapi")
    assert res["applied"] is True, res
    assert res["files_changed"] == ["pkgs/tools/networking/openssh/default.nix"]
    assert res["package_file_remap"] == (
        "package.nix -> pkgs/tools/networking/openssh/default.nix (content-match)"
    )
    assert (pkg_dir / "default.nix").read_text() == 'version = "10.1p1"; # see package.nix notes\n'
    assert (pkg_dir / "common.nix").read_text() == "{ lib }: { }\n"  # sibling untouched
    assert patch.read_text() == _PKG_DIFF


def test_apply_patch_remaps_via_apply_check_fallback(tmp_path: Path, monkeypatch) -> None:
    """When no bundled package.nix byte-matches, the Builder falls back to a unique
    git-apply --check hit among *.nix candidates (default.nix applies, common.nix does
    not), and records method=apply-check."""
    if not _git_on_path():
        pytest.skip("git not on PATH")
    from agents.builder import runner as R
    checkout, pkg_dir = _multivariant_checkout(tmp_path)
    _init_git_checkout(checkout)
    patch = tmp_path / "patch.diff"
    patch.write_text(_PKG_DIFF)
    # no bundled package.nix => content-match stage is skipped
    monkeypatch.setattr(
        R, "_resolve_attr_package_file",
        lambda co, attr: "pkgs/tools/networking/openssh/common.nix",
    )
    res = R._apply_patch(patch_diff_path=patch, nixpkgs_checkout=checkout, attr="openssh_gssapi")
    assert res["applied"] is True, res
    assert res["package_file_remap"] == (
        "package.nix -> pkgs/tools/networking/openssh/default.nix (apply-check)"
    )
    assert (pkg_dir / "default.nix").read_text() == 'version = "10.1p1"; # see package.nix notes\n'


def test_apply_patch_refuses_remap_for_multifile_patch(tmp_path: Path, monkeypatch) -> None:
    """When the resolved file is non-by-name (default.nix) but the patch touches more
    than the canonical package.nix, the Builder refuses to remap (codex constraint)."""
    if not _git_on_path():
        pytest.skip("git not on PATH")
    from agents.builder import runner as R
    checkout = tmp_path / "checkout"
    pkg_dir = checkout / "pkgs" / "tools" / "networking" / "openssh"
    pkg_dir.mkdir(parents=True)
    (pkg_dir / "default.nix").write_text('version = "10.0p2";\n')
    _init_git_checkout(checkout)
    multi = tmp_path / "patch.diff"
    multi.write_text(
        _PKG_DIFF
        + "diff --git a/common.nix b/common.nix\n"
        "--- a/common.nix\n+++ b/common.nix\n@@ -1 +1 @@\n-a\n+b\n"
    )
    monkeypatch.setattr(
        R, "_resolve_attr_package_file",
        lambda co, attr: "pkgs/tools/networking/openssh/default.nix",
    )
    res = R._apply_patch(patch_diff_path=multi, nixpkgs_checkout=checkout, attr="openssh_gssapi")
    # common.nix is a top-level bundle-relative path NOT contained in the resolved
    # package dir, so direct-package-dir apply is ineligible and (being multi-file)
    # the canonical remap refuses too.
    assert res["applied"] is False
    assert "refusing to apply onto a non-by-name package" in res["reason"]


def test_apply_patch_refuses_remap_for_sibling_deletion(tmp_path: Path, monkeypatch) -> None:
    """Security regression: a patch that edits package.nix AND deletes a sibling file
    (via `+++ /dev/null`) must be refused. The `+++ b/`-only extractor is blind to
    deletions; the gate enforces the single-file invariant via `git apply --numstat`,
    so the sibling is never mutated. (security-review 2026-06-15)"""
    if not _git_on_path():
        pytest.skip("git not on PATH")
    from agents.builder import runner as R
    checkout = tmp_path / "checkout"
    pkg_dir = checkout / "pkgs" / "tools" / "networking" / "openssh"
    pkg_dir.mkdir(parents=True)
    (pkg_dir / "default.nix").write_text('version = "10.0p2"; # see package.nix notes\n')
    (pkg_dir / "victim.nix").write_text("# load-bearing sibling\n")
    _init_git_checkout(checkout)
    sneaky = tmp_path / "patch.diff"
    sneaky.write_text(
        _PKG_DIFF
        + "diff --git a/victim.nix b/victim.nix\n"
        "deleted file mode 100644\n"
        "--- a/victim.nix\n"
        "+++ /dev/null\n"
        "@@ -1 +0,0 @@\n"
        "-# load-bearing sibling\n"
    )
    monkeypatch.setattr(
        R, "_resolve_attr_package_file",
        lambda co, attr: "pkgs/tools/networking/openssh/default.nix",
    )
    res = R._apply_patch(patch_diff_path=sneaky, nixpkgs_checkout=checkout, attr="openssh_gssapi")
    # The sibling deletion makes the diff "unsafe" (deleted file mode), so
    # direct-package-dir apply is refused; the multi-file shape also fails the
    # canonical remap. The victim file is never mutated.
    assert res["applied"] is False, res
    assert "refusing to apply onto a non-by-name package" in res["reason"]
    assert (pkg_dir / "victim.nix").read_text() == "# load-bearing sibling\n"
    # the sibling file must be untouched
    assert (pkg_dir / "victim.nix").is_file()


def test_resolve_attr_package_dir_rejects_unsafe_attr(tmp_path: Path) -> None:
    """Attrs that fail _ATTR_SAFE_RE must return None without calling nix eval."""
    from agents.builder.runner import _resolve_attr_package_dir
    checkout = tmp_path / "checkout"
    checkout.mkdir()
    for bad in ["ruby}; builtins.readFile /etc/passwd; ({", "a b", "1start", ".leading", "a..b", ""]:
        assert _resolve_attr_package_dir(checkout, bad) is None, f"expected None for {bad!r}"


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
        # Order (per F7): unpatched, patched_build, patched.
        _ok_outcome("unpatched repro\n"),
        _ok_outcome("patched-build ok\n"),
        _ok_outcome("patched repro\n"),
    ])
    result = run_builder(
        bundle_dir=bundle, build_runner=runner,
        nixpkgs_checkout=None, apply_patch=False,
    )
    assert result.dispatch_outcome == "ok"
    assert result.build_json["instrumentation"] == "asan"
    _assert_valid(result.build_json)
    # Three calls in F7 order: unpatched repro (pre-patch), patched_build
    # sanity, patched repro (post-patch). User contract: "apply to both
    # unpatched and patched builds" — those are the two reproducer phases.
    # The patched_build sanity check is intentionally NOT instrumented.
    assert len(runner.calls) == 3
    assert runner.calls[0]["instrumentation"] == "asan"  # unpatched repro
    assert runner.calls[1]["instrumentation"] is None    # patched_build
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


def test_instrumentation_only_schema_version_is_noop(tmp_path: Path) -> None:
    """A bundle with `{schema_version: "1.0.0"}` and no other keys is
    equivalent to absent file: both knobs default to false, no refusal."""
    bundle = _scaffold_bundle(tmp_path)
    (bundle / "reproducer-instrumentation.json").write_text(
        json.dumps({"schema_version": "1.0.0"})
    )
    runner = FakeBuildRunner(responses=[_ok_outcome(), _ok_outcome(), _ok_outcome()])
    result = run_builder(
        bundle_dir=bundle, build_runner=runner,
        nixpkgs_checkout=None, apply_patch=False,
    )
    assert result.dispatch_outcome == "ok"
    assert result.build_json["instrumentation"] is None


def test_instrumentation_disable_doCheck_true_wraps_patched_build(
    tmp_path: Path,
) -> None:
    """When disable_doCheck=true, the patched-build phase uses the
    nix_expression mode (wrapping pkgs.<attr>.overrideAttrs(doCheck=false))
    rather than the attr mode. Reproducer-run phases are unaffected
    (their derivations are constructed by reproducer.nix author)."""
    bundle = _scaffold_bundle(tmp_path)
    (bundle / "reproducer-instrumentation.json").write_text(
        json.dumps({"schema_version": "1.0.0", "disable_doCheck": True})
    )
    runner = FakeBuildRunner(responses=[
        # Order (per F7): unpatched, patched_build, patched.
        _ok_outcome("unpatched repro ok\n"),
        _ok_outcome("patched-build ok\n"),
        _ok_outcome("patched repro ok\n"),
    ])
    result = run_builder(
        bundle_dir=bundle, build_runner=runner,
        nixpkgs_checkout=None, apply_patch=False,
    )
    assert result.dispatch_outcome == "ok"
    # patched-build phase (runner.calls[1] under F7 ordering):
    # nix_expression mode with doCheck=false wrap.
    pb_call = runner.calls[1]
    assert pb_call["attr"] is None
    assert pb_call["nix_expression"] is not None
    assert "overrideAttrs (old: { doCheck = false; })" in pb_call["nix_expression"]
    # Reproducer-run phases (calls[0], calls[2]) use reproducer.nix.
    for call in (runner.calls[0], runner.calls[2]):
        assert "reproducer.nix" in (call["nix_expression"] or "")


def test_instrumentation_disable_doCheck_false_keeps_attr_mode(
    tmp_path: Path,
) -> None:
    """disable_doCheck=false (or absent) → patched-build phase uses
    attr mode (vanilla nix-build -A <attr>)."""
    bundle = _scaffold_bundle(tmp_path)
    (bundle / "reproducer-instrumentation.json").write_text(
        json.dumps({"schema_version": "1.0.0", "disable_doCheck": False})
    )
    runner = FakeBuildRunner(responses=[
        _ok_outcome(), _ok_outcome(), _ok_outcome(),
    ])
    run_builder(
        bundle_dir=bundle, build_runner=runner,
        nixpkgs_checkout=None, apply_patch=False,
    )
    # patched-build phase is calls[1] under F7 ordering (unpatched runs first).
    pb_call = runner.calls[1]
    assert pb_call["attr"] == "demo"
    assert pb_call["nix_expression"] is None


def test_instrumentation_disable_doCheck_not_bool_is_refusal(
    tmp_path: Path,
) -> None:
    bundle = _scaffold_bundle(tmp_path)
    (bundle / "reproducer-instrumentation.json").write_text(
        json.dumps({"schema_version": "1.0.0", "disable_doCheck": "yes"})
    )
    runner = FakeBuildRunner(response=_ok_outcome())
    result = run_builder(
        bundle_dir=bundle, build_runner=runner,
        nixpkgs_checkout=None, apply_patch=False,
    )
    assert result.dispatch_outcome == "instrumentation-malformed"
    assert "disable_doCheck" in result.build_json["patch_apply"]["reason"]
    assert "boolean" in result.build_json["patch_apply"]["reason"]


# ─── 64 KiB truncation ───────────────────────────────────────────────────


def test_oversize_log_truncated_with_sha256_recorded(tmp_path: Path) -> None:
    huge_log = "x" * 80000  # > 64 KiB
    runner = FakeBuildRunner(responses=[
        # Order (per F7): unpatched, patched_build (HUGE log), patched.
        _ok_outcome(),
        BuildOutcome(exit_code=0, drv_path=None, out_path=None,
                     stdout_stderr=huge_log, elapsed_seconds=1.0),
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


# ─── reproducer-side nixpkgs pin ──────────────────────────────────────────


def test_repro_nix_expression_unpinned_uses_system_nixpkgs(tmp_path: Path) -> None:
    """Default form: no pin → reproducer.nix invoked with `{}`, so its
    `pkgs ? import <nixpkgs> {}` default resolves via NIX_PATH."""
    from agents.builder.runner import _repro_nix_expression

    repro = tmp_path / "reproducer.nix"
    repro.write_text("{ pkgs ? import <nixpkgs> {} }: { unpatched = {}; patched = {}; }")
    expr = _repro_nix_expression(repro, attr_in_repro="unpatched.test")
    assert "(import" in expr
    assert ".unpatched.test)" in expr
    # No nixpkgs-pin override
    assert "pkgs = import" not in expr


def test_unpatched_test_runs_before_patch_apply(tmp_path: Path) -> None:
    """F7: unpatched.test must run against the pre-patch nixpkgs tree.

    With apply_patch=True against a real git checkout, the Builder
    should:
      1. Run unpatched.test BEFORE patch-apply mutates the working tree.
      2. Apply the patch.
      3. Run patched_build and patched.test against the post-patch tree.

    Verified by intercepting the checkout's package.nix content at each
    BuildRunner call: the first call sees the pre-patch text, the
    later calls see the post-patch text.
    """
    if not _git_on_path():
        pytest.skip("git not on PATH")
    checkout = tmp_path / "checkout"
    pkg_dir = checkout / "pkgs" / "by-name" / "de" / "demo"
    pkg_dir.mkdir(parents=True)
    pkg_path = pkg_dir / "package.nix"
    pkg_path.write_text('version = "1.0.0";\n')
    _init_git_checkout(checkout)

    seen_content: list[str] = []

    class RecordingRunner:
        is_available = True
        calls: list[dict[str, Any]] = []

        def run(self, *, nix_expression=None, attr=None, cwd, timeout_seconds,
                instrumentation=None):
            seen_content.append(pkg_path.read_text())
            self.calls.append({
                "attr": attr, "nix_expression": nix_expression,
                "instrumentation": instrumentation,
            })
            return _ok_outcome()

    runner = RecordingRunner()
    bundle = _scaffold_bundle(tmp_path)
    run_builder(
        bundle_dir=bundle, build_runner=runner,
        nixpkgs_checkout=checkout, apply_patch=True,
    )
    # First BuildRunner call is unpatched.test against the PRE-patch tree.
    assert seen_content[0] == 'version = "1.0.0";\n', seen_content
    assert "unpatched.test" in (runner.calls[0]["nix_expression"] or "")
    # Subsequent calls (patched_build, patched.test) see the POST-patch tree.
    assert seen_content[1] == 'version = "1.0.1";\n', seen_content
    assert seen_content[2] == 'version = "1.0.1";\n', seen_content
    assert "patched.test" in (runner.calls[2]["nix_expression"] or "")


def test_repro_nix_expression_pinned_passes_nixpkgs_path(tmp_path: Path) -> None:
    """With nixpkgs_pin, reproducer.nix is invoked with `{ pkgs = import
    <pin> {}; }` so `pkgs.<attr>` references bind to the bundle's pinned
    tree, not the system default. This is what keeps reproducer-side
    behaviour deterministic against the bundle's nixpkgs_rev."""
    from agents.builder.runner import _repro_nix_expression

    repro = tmp_path / "reproducer.nix"
    repro.write_text("{ pkgs ? import <nixpkgs> {} }: { unpatched = {}; patched = {}; }")
    pin = tmp_path / "nixpkgs-checkout"
    pin.mkdir()
    expr = _repro_nix_expression(
        repro, attr_in_repro="patched.test", nixpkgs_pin=pin,
    )
    assert f"pkgs = import {pin.resolve()}" in expr
    assert ".patched.test)" in expr
