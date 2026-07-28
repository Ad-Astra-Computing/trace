"""Tests for the shared pinned-source unpack primitive (tools/trace_cli/pinned_source.py).

Extracted alongside the primitive itself (semantic-backport-adaptation slice 1).
The nix fetch path is integration-only (network); these cover the pure logic —
field fallback, archive extraction + top-dir descent, and the feed-sourced
attr/rev injection guards that must reject before any nix invocation.
"""

from __future__ import annotations

import json
import subprocess
import tarfile
from pathlib import Path

import pytest

from tools.trace_cli import pinned_source


# ─── read_bundle_field ─────────────────────────────────────────────────────

def test_read_bundle_field_falls_through(tmp_path: Path) -> None:
    bd = tmp_path / "bundle"
    bd.mkdir()
    (bd / "impact.json").write_text(json.dumps({"nixpkgs_rev": "a" * 40}))
    got = pinned_source.read_bundle_field(
        bd, ("bundle.json", "nixpkgs_rev"), ("impact.json", "nixpkgs_rev"),
    )
    assert got == "a" * 40


def test_read_bundle_field_none_when_absent(tmp_path: Path) -> None:
    bd = tmp_path / "bundle"
    bd.mkdir()
    assert pinned_source.read_bundle_field(bd, ("bundle.json", "x")) is None


# ─── unpack_source_store_path ──────────────────────────────────────────────

def test_unpack_source_store_path_dir_passthrough(tmp_path: Path) -> None:
    """A directory `src` (fetchFromGitHub/fetchzip) is returned unchanged."""
    src = tmp_path / "already-unpacked"
    src.mkdir()
    (src / "foo.c").write_text("x\n")
    out = pinned_source.unpack_source_store_path(src, tmp_path / "dest")
    assert out == src


def test_unpack_source_store_path_extracts_and_descends(tmp_path: Path) -> None:
    """A tarball `src` with a single top dir extracts and descends into it."""
    root = tmp_path / "pkg-1.2.3"
    root.mkdir()
    (root / "inflate.c").write_text("int main(void){return 0;}\n")
    tarball = tmp_path / "pkg-1.2.3.tar.gz"
    with tarfile.open(tarball, "w:gz") as tf:
        tf.add(root, arcname="pkg-1.2.3")
    out = pinned_source.unpack_source_store_path(tarball, tmp_path / "dest")
    assert out.name == "pkg-1.2.3"
    assert (out / "inflate.c").is_file()


# ─── injection guard: malicious attr/rev never reach nix ───────────────────

def test_unpack_rejects_malicious_attr(tmp_path: Path) -> None:
    bd = tmp_path / "bundle"
    bd.mkdir()
    (bd / "resolver-input.json").write_text(
        json.dumps({"attr_path": 'zlib"; builtins.exec ""; x = "'})
    )
    (bd / "bundle.json").write_text(json.dumps({"nixpkgs_rev": "b" * 40}))
    with pytest.raises(RuntimeError, match="valid nixpkgs attr"):
        pinned_source.unpack_pinned_source(bd, tmp_path)


def test_unpack_rejects_bad_rev(tmp_path: Path) -> None:
    bd = tmp_path / "bundle"
    bd.mkdir()
    (bd / "resolver-input.json").write_text(json.dumps({"attr_path": "zlib"}))
    (bd / "bundle.json").write_text(json.dumps({"nixpkgs_rev": "not-a-sha"}))
    with pytest.raises(RuntimeError, match="40-char git SHA"):
        pinned_source.unpack_pinned_source(bd, tmp_path)


def test_unpack_rejects_missing_attr(tmp_path: Path) -> None:
    bd = tmp_path / "bundle"
    bd.mkdir()
    (bd / "bundle.json").write_text(json.dumps({"nixpkgs_rev": "c" * 40}))
    with pytest.raises(RuntimeError, match="attr_path not found"):
        pinned_source.unpack_pinned_source(bd, tmp_path)


# ─── eval_source_root: fail closed on eval failure, None only on genuine unset ─
#
# A silent None on eval FAILURE would make the gate validate a patch against the
# tarball root instead of the derivation's real sourceRoot — the exact fail-open
# (krb5 `sourceRoot = "krb5-.../src"`) the gate exists to catch.

def _fake_run(stdout: str = "", returncode: int = 0):
    def run(*_a, **_k):
        return subprocess.CompletedProcess(args=[], returncode=returncode,
                                           stdout=stdout, stderr="boom")
    return run


def test_eval_source_root_raises_when_nix_instantiate_missing(monkeypatch) -> None:
    monkeypatch.setattr(pinned_source.shutil, "which", lambda _n: None)
    with pytest.raises(pinned_source.SourceRootEvalError, match="nix-instantiate not on PATH"):
        pinned_source.eval_source_root("let pkgs = x {};", '["zlib"]')


def test_eval_source_root_raises_on_nonzero_exit(monkeypatch) -> None:
    monkeypatch.setattr(pinned_source.shutil, "which", lambda _n: "/usr/bin/nix-instantiate")
    monkeypatch.setattr(pinned_source.subprocess, "run", _fake_run("", returncode=1))
    with pytest.raises(pinned_source.SourceRootEvalError, match="failed"):
        pinned_source.eval_source_root("let pkgs = x {};", '["zlib"]')


def test_eval_source_root_raises_on_malformed_output(monkeypatch) -> None:
    monkeypatch.setattr(pinned_source.shutil, "which", lambda _n: "/usr/bin/nix-instantiate")
    monkeypatch.setattr(pinned_source.subprocess, "run", _fake_run("not json", returncode=0))
    with pytest.raises(pinned_source.SourceRootEvalError, match="malformed"):
        pinned_source.eval_source_root("let pkgs = x {};", '["zlib"]')


def test_eval_source_root_returns_none_on_genuine_unset(monkeypatch) -> None:
    monkeypatch.setattr(pinned_source.shutil, "which", lambda _n: "/usr/bin/nix-instantiate")
    monkeypatch.setattr(pinned_source.subprocess, "run", _fake_run("null", returncode=0))
    assert pinned_source.eval_source_root("let pkgs = x {};", '["zlib"]') is None


def test_eval_source_root_returns_string_override(monkeypatch) -> None:
    monkeypatch.setattr(pinned_source.shutil, "which", lambda _n: "/usr/bin/nix-instantiate")
    monkeypatch.setattr(pinned_source.subprocess, "run",
                        _fake_run('"krb5-1.22.1/src"', returncode=0))
    assert pinned_source.eval_source_root("let pkgs = x {};", '["krb5"]') == "krb5-1.22.1/src"


# ─── resolve_effective_source_root ─────────────────────────────────────────

def test_resolve_effective_source_root_none_is_tree(tmp_path: Path) -> None:
    tree = tmp_path / "pkg-1.0"
    tree.mkdir()
    assert pinned_source.resolve_effective_source_root(tree, None) == tree


def test_resolve_effective_source_root_dot_fails_closed(tmp_path: Path) -> None:
    """`sourceRoot = "."` is build-root-relative and ambiguous from the
    descended tree alone (build root is tree.parent for a single-root archive,
    tree for a multi-root one) — must fail closed, never guess."""
    tree = tmp_path / "extracted"
    tree.mkdir()
    for sr in (".", "./"):
        with pytest.raises(ValueError, match="build-root-relative"):
            pinned_source.resolve_effective_source_root(tree, sr)


def test_resolve_effective_source_root_subdir_against_parent(tmp_path: Path) -> None:
    tree = tmp_path / "krb5-1.22.1"
    (tree / "src").mkdir(parents=True)
    assert pinned_source.resolve_effective_source_root(tree, "krb5-1.22.1/src") == tree / "src"


def test_resolve_effective_source_root_unresolvable_raises(tmp_path: Path) -> None:
    tree = tmp_path / "pkg-1.0"
    tree.mkdir()
    with pytest.raises(ValueError, match="sourceRoot"):
        pinned_source.resolve_effective_source_root(tree, "nonexistent/dir")


# ─── eval_patch_flags: best-effort by default, strict fails closed ──────────

def test_eval_patch_flags_best_effort_returns_default(monkeypatch) -> None:
    monkeypatch.setattr(pinned_source.shutil, "which", lambda _n: None)
    assert pinned_source.eval_patch_flags("p", "[x]") == ["-p1"]           # no raise


def test_eval_patch_flags_strict_raises_on_failure(monkeypatch) -> None:
    monkeypatch.setattr(pinned_source.shutil, "which", lambda _n: "/usr/bin/nix-instantiate")
    monkeypatch.setattr(pinned_source.subprocess, "run", _fake_run("", returncode=1))
    with pytest.raises(pinned_source.PatchFlagsEvalError):
        pinned_source.eval_patch_flags("p", "[x]", strict=True)


def test_eval_patch_flags_strict_genuine_default_ok(monkeypatch) -> None:
    """A genuine unset patchFlags resolves to ["-p1"] via the nix `or` default —
    a successful eval, NOT a failure — so strict must not raise."""
    monkeypatch.setattr(pinned_source.shutil, "which", lambda _n: "/usr/bin/nix-instantiate")
    monkeypatch.setattr(pinned_source.subprocess, "run", _fake_run('["-p1"]', returncode=0))
    assert pinned_source.eval_patch_flags("p", "[x]", strict=True) == ["-p1"]


# ─── eval_preceding_patches_count: always fails closed ─────────────────────

def test_eval_preceding_patches_count_raises_on_failure(monkeypatch) -> None:
    monkeypatch.setattr(pinned_source.shutil, "which", lambda _n: "/usr/bin/nix-instantiate")
    monkeypatch.setattr(pinned_source.subprocess, "run", _fake_run("", returncode=1))
    with pytest.raises(pinned_source.PatchesEvalError):
        pinned_source.eval_preceding_patches_count("p", "[x]")


def test_eval_preceding_patches_count_parses_int(monkeypatch) -> None:
    monkeypatch.setattr(pinned_source.shutil, "which", lambda _n: "/usr/bin/nix-instantiate")
    monkeypatch.setattr(pinned_source.subprocess, "run", _fake_run("2", returncode=0))
    assert pinned_source.eval_preceding_patches_count("p", "[x]") == 2
