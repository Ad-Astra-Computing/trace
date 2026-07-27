"""Tests for `trace bundle preflight` (tools/trace_cli/preflight.py).

The load-bearing case is `test_apply_patch_fails_on_base_mismatch`: it reproduces the
libarchive CVE-2026-15028 failure shape — a source patch whose target context is
absent from the pinned source — which the pre-existing tree-level `git apply`
check let slip through to (expensive) cert. The apply logic runs against a
supplied `--source-tree`, so no network / nix fetch is needed.
"""

from __future__ import annotations

import argparse
import json
import subprocess
from pathlib import Path

import pytest

from tools.trace_cli import preflight


# ─── fixtures ──────────────────────────────────────────────────────────────

_SRC_BEFORE = "int main(void) {\n    int x = 1;\n    return x;\n}\n"
_SRC_AFTER = "int main(void) {\n    int x = 2;\n    return x;\n}\n"
_SRC_FINAL = "int main(void) {\n    int x = 3;\n    return x;\n}\n"
# Divergent base: the `int x = 1;` line the patch edits is simply absent, like
# libarchive 3.8.7 lacking the archive_ckd_* helpers the upstream fix touched.
_SRC_DIVERGENT = "int compute(int n) {\n    long value = 42;\n    return n;\n}\n"


def _make_patch(tmp: Path, before: str, after: str) -> Path:
    a = tmp / "before"
    b = tmp / "after"
    a.write_text(before)
    b.write_text(after)
    proc = subprocess.run(
        ["diff", "-u", "--label", "a/foo.c", "--label", "b/foo.c", str(a), str(b)],
        capture_output=True, text=True,
    )
    # diff exits 1 when files differ; that is the expected/normal path here.
    assert proc.returncode == 1, proc.stderr
    patch = tmp / "fix.patch"
    patch.write_text(proc.stdout)
    return patch


def _source_tree(tmp: Path, name: str, content: str) -> Path:
    root = tmp / name
    root.mkdir()
    (root / "foo.c").write_text(content)
    return root


# ─── apply_patch ───────────────────────────────────────────────────────────

def test_apply_patch_applies_clean(tmp_path: Path) -> None:
    patch = _make_patch(tmp_path, _SRC_BEFORE, _SRC_AFTER)
    tree = _source_tree(tmp_path, "src-ok", _SRC_BEFORE)
    ok, output = preflight.apply_patch(tree, patch, ["-p1"])
    assert ok is True, output
    assert (tree / "foo.c").read_text() == _SRC_AFTER


def test_apply_patch_fails_on_base_mismatch(tmp_path: Path) -> None:
    """The libarchive shape: the edited context is absent from the pinned base."""
    patch = _make_patch(tmp_path, _SRC_BEFORE, _SRC_AFTER)
    tree = _source_tree(tmp_path, "src-divergent", _SRC_DIVERGENT)
    ok, output = preflight.apply_patch(tree, patch, ["-p1"])
    assert ok is False
    assert "FAILED" in output or "malformed" in output.lower() or output


# ─── discover_source_patches ───────────────────────────────────────────────

def test_discover_defaults_to_upstream_fix(tmp_path: Path) -> None:
    bd = tmp_path / "bundle"
    bd.mkdir()
    (bd / "upstream-fix.patch").write_text("dummy\n")
    got = preflight.discover_source_patches(bd, None)
    assert got == [(bd / "upstream-fix.patch").resolve()]


def test_discover_raises_when_no_upstream_fix(tmp_path: Path) -> None:
    bd = tmp_path / "bundle"
    bd.mkdir()
    with pytest.raises(FileNotFoundError):
        preflight.discover_source_patches(bd, None)


def test_discover_resolves_overrides_relative_to_bundle(tmp_path: Path) -> None:
    bd = tmp_path / "bundle"
    bd.mkdir()
    (bd / "custom.patch").write_text("dummy\n")
    got = preflight.discover_source_patches(bd, [Path("custom.patch")])
    assert got == [(bd / "custom.patch").resolve()]


def test_discover_missing_override_raises(tmp_path: Path) -> None:
    bd = tmp_path / "bundle"
    bd.mkdir()
    with pytest.raises(FileNotFoundError):
        preflight.discover_source_patches(bd, [Path("nope.patch")])


# ─── _read_bundle_field fallback ───────────────────────────────────────────

def test_read_bundle_field_falls_through(tmp_path: Path) -> None:
    bd = tmp_path / "bundle"
    bd.mkdir()
    (bd / "impact.json").write_text(json.dumps({"nixpkgs_rev": "a" * 40}))
    got = preflight._read_bundle_field(
        bd, ("bundle.json", "nixpkgs_rev"), ("impact.json", "nixpkgs_rev"),
    )
    assert got == "a" * 40


# ─── injection guard: malicious attr/rev never reach nix ───────────────────

def test_unpack_rejects_malicious_attr(tmp_path: Path) -> None:
    bd = tmp_path / "bundle"
    bd.mkdir()
    (bd / "resolver-input.json").write_text(
        json.dumps({"attr_path": 'zlib"; builtins.exec ""; x = "'})
    )
    (bd / "bundle.json").write_text(json.dumps({"nixpkgs_rev": "b" * 40}))
    with pytest.raises(RuntimeError, match="valid nixpkgs attr"):
        preflight.unpack_pinned_source(bd, tmp_path)


def test_unpack_rejects_bad_rev(tmp_path: Path) -> None:
    bd = tmp_path / "bundle"
    bd.mkdir()
    (bd / "resolver-input.json").write_text(json.dumps({"attr_path": "zlib"}))
    (bd / "bundle.json").write_text(json.dumps({"nixpkgs_rev": "not-a-sha"}))
    with pytest.raises(RuntimeError, match="40-char git SHA"):
        preflight.unpack_pinned_source(bd, tmp_path)


# ─── end-to-end run() via --source-tree ────────────────────────────────────

def _args(**kw: object) -> argparse.Namespace:
    base = dict(source_tree=None, patches=None, strip=1, format="json")
    base.update(kw)
    return argparse.Namespace(**base)


def test_run_ok_when_patch_applies(tmp_path: Path, capsys: pytest.CaptureFixture) -> None:
    patch = _make_patch(tmp_path, _SRC_BEFORE, _SRC_AFTER)
    tree = _source_tree(tmp_path, "src-ok", _SRC_BEFORE)
    bd = tmp_path / "bundle"
    bd.mkdir()
    rc = preflight.run(
        _args(bundle_dir=bd, source_tree=tree, patches=[patch]),
        repo_root=tmp_path,
    )
    assert rc == preflight.EXIT_OK
    payload = json.loads(capsys.readouterr().out)
    assert payload["ok"] is True
    assert payload["patches"][0]["applies"] is True


def test_run_fails_when_patch_does_not_apply(
    tmp_path: Path, capsys: pytest.CaptureFixture
) -> None:
    patch = _make_patch(tmp_path, _SRC_BEFORE, _SRC_AFTER)
    tree = _source_tree(tmp_path, "src-divergent", _SRC_DIVERGENT)
    bd = tmp_path / "bundle"
    bd.mkdir()
    rc = preflight.run(
        _args(bundle_dir=bd, source_tree=tree, patches=[patch]),
        repo_root=tmp_path,
    )
    assert rc == preflight.EXIT_APPLY_FAILED
    payload = json.loads(capsys.readouterr().out)
    assert payload["ok"] is False
    assert payload["patches"][0]["applies"] is False


def test_run_not_found_on_missing_bundle(
    tmp_path: Path, capsys: pytest.CaptureFixture
) -> None:
    rc = preflight.run(
        _args(bundle_dir=tmp_path / "nope"),
        repo_root=tmp_path,
    )
    assert rc == preflight.EXIT_NOT_FOUND


def test_run_leaves_original_source_untouched(
    tmp_path: Path, capsys: pytest.CaptureFixture
) -> None:
    """run() applies on a throwaway copy; the supplied source tree is unchanged."""
    patch = _make_patch(tmp_path, _SRC_BEFORE, _SRC_AFTER)
    tree = _source_tree(tmp_path, "src-ok", _SRC_BEFORE)
    bd = tmp_path / "bundle"
    bd.mkdir()
    rc = preflight.run(
        _args(bundle_dir=bd, source_tree=tree, patches=[patch]),
        repo_root=tmp_path,
    )
    assert rc == preflight.EXIT_OK
    assert (tree / "foo.c").read_text() == _SRC_BEFORE


def test_run_applies_dependent_patches_cumulatively(
    tmp_path: Path, capsys: pytest.CaptureFixture
) -> None:
    """A series where patch 2 depends on patch 1 must pass — nix patchPhase
    semantics. Independent dry-runs against the pristine tree would false-fail
    patch 2 (the P2 finding this covers)."""
    p1 = tmp_path / "p1"
    p1.mkdir()
    patch1 = _make_patch(p1, _SRC_BEFORE, _SRC_AFTER)   # x=1 -> x=2
    p2 = tmp_path / "p2"
    p2.mkdir()
    patch2 = _make_patch(p2, _SRC_AFTER, _SRC_FINAL)    # x=2 -> x=3 (needs patch1)
    tree = _source_tree(tmp_path, "src", _SRC_BEFORE)
    bd = tmp_path / "bundle"
    bd.mkdir()

    # Sanity: patch2 alone against the pristine base fails (proves order matters).
    lone = _source_tree(tmp_path, "src-lone", _SRC_BEFORE)
    ok_lone, _ = preflight.apply_patch(lone, patch2, ["-p1"])
    assert ok_lone is False

    rc = preflight.run(
        _args(bundle_dir=bd, source_tree=tree, patches=[patch1, patch2]),
        repo_root=tmp_path,
    )
    assert rc == preflight.EXIT_OK
    payload = json.loads(capsys.readouterr().out)
    assert [r["applies"] for r in payload["patches"]] == [True, True]
