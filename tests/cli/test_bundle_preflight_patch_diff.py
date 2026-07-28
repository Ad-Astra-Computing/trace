"""Tests for `trace bundle preflight --patch-diff` (tools/trace_cli/preflight.py).

The load-bearing case reproduces the krb5 CVE-2026-40356 cert-failure shape:
nixpkgs krb5 sets `sourceRoot = "krb5-${version}/src"` — a SUBDIRECTORY of the
tarball root — but the default `preflight` flow (upstream-fix.patch dry-run
against the raw pkg.src tree) never exercises the model's actual `patch.diff`
against that subdirectory. `--patch-diff` closes that gap: it dry-runs the
MODEL's own nested source patch against the derivation's EFFECTIVE sourceRoot.
All cases run via `--source-tree` (no network / nix fetch needed) — offline,
`--source-tree` IS taken to already be the effective root, mirroring the
default preflight flow's own `--source-tree` semantics.
"""

from __future__ import annotations

import argparse
import json
import subprocess
from pathlib import Path

import pytest

from tools.trace_cli import preflight


_SRC_BEFORE = "int main(void) {\n    int x = 1;\n    return x;\n}\n"
_SRC_AFTER = "int main(void) {\n    int x = 2;\n    return x;\n}\n"


def _diff_text(tmp: Path, tag: str, label: str, before: str, after: str) -> str:
    a = tmp / f"{tag}-before.c"
    b = tmp / f"{tag}-after.c"
    a.write_text(before)
    b.write_text(after)
    proc = subprocess.run(
        ["diff", "-u", "--label", f"a/{label}", "--label", f"b/{label}", str(a), str(b)],
        capture_output=True, text=True,
    )
    assert proc.returncode == 1, proc.stderr
    return proc.stdout


def _wrap_as_added_patch_file(inner_diff_text: str, patch_filename: str = "CVE-9999.patch") -> str:
    """Wrap an inner unified diff as the git "new file" addition shape the
    Patcher emits for a nested `CVE-*.patch` (see nested_patch.py docstring)."""
    lines = inner_diff_text.splitlines()
    n = len(lines)
    body = "\n".join("+" + line for line in lines)
    return (
        f"diff --git a/{patch_filename} b/{patch_filename}\n"
        f"new file mode 100644\n"
        f"--- /dev/null\n"
        f"+++ b/{patch_filename}\n"
        f"@@ -0,0 +1,{n} @@\n"
        f"{body}\n"
    )


def _effective_root(tmp: Path, rel_file: str, content: str) -> Path:
    root = tmp / "effective-root"
    target = root / rel_file
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(content)
    return root


def _args(**kw: object) -> argparse.Namespace:
    base: dict[str, object] = dict(
        source_tree=None, patches=None, strip=None, format="json", patch_diff=True,
    )
    base.update(kw)
    return argparse.Namespace(**base)


# ─── the krb5 shape ─────────────────────────────────────────────────────────

def test_patch_diff_fails_closed_on_subdir_sourceroot_mismatch(
    tmp_path: Path, capsys: pytest.CaptureFixture
) -> None:
    """krb5 shape: effective root only has `lib/gssapi/spnego/negoex_util.c`
    (sourceRoot already descended past `src/`), but the model's nested patch
    carries tarball-root paths (`src/lib/gssapi/spnego/negoex_util.c`) — one
    component too many. Must fail closed, not silently "succeed" against the
    wrong directory."""
    root = _effective_root(
        tmp_path, "lib/gssapi/spnego/negoex_util.c", _SRC_BEFORE)
    inner = _diff_text(
        tmp_path, "wrong", "src/lib/gssapi/spnego/negoex_util.c", _SRC_BEFORE, _SRC_AFTER)
    bd = tmp_path / "bundle"
    bd.mkdir()
    (bd / "patch.diff").write_text(_wrap_as_added_patch_file(inner))

    rc = preflight.run(_args(bundle_dir=bd, source_tree=root), repo_root=tmp_path)

    assert rc == preflight.EXIT_APPLY_FAILED
    payload = json.loads(capsys.readouterr().out)
    assert payload["ok"] is False
    assert payload["applies"] is False
    assert payload["nested_patch_files"] == ["CVE-9999.patch"]
    sidecar = json.loads((bd / "patch-diff-preflight.json").read_text())
    assert sidecar["ok"] is False


def test_patch_diff_passes_with_sourceroot_relative_paths(
    tmp_path: Path, capsys: pytest.CaptureFixture
) -> None:
    """Same effective root, but the nested patch uses the CORRECT
    sourceRoot-relative paths (no `src/` prefix) — must pass."""
    root = _effective_root(
        tmp_path, "lib/gssapi/spnego/negoex_util.c", _SRC_BEFORE)
    inner = _diff_text(
        tmp_path, "right", "lib/gssapi/spnego/negoex_util.c", _SRC_BEFORE, _SRC_AFTER)
    bd = tmp_path / "bundle"
    bd.mkdir()
    (bd / "patch.diff").write_text(_wrap_as_added_patch_file(inner))

    rc = preflight.run(_args(bundle_dir=bd, source_tree=root), repo_root=tmp_path)

    assert rc == preflight.EXIT_OK
    payload = json.loads(capsys.readouterr().out)
    assert payload["ok"] is True
    assert payload["applies"] is True


# ─── error paths ────────────────────────────────────────────────────────────

def test_patch_diff_missing_file_not_found(
    tmp_path: Path, capsys: pytest.CaptureFixture
) -> None:
    bd = tmp_path / "bundle"
    bd.mkdir()
    rc = preflight.run(
        _args(bundle_dir=bd, source_tree=tmp_path / "root"), repo_root=tmp_path)
    assert rc == preflight.EXIT_NOT_FOUND


def test_patch_diff_source_tree_missing_dir(
    tmp_path: Path, capsys: pytest.CaptureFixture
) -> None:
    bd = tmp_path / "bundle"
    bd.mkdir()
    inner = _diff_text(tmp_path, "x", "foo.c", _SRC_BEFORE, _SRC_AFTER)
    (bd / "patch.diff").write_text(_wrap_as_added_patch_file(inner))
    rc = preflight.run(
        _args(bundle_dir=bd, source_tree=tmp_path / "does-not-exist"),
        repo_root=tmp_path,
    )
    assert rc == preflight.EXIT_NOT_FOUND


def test_patch_diff_malformed_extract_failed(
    tmp_path: Path, capsys: pytest.CaptureFixture
) -> None:
    bd = tmp_path / "bundle"
    bd.mkdir()
    (bd / "patch.diff").write_text(
        "diff --git a/package.nix b/package.nix\n"
        "--- a/package.nix\n+++ b/package.nix\n@@ -1,1 +1,1 @@\n-a\n+b\n"
    )
    rc = preflight.run(
        _args(bundle_dir=bd, source_tree=tmp_path / "root"), repo_root=tmp_path)
    assert rc == preflight.EXIT_EXTRACT_FAILED


def test_default_flow_unaffected_when_patch_diff_flag_absent(
    tmp_path: Path, capsys: pytest.CaptureFixture
) -> None:
    """Regression guard: existing (non---patch-diff) preflight callers that
    construct an argparse.Namespace without a `patch_diff` attribute at all
    (pre-existing tests) must still take the default upstream-fix.patch path."""
    bd = tmp_path / "bundle"
    bd.mkdir()
    (bd / "upstream-fix.patch").write_text(
        _diff_text(tmp_path, "u", "foo.c", _SRC_BEFORE, _SRC_AFTER))
    root = _effective_root(tmp_path, "foo.c", _SRC_BEFORE)
    ns = argparse.Namespace(
        bundle_dir=bd, source_tree=root, patches=None, strip=1, format="json"
    )  # no patch_diff attribute at all
    rc = preflight.run(ns, repo_root=tmp_path)
    assert rc == preflight.EXIT_OK


def test_source_tree_honors_patch_flags_override(tmp_path: Path) -> None:
    """On the --source-tree path (no nix eval) the gate must dry-run with the
    supplied patchFlags, not a hard-coded -p1: a git-style patch that needs
    -p1 to place `a/foo.c` fails under an explicit -p0 override, proving the
    flags are threaded (guards finalize --gate-source-tree fidelity)."""
    root = _effective_root(tmp_path, "foo.c", _SRC_BEFORE)
    inner = _diff_text(tmp_path, "flags", "foo.c", _SRC_BEFORE, _SRC_AFTER)
    bd = tmp_path / "bundle"
    bd.mkdir()
    (bd / "patch.diff").write_text(_wrap_as_added_patch_file(inner))

    ok_default = preflight.check_patch_diff_effective_root(bd, source_tree=root)
    ok_p0 = preflight.check_patch_diff_effective_root(
        bd, source_tree=root, patch_flags=["-p0"])

    assert ok_default["applies"] is True           # a/foo.c strips to foo.c at -p1
    assert ok_default["patch_flags"] == ["-p1"]
    assert ok_p0["applies"] is False               # -p0 keeps a/foo.c, not in tree
    assert ok_p0["patch_flags"] == ["-p0"]
