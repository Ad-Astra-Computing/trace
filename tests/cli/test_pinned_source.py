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
