"""Patcher's package-source path resolver.

Given an attr_path and a nixpkgs checkout, returns the file path of
the package definition. Two strategies, in order:

  1. pkgs/by-name/<2-letter>/<attr>/package.nix  (modern convention,
     covers ~95% of post-2024 nixpkgs)
  2. `nix eval --raw nixpkgs#<attr>.meta.position` fallback for the
     long tail (development/, applications/, etc.).

Tests pin the by-name path; the nix-eval fallback has its own
real-nix smoke gated on TRACE_REAL_NIX_PATH=1.
"""

from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

import pytest

from agents.patcher.path_resolver import (
    PackageSourceNotFound,
    resolve_package_source,
)


def _mk_nixpkgs(root: Path) -> Path:
    """Build a tiny fake nixpkgs checkout with by-name layout."""
    (root / "pkgs" / "by-name" / "ra" / "radare2").mkdir(parents=True)
    (root / "pkgs" / "by-name" / "ra" / "radare2" / "package.nix").write_text(
        '{ ... }: { version = "6.1.2"; }'
    )
    (root / "pkgs" / "by-name" / "cy" / "cyberchef").mkdir(parents=True)
    (root / "pkgs" / "by-name" / "cy" / "cyberchef" / "package.nix").write_text(
        '{ ... }: { version = "10.23.0"; }'
    )
    return root


def test_by_name_resolves_modern_attr(tmp_path: Path) -> None:
    nixpkgs = _mk_nixpkgs(tmp_path)
    result = resolve_package_source("radare2", nixpkgs_root=nixpkgs)
    assert result.path.name == "package.nix"
    assert result.path.parent.name == "radare2"
    assert result.relative == "pkgs/by-name/ra/radare2/package.nix"
    assert result.strategy == "by-name"
    assert "version = \"6.1.2\"" in result.content


def test_by_name_two_letter_directory_correct(tmp_path: Path) -> None:
    """The by-name shard is the first two characters of the attr_path,
    lowercased. Single-character names use a single letter directory
    (the convention is to pad with the same letter, but trace v0 only
    handles 2+ chars; one-char attrs fall through to error)."""
    nixpkgs = _mk_nixpkgs(tmp_path)
    result = resolve_package_source("cyberchef", nixpkgs_root=nixpkgs)
    assert "by-name/cy/cyberchef" in str(result.path)


def test_attr_not_in_by_name_falls_through(tmp_path: Path) -> None:
    """When the by-name path doesn't exist, the resolver raises
    PackageSourceNotFound (the nix-eval fallback is opt-in via
    use_nix_eval=True). v0 keeps the default offline-only."""
    nixpkgs = _mk_nixpkgs(tmp_path)
    with pytest.raises(PackageSourceNotFound):
        resolve_package_source("missing-attr", nixpkgs_root=nixpkgs)


def test_invalid_nixpkgs_root_raises(tmp_path: Path) -> None:
    with pytest.raises(PackageSourceNotFound, match="nixpkgs root"):
        resolve_package_source("radare2", nixpkgs_root=tmp_path / "absent")


def test_namespaced_attr_without_nix_eval_raises(tmp_path: Path) -> None:
    """A dotted attr like haskellPackages.total never lives in by-name.
    Without use_nix_eval=True the resolver raises with a clear reason."""
    nixpkgs = _mk_nixpkgs(tmp_path)
    with pytest.raises(PackageSourceNotFound, match="namespaced"):
        resolve_package_source(
            "python3Packages.requests", nixpkgs_root=nixpkgs
        )


def test_namespaced_attr_with_nix_eval_resolves(tmp_path: Path) -> None:
    """When use_nix_eval=True a namespaced attr goes straight to
    nix-eval (no by-name attempt). This is the cron path for
    haskellPackages.total / linuxKernel.kernels.* / etc."""
    nixpkgs = _mk_nixpkgs(tmp_path)
    target = nixpkgs / "pkgs" / "development" / "haskell-modules" / "configuration-common.nix"
    target.parent.mkdir(parents=True)
    target.write_text('{ ... }: { }')
    with patch("agents.patcher.path_resolver._run_nix_eval_position",
               return_value=(f"{target}:1", "ok")):
        result = resolve_package_source(
            "haskellPackages.total",
            nixpkgs_root=nixpkgs,
            use_nix_eval=True,
        )
    assert result.strategy == "nix-eval"
    assert result.path == target


def test_nix_eval_fallback_invoked_when_use_nix_eval_true(tmp_path: Path) -> None:
    """When use_nix_eval=True and by-name misses, the resolver shells
    out to `nix eval --raw nixpkgs#<attr>.meta.position`. Mocked here
    to avoid a real nix invocation."""
    nixpkgs = _mk_nixpkgs(tmp_path)
    target = nixpkgs / "pkgs" / "development" / "tools" / "radamsa" / "default.nix"
    target.parent.mkdir(parents=True)
    target.write_text('{ ... }: { version = "0.6"; }')

    with patch("agents.patcher.path_resolver._run_nix_eval_position",
               return_value=(f"{target}:1", "ok")):
        result = resolve_package_source(
            "radamsa",
            nixpkgs_root=nixpkgs,
            use_nix_eval=True,
        )
    assert result.strategy == "nix-eval"
    assert result.path == target
    assert result.relative == "pkgs/development/tools/radamsa/default.nix"


def test_nix_eval_fallback_failure_surfaces_diagnostic(tmp_path: Path) -> None:
    nixpkgs = _mk_nixpkgs(tmp_path)
    with patch("agents.patcher.path_resolver._run_nix_eval_position",
               return_value=(None, "nix-eval-exit-1:attr 'long-tail-pkg' missing")):
        with pytest.raises(PackageSourceNotFound, match="nix-eval-exit-1"):
            resolve_package_source(
                "long-tail-pkg",
                nixpkgs_root=nixpkgs,
                use_nix_eval=True,
            )


def test_nix_eval_position_outside_nixpkgs_root_rejected(tmp_path: Path) -> None:
    """nix eval might return a path outside the nixpkgs root if a flake
    overlay is in play. Reject for safety: the resolver's contract is
    to surface paths inside the supplied root."""
    nixpkgs = _mk_nixpkgs(tmp_path / "nixpkgs")
    nixpkgs.parent.mkdir(parents=True, exist_ok=True)
    elsewhere_root = tmp_path / "elsewhere"
    elsewhere_root.mkdir()
    (elsewhere_root / "default.nix").write_text("{}")
    # `elsewhere_root` is a sibling of nixpkgs, not under it.
    with patch("agents.patcher.path_resolver._run_nix_eval_position",
               return_value=(str(elsewhere_root / "default.nix") + ":1", "ok")):
        with pytest.raises(PackageSourceNotFound, match="outside"):
            resolve_package_source(
                "alien-pkg",
                nixpkgs_root=nixpkgs,
                use_nix_eval=True,
            )
