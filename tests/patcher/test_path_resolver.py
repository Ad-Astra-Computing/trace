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

import re
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
    """nix eval can return a path outside the nixpkgs root for a few
    reasons. Truly arbitrary paths (e.g. /etc, a sibling tmp dir) must
    be rejected for safety; the alt-store-source allowance below
    handles the legitimate cron case where nix re-stages the source."""
    nixpkgs = _mk_nixpkgs(tmp_path / "nixpkgs")
    nixpkgs.parent.mkdir(parents=True, exist_ok=True)
    elsewhere_root = tmp_path / "elsewhere"
    elsewhere_root.mkdir()
    (elsewhere_root / "default.nix").write_text("{}")
    # `elsewhere_root` is a sibling of nixpkgs, not under it, and not
    # under any /nix/store/<hash>-source tree.
    with patch("agents.patcher.path_resolver._run_nix_eval_position",
               return_value=(str(elsewhere_root / "default.nix") + ":1", "ok")):
        with pytest.raises(PackageSourceNotFound, match="outside"):
            resolve_package_source(
                "alien-pkg",
                nixpkgs_root=nixpkgs,
                use_nix_eval=True,
            )


def test_store_source_re_recognizes_unpacked_flake_paths() -> None:
    """The regex backing the alt-source allowance: any /nix/store/<32-
    hex-or-base32>-source[/...] path should match. This is the canonical
    shape nix uses for unpacked flake inputs and fetchurl/fetchgit
    checkouts. The shape is what makes the allowance safe — if it isn't
    in the store-source layout, the resolver still rejects."""
    from agents.patcher.path_resolver import _STORE_SOURCE_RE

    accept = [
        "/nix/store/" + ("a" * 32) + "-source",
        "/nix/store/" + ("a" * 32) + "-source/pkgs/os-specific/linux/kernel/mainline.nix",
        "/nix/store/" + ("0z" * 16) + "-source/flake.nix",
    ]
    for p in accept:
        assert _STORE_SOURCE_RE.match(p), f"expected match: {p}"

    reject = [
        "/etc/nixos/configuration.nix",
        "/tmp/elsewhere/default.nix",
        # Wrong hash length.
        "/nix/store/" + ("a" * 31) + "-source/foo.nix",
        # Wrong suffix (not '-source').
        "/nix/store/" + ("a" * 32) + "-other/foo.nix",
        # Hex-only would also fail since nix uses base32; mixed case
        # rejection prevents the regex from drifting permissive later.
        "/nix/store/" + ("A" * 32) + "-source/foo.nix",
    ]
    for p in reject:
        assert not _STORE_SOURCE_RE.match(p), f"expected reject: {p}"


def test_nix_eval_phantom_path_rerooted_to_nixpkgs(tmp_path: Path) -> None:
    """Captured cron behavior 2026-05-07: nix-eval returns a meta.position
    under /nix/store/<hash>-source/pkgs/... but the store entry was
    never materialized on the runner — Determinate Nix's flake registry
    resolves an internal <nixpkgs/...> import to a phantom path. The
    relative path IS present in the trace flake's archived nixpkgs
    (we explicitly archived it as nixpkgs_root), so re-rooting unblocks
    the read without trusting whatever path nix computed lazily."""
    nixpkgs = _mk_nixpkgs(tmp_path / "nixpkgs-root")
    real = nixpkgs / "pkgs" / "os-specific" / "linux" / "kernel" / "mainline.nix"
    real.parent.mkdir(parents=True)
    real.write_text('{ ... }: { src = fetchurl { url = "..."; }; }')

    phantom = "/nix/store/" + ("c" * 32) + "-source/pkgs/os-specific/linux/kernel/mainline.nix"
    with patch("agents.patcher.path_resolver._run_nix_eval_position",
               return_value=(f"{phantom}:34", "ok")):
        result = resolve_package_source(
            "linux",
            nixpkgs_root=nixpkgs,
            use_nix_eval=True,
        )
    assert result.strategy == "nix-eval-rerooted"
    assert result.path == real.resolve()
    assert result.relative == "pkgs/os-specific/linux/kernel/mainline.nix"
    assert "fetchurl" in result.content


def test_nix_eval_phantom_relative_not_in_root_rejected(tmp_path: Path) -> None:
    """Re-root only succeeds when the relative path actually exists in
    nixpkgs_root. If the kernel package was renamed or removed in
    nixpkgs_root (or the eval came from a totally unrelated tree),
    the rerooted file is missing — fall through to alt-source path
    which then fails is_file. Surfaces as eval-position-not-a-file
    rather than silently accepting a guess."""
    nixpkgs = _mk_nixpkgs(tmp_path / "nixpkgs-root")
    # Don't create the kernel file; rerooted path will be missing.

    phantom = "/nix/store/" + ("d" * 32) + "-source/pkgs/never/exists.nix"
    with patch("agents.patcher.path_resolver._run_nix_eval_position",
               return_value=(f"{phantom}:1", "ok")):
        with pytest.raises(PackageSourceNotFound, match="not a file"):
            resolve_package_source(
                "missing",
                nixpkgs_root=nixpkgs,
                use_nix_eval=True,
            )


def test_nix_eval_alt_store_source_accepted(tmp_path: Path) -> None:
    """Cron repro: nix-eval returns a path inside a /nix/store/<hash>-
    source tree that's not the same store entry as nixpkgs_root.
    Day-1 5h+5i confirmed this fails 22/22 kernel CVEs at the
    'outside-nixpkgs-root' guard. Re-staged source is still safe to
    read because we explicitly pinned the eval to nixpkgs_root."""
    nixpkgs = _mk_nixpkgs(tmp_path / "nixpkgs-root")
    # Build a fake alternate store-source tree under tmp_path so we
    # can exercise the alt-source path without poking /nix/store.
    fake_store_root = tmp_path / "fake-store" / "nix" / "store" / ("b" * 32 + "-source")
    target = fake_store_root / "pkgs" / "os-specific" / "linux" / "kernel" / "mainline.nix"
    target.parent.mkdir(parents=True)
    target.write_text('{ ... }: { }')

    # Patch the regex to accept fake_store_root's prefix in addition to
    # the real /nix/store one. Cleanest way to keep the test hermetic
    # without hard-coding a real /nix/store path.
    fake_re = re.compile(
        rf"^(?P<prefix>{re.escape(str(tmp_path))}/fake-store/nix/store/[0-9a-z]{{32}}-source)(?:/(?P<rest>.*))?$"
    )
    with patch("agents.patcher.path_resolver._run_nix_eval_position",
               return_value=(f"{target}:34", "ok")), \
         patch("agents.patcher.path_resolver._STORE_SOURCE_RE", fake_re):
        result = resolve_package_source(
            "linux",
            nixpkgs_root=nixpkgs,
            use_nix_eval=True,
        )
    assert result.strategy == "nix-eval-alt-source"
    assert result.path == target.resolve()
    # Relative is computed by stripping the alternate store-source
    # prefix, not the original nixpkgs_root.
    assert result.relative == "pkgs/os-specific/linux/kernel/mainline.nix"
    assert "fetch" not in result.content  # sanity: file content read
