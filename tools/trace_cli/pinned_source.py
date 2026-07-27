"""Shared primitive: unpack the nixpkgs-pinned upstream source of a bundle.

Extracted from ``preflight.py`` (2026-07-27, semantic-backport-adaptation arc
slice 1) so both the source-apply preflight and — in a later slice — the
Patcher's source-input assembly resolve "the pinned base" through one code path.

The unpack builds only the fixed-output ``pkg.src`` derivation (the source fetch),
never ``srcOnly pkg`` — the latter pulls the whole stdenv toolchain in just to run
unpackPhase. Feed-sourced ``attr_path`` / ``nixpkgs_rev`` are validated before any
nix-expression interpolation (shell/expr-injection threat model).
"""

from __future__ import annotations

import json
import re
import shutil
import subprocess
from pathlib import Path


# Feed-sourced strings interpolated into a nix expression. Validate hard before
# use (shell/expr-injection threat model): attr paths are dotted nixpkgs
# identifiers; a nixpkgs rev is a 40-char git SHA.
_ATTR_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_.-]*$")
_REV_RE = re.compile(r"^[0-9a-f]{40}$")


def read_bundle_field(bundle_dir: Path, *candidates: tuple[str, str]) -> str | None:
    """Return the first present ``field`` value across ``(filename, field)`` pairs."""
    for fname, field in candidates:
        fp = bundle_dir / fname
        if not fp.is_file():
            continue
        try:
            data = json.loads(fp.read_text())
        except json.JSONDecodeError:
            continue
        val = data.get(field)
        if isinstance(val, str) and val:
            return val
    return None


def unpack_source_store_path(store_path: Path, dest: Path) -> Path:
    """Return an unpacked source tree from a `pkg.src` store path.

    `pkg.src` is a directory (fetchFromGitHub / fetchzip already unpack) or a
    single archive file (fetchurl tarball). For the archive case, extract into
    ``dest`` and descend into the single top-level directory if the archive has
    the usual ``<name>-<version>/`` root.
    """
    if store_path.is_dir():
        return store_path
    dest.mkdir(parents=True, exist_ok=True)
    # GNU tar autodetects gz/xz/bz2/zst; fall back to unzip for .zip.
    tar_bin = shutil.which("tar")
    unzip_bin = shutil.which("unzip")
    extracted = False
    if tar_bin is not None:
        proc = subprocess.run(
            [tar_bin, "-xf", str(store_path), "-C", str(dest)],
            capture_output=True, text=True,
        )
        extracted = proc.returncode == 0
    if not extracted and unzip_bin is not None:
        proc = subprocess.run(
            [unzip_bin, "-q", str(store_path), "-d", str(dest)],
            capture_output=True, text=True,
        )
        extracted = proc.returncode == 0
    if not extracted:
        raise RuntimeError(
            f"could not extract source archive {store_path.name} "
            f"(need tar or unzip on PATH)"
        )
    entries = list(dest.iterdir())
    if len(entries) == 1 and entries[0].is_dir():
        return entries[0]
    return dest


def eval_patch_flags(nix_expr_prefix: str, attr_path_list: str) -> list[str]:
    """`nix-instantiate --eval` the pinned pkg's ``patchFlags`` (default ["-p1"]).

    Best-effort: returns ["-p1"] if nix-instantiate is unavailable or the eval
    fails, so a patchFlags-resolution hiccup never blocks the source-apply check.
    """
    nix_eval = shutil.which("nix-instantiate")
    if nix_eval is None:
        return ["-p1"]
    expr = (
        f"{nix_expr_prefix} "
        f"pkg = pkgs.lib.attrByPath {attr_path_list} "
        '(throw "attr not found") pkgs; '
        'in pkg.patchFlags or [ "-p1" ]'
    )
    proc = subprocess.run(
        [nix_eval, "--eval", "--strict", "--json", "--expr", expr],
        capture_output=True, text=True,
    )
    if proc.returncode != 0:
        return ["-p1"]
    try:
        flags = json.loads(proc.stdout.strip())
    except json.JSONDecodeError:
        return ["-p1"]
    return [str(f) for f in flags] if isinstance(flags, list) else ["-p1"]


def unpack_pinned_source(
    bundle_dir: Path, tmp_root: Path, nixpkgs_override: str | None = None
) -> tuple[Path, list[str]]:
    """Unpack the pinned source via nix `pkg.src`, returning (tree, patch_flags).

    Reads ``attr_path`` (resolver-input.json / bundle.json) and ``nixpkgs_rev``
    (bundle.json / impact.json). Builds only the fixed-output ``src`` derivation
    (no stdenv) and unpacks it. ``patch_flags`` is the package's configured
    ``patchFlags`` (nixpkgs default ``["-p1"]``) so a downstream dry-run mirrors
    patchPhase fidelity — strip level and any other flags. Raises RuntimeError with
    an actionable message on any failure; the caller surfaces it and points the
    user at a pre-unpacked source.
    """
    attr = read_bundle_field(
        bundle_dir,
        ("resolver-input.json", "attr_path"),
        ("bundle.json", "attr_path"),
    )
    rev = read_bundle_field(
        bundle_dir,
        ("bundle.json", "nixpkgs_rev"),
        ("impact.json", "nixpkgs_rev"),
    )
    if not attr:
        raise RuntimeError(
            "attr_path not found in resolver-input.json/bundle.json; "
            "cannot resolve the nixpkgs attr to unpack. Use --source-tree."
        )
    if not attr or not _ATTR_RE.match(attr):
        raise RuntimeError(f"attr_path {attr!r} is not a valid nixpkgs attr path")
    if not rev or not _REV_RE.match(rev):
        raise RuntimeError(
            f"nixpkgs_rev {rev!r} is not a 40-char git SHA; cannot pin the source. "
            f"Use --source-tree."
        )
    nix_bin = shutil.which("nix-build")
    if nix_bin is None:
        raise RuntimeError(
            "nix-build not found on PATH; run inside `nix develop` or pass "
            "--source-tree with a pre-unpacked source."
        )

    # attr/rev are validated above; interpolation is injection-safe.
    if nixpkgs_override:
        nixpkgs_expr = f'(import {json.dumps(nixpkgs_override)})'
    else:
        nixpkgs_expr = (
            'import (builtins.fetchTarball '
            f'"https://github.com/NixOS/nixpkgs/archive/{rev}.tar.gz")'
        )
    attr_path_list = "[" + " ".join(json.dumps(seg) for seg in attr.split(".")) + "]"
    nix_expr_prefix = f"let pkgs = {nixpkgs_expr} {{}};"
    expr = (
        f"{nix_expr_prefix} "
        f"pkg = pkgs.lib.attrByPath {attr_path_list} "
        f'(throw "attr {attr} not found in pinned nixpkgs") pkgs; '
        "in pkg.src"
    )
    out_link = tmp_root / "src-result"
    proc = subprocess.run(
        [nix_bin, "--no-build-output", "-E", expr, "-o", str(out_link)],
        capture_output=True,
        text=True,
    )
    if proc.returncode != 0:
        raise RuntimeError(
            f"nix-build of {attr}.src @ {rev[:12]} failed:\n{proc.stderr.strip()}"
        )
    store_path = Path(out_link.resolve())
    tree = unpack_source_store_path(store_path, tmp_root / "unpacked")
    patch_flags = eval_patch_flags(nix_expr_prefix, attr_path_list)
    return tree, patch_flags
