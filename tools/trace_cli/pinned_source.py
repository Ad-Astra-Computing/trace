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
from typing import NamedTuple


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


class PatchFlagsEvalError(RuntimeError):
    """``pkg.patchFlags`` could not be *evaluated* (distinct from a genuine
    default). Raised in ``strict`` mode so a fail-closed gate never dry-runs
    with a wrong strip that silently diverges from real ``patchPhase``."""


def eval_patch_flags(
    nix_expr_prefix: str, attr_path_list: str, strict: bool = False
) -> list[str]:
    """`nix-instantiate --eval` the pinned pkg's ``patchFlags`` (default ["-p1"]).

    ``strict=False`` (default) is best-effort: returns ["-p1"] if
    nix-instantiate is unavailable or the eval fails, so a patchFlags hiccup
    never blocks the plain source-apply check. ``strict=True`` (the fail-closed
    effective-root gate) instead raises :class:`PatchFlagsEvalError` when the
    value cannot be *determined* — evaluating with a wrong strip would let the
    gate approve/reject a bundle differently from real ``patchPhase``. A
    genuine unset ``patchFlags`` still resolves to ["-p1"] via the nix `or`
    default in BOTH modes (that is a successful eval, not a failure).
    """
    nix_eval = shutil.which("nix-instantiate")
    if nix_eval is None:
        if strict:
            raise PatchFlagsEvalError(
                "nix-instantiate not on PATH; cannot evaluate pkg.patchFlags. "
                "Run inside `nix develop` or pass a pre-unpacked --source-tree."
            )
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
        if strict:
            raise PatchFlagsEvalError(
                f"nix-instantiate eval of pkg.patchFlags failed "
                f"(exit {proc.returncode}):\n{proc.stderr.strip()}"
            )
        return ["-p1"]
    try:
        flags = json.loads(proc.stdout.strip())
    except json.JSONDecodeError as exc:
        if strict:
            raise PatchFlagsEvalError(
                f"nix-instantiate eval of pkg.patchFlags returned malformed "
                f"output: {proc.stdout.strip()!r}"
            ) from exc
        return ["-p1"]
    if isinstance(flags, list):
        return [str(f) for f in flags]
    if strict:
        raise PatchFlagsEvalError(
            f"pkg.patchFlags evaluated to a non-list: {flags!r}"
        )
    return ["-p1"]


class SourceRootEvalError(RuntimeError):
    """``pkg.sourceRoot`` could not be *evaluated* (distinct from a genuine
    unset/``null`` sourceRoot, which is a valid answer). Raised so the
    fail-closed gate never mistakes an eval hiccup for "no override" and
    silently validates a patch against the tarball root — the exact fail-open
    the gate exists to prevent."""


def eval_source_root(nix_expr_prefix: str, attr_path_list: str) -> str | None:
    """`nix-instantiate --eval` the pinned pkg's ``sourceRoot``.

    ``sourceRoot`` is unset for most packages — stdenv's default is to cd into
    the single top-level directory an archive unpacks to, which is exactly
    what :func:`unpack_source_store_path` already returns. Some packages
    override it explicitly to cd one level *deeper* (krb5:
    ``sourceRoot = "krb5-${version}/src"``, since the release tarball's own
    ``patches=[]`` phase runs from inside ``src/``, not the tarball root).
    That extra descent is invisible to a check that always dry-runs against
    the tarball-root tree — this eval is what makes it visible.

    Returns the evaluated ``sourceRoot`` string, or ``None`` when the package
    genuinely leaves it unset (nixpkgs default). Raises
    :class:`SourceRootEvalError` when the value cannot be *determined* at all —
    ``nix-instantiate`` missing, a non-zero eval, or malformed output. A
    fail-closed gate MUST NOT treat "couldn't evaluate" as "unset": a
    ``src/``-prefixed patch would then pass a check run against the tarball
    root while still failing in real ``patchPhase`` (the krb5 failure mode).
    """
    nix_eval = shutil.which("nix-instantiate")
    if nix_eval is None:
        raise SourceRootEvalError(
            "nix-instantiate not on PATH; cannot evaluate pkg.sourceRoot. "
            "Run inside `nix develop` or pass a pre-unpacked --source-tree."
        )
    expr = (
        f"{nix_expr_prefix} "
        f"pkg = pkgs.lib.attrByPath {attr_path_list} "
        '(throw "attr not found") pkgs; '
        'in if (pkg.sourceRoot or null) == null then null else toString pkg.sourceRoot'
    )
    proc = subprocess.run(
        [nix_eval, "--eval", "--strict", "--json", "--expr", expr],
        capture_output=True, text=True,
    )
    if proc.returncode != 0:
        raise SourceRootEvalError(
            f"nix-instantiate eval of pkg.sourceRoot failed "
            f"(exit {proc.returncode}):\n{proc.stderr.strip()}"
        )
    try:
        val = json.loads(proc.stdout.strip())
    except json.JSONDecodeError as exc:
        raise SourceRootEvalError(
            f"nix-instantiate eval of pkg.sourceRoot returned malformed output: "
            f"{proc.stdout.strip()!r}"
        ) from exc
    if val is None:
        return None
    if isinstance(val, str) and val:
        return val
    raise SourceRootEvalError(
        f"pkg.sourceRoot evaluated to an unexpected value: {val!r}"
    )


class PatchesEvalError(RuntimeError):
    """The pinned pkg's ``patches`` list could not be evaluated. Raised so the
    fail-closed gate never assumes a pristine-src dry-run mirrors patchPhase
    when it cannot even determine whether preceding patches exist."""


def eval_preceding_patches_count(nix_expr_prefix: str, attr_path_list: str) -> int:
    """`nix-instantiate --eval` the LENGTH of the pinned pkg's resolved
    ``patches`` list, for the build platform (so a platform-gated
    ``lib.optionals stdenv.hostPlatform.isFreeBSD [...]`` resolves to 0 on
    Linux). ``patchPhase`` applies these BEFORE the model-added patch, so a
    non-zero count means a pristine-``pkg.src`` dry-run may not mirror the real
    apply. Raises :class:`PatchesEvalError` on any eval failure — the gate
    fails closed rather than assume zero."""
    nix_eval = shutil.which("nix-instantiate")
    if nix_eval is None:
        raise PatchesEvalError(
            "nix-instantiate not on PATH; cannot evaluate pkg.patches. "
            "Run inside `nix develop` or pass a pre-unpacked --source-tree."
        )
    expr = (
        f"{nix_expr_prefix} "
        f"pkg = pkgs.lib.attrByPath {attr_path_list} "
        '(throw "attr not found") pkgs; '
        'in builtins.length (pkg.patches or [])'
    )
    proc = subprocess.run(
        [nix_eval, "--eval", "--strict", "--json", "--expr", expr],
        capture_output=True, text=True,
    )
    if proc.returncode != 0:
        raise PatchesEvalError(
            f"nix-instantiate eval of pkg.patches length failed "
            f"(exit {proc.returncode}):\n{proc.stderr.strip()}"
        )
    try:
        n = json.loads(proc.stdout.strip())
    except json.JSONDecodeError as exc:
        raise PatchesEvalError(
            f"nix-instantiate eval of pkg.patches length returned malformed "
            f"output: {proc.stdout.strip()!r}"
        ) from exc
    if not isinstance(n, int) or n < 0:
        raise PatchesEvalError(f"pkg.patches length evaluated to {n!r}")
    return n


def resolve_effective_source_root(tree: Path, source_root: str | None) -> Path:
    """Return the directory nixpkgs' ``patchPhase`` actually cds into.

    ``tree`` is :func:`unpack_pinned_source`'s default result — the tarball's
    own top-level directory, which is correct whenever a package does not
    override ``sourceRoot`` (the common case). When ``source_root`` names an
    explicit override, it conventionally *repeats* the tarball's own
    top-level directory name (krb5: tarball root is ``krb5-1.22.1/``,
    ``sourceRoot`` is ``"krb5-1.22.1/src"``) — so it is resolved relative to
    ``tree``'s PARENT (the build-top stdenv names ``sourceRoot`` from), tried
    first. As a fallback, for a ``sourceRoot`` authored relative to ``tree``
    itself (e.g. just ``"src"``), ``tree / source_root`` is tried too.

    An explicit ``sourceRoot = "."`` names the extraction/build root itself,
    but which local path that is depends on whether
    :func:`unpack_source_store_path` descended: for a single-top-level archive
    it already cd'd into that directory (so the build root is ``tree.parent``),
    while for a multi-top-level archive it returned the extraction dir (so the
    build root is ``tree``). This function receives only ``tree`` and cannot
    tell the two apart, so rather than guess wrong either way it FAILS CLOSED
    on ``"."`` — no current corpus bundle uses it; a real one would thread the
    true build root through here first.

    KNOWN LIMITATION: for a package whose ``pkg.src`` is already a *directory*
    (fetchFromGitHub/fetchgit — no archive to descend), stdenv names a
    build-root-relative ``sourceRoot`` (e.g. ``"source/subdir"``) from a build
    top this function doesn't see, so neither candidate below matches and it
    FAILS CLOSED (never mis-resolves). Pass ``--source-tree`` with the exact
    ``patchPhase`` directory to gate such a bundle. No current corpus bundle
    hits this; a real one would thread the unpack descent state through here.

    Raises ValueError, naming every path attempted, if neither resolves to a
    real directory — fail closed rather than guess at a third interpretation.
    """
    if not source_root:
        return tree
    normalized = source_root.rstrip("/")
    if normalized in ("", "."):
        raise ValueError(
            f"package declares sourceRoot={source_root!r} (build-root-relative); "
            f"the effective root cannot be determined from the descended tree "
            f"alone. Pass a pre-unpacked --source-tree (the exact dir patchPhase "
            f"cds into) to gate this bundle."
        )
    candidates = [tree.parent / normalized, tree / normalized]
    for cand in candidates:
        if cand.is_dir():
            return cand
    raise ValueError(
        f"package declares sourceRoot={source_root!r} but neither candidate "
        f"resolves to a directory: {[str(c) for c in candidates]} (tree={tree}). "
        f"If pkg.src is a directory source (not an archive), pass the exact "
        f"patchPhase dir via --source-tree."
    )


def _resolve_attr_rev(bundle_dir: Path) -> tuple[str, str]:
    """Read + validate ``attr_path``/``nixpkgs_rev`` from the bundle's resolver
    docs. Raises RuntimeError (actionable, points at ``--source-tree``) on any
    missing/invalid field — shared validation gate before nix-expression
    interpolation (shell/expr-injection threat model)."""
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
    if not _ATTR_RE.match(attr):
        raise RuntimeError(f"attr_path {attr!r} is not a valid nixpkgs attr path")
    if not rev or not _REV_RE.match(rev):
        raise RuntimeError(
            f"nixpkgs_rev {rev!r} is not a 40-char git SHA; cannot pin the source. "
            f"Use --source-tree."
        )
    return attr, rev


def _nix_expr_parts(
    attr: str, rev: str, nixpkgs_override: str | None
) -> tuple[str, str]:
    """Build the injection-safe ``(nix_expr_prefix, attr_path_list)`` fragments
    shared by every eval/build against the pinned nixpkgs. ``attr``/``rev``
    must already be validated (see :func:`_resolve_attr_rev`)."""
    if nixpkgs_override:
        nixpkgs_expr = f'(import {json.dumps(nixpkgs_override)})'
    else:
        nixpkgs_expr = (
            'import (builtins.fetchTarball '
            f'"https://github.com/NixOS/nixpkgs/archive/{rev}.tar.gz")'
        )
    attr_path_list = "[" + " ".join(json.dumps(seg) for seg in attr.split(".")) + "]"
    nix_expr_prefix = f"let pkgs = {nixpkgs_expr} {{}};"
    return nix_expr_prefix, attr_path_list


def _build_pinned_src(
    bundle_dir: Path, tmp_root: Path, nixpkgs_override: str | None
) -> tuple[Path, str, str, str, str]:
    """Resolve + `nix-build` the pinned ``pkg.src`` fixed-output fetch.

    Returns ``(store_path, nix_expr_prefix, attr_path_list, attr, rev)``. The
    single nix-build call this performs is shared by every public function in
    this module that needs the pinned source, so the store fetch happens once
    per call site rather than being silently re-triggered.
    """
    attr, rev = _resolve_attr_rev(bundle_dir)
    nix_bin = shutil.which("nix-build")
    if nix_bin is None:
        raise RuntimeError(
            "nix-build not found on PATH; run inside `nix develop` or pass "
            "--source-tree with a pre-unpacked source."
        )
    nix_expr_prefix, attr_path_list = _nix_expr_parts(attr, rev, nixpkgs_override)
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
    return store_path, nix_expr_prefix, attr_path_list, attr, rev


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
    store_path, nix_expr_prefix, attr_path_list, _attr, _rev = _build_pinned_src(
        bundle_dir, tmp_root, nixpkgs_override)
    tree = unpack_source_store_path(store_path, tmp_root / "unpacked")
    patch_flags = eval_patch_flags(nix_expr_prefix, attr_path_list)
    return tree, patch_flags


class EffectiveSource(NamedTuple):
    """Result of :func:`unpack_pinned_source_with_effective_root`."""

    tree: Path
    """The tarball's own top-level directory (nixpkgs' unpackPhase default)."""
    patch_flags: list[str]
    """The pinned package's evaluated ``patchFlags`` (nixpkgs default ``["-p1"]``)."""
    effective_root: Path
    """Where `patchPhase` actually runs from — ``tree`` unless the package
    overrides ``sourceRoot``, in which case it is one (or more) levels deeper."""
    source_root: str | None
    """The raw evaluated ``sourceRoot`` string, or None if unset."""
    store_path: Path
    """The nix store path of the fixed-output ``pkg.src`` fetch — its basename
    is content-addressed (fetch-integrity anchor for provenance/attestation)."""
    nixpkgs_rev: str
    """The pinned nixpkgs revision this was resolved against."""
    preceding_patches: int
    """Count of the package's resolved ``patches`` (for the build platform)
    that ``patchPhase`` applies BEFORE the model-added patch. Non-zero means a
    pristine-``pkg.src`` dry-run may not mirror the real apply — the gate fails
    closed on it."""


def unpack_pinned_source_with_effective_root(
    bundle_dir: Path, tmp_root: Path, nixpkgs_override: str | None = None
) -> EffectiveSource:
    """Like :func:`unpack_pinned_source`, plus the EFFECTIVE `patchPhase` root.

    Performs the same single `pkg.src` `nix-build`, then separately
    `nix-instantiate`-evals ``pkg.sourceRoot`` (a plain eval, no second build)
    and resolves it against ``tree`` via :func:`resolve_effective_source_root`.
    Use ``effective_root`` (never ``tree`` directly) as the cwd for a patch
    dry-run that must mirror real `patchPhase` path resolution — see the krb5
    ``sourceRoot = "krb5-${version}/src"`` case in this module's docstring.
    """
    store_path, nix_expr_prefix, attr_path_list, _attr, rev = _build_pinned_src(
        bundle_dir, tmp_root, nixpkgs_override)
    tree = unpack_source_store_path(store_path, tmp_root / "unpacked")
    # strict: this is the fail-closed effective-root path — an eval hiccup must
    # surface, never silently degrade to a wrong strip / assumed sourceRoot.
    patch_flags = eval_patch_flags(nix_expr_prefix, attr_path_list, strict=True)
    source_root = eval_source_root(nix_expr_prefix, attr_path_list)
    preceding_patches = eval_preceding_patches_count(nix_expr_prefix, attr_path_list)
    effective_root = resolve_effective_source_root(tree, source_root)
    return EffectiveSource(
        tree=tree,
        patch_flags=patch_flags,
        effective_root=effective_root,
        source_root=source_root,
        store_path=store_path,
        nixpkgs_rev=rev,
        preceding_patches=preceding_patches,
    )
