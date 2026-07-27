"""`trace bundle preflight`: dry-run source patches against the unpacked pinned source.

Catches source-backport BASE MISMATCH before any model spend or cert dispatch.

The bundle-bootstrap flow's tree-level `git apply --check` only verifies that a
`patch.diff` wires into the nixpkgs tree (creates the `CVE-xxxx.patch` file and
edits `package.nix`'s `patches` list). It never checks that the source patch
itself applies to the *unpacked upstream source*. A patch whose context targets a
divergent base — e.g. an upstream fix that rewrites a function to use helpers
absent from the pinned release — passes the tree apply but fails nix's `patchPhase`
at cert time, after the (expensive) Linux cert has been dispatched and, worse,
after the Patcher has already been paid to transcribe it.

This command mirrors `patchPhase`: unpack the pinned source and `patch -p1
--dry-run` each source patch. Run it in the bootstrap BEFORE
`trace replay --execute --role patcher`, so a candidate whose ground-truth
`upstream-fix.patch` cannot apply to the pinned base is retired pre-spend.

# Inputs

Operates on a bundle dir that has at least `upstream-fix.patch` (the
source-backport ground truth) plus the resolver-side metadata (`resolver-input.json`
for `attr_path`, `bundle.json`/`impact.json` for `nixpkgs_rev`). The patches to
test default to `upstream-fix.patch`; override with `--patch`.

The unpacked source is obtained via `nix-build` (`srcOnly` on the pinned nixpkgs
attr). This needs nix + network at dev time (the offline agent sandbox is not
where bootstrap runs). Pass `--source-tree DIR` to skip the nix unpack entirely
and dry-run against a source tree you already have — this is also how the unit
tests exercise the apply logic without a network fetch.

# Fidelity note

The dry-run tests each patch against the *raw unpacked* source at the pinned rev,
not against the source after nixpkgs' pre-existing `patches` have been applied. For
the base-existence mismatch class (context lines / symbols simply absent from the
pinned release — the libarchive CVE-2026-15028 failure) this is exact. A rarer
secondary failure — a clean patch that only fails because an existing nixpkgs patch
shifted line numbers — would need the post-existing-patch tree; that is out of
scope for v1 and called out here rather than silently assumed away.
"""

from __future__ import annotations

import argparse
import json
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any



EXIT_OK = 0
EXIT_USAGE = 64
EXIT_NOT_FOUND = 65
EXIT_APPLY_FAILED = 66
EXIT_UNPACK_FAILED = 67

# Feed-sourced strings interpolated into a nix expression. Validate hard before
# use (shell/expr-injection threat model): attr paths are dotted nixpkgs
# identifiers; a nixpkgs rev is a 40-char git SHA.
_ATTR_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_.-]*$")
_REV_RE = re.compile(r"^[0-9a-f]{40}$")


def add_parser(subs: argparse._SubParsersAction) -> argparse.ArgumentParser:
    """Register the `bundle preflight` subcommand under the bundle group."""
    p = subs.add_parser(
        "preflight",
        help=(
            "dry-run a source-backport's patch(es) against the unpacked pinned "
            "source to catch base mismatches BEFORE model spend / cert dispatch"
        ),
        description=(
            "Mirror nix patchPhase: unpack the pinned upstream source and "
            "`patch -p1 --dry-run` each source patch (default: upstream-fix.patch). "
            "Run before `replay --execute --role patcher`. Exits non-zero if any "
            "patch fails to apply."
        ),
    )
    p.add_argument(
        "bundle_dir",
        type=Path,
        help="bundle directory to preflight (must contain upstream-fix.patch "
             "unless --patch is given)",
    )
    p.add_argument(
        "--source-tree",
        type=Path,
        default=None,
        help="pre-unpacked source root to dry-run against; skips the nix unpack "
             "(use when you already have the source, or in offline environments)",
    )
    p.add_argument(
        "--patch",
        type=Path,
        action="append",
        default=None,
        dest="patches",
        help="patch file to dry-run (repeatable); default: <bundle>/upstream-fix.patch",
    )
    p.add_argument(
        "--strip",
        type=int,
        default=None,
        help="patch -p<N> strip count. Default: resolved from the pinned "
             "package's patchFlags on the nix path (nixpkgs default 1), or 1 "
             "when --source-tree is used. Pass to override.",
    )
    p.add_argument(
        "--format",
        choices=("human", "json"),
        default="human",
    )
    return p


def discover_source_patches(
    bundle_dir: Path, overrides: list[Path] | None
) -> list[Path]:
    """Resolve the patch files to dry-run.

    With ``overrides`` (from --patch), resolve each relative to CWD then to the
    bundle dir. Otherwise default to ``upstream-fix.patch`` in the bundle. Raises
    FileNotFoundError if a named patch is missing, or if no default exists.
    """
    if overrides:
        resolved: list[Path] = []
        for pth in overrides:
            cand = pth if pth.is_absolute() else Path(pth)
            if not cand.is_file():
                alt = bundle_dir / pth
                if alt.is_file():
                    cand = alt
                else:
                    raise FileNotFoundError(f"patch not found: {pth}")
            resolved.append(cand.resolve())
        return resolved
    default = bundle_dir / "upstream-fix.patch"
    if not default.is_file():
        raise FileNotFoundError(
            f"no upstream-fix.patch in {bundle_dir}; this command targets "
            f"source-backport bundles. Pass --patch to test a specific patch."
        )
    return [default.resolve()]


def apply_patch(
    tree: Path, patch_path: Path, patch_flags: list[str]
) -> tuple[bool, str]:
    """`patch <patch_flags>` a single patch against ``tree``, returning (ok, output).

    ``patch_flags`` is the package's full evaluated ``patchFlags`` (e.g.
    ``["-p1"]``, or ``["-p0", "-d", "src"]``) so the dry-run mirrors nix
    ``patchPhase`` exactly — not just the strip level. ``patch`` runs with
    ``cwd=tree`` (rather than a ``-d`` we impose) so any ``-d`` inside
    ``patch_flags`` resolves relative to the source root, as it would in
    patchPhase.

    Applies for real (no ``--dry-run``) so that a series applied in sequence
    reproduces patchPhase cumulative semantics — patch N+1 sees patch N's result.
    Callers pass a throwaway writable copy (see ``_make_writable_copy``), so the
    real source is never touched. ``--no-backup-if-mismatch`` avoids scattering
    ``.orig`` files into the copy.
    """
    patch_bin = shutil.which("patch")
    if patch_bin is None:
        return False, "error: `patch` not found on PATH"
    proc = subprocess.run(
        [
            patch_bin,
            *patch_flags,
            "--force",  # batch mode: never prompt, never fall back to interactive
            "--no-backup-if-mismatch",
            "-i", str(patch_path.resolve()),  # abs: cwd is the source tree
        ],
        cwd=str(tree),
        capture_output=True,
        text=True,
    )
    out = (proc.stdout + proc.stderr).strip()
    return proc.returncode == 0, out


def _make_writable_copy(src: Path, dst: Path) -> None:
    """Copy ``src`` tree to ``dst`` and make every path user-writable.

    Source trees from the nix store are read-only; `patch` needs to write in
    place. Symlinks are preserved rather than followed.
    """
    shutil.copytree(src, dst, symlinks=True)
    dst.chmod(dst.stat().st_mode | 0o700)
    for p in dst.rglob("*"):
        if p.is_symlink():
            continue
        p.chmod(p.stat().st_mode | (0o700 if p.is_dir() else 0o200))


def _read_bundle_field(bundle_dir: Path, *candidates: tuple[str, str]) -> str | None:
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


def _unpack_source_store_path(store_path: Path, dest: Path) -> Path:
    """Return an unpacked source tree from a `pkg.src` store path.

    `pkg.src` is a directory (fetchFromGitHub / fetchzip already unpack) or a
    single archive file (fetchurl tarball). For the archive case, extract into
    ``dest`` and descend into the single top-level directory if the archive has
    the usual ``<name>-<version>/`` root. No stdenv is involved — this is why we
    build ``pkg.src`` rather than ``srcOnly pkg`` (the latter pulls the whole
    toolchain just to run unpackPhase).
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


def _eval_patch_flags(nix_expr_prefix: str, attr_path_list: str) -> list[str]:
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
    ``patchFlags`` (nixpkgs default ``["-p1"]``) so the dry-run mirrors patchPhase
    fidelity — strip level and any other flags. Raises RuntimeError with an
    actionable message on any failure; the caller surfaces it and points the user
    at --source-tree.
    """
    attr = _read_bundle_field(
        bundle_dir,
        ("resolver-input.json", "attr_path"),
        ("bundle.json", "attr_path"),
    )
    rev = _read_bundle_field(
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
    tree = _unpack_source_store_path(store_path, tmp_root / "unpacked")
    patch_flags = _eval_patch_flags(nix_expr_prefix, attr_path_list)
    return tree, patch_flags


def run(args: argparse.Namespace, repo_root: Path) -> int:
    bundle_dir: Path = args.bundle_dir.resolve()
    if not bundle_dir.is_dir():
        return _emit_error(args.format, EXIT_NOT_FOUND,
                           f"bundle dir not found: {bundle_dir}")

    try:
        patches = discover_source_patches(bundle_dir, args.patches)
    except FileNotFoundError as exc:
        return _emit_error(args.format, EXIT_NOT_FOUND, str(exc))

    tmp_ctx: tempfile.TemporaryDirectory[str] | None = None
    try:
        tmp_ctx = tempfile.TemporaryDirectory(prefix="trace-preflight-")
        tmp_root = Path(tmp_ctx.name)
        if args.source_tree is not None:
            source_tree = args.source_tree.resolve()
            if not source_tree.is_dir():
                return _emit_error(args.format, EXIT_NOT_FOUND,
                                   f"--source-tree not a directory: {source_tree}")
            source_origin = "supplied"
            patch_flags = [f"-p{args.strip}"] if args.strip is not None else ["-p1"]
        else:
            try:
                source_tree, resolved_flags = unpack_pinned_source(bundle_dir, tmp_root)
            except RuntimeError as exc:
                return _emit_error(args.format, EXIT_UNPACK_FAILED, str(exc))
            source_origin = "nix-src"
            # An explicit --strip overrides the resolved patchFlags strip level.
            patch_flags = [f"-p{args.strip}"] if args.strip is not None else resolved_flags

        # Apply cumulatively against a throwaway writable copy so patch N+1 sees
        # patch N's result (nix patchPhase semantics) and the real source is
        # never touched. Stop at the first failure: later patches in a series
        # generally depend on earlier ones, so their result is meaningless once
        # the base is inconsistent.
        work = tmp_root / "work"
        _make_writable_copy(source_tree, work)

        results = []
        all_ok = True
        for patch_path in patches:
            if not all_ok:
                results.append({
                    "patch": str(patch_path),
                    "applies": None,
                    "output": "skipped: a prior patch in the series failed to apply",
                })
                continue
            ok, output = apply_patch(work, patch_path, patch_flags)
            all_ok = all_ok and ok
            results.append({
                "patch": str(patch_path),
                "applies": ok,
                "output": output,
            })
    finally:
        if tmp_ctx is not None:
            tmp_ctx.cleanup()

    return _emit_result(
        args.format,
        bundle_dir=bundle_dir,
        source_tree=str(source_tree),
        source_origin=source_origin,
        patch_flags=patch_flags,
        results=results,
        all_ok=all_ok,
    )


def _emit_error(fmt: str, exit_code: int, message: str) -> int:
    if fmt == "json":
        json.dump({"ok": False, "error": message}, sys.stdout, indent=2)
        sys.stdout.write("\n")
    else:
        print(f"error: {message}", file=sys.stderr)
    return exit_code


def _emit_result(fmt: str, **kwargs: Any) -> int:
    all_ok: bool = kwargs["all_ok"]
    payload = {
        "ok": all_ok,
        "bundle_dir": kwargs["bundle_dir"] if isinstance(kwargs["bundle_dir"], str)
        else str(kwargs["bundle_dir"]),
        "source_tree": kwargs["source_tree"],
        "source_origin": kwargs["source_origin"],
        "patch_flags": kwargs["patch_flags"],
        "patches": kwargs["results"],
    }
    if fmt == "json":
        json.dump(payload, sys.stdout, indent=2)
        sys.stdout.write("\n")
    else:
        header = "PREFLIGHT OK" if all_ok else "PREFLIGHT FAILED"
        print(header)
        print(f"  bundle:   {payload['bundle_dir']}")
        print(f"  source:   {payload['source_tree']} ({payload['source_origin']})")
        print(f"  flags:    {' '.join(payload['patch_flags'])}")
        for r in payload["patches"]:
            if r["applies"] is None:
                mark = "skip"
            elif r["applies"]:
                mark = "applies"
            else:
                mark = "FAILS"
            print(f"  [{mark}] {r['patch']}")
            if r["applies"] is False and r["output"]:
                for line in r["output"].splitlines():
                    print(f"      {line}", file=sys.stderr)
        if not all_ok:
            print(
                "  → at least one patch does not apply to the pinned source. "
                "This is a base mismatch: retire/reharvest before spending on "
                "the Patcher or dispatching cert.",
                file=sys.stderr,
            )
    return EXIT_OK if all_ok else EXIT_APPLY_FAILED
