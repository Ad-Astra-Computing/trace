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

The unpacked source is obtained via the shared `pinned_source` primitive (nix
`pkg.src`, the fixed-output fetch — not `srcOnly`, which drags the whole stdenv
in). This needs nix + network at dev time (the offline agent sandbox is not
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
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any

from tools.trace_cli import pinned_source


EXIT_OK = 0
EXIT_USAGE = 64
EXIT_NOT_FOUND = 65
EXIT_APPLY_FAILED = 66
EXIT_UNPACK_FAILED = 67


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
                source_tree, resolved_flags = pinned_source.unpack_pinned_source(
                    bundle_dir, tmp_root)
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
