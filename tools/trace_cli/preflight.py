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
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any

from tools.trace_cli import nested_patch, pinned_source


EXIT_OK = 0
EXIT_USAGE = 64
EXIT_NOT_FOUND = 65
EXIT_APPLY_FAILED = 66
EXIT_UNPACK_FAILED = 67
EXIT_EXTRACT_FAILED = 68


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
        "--patch-flags",
        type=str,
        default=None,
        metavar="FLAGS",
        help="(--patch-diff with --source-tree) the package's full patchFlags "
             "as one whitespace-separated string; use the `=` form so argparse "
             "accepts dashes, e.g. --patch-flags=-p0 or --patch-flags='-p1 -d "
             "sub'. Supersedes --strip. Ignored on the nix-unpack path "
             "(evaluated patchFlags win).",
    )
    p.add_argument(
        "--patch-diff",
        action="store_true",
        help="validate the MODEL's patch.diff nested source patch (not "
             "upstream-fix.patch) against the derivation's EFFECTIVE "
             "sourceRoot. Catches a path-strip / subdir-sourceRoot mismatch "
             "(e.g. krb5's sourceRoot=\"krb5-${version}/src\") that the "
             "raw-tree upstream-fix check cannot see, since the model's "
             "patch may use different path prefixes than upstream-fix.patch. "
             "Ignores --patch/discover_source_patches; reads <bundle>/patch.diff. "
             "Writes an auditable verdict to <bundle>/patch-diff-preflight.json.",
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
    # Baseline the escaping symlinks already in the tree (legitimate ones can ship
    # in the pinned source) so only patch-introduced escapes are attributed here.
    before = _escaping_symlinks(tree)
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
    if proc.returncode != 0:
        return False, out
    # Defense-in-depth: `patch` honours git `mode 120000` and creates symlinks, so
    # a crafted patch can plant a link pointing outside the work tree that a later
    # patch in the cumulative series then writes through — an arbitrary-write
    # primitive against a model-authored / feed-sourced patch. Refuse any escape
    # this patch introduced (or redirected out of the tree).
    after = _escaping_symlinks(tree)
    introduced = {p: t for p, t in after.items() if before.get(p) != t}
    if introduced:
        listing = ", ".join(f"{p} -> {t}" for p, t in sorted(introduced.items()))
        return False, (
            "refused: patch introduced symlink(s) escaping the work tree "
            f"(path-traversal write primitive): {listing}"
            + (f"\n{out}" if out else "")
        )
    return True, out


def classify_patch_output(output: str) -> str:
    """Why a dry-run failed: "already-applied" or "does-not-apply".

    `patch` reports "Reversed (or previously applied) patch detected" when the
    tree already contains the change. That is a different disposition from a base
    mismatch: the pinned source is not vulnerable, so the candidate is retired
    rather than reharvested against another base.
    """
    text = output or ""
    applied = "previously applied" in text
    failed = "FAILED" in text
    if applied and failed:
        return "mixed"
    if applied:
        return "already-applied"
    return "does-not-apply"


def _escaping_symlinks(tree: Path) -> dict[str, str]:
    """Map ``symlink path -> readlink target`` for every symlink under ``tree``
    whose resolved destination lands outside ``tree``.

    Walks without following symlinks (``os.walk`` default) so a symlinked dir
    cannot redirect the traversal out of the tree. Resolution failures (loops,
    unreadable) are treated as escapes: fail closed.
    """
    root = tree.resolve()
    escaping: dict[str, str] = {}
    for dirpath, dirnames, filenames in os.walk(tree):
        for name in (*dirnames, *filenames):
            p = Path(dirpath) / name
            if not p.is_symlink():
                continue
            try:
                target = p.resolve()
                escapes = not target.is_relative_to(root)
            except (OSError, RuntimeError):
                escapes = True
            if escapes:
                try:
                    escaping[str(p)] = os.readlink(p)
                except OSError:
                    escaping[str(p)] = "<unreadable>"
    return escaping


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

    if getattr(args, "patch_diff", False):
        return _run_patch_diff(args, bundle_dir)

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


def check_patch_diff_effective_root(
    bundle_dir: Path, source_tree: Path | None = None, strip: int | None = None,
    patch_flags: list[str] | None = None,
) -> dict[str, Any]:
    """Pure check: does ``bundle_dir``'s `patch.diff` nested/flat source patch
    apply from the derivation's EFFECTIVE `sourceRoot` with the package's real
    ``patchFlags``?

    No stdout, no sidecar write — just the result dict (the same shape
    `--patch-diff` writes to ``patch-diff-preflight.json``). Shared by the
    `--patch-diff` CLI mode and `bundle.finalize_bundle`'s opt-in
    ``gate_sourceroot`` check, so both go through one code path (mirrors this
    module's existing "resolved through one code path" convention for the
    pinned-source primitive).

    On the nix-unpack path the package's evaluated ``patchFlags`` are used. On
    the ``source_tree`` path there is no nix eval, so ``patch_flags`` (or the
    ``-p{strip}`` shorthand) MUST be supplied for any package whose real flags
    are not the ``-p1`` default — else the gate could pass/fail differently
    from ``patchPhase``. ``patch_flags`` wins over ``strip``; both default to
    ``["-p1"]``.

    Raises ``FileNotFoundError`` (missing patch.diff / bad --source-tree),
    ``nested_patch.NestedPatchError`` (malformed patch.diff), or
    ``RuntimeError``/``ValueError`` (nix unpack / sourceRoot resolution
    failure) — the caller decides how each maps to its own error surface.
    """
    patch_diff_path = bundle_dir / "patch.diff"
    if not patch_diff_path.is_file():
        raise FileNotFoundError(
            f"no patch.diff in {bundle_dir}; this check requires a bundle "
            f"with Patcher output already on disk."
        )
    inner_text, nested_names = nested_patch.extract_nested_source_patch(
        patch_diff_path.read_text())

    with tempfile.TemporaryDirectory(prefix="trace-preflight-patchdiff-") as tmp:
        tmp_root = Path(tmp)
        source_root: str | None = None
        preceding_patches: int | None = None
        if source_tree is not None:
            effective_root = source_tree.resolve()
            if not effective_root.is_dir():
                raise FileNotFoundError(f"--source-tree not a directory: {effective_root}")
            source_root_mode = "supplied"
            if patch_flags is not None:
                patch_flags = list(patch_flags)
            elif strip is not None:
                patch_flags = [f"-p{strip}"]
            else:
                patch_flags = ["-p1"]
        else:
            eff = pinned_source.unpack_pinned_source_with_effective_root(bundle_dir, tmp_root)
            # patchPhase applies the package's own `patches` list BEFORE the
            # model patch. A pristine-pkg.src dry-run does not reflect those, so
            # if any exist (resolved for the build platform) the gate cannot
            # faithfully mirror the real apply — fail closed and point at the
            # --source-tree escape hatch (a tree already prepared through them).
            if eff.preceding_patches > 0:
                raise RuntimeError(
                    f"package applies {eff.preceding_patches} preceding "
                    f"patch(es) before the model patch; a pristine-pkg.src "
                    f"dry-run may not mirror patchPhase. Pass --source-tree "
                    f"with a tree already prepared through those patches to "
                    f"gate this bundle faithfully."
                )
            effective_root = eff.effective_root
            source_root = eff.source_root
            source_root_mode = "declared" if source_root else "default"
            patch_flags = [f"-p{strip}"] if strip is not None else eff.patch_flags
            preceding_patches = eff.preceding_patches

        patch_file = tmp_root / "nested-source.patch"
        patch_file.write_text(inner_text)

        work = tmp_root / "work"
        _make_writable_copy(effective_root, work)
        ok, output = apply_patch(work, patch_file, patch_flags)

    return {
        "ok": ok,
        "bundle_dir": str(bundle_dir),
        "patch_diff": "patch.diff",
        "nested_patch_files": nested_names,
        "source_root_mode": source_root_mode,
        "source_root": source_root,
        "effective_root": str(effective_root),
        "patch_flags": patch_flags,
        "preceding_patches": preceding_patches,
        "applies": ok,
        "diagnostics": output[:4096],
    }


def _run_patch_diff(args: argparse.Namespace, bundle_dir: Path) -> int:
    """`--patch-diff` mode: dry-run the MODEL's own patch.diff against the
    derivation's EFFECTIVE sourceRoot.

    Distinct from the default upstream-fix.patch flow above: that flow always
    dry-runs against the raw unpacked ``pkg.src`` tree (nixpkgs' default cd
    target), which is correct for the common case but blind to a package that
    overrides ``sourceRoot`` to cd one level deeper (krb5). This mode resolves
    the real effective root and dry-runs the model's extracted source patch
    from there — catching a path-strip mismatch the upstream-fix check cannot
    see, since the model's own transcription may use different path prefixes
    than upstream-fix.patch. Thin CLI wrapper over
    :func:`check_patch_diff_effective_root`; writes the sidecar + stdout.
    """
    _pf = getattr(args, "patch_flags", None)
    patch_flags = _pf.split() if isinstance(_pf, str) else _pf
    try:
        result = check_patch_diff_effective_root(
            bundle_dir, source_tree=args.source_tree, strip=args.strip,
            patch_flags=patch_flags)
    except FileNotFoundError as exc:
        return _emit_error(args.format, EXIT_NOT_FOUND, str(exc))
    except nested_patch.NestedPatchError as exc:
        return _emit_error(args.format, EXIT_EXTRACT_FAILED, str(exc))
    except (RuntimeError, ValueError) as exc:
        return _emit_error(args.format, EXIT_UNPACK_FAILED, str(exc))

    (bundle_dir / "patch-diff-preflight.json").write_text(
        json.dumps(result, indent=2) + "\n")

    ok = result["ok"]
    if args.format == "json":
        json.dump(result, sys.stdout, indent=2)
        sys.stdout.write("\n")
    else:
        header = "PATCH-DIFF PREFLIGHT OK" if ok else "PATCH-DIFF PREFLIGHT FAILED"
        print(header)
        print(f"  bundle:           {result['bundle_dir']}")
        print(f"  nested patch(es): {', '.join(result['nested_patch_files']) or '(flat diff)'}")
        print(f"  source root mode: {result['source_root_mode']}"
              + (f" ({result['source_root']!r})" if result['source_root'] else ""))
        print(f"  effective root:   {result['effective_root']}")
        print(f"  flags:            {' '.join(result['patch_flags'])}")
        if not ok:
            for line in result["diagnostics"].splitlines():
                print(f"      {line}", file=sys.stderr)
            print(
                "  → the model's patch.diff does not apply -p1 from the "
                "derivation's effective sourceRoot. This is a path-strip / "
                "base mismatch: fix the nested patch's path prefixes (see "
                "`trace bundle normalize-sourceroot`) before dispatching cert.",
                file=sys.stderr,
            )
    return EXIT_OK if ok else EXIT_APPLY_FAILED


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
            failed = [r for r in payload["patches"] if r["applies"] is False]
            classes = {classify_patch_output(r.get("output", "")) for r in failed}
            if failed and classes <= {"already-applied", "mixed"}:
                extra = (
                    " Some hunks also failed outright, so read the output before retiring."
                    if "mixed" in classes else ""
                )
                print(
                    "  -> the pinned source already contains this fix, so it is not "
                    "vulnerable. Retire the candidate rather than reharvesting a base."
                    + extra,
                    file=sys.stderr,
                )
            else:
                print(
                    "  -> at least one patch does not apply to the pinned source. "
                    "This is a base mismatch: retire/reharvest before spending on "
                    "the Patcher or dispatching cert.",
                    file=sys.stderr,
                )
    return EXIT_OK if all_ok else EXIT_APPLY_FAILED
