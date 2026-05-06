"""Resolve a nixpkgs attr_path to its package definition file.

Given a flat attr_path (e.g. 'radare2', 'cyberchef') and a nixpkgs
checkout, find the file that defines it. Two strategies:

  1. pkgs/by-name/<2-letter-shard>/<attr>/package.nix   (modern)
  2. `nix eval --raw nixpkgs#<attr>.meta.position`      (fallback,
     opt-in via use_nix_eval=True)

The by-name path covers the bulk of post-2024 nixpkgs and stays
fully offline; nix-eval handles the long tail at the cost of a
real nix invocation per resolve.

Namespaced attr_paths (`python3Packages.requests`) are NOT handled
by v0: they require traversing nested attribute sets and conflict
with the by-name shortcut. Caller routes them via use_nix_eval=True
or rejects upstream.
"""

from __future__ import annotations

import re
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Optional


# /nix/store/<32-char-hash>-source[/...] — the canonical shape of an
# unpacked flake input or fetchurl/fetchgit checkout. Used to recognize
# eval-returned positions that live in *some* nix-managed source tree
# even when they don't share a prefix with the flake input we pinned.
# Captures everything up to (and including) the trailing slash so the
# alt-source allowance below can strip the prefix to compute a useful
# relative path.
_STORE_SOURCE_RE = re.compile(
    r"^(?P<prefix>/nix/store/[0-9a-z]{32}-source)(?:/(?P<rest>.*))?$"
)


class PackageSourceNotFound(LookupError):
    """The resolver could not locate the package definition file."""


@dataclass(frozen=True)
class PackageSource:
    path: Path
    relative: str
    strategy: str
    content: str


def resolve_package_source(
    attr_path: str,
    *,
    nixpkgs_root: Path,
    use_nix_eval: bool = False,
) -> PackageSource:
    if not nixpkgs_root.is_dir():
        raise PackageSourceNotFound(
            f"nixpkgs root does not exist or is not a directory: {nixpkgs_root}"
        )
    namespaced = "." in attr_path
    # Namespaced attrs (e.g. `haskellPackages.total`, `python3Packages.requests`)
    # never live in pkgs/by-name/. Skip the by-name attempt for those and
    # go straight to nix-eval. When use_nix_eval=False the caller gets a
    # clear error explaining the gap.
    if namespaced:
        if not use_nix_eval:
            raise PackageSourceNotFound(
                f"namespaced attr_path {attr_path!r} cannot be resolved without "
                f"use_nix_eval=True; the by-name layout is flat-only"
            )
    else:
        if len(attr_path) < 2:
            raise PackageSourceNotFound(
                f"attr_path {attr_path!r} too short for by-name shard"
            )
        by_name_relative = f"pkgs/by-name/{attr_path[:2].lower()}/{attr_path}/package.nix"
        by_name_path = nixpkgs_root / by_name_relative
        if by_name_path.is_file():
            return PackageSource(
                path=by_name_path,
                relative=by_name_relative,
                strategy="by-name",
                content=by_name_path.read_text(encoding="utf-8"),
            )
        if not use_nix_eval:
            raise PackageSourceNotFound(
                f"no package.nix at {by_name_relative}; pass use_nix_eval=True "
                f"to fall back to `nix eval` for the long-tail layout"
            )

    raw, diag = _run_nix_eval_position(attr_path, nixpkgs_root=nixpkgs_root)
    if not raw:
        raise PackageSourceNotFound(
            f"nix eval did not return a meta.position for {attr_path!r}: {diag}"
        )
    file_str = raw.split(":", 1)[0]
    try:
        path = Path(file_str).resolve()
        root_resolved = nixpkgs_root.resolve()
    except OSError as e:
        raise PackageSourceNotFound(f"could not resolve {file_str}: {e}") from e
    try:
        relative = path.relative_to(root_resolved)
        strategy = "nix-eval"
    except ValueError:
        # Eval can resolve to a different store-source entry than the
        # flake input we pinned (e.g. when nix re-stages the source
        # for evaluation, or when meta.position traces through an
        # internal import chain). The file we got back is still
        # inside a nix-managed unpacked flake source; reading it is
        # safe and equivalent because we passed nixpkgs_root as the
        # explicit flakeref to the eval. Restricting to the
        # /nix/store/<hash>-source shape keeps a guardrail against
        # accidental reads of arbitrary filesystem paths.
        store_match = _STORE_SOURCE_RE.match(str(path))
        if not store_match:
            raise PackageSourceNotFound(
                f"nix eval returned {path!r} which is outside nixpkgs root "
                f"{root_resolved!r} and not under /nix/store/<hash>-source; "
                f"refusing to read"
            )
        # Compute the relative-within-the-alt-source-tree from the same
        # match; keeps `relative` informative for downstream consumers
        # without overstating where the file came from.
        relative = store_match.group("rest") or ""
        strategy = "nix-eval-alt-source"
    if not path.is_file():
        raise PackageSourceNotFound(
            f"nix eval position {path!r} is not a file"
        )
    return PackageSource(
        path=path,
        relative=str(relative),
        strategy=strategy,
        content=path.read_text(encoding="utf-8"),
    )


def _run_nix_eval_position(
    attr_path: str,
    *,
    nixpkgs_root: Path,
) -> tuple[Optional[str], str]:
    """Shell out to `nix eval --raw <root>#<attr>.meta.position`.

    Returns (raw_path_or_None, diagnostic). The diagnostic carries a
    short explanation (timeout, exit code + stderr excerpt, etc.) so
    the caller can surface why nix-eval declined to provide a path.
    """
    if shutil.which("nix") is None:
        return None, "nix-not-on-path"
    try:
        proc = subprocess.run(
            [
                "nix",
                "eval",
                "--raw",
                "--no-write-lock-file",
                f"{nixpkgs_root}#{attr_path}.meta.position",
            ],
            capture_output=True,
            text=True,
            check=False,
            timeout=120,
        )
    except subprocess.TimeoutExpired:
        return None, "nix-eval-timeout-120s"
    except (subprocess.SubprocessError, OSError) as exc:
        return None, f"nix-eval-exec-error:{exc}"
    if proc.returncode != 0:
        stderr = (proc.stderr or "").strip().replace("\n", " ")
        return None, f"nix-eval-exit-{proc.returncode}:{stderr[:300]}"
    out = proc.stdout.strip()
    if not out:
        return None, "nix-eval-empty-output"
    return out, "ok"
