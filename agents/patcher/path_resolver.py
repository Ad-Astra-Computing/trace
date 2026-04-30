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

import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Optional


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
    if "." in attr_path:
        raise PackageSourceNotFound(
            f"namespaced attr_path {attr_path!r} not supported by by-name resolver; "
            f"caller must provide a flat attr or use a different resolver"
        )
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

    raw = _run_nix_eval_position(attr_path, nixpkgs_root=nixpkgs_root)
    if not raw:
        raise PackageSourceNotFound(
            f"nix eval did not return a meta.position for {attr_path!r}"
        )
    file_str = raw.split(":", 1)[0]
    try:
        path = Path(file_str).resolve()
        root_resolved = nixpkgs_root.resolve()
    except OSError as e:
        raise PackageSourceNotFound(f"could not resolve {file_str}: {e}") from e
    try:
        relative = path.relative_to(root_resolved)
    except ValueError:
        raise PackageSourceNotFound(
            f"nix eval returned {path!r} which is outside nixpkgs root {root_resolved!r}; "
            f"refusing to read"
        )
    if not path.is_file():
        raise PackageSourceNotFound(
            f"nix eval position {path!r} is not a file"
        )
    return PackageSource(
        path=path,
        relative=str(relative),
        strategy="nix-eval",
        content=path.read_text(encoding="utf-8"),
    )


def _run_nix_eval_position(
    attr_path: str,
    *,
    nixpkgs_root: Path,
) -> Optional[str]:
    """Shell out to `nix eval --raw <root>#<attr>.meta.position`.
    Returns the raw `path:line` string or None on any failure."""
    if shutil.which("nix") is None:
        return None
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
    except (subprocess.SubprocessError, OSError):
        return None
    if proc.returncode != 0:
        return None
    out = proc.stdout.strip()
    return out or None
