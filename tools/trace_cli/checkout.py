"""Preconditions on a nixpkgs checkout before the two-arm Builder touches it.

Shared by `trace reproducer sample` and `trace bundle probe`. Both mutate the
checkout during patch-apply and restore it afterwards, so a checkout with
uncommitted work would be destroyed and a checkout at the wrong revision would
build both arms against the wrong tree.
"""
from __future__ import annotations

import json
import subprocess
from pathlib import Path

def validate_checkout(checkout: Path, bundle_dir: Path) -> str | None:
    """Precondition-check a nixpkgs checkout for the real local screen.

    Returns an error string or None. The screen resets the checkout to HEAD
    between draws (`git reset --hard` + `clean -fdq`), so a checkout with
    uncommitted work would be silently destroyed; and a checkout whose HEAD is
    not the bundle's pinned nixpkgs_rev builds both arms against the wrong tree,
    producing evidence unrelated to the finalized bundle. Both are refused
    before any model spend.
    """
    if not checkout.is_dir() or not (checkout / ".git").exists():
        return (f"--nixpkgs-checkout {checkout} is not a git checkout "
                "(patch-apply and per-draw restore need a git working tree)")

    def _git(*a: str) -> subprocess.CompletedProcess:
        return subprocess.run(["git", "-C", str(checkout), *a],
                              capture_output=True, text=True)

    status = _git("status", "--porcelain")
    if status.returncode != 0:
        return f"--nixpkgs-checkout {checkout}: git status failed: {status.stderr.strip()}"
    if status.stdout.strip():
        return (f"--nixpkgs-checkout {checkout} has uncommitted changes; the screen "
                "resets it to HEAD between draws and would destroy that work. "
                "Use a clean, disposable checkout.")

    # Pinned-rev check: HEAD must be the bundle's nixpkgs_rev, or the arms build
    # against the wrong tree. Skip only when the bundle records no rev.
    pinned = None
    for fname, key in (("bundle.json", "nixpkgs_rev"), ("finding.json", "nixpkgs_rev")):
        p = bundle_dir / fname
        if p.is_file():
            try:
                pinned = json.loads(p.read_text()).get(key) or pinned
            except json.JSONDecodeError:
                pass
    if pinned:
        head = _git("rev-parse", "HEAD")
        if head.returncode != 0:
            return f"--nixpkgs-checkout {checkout}: git rev-parse HEAD failed"
        head_sha = head.stdout.strip()
        if head_sha != pinned and not head_sha.startswith(pinned) and not pinned.startswith(head_sha):
            return (f"--nixpkgs-checkout HEAD {head_sha[:12]} != bundle nixpkgs_rev "
                    f"{pinned[:12]}; the screen would build against the wrong tree")
    return None

