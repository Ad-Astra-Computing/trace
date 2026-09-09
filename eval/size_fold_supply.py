"""Size the fold-shaped harvest supply in nixpkgs history (Fable Phase-B feasibility).

Phase-B needs ~40 shape-targeted (condition-fold / security-guard-add) behavioral-validated
bundles. Before investing, this answers: is there even enough fold-shaped SUPPLY in the
nixpkgs source-backport vein? It walks recently-added `.patch` files (the source-backport
signal), classifies each with `eval.classify_edit_shape`, and tallies the shape mix. Free
(reads commit diffs, no builds/GPU); a lower bound (samples a recent window).

Usage: python3 eval/size_fold_supply.py [--repo ../nixpkgs] [--limit 4000]
"""

from __future__ import annotations

import argparse
import subprocess
import sys
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from eval.classify_edit_shape import classify_diff  # noqa: E402


def _git(repo: Path, *args: str) -> str:
    # patches can carry non-UTF-8 bytes — decode leniently
    return subprocess.run(
        ["git", "-C", str(repo), *args], capture_output=True
    ).stdout.decode("utf-8", "replace")


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--repo", type=Path, default=ROOT.parent / "nixpkgs")
    ap.add_argument("--limit", type=int, default=4000, help="commits to scan back")
    ap.add_argument(
        "--max-patches", type=int, default=400, help="cap .patch files classified"
    )
    args = ap.parse_args()

    # recently-ADDED .patch files under pkgs/ (source-backport vein), with their commit
    out = _git(
        args.repo,
        "log",
        f"-n{args.limit}",
        "--diff-filter=A",
        "--name-only",
        "--format=@@%H",
        "--",
        "pkgs/**/*.patch",
    )
    sha = None
    pairs: list[tuple[str, str]] = []
    for line in out.splitlines():
        if line.startswith("@@"):
            sha = line[2:]
        elif line.endswith(".patch") and sha:
            pairs.append((sha, line))

    shapes = Counter()
    fold_leads: list[tuple[str, str, str]] = []
    n = 0
    for sha, path in pairs:
        if n >= args.max_patches:
            break
        content = _git(args.repo, "show", f"{sha}:{path}")
        if not content.strip():
            continue
        n += 1
        c = classify_diff(content)
        shapes[c["shape"]] += 1
        if c["shape"] in ("condition-fold", "security-guard-add"):
            fold_leads.append((c["shape"], c["subshape"], path))

    total = sum(shapes.values())
    print(
        f"scanned {args.limit} commits → {len(pairs)} added .patch files, classified {total}"
    )
    for shape, k in shapes.most_common():
        print(f"  {shape:20} {k:3}  ({k / total:.0%})" if total else f"  {shape}: {k}")
    fold = shapes.get("condition-fold", 0) + shapes.get("security-guard-add", 0)
    print(
        f"\n  fold + security-guard-add supply: {fold}/{total} ({fold / total:.0%})"
        if total
        else "  no patches classified"
    )
    print(
        f"  → Phase-B needs ~40 (behavioral-validated); raw shape-matched leads here: {fold}"
    )
    print("\n  sample fold-shaped leads (shape / subshape / patch):")
    for shape, sub, path in fold_leads[:15]:
        print(f"    {shape:20} {sub:16} {path}")


if __name__ == "__main__":
    main()
