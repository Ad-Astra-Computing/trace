"""Scorer #3: unrelated-file touch rate.

Lower-better re-expressed as higher-better-in-[0,1]:

  score = 1 - (unrelated / total_touched)

A "touched file" is any file appearing in a `+++ b/<path>` header in
patch.diff (the post-image side; the pre-image '--- a/<path>' would
double-count). A file is "related" if its path is under the affected
attr's source path, derived from finding.json.

For nixpkgs the affected source path is conventionally one of:

  pkgs/by-name/<2-letter>/<attr>/...
  pkgs/development/.../<attr>/...
  pkgs/applications/.../<attr>/...

without consulting the live nixpkgs tree we can't always derive the
exact path, so the scorer accepts a permissive heuristic: a touched
file is related if the attr name appears as a path segment OR the
file basename matches the recorded `package.nix` / `default.nix` /
`<attr>.nix` convention. Synthetic fixtures with `package.nix` at the
bundle root use the basename heuristic.

Refusal-shape invocations: applies=False.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from agents.scorers.types import SCORER_VERSION, ScorerResult


_DIFF_PLUS_RE = re.compile(r"^\+\+\+\s+b/(.+?)(?:\s|$)", re.MULTILINE)
_DIFF_PLUS_NOPREFIX_RE = re.compile(r"^\+\+\+\s+([^/].+?)(?:\s|$)", re.MULTILINE)


class UnrelatedFileTouchRateScorer:
    name = "unrelated-file-touch-rate"
    version = SCORER_VERSION
    advisory = False

    def score(self, *, bundle_dir: Path, invocation: dict[str, Any]) -> ScorerResult:
        out_paths = {o["path"] for o in invocation.get("outputs") or []}
        if "refusal.json" in out_paths:
            return ScorerResult(
                self.name, self.version,
                applies=False, advisory=False, score=None,
                notes="refusal: nothing was touched",
            )

        diff_path = bundle_dir / "patch.diff"
        finding_path = bundle_dir / "finding.json"
        if not diff_path.is_file():
            return ScorerResult(
                self.name, self.version,
                applies=True, advisory=False, score=0.0,
                notes="patch.diff not on disk",
            )
        if not finding_path.is_file():
            return ScorerResult(
                self.name, self.version,
                applies=False, advisory=False, score=None,
                notes="finding.json missing; cannot determine related paths",
            )

        diff = diff_path.read_text()
        finding = json.loads(finding_path.read_text())
        affected = finding.get("affected") or []
        attrs = [a.get("attr_path") for a in affected if isinstance(a, dict) and a.get("attr_path")]
        attr_basenames = [a.split(".")[-1] for a in attrs]

        touched = _extract_touched_paths(diff)
        if not touched:
            return ScorerResult(
                self.name, self.version,
                applies=True, advisory=False, score=1.0,
                notes="no files touched (vacuously zero unrelated)",
                details={"touched": [], "unrelated": []},
            )

        related: list[str] = []
        unrelated: list[str] = []
        for path in touched:
            if _is_related(path, attr_basenames):
                related.append(path)
            else:
                unrelated.append(path)

        score = 1.0 - (len(unrelated) / len(touched))
        return ScorerResult(
            self.name, self.version,
            applies=True, advisory=False, score=score,
            notes=(
                f"{len(unrelated)}/{len(touched)} touched files unrelated to "
                f"affected attrs={attrs}"
            ),
            details={
                "touched": touched,
                "related": related,
                "unrelated": unrelated,
                "attrs": attrs,
            },
        )


def _extract_touched_paths(diff: str) -> list[str]:
    """Return the unique post-image paths from `+++ b/<path>` (or `+++ <path>`) headers."""
    seen: set[str] = set()
    out: list[str] = []
    for m in _DIFF_PLUS_RE.finditer(diff):
        p = m.group(1).strip()
        if p and p != "/dev/null" and p not in seen:
            seen.add(p)
            out.append(p)
    if not out:
        for m in _DIFF_PLUS_NOPREFIX_RE.finditer(diff):
            p = m.group(1).strip()
            if p and p != "/dev/null" and p not in seen:
                seen.add(p)
                out.append(p)
    return out


def _is_related(path: str, attr_basenames: list[str]) -> bool:
    """Permissive 'related' heuristic.

    True if any of:
      - path contains an attr basename as a path segment
      - path's basename is package.nix / default.nix
      - path's basename is `<attr>.nix` for any attr basename
    """
    parts = path.split("/")
    basename = parts[-1] if parts else path
    if basename in {"package.nix", "default.nix"}:
        return True
    for attr in attr_basenames:
        if attr in parts:
            return True
        if basename == f"{attr}.nix":
            return True
    return False
