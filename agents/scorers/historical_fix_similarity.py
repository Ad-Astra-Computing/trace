"""Scorer #5: historical-fix similarity.

ADVISORY ONLY. Per MODEL_EVAL_PLAN.md and the locked-scorer brief:
  "noisy signal useful for trend detection, NOT a hard gate."

The composite merge-ready computation MUST exclude this scorer
(`advisory=True` is set on the result; the runner respects it).

Compares the Patcher's `patch.diff` to the corpus entry's
`historical_fix.nixpkgs_fix_commit_sha` diff. v0: the historical diff
is not yet auto-fetched, so when the historical-fix metadata is
absent or unreachable, the scorer reports `applies=False`.

When a historical-fix DIFF is reachable (future enhancement: fetch
via gh api or a local nixpkgs clone), the score is a normalized
similarity in [0, 1] using a difflib SequenceMatcher ratio over the
two diffs' added/removed lines.
"""

from __future__ import annotations

import json
from difflib import SequenceMatcher
from pathlib import Path
from typing import Any

from agents.scorers.types import SCORER_VERSION, ScorerResult


class HistoricalFixSimilarityScorer:
    name = "historical-fix-similarity"
    version = SCORER_VERSION
    advisory = True

    def score(self, *, bundle_dir: Path, invocation: dict[str, Any]) -> ScorerResult:
        out_paths = {o["path"] for o in invocation.get("outputs") or []}
        if "refusal.json" in out_paths:
            return ScorerResult(
                self.name,
                self.version,
                applies=False,
                advisory=True,
                score=None,
                notes="refusal: similarity is not applicable",
            )

        diff_path = bundle_dir / "patch.diff"
        if not diff_path.is_file():
            return ScorerResult(
                self.name,
                self.version,
                applies=True,
                advisory=True,
                score=0.0,
                notes="patch.diff not on disk",
            )

        # In v0 the historical diff bytes are not auto-fetched. We surface
        # whether the metadata is even available, so future runs can
        # distinguish "no historical fix recorded" from "fetch failed."
        finding_path = bundle_dir / "finding.json"
        historical_diff = _try_load_historical_diff(bundle_dir, finding_path)
        if historical_diff is None:
            return ScorerResult(
                self.name,
                self.version,
                applies=False,
                advisory=True,
                score=None,
                notes=(
                    "historical-fix diff is not reachable from the bundle in v0. "
                    "Advisory scorer; not gating. Upgrade once historical diffs "
                    "are auto-fetched (gh api / local clone)."
                ),
            )

        patch_lines = _changed_lines(diff_path.read_text())
        hist_lines = _changed_lines(historical_diff)
        if not patch_lines or not hist_lines:
            return ScorerResult(
                self.name,
                self.version,
                applies=True,
                advisory=True,
                score=0.0,
                notes="one of the diffs has no changed lines",
            )

        ratio = SequenceMatcher(a=patch_lines, b=hist_lines).ratio()
        return ScorerResult(
            self.name,
            self.version,
            applies=True,
            advisory=True,
            score=ratio,
            notes=(
                f"difflib SequenceMatcher ratio over changed lines: {ratio:.3f}. "
                f"Advisory only; not gating."
            ),
            details={
                "patch_changed_lines": len(patch_lines),
                "historical_changed_lines": len(hist_lines),
            },
        )


def _changed_lines(diff_text: str) -> list[str]:
    out: list[str] = []
    for line in diff_text.splitlines():
        if line.startswith("--- ") or line.startswith("+++ "):
            continue
        if line.startswith("+") or line.startswith("-"):
            out.append(line)
    return out


def _try_load_historical_diff(bundle_dir: Path, finding_path: Path) -> str | None:
    """Return the historical fix diff text if available, else None.

    v0 path: look for `historical-fix.diff` cached alongside the bundle.
    Future: fetch via gh api / local clone given finding_path's
    historical_fix metadata. Caller treats None as 'not reachable'.
    """
    cached = bundle_dir / "historical-fix.diff"
    if cached.is_file():
        return cached.read_text()
    return None
