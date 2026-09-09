"""Scorer #4: minimality.

Defined per MODEL_EVAL_PLAN.md Model-specific metrics:

  hunk-count + changed-line-count ratio against the historical fix
  referenced in the corpus entry's historical_fix, capped at 1.0

In v0 the historical-fix DIFF content is not directly reachable from
the bundle (we have the commit_sha but not the diff bytes). We compute:

  * the patch's hunk_count and changed_line_count (always)
  * a normalized minimality score based on those alone:
      score = clamp(1 / (1 + log2(max(1, total_changed_lines / 10))), 0, 1)
    so a 10-line patch scores 1.0, 20 lines scores ~0.5, 80 lines ~0.25
  * if a historical-fix-similarity scorer ran before this one and
    recorded the historical hunk/line counts in invocation extras,
    upgrade to the proper ratio. Until that lands, the v0 score is
    reported as a SELF-MEASURE only (notes call this out).

Refusal-shape invocations: applies=False.
"""

from __future__ import annotations

import math
import re
from pathlib import Path
from typing import Any

from agents.scorers.types import SCORER_VERSION, ScorerResult


_HUNK_RE = re.compile(r"^@@\s", re.MULTILINE)


class MinimalityScorer:
    name = "minimality"
    version = SCORER_VERSION
    advisory = False

    def score(self, *, bundle_dir: Path, invocation: dict[str, Any]) -> ScorerResult:
        out_paths = {o["path"] for o in invocation.get("outputs") or []}
        if "refusal.json" in out_paths:
            return ScorerResult(
                self.name,
                self.version,
                applies=False,
                advisory=False,
                score=None,
                notes="refusal: minimality is not applicable",
            )

        diff_path = bundle_dir / "patch.diff"
        if not diff_path.is_file():
            return ScorerResult(
                self.name,
                self.version,
                applies=True,
                advisory=False,
                score=0.0,
                notes="patch.diff not on disk",
            )
        diff = diff_path.read_text()

        hunk_count = len(_HUNK_RE.findall(diff))
        changed = _count_changed_lines(diff)

        # Self-measure normalisation. 10-line patches score 1.0; longer
        # patches decay logarithmically to 0.
        if changed <= 10:
            score = 1.0
        else:
            score = 1.0 / (1.0 + math.log2(changed / 10.0))
        score = max(0.0, min(1.0, score))

        return ScorerResult(
            self.name,
            self.version,
            applies=True,
            advisory=False,
            score=score,
            notes=(
                f"v0 self-measure: hunk_count={hunk_count}, "
                f"changed_lines={changed}. Historical-fix-similarity ratio "
                f"is not yet wired; upgrade this scorer once historical diffs "
                f"are reachable."
            ),
            details={
                "hunk_count": hunk_count,
                "changed_lines": changed,
                "self_measure_only": True,
            },
        )


def _count_changed_lines(diff: str) -> int:
    """Count added/removed lines, excluding diff metadata lines (---/+++)."""
    n = 0
    for line in diff.splitlines():
        if line.startswith("--- ") or line.startswith("+++ "):
            continue
        if line.startswith("+") or line.startswith("-"):
            n += 1
    return n
