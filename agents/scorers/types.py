"""Shared types for the five Patcher scorers.

Each scorer:
  * is a callable: (bundle_dir, invocation) -> ScorerResult
  * reads ONLY the on-disk Patcher outputs + recorded invocation metadata
  * never reads in-memory runner state
  * returns a ScorerResult with `applies`, `advisory`, `score`, `notes`
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Protocol


SCORER_VERSION: str = "1.0.0"


def canonical_scorer_names() -> tuple[str, ...]:
    """The five locked Patcher scorer names, in canonical order."""
    return (
        "schema-valid",
        "upstream-ref-compliance",
        "unrelated-file-touch-rate",
        "minimality",
        "historical-fix-similarity",
    )


@dataclass(frozen=True)
class ScorerResult:
    scorer_name: str
    scorer_version: str
    applies: bool
    advisory: bool
    score: float | None
    notes: str
    details: dict[str, Any] | None = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {
            "scorer_name": self.scorer_name,
            "scorer_version": self.scorer_version,
            "applies": self.applies,
            "advisory": self.advisory,
            "score": self.score,
            "notes": self.notes,
        }
        if self.details:
            d["details"] = dict(self.details)
        else:
            d["details"] = {}
        return d


class Scorer(Protocol):
    """Protocol every Patcher scorer satisfies."""

    name: str
    version: str
    advisory: bool

    def score(
        self,
        *,
        bundle_dir: Path,
        invocation: dict[str, Any],
    ) -> ScorerResult: ...
