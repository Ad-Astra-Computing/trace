"""Run the Reviewer scorer set (canonical five + adaptation-equivalence)
against a (bundle_dir, invocation) pair and shape the result into a
review-scoring-report.json report.

Mirrors `agents/scorers/runner.py` (the Patcher runner) in structure and
style. Two load-bearing differences:

  * No composite/denominator field. The Patcher runner computes a single
    merge-ready rate across non-advisory, applicable scorers; the Reviewer
    scorer set has no equivalent single number. Each scorer's own
    applies/advisory/score already encodes explicit abstention, and cohort
    aggregation (`agents/scorers/reviewer_aggregator.py`) reads the
    per-scorer rows directly.
  * A `provenance` object recording input hashes (review.md, patch.diff,
    prompt_sha, scorer_schema_version) so a report can be re-verified
    against the bundle bytes it was scored from.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime, timezone
from hashlib import sha256
from pathlib import Path
from typing import Any

from agents.scorers.reviewer_scorers import (
    ReviewAdaptationEquivalenceScorer,
    ReviewCrossFamilyAttestationScorer,
    ReviewDisagreementScorer,
    ReviewEvidenceCitedScorer,
    ReviewPatchComparisonPresentScorer,
    ReviewSchemaValidScorer,
)
from agents.scorers.types import SCORER_VERSION, Scorer, ScorerResult


REVIEWER_SCORING_SCHEMA_VERSION = "1.0.0"


def _default_reviewer_scorers() -> list[Scorer]:
    # Fixed order so report.scorers[] is stable across runs.
    return [
        ReviewSchemaValidScorer(),
        ReviewEvidenceCitedScorer(),
        ReviewCrossFamilyAttestationScorer(),
        ReviewPatchComparisonPresentScorer(),
        ReviewAdaptationEquivalenceScorer(),
        ReviewDisagreementScorer(),
    ]


def _read_json_dict(path: Path) -> dict[str, Any] | None:
    if not path.is_file():
        return None
    try:
        data = json.loads(path.read_text())
    except json.JSONDecodeError:
        return None
    return data if isinstance(data, dict) else None


def _sha256_of_file(path: Path) -> str | None:
    if not path.is_file():
        return None
    return sha256(path.read_bytes()).hexdigest()


@dataclass(frozen=True)
class ReviewerScorerRunReport:
    bundle_dir: str
    bundle_id: str | None
    cve_id: str | None
    invocation_id: str
    model_id: str | None
    prompt_sha: str | None
    scored_at: str
    provenance: dict[str, Any]
    scorers: list[ScorerResult]

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": REVIEWER_SCORING_SCHEMA_VERSION,
            "scope": "reviewer",
            "bundle_dir": self.bundle_dir,
            "bundle_id": self.bundle_id,
            "cve_id": self.cve_id,
            "invocation_id": self.invocation_id,
            "model_id": self.model_id,
            "prompt_sha": self.prompt_sha,
            "scored_at": self.scored_at,
            "provenance": dict(self.provenance),
            "scorers": [s.to_dict() for s in self.scorers],
        }


def run_reviewer_scorers(
    *,
    bundle_dir: Path,
    invocation: dict[str, Any],
    scorers: list[Scorer] | None = None,
) -> ReviewerScorerRunReport:
    """Run the Reviewer scorer set against one (bundle_dir, invocation) pair.

    Scorer inapplicability (applies=False) is not an error; it is how a
    scorer encodes explicit abstention (refusal-shape invocation, wrong
    lane, missing oracle, etc.). Genuine programming errors (a scorer
    raising) are allowed to propagate.
    """
    if scorers is None:
        scorers = _default_reviewer_scorers()

    results: list[ScorerResult] = [
        s.score(bundle_dir=bundle_dir, invocation=invocation) for s in scorers
    ]

    bundle = _read_json_dict(bundle_dir / "bundle.json") or {}
    finding = _read_json_dict(bundle_dir / "finding.json") or {}
    bundle_id = bundle.get("bundle_id")
    cve_id = finding.get("cve_id")

    prompt = invocation.get("prompt")
    prompt_sha = prompt.get("sha256") if isinstance(prompt, dict) else None
    model = invocation.get("model")
    model_id = model.get("model_id") if isinstance(model, dict) else None
    prompt_sha = prompt_sha if isinstance(prompt_sha, str) else None

    provenance = {
        "review_md_sha256": _sha256_of_file(bundle_dir / "review.md"),
        "patch_diff_sha256": _sha256_of_file(bundle_dir / "patch.diff"),
        "prompt_sha": prompt_sha,
        "scorer_schema_version": SCORER_VERSION,
    }

    return ReviewerScorerRunReport(
        bundle_dir=str(bundle_dir),
        bundle_id=bundle_id if isinstance(bundle_id, str) else None,
        cve_id=cve_id if isinstance(cve_id, str) else None,
        invocation_id=invocation.get("invocation_id") or "",
        model_id=model_id if isinstance(model_id, str) else None,
        prompt_sha=prompt_sha,
        scored_at=datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        provenance=provenance,
        scorers=results,
    )


__all__ = [
    "REVIEWER_SCORING_SCHEMA_VERSION",
    "ReviewerScorerRunReport",
    "run_reviewer_scorers",
]
