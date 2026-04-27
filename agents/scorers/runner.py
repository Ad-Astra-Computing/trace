"""Run all five Patcher scorers against (bundle_dir, invocation).

Composite merge-ready rate = mean of non-advisory scorers where
applies==True. Advisory scorers (historical-fix-similarity) and
inapplicable ones (refusal-shape; missing inputs) are excluded with
explicit reason codes per the schema.

Dispatch guards: the runner refuses to score if the bundle's
upstream-ref.json verdict is `ineligible-*` or bundle.kind is
`advisory-only` — these advisory-only / dispatch-guard cases are
explicitly excluded from the Patcher scorer denominator per
MODEL_EVAL_PLAN.md Terminology.
"""

from __future__ import annotations

import json
import statistics
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from agents.scorers.hash_verifiability import HashVerifiabilityScorer
from agents.scorers.historical_fix_similarity import HistoricalFixSimilarityScorer
from agents.scorers.minimality import MinimalityScorer
from agents.scorers.schema_valid import SchemaValidScorer
from agents.scorers.types import (
    SCORER_VERSION,
    Scorer,
    ScorerResult,
    canonical_scorer_names,
)
from agents.scorers.unrelated_file_touch_rate import UnrelatedFileTouchRateScorer
from agents.scorers.upstream_ref_compliance import UpstreamRefComplianceScorer


class ScoringRefused(Exception):
    """Bundle is dispatch-guarded; scoring it would mix advisory-only with the
    real Patcher denominator."""


SCHEMA_VERSION = "1.0.0"


def _default_scorers() -> list[Scorer]:
    return [
        SchemaValidScorer(),
        UpstreamRefComplianceScorer(),
        HashVerifiabilityScorer(),
        UnrelatedFileTouchRateScorer(),
        MinimalityScorer(),
        HistoricalFixSimilarityScorer(),
    ]


@dataclass(frozen=True)
class ScorerRunReport:
    bundle_dir: str
    invocation_id: str
    patcher_kind: str  # "patch" | "refusal"
    scored_at: str
    scorers: list[ScorerResult]
    composite_merge_ready_rate: float | None
    scorers_in_denominator: list[str]
    scorers_excluded: list[dict[str, str]]

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": SCHEMA_VERSION,
            "bundle_dir": self.bundle_dir,
            "invocation_id": self.invocation_id,
            "patcher_kind": self.patcher_kind,
            "scored_at": self.scored_at,
            "scorers": [s.to_dict() for s in self.scorers],
            "composite": {
                "merge_ready_rate": self.composite_merge_ready_rate,
                "scorers_in_denominator": list(self.scorers_in_denominator),
                "scorers_excluded": [dict(x) for x in self.scorers_excluded],
            },
        }


def run_scorers(
    *,
    bundle_dir: Path,
    invocation: dict[str, Any],
    scorers: list[Scorer] | None = None,
) -> ScorerRunReport:
    """Run all five scorers against one (bundle_dir, invocation) pair.

    Raises:
        ScoringRefused: if the bundle is structurally dispatch-guarded
            (advisory-only kind, or upstream-ref ineligible-*). These are
            never in the Patcher scorer denominator.
    """
    _enforce_dispatch_guard(bundle_dir)

    if scorers is None:
        scorers = _default_scorers()

    out_paths = {o["path"] for o in invocation.get("outputs") or []}
    patcher_kind = "refusal" if "refusal.json" in out_paths else "patch"

    results: list[ScorerResult] = []
    for s in scorers:
        results.append(s.score(bundle_dir=bundle_dir, invocation=invocation))

    in_denom: list[str] = []
    excluded: list[dict[str, str]] = []
    denom_scores: list[float] = []
    for r in results:
        if r.advisory:
            excluded.append({"scorer_name": r.scorer_name, "reason": "advisory"})
            continue
        if not r.applies:
            reason = "patcher-refusal" if patcher_kind == "refusal" else "inapplicable"
            excluded.append({"scorer_name": r.scorer_name, "reason": reason})
            continue
        in_denom.append(r.scorer_name)
        if r.score is not None:
            denom_scores.append(r.score)

    composite = statistics.mean(denom_scores) if denom_scores else None

    return ScorerRunReport(
        bundle_dir=str(bundle_dir),
        invocation_id=invocation.get("invocation_id") or "",
        patcher_kind=patcher_kind,
        scored_at=datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        scorers=results,
        composite_merge_ready_rate=composite,
        scorers_in_denominator=in_denom,
        scorers_excluded=excluded,
    )


def _enforce_dispatch_guard(bundle_dir: Path) -> None:
    """Refuse to score advisory-only / ineligible bundles."""
    bundle_path = bundle_dir / "bundle.json"
    if bundle_path.is_file():
        bundle = json.loads(bundle_path.read_text())
        if bundle.get("kind") == "advisory-only":
            raise ScoringRefused(
                "bundle.kind == 'advisory-only': dispatch guard, excluded "
                "from Patcher scorer denominator"
            )
    upstream_ref_path = bundle_dir / "upstream-ref.json"
    if upstream_ref_path.is_file():
        upstream_ref = json.loads(upstream_ref_path.read_text())
        verdict = (upstream_ref.get("eligibility") or {}).get("verdict") or ""
        if verdict.startswith("ineligible-"):
            raise ScoringRefused(
                f"upstream-ref.eligibility.verdict == {verdict!r}: "
                f"dispatch guard, excluded from Patcher scorer denominator"
            )


__all__ = [
    "ScorerRunReport",
    "ScoringRefused",
    "run_scorers",
]
