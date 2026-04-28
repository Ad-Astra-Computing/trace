"""Cohort-level aggregation over reviewer scoring reports.

Item 2 from the 2026-04-27 reviewer next-session plan. Mirrors the
patcher aggregator's shape (`agents/scorers/aggregator.py`) but
reports the verdict-distribution + per-scorer rates the user locked:

  accept_rate
  reject_rate
  escalate_rate
  evidence_cited_mean
  attestation_correct_rate
  reviewer_steward_disagreement_rate
  provenance list per run

The aggregator reads files in two shapes:

  (a) the canonical shape produced by the runner (when the runner
      grows reviewer-scorer aggregation; not yet wired);
  (b) the hand-written shape used during the first two live reviewer
      runs (`review-scoring-report.json` files committed under
      `traces/example/.../`); the aggregator reads `scorers[]`
      entries by `scorer_name` and is tolerant of missing keys.

`reviewer_steward_disagreement_rate` is the fraction of in-cohort
reviewer reports whose `review-disagreement` scorer reports < 1.0
(non-aligned). Per the user's instruction the rate is informational
until a stronger oracle (build outcome / known-bad labels) lands;
consumers must read it accordingly.
"""

from __future__ import annotations

import glob
import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


KNOWN_REVIEWER_COHORT_LABELS = (
    "synthetic", "real-single", "inner-loop", "full-corpus", "real-ci-smoke",
)


@dataclass(frozen=True)
class ReviewerProvenanceEntry:
    file: str
    bundle_id: str | None
    invocation_id: str | None
    prompt_sha: str | None
    model_id: str | None
    verdict: str | None  # accept | reject | escalate | None

    def to_dict(self) -> dict[str, Any]:
        return {
            "file": self.file,
            "bundle_id": self.bundle_id,
            "invocation_id": self.invocation_id,
            "prompt_sha": self.prompt_sha,
            "model_id": self.model_id,
            "verdict": self.verdict,
        }


@dataclass(frozen=True)
class ReviewerAggregateResult:
    cohort: str
    aggregated_at: str
    totals: dict[str, int]
    accept_rate: float | None
    reject_rate: float | None
    escalate_rate: float | None
    evidence_cited_mean: float | None
    attestation_correct_rate: float | None
    reviewer_steward_disagreement_rate: float | None
    provenance: list[ReviewerProvenanceEntry] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "cohort": self.cohort,
            "aggregated_at": self.aggregated_at,
            "totals": dict(self.totals),
            "accept_rate": self.accept_rate,
            "reject_rate": self.reject_rate,
            "escalate_rate": self.escalate_rate,
            "evidence_cited_mean": self.evidence_cited_mean,
            "attestation_correct_rate": self.attestation_correct_rate,
            "reviewer_steward_disagreement_rate": self.reviewer_steward_disagreement_rate,
            "provenance": [p.to_dict() for p in self.provenance],
        }


def aggregate_reviewer_reports(
    *,
    report_paths: list[Path],
    cohort: str,
) -> ReviewerAggregateResult:
    """Aggregate a list of review-scoring-report.json files into one cohort report."""
    provenance: list[ReviewerProvenanceEntry] = []
    verdict_counts = {"accept": 0, "reject": 0, "escalate": 0}
    parse_errors = 0
    refusals = 0

    evidence_samples: list[float] = []
    attestation_match_samples: list[float] = []
    disagreement_aligned_samples: list[float] = []  # 1.0 if score == 1.0, 0.0 otherwise

    for path in report_paths:
        try:
            doc = json.loads(path.read_text())
        except (OSError, json.JSONDecodeError):
            parse_errors += 1
            continue

        verdict = _extract_reviewer_verdict(doc)
        if verdict is None:
            refusals += 1
        else:
            verdict_counts[verdict] = verdict_counts.get(verdict, 0) + 1

        provenance.append(ReviewerProvenanceEntry(
            file=str(path),
            bundle_id=_pick(doc, "bundle_id"),
            invocation_id=_pick(doc, "invocation_id", "patcher_invocation_id"),
            prompt_sha=_pick(doc, "prompt_sha", "rescored_under_prompt_sha"),
            model_id=_pick(doc, "model_id"),
            verdict=verdict,
        ))

        # Per-scorer rates. The reports' `scorers[]` is a list of dicts
        # with `scorer_name` + `score` + `applies`. Read each by name;
        # missing scorer = no contribution to its rate.
        for entry in doc.get("scorers") or []:
            if not isinstance(entry, dict):
                continue
            name = entry.get("scorer_name")
            score = entry.get("score")
            if not entry.get("applies"):
                continue
            if score is None:
                continue
            if name == "review-evidence-cited":
                evidence_samples.append(float(score))
            elif name == "review-cross-family-attestation":
                attestation_match_samples.append(float(score))
            elif name == "review-disagreement":
                # disagreement_rate counts the fraction of reports
                # whose verdict diverged from Steward (score < 1.0).
                disagreement_aligned_samples.append(1.0 if float(score) == 1.0 else 0.0)

    n_verdict = sum(verdict_counts.values())
    totals = {
        "scoring_reports": len(report_paths),
        "parse_errors": parse_errors,
        "verdicts": n_verdict,
        "refusals": refusals,
        "accept": verdict_counts.get("accept", 0),
        "reject": verdict_counts.get("reject", 0),
        "escalate": verdict_counts.get("escalate", 0),
    }

    def _rate(num: int, den: int) -> float | None:
        return (num / den) if den > 0 else None

    accept_rate = _rate(verdict_counts.get("accept", 0), n_verdict)
    reject_rate = _rate(verdict_counts.get("reject", 0), n_verdict)
    escalate_rate = _rate(verdict_counts.get("escalate", 0), n_verdict)
    evidence_cited_mean = (
        sum(evidence_samples) / len(evidence_samples)
        if evidence_samples else None
    )
    attestation_correct_rate = (
        sum(attestation_match_samples) / len(attestation_match_samples)
        if attestation_match_samples else None
    )
    # Disagreement rate = fraction NOT aligned with Steward.
    disagreement_rate = (
        1.0 - (sum(disagreement_aligned_samples) / len(disagreement_aligned_samples))
        if disagreement_aligned_samples else None
    )

    return ReviewerAggregateResult(
        cohort=cohort,
        aggregated_at=_utc_now_iso(),
        totals=totals,
        accept_rate=accept_rate,
        reject_rate=reject_rate,
        escalate_rate=escalate_rate,
        evidence_cited_mean=evidence_cited_mean,
        attestation_correct_rate=attestation_correct_rate,
        reviewer_steward_disagreement_rate=disagreement_rate,
        provenance=provenance,
    )


def expand_review_glob(pattern: str, *, root: Path | None = None) -> list[Path]:
    """Expand a glob pattern into a sorted list of paths."""
    base = root or Path.cwd()
    paths = sorted(Path(p) for p in glob.glob(pattern, recursive=True))
    if not paths:
        paths = sorted((base / p) for p in glob.glob(str(base / pattern), recursive=True))
    return [p for p in paths if p.is_file()]


# ─── extraction helpers ────────────────────────────────────────────────────


def _extract_reviewer_verdict(doc: dict) -> str | None:
    """Pull the reviewer's verdict out of common report shapes.
    Looks for `scorers[].details.verdict` first (canonical-shape on
    review-schema-valid carries the verdict in details), then falls
    back to `parsed_review.verdict` or top-level `verdict` if any
    future shape adds them.
    """
    for entry in doc.get("scorers") or []:
        if not isinstance(entry, dict):
            continue
        if entry.get("scorer_name") == "review-schema-valid":
            details = entry.get("details") or {}
            v = details.get("verdict")
            if v in ("accept", "reject", "escalate"):
                return v
    for key in ("verdict",):
        v = doc.get(key)
        if v in ("accept", "reject", "escalate"):
            return v
    return None


def _pick(doc: dict, *keys: str) -> str | None:
    for k in keys:
        v = doc.get(k)
        if isinstance(v, str) and v:
            return v
    return None


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


__all__ = [
    "KNOWN_REVIEWER_COHORT_LABELS",
    "ReviewerAggregateResult",
    "ReviewerProvenanceEntry",
    "aggregate_reviewer_reports",
    "expand_review_glob",
]
