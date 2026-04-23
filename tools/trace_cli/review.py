"""`trace review` subcommand: load review rubric files and summarize them.

Deterministic, boring aggregation per SPEC §5b and the build-container brief:
  * decision counts: merge / reject / escalate
  * mean confidence (1-5)
  * median time_to_decision_seconds
  * percent of reviews where needed_external_access is true
  * primary_rejection_reason counts (only over non-merge decisions)
  * simple pairwise percent agreement on `decision`, per bundle with >=2 reviews

Deliberately NOT built yet:
  * weighted agreement (Cohen's kappa, Fleiss' kappa)
  * confidence-weighted rejection statistics
  * trend-over-time plots

Those arrive only when the panel has enough real data to warrant them.

Exclusion rule:
  is_example: true reviews are skipped unless --include-examples is passed.
  The seed directory must not contaminate real panel aggregation.
"""

from __future__ import annotations

import json
import statistics
from collections import Counter
from itertools import combinations
from pathlib import Path
from typing import Any


def load_reviews(
    directory: Path,
    include_examples: bool = False,
    bundle_filter: str | None = None,
) -> list[dict[str, Any]]:
    if not directory.is_dir():
        raise FileNotFoundError(f"review directory not found: {directory}")
    reviews: list[dict[str, Any]] = []
    for p in sorted(directory.glob("*.json")):
        doc = json.loads(p.read_text())
        if doc.get("is_example") and not include_examples:
            continue
        if bundle_filter is not None and doc.get("bundle_id") != bundle_filter:
            continue
        reviews.append(doc)
    return reviews


def summarize(reviews: list[dict[str, Any]]) -> dict[str, Any]:
    n = len(reviews)
    if n == 0:
        return {
            "count": 0,
            "decisions": {"merge": 0, "reject": 0, "escalate": 0},
            "confidence_mean": None,
            "time_to_decision_seconds_median": None,
            "percent_needed_external_access": None,
            "primary_rejection_reasons": {},
            "percent_agreement_on_decision": None,
            "bundles_with_multiple_reviews": 0,
        }

    decisions = Counter(r["decision"] for r in reviews)
    decision_counts = {
        "merge": decisions.get("merge", 0),
        "reject": decisions.get("reject", 0),
        "escalate": decisions.get("escalate", 0),
    }

    confidences = [r["confidence"] for r in reviews]
    confidence_mean = sum(confidences) / len(confidences)

    times = [r["time_to_decision_seconds"] for r in reviews]
    time_median = statistics.median(times)

    needed_external = sum(1 for r in reviews if r["needed_external_access"])
    percent_external = 100.0 * needed_external / n

    rejection_counts = dict(
        Counter(
            r["primary_rejection_reason"]
            for r in reviews
            if r["decision"] != "merge"
        )
    )

    # Pairwise percent agreement on `decision`, restricted to bundles with >=2
    # reviews. For each such bundle, count unordered pairs of reviews; a pair
    # agrees iff both recorded the same decision. Overall percent agreement is
    # (agreeing pairs / total pairs) * 100. Bundles with exactly one review
    # contribute zero pairs and do not affect the metric.
    by_bundle: dict[str, list[dict[str, Any]]] = {}
    for r in reviews:
        by_bundle.setdefault(r["bundle_id"], []).append(r)

    total_pairs = 0
    agreeing_pairs = 0
    bundles_with_multi = 0
    for bundle_id, bundle_reviews in by_bundle.items():
        if len(bundle_reviews) < 2:
            continue
        bundles_with_multi += 1
        for a, b in combinations(bundle_reviews, 2):
            total_pairs += 1
            if a["decision"] == b["decision"]:
                agreeing_pairs += 1

    percent_agreement: float | None = None
    if total_pairs > 0:
        percent_agreement = 100.0 * agreeing_pairs / total_pairs

    return {
        "count": n,
        "decisions": decision_counts,
        "confidence_mean": confidence_mean,
        "time_to_decision_seconds_median": time_median,
        "percent_needed_external_access": percent_external,
        "primary_rejection_reasons": rejection_counts,
        "percent_agreement_on_decision": percent_agreement,
        "bundles_with_multiple_reviews": bundles_with_multi,
    }


def emit_summary(summary: dict[str, Any], fmt: str) -> str:
    if fmt == "json":
        return json.dumps(summary, indent=2, sort_keys=True)

    def _fmt(v: Any) -> str:
        if v is None:
            return "n/a"
        if isinstance(v, float):
            return f"{v:.2f}"
        return str(v)

    lines = [
        f"reviews aggregated:              {summary['count']}",
        f"  merge / reject / escalate:     "
        f"{summary['decisions']['merge']} / {summary['decisions']['reject']} / {summary['decisions']['escalate']}",
        f"  confidence mean (1-5):         {_fmt(summary['confidence_mean'])}",
        f"  time-to-decision median (s):   {_fmt(summary['time_to_decision_seconds_median'])}",
        f"  needed external access (%):    {_fmt(summary['percent_needed_external_access'])}",
        f"  bundles with ≥2 reviews:       {summary['bundles_with_multiple_reviews']}",
        f"  percent agreement (decision):  {_fmt(summary['percent_agreement_on_decision'])}",
    ]
    rr = summary["primary_rejection_reasons"]
    if rr:
        lines.append("  primary rejection reasons:")
        for reason, count in sorted(rr.items(), key=lambda kv: (-kv[1], kv[0])):
            lines.append(f"    {reason:<28} {count}")
    return "\n".join(lines)
