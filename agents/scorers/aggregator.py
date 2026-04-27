"""Cohort-level aggregation over `scoring-report.json` files.

Punch-list item 4 from the 2026-04-27 closeout. The per-bundle
`merge-ready rate` measures whether a single (bundle, invocation) pair
honoured the contract. Patcher productivity across a corpus needs a
cohort-level metric — `patch_rate` — that distinguishes "Patcher
refused for the right reason on every input" from "Patcher produced
merge-ready patches on every dispatchable input."

Constraints (from the locked plan):

  * Cohort labels are explicit and boring. v0 set:
      synthetic    — synthetic fixtures only (no real model calls)
      real-single  — one real-bundle run, anchor case
      inner-loop   — the 8-entry inner-loop subset of the frozen corpus
      full-corpus  — the full 51-entry frozen corpus
    Free-form labels are accepted (an aggregator that finds an unknown
    label still works); these four are the recommended baselines.
  * Aggregate ONLY dispatchable bundles. Dispatch-guard cases (advisory-
    only, ineligible-*) raise `ScoringRefused` at scoring time and
    therefore have no scoring-report.json to begin with — they are
    naturally excluded. The aggregator does not need a separate filter.
  * Report BOTH raw scorer means AND merge-ready rate (the SPEC §5
    contract metric) AND patch_rate (the productivity metric).
  * Preserve per-invocation provenance: every input report shows up in
    `provenance[]` with (bundle_id, invocation_id, prompt_sha,
    model_id, patcher_kind, composite, file).

Reads scoring-report.json files in two shapes:
  (a) the canonical shape produced by `agents.scorers.runner` (validates
      against `policy/eval-scorer-result-schema.json`).
  (b) the hand-written shape used during today's live runs (carries
      extra fields like `comparison_to_run_1`; the aggregator looks for
      the canonical field paths and falls back gracefully).
"""

from __future__ import annotations

import glob
import json
import statistics
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


KNOWN_COHORT_LABELS = ("synthetic", "real-single", "inner-loop", "full-corpus")

# Threshold for counting a patch toward `patch_rate`. Mirrors the SPEC §5
# ship gate as spelled out in MODEL_EVAL_PLAN.md: a patch counts only if
# its per-bundle composite is >= 0.95.
PATCH_RATE_COMPOSITE_THRESHOLD = 0.95


@dataclass(frozen=True)
class ProvenanceEntry:
    """Per-invocation traceability link. Every aggregate carries one of
    these per input report so any number can be traced back to the
    artifact that produced it."""

    file: str
    bundle_id: str | None
    invocation_id: str | None
    prompt_sha: str | None
    model_id: str | None
    patcher_kind: str | None  # "patch" | "refusal" | None (unparseable)
    composite_merge_ready_rate: float | None

    def to_dict(self) -> dict[str, Any]:
        return {
            "file": self.file,
            "bundle_id": self.bundle_id,
            "invocation_id": self.invocation_id,
            "prompt_sha": self.prompt_sha,
            "model_id": self.model_id,
            "patcher_kind": self.patcher_kind,
            "composite_merge_ready_rate": self.composite_merge_ready_rate,
        }


@dataclass(frozen=True)
class AggregateResult:
    cohort: str
    aggregated_at: str
    totals: dict[str, int]
    patch_rate: float | None
    merge_ready_rate_mean: float | None
    scorer_means: dict[str, float | None]
    provenance: list[ProvenanceEntry] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "cohort": self.cohort,
            "aggregated_at": self.aggregated_at,
            "totals": dict(self.totals),
            "patch_rate": self.patch_rate,
            "merge_ready_rate_mean": self.merge_ready_rate_mean,
            "scorer_means": dict(self.scorer_means),
            "provenance": [p.to_dict() for p in self.provenance],
        }


def aggregate_reports(
    *,
    report_paths: list[Path],
    cohort: str,
) -> AggregateResult:
    """Aggregate a list of scoring-report.json files into one cohort report.

    Args:
        report_paths: explicit list of paths to scoring-report.json files.
            Use `expand_glob()` if you have a glob expression.
        cohort: cohort label. Recommended values in KNOWN_COHORT_LABELS;
            free-form strings accepted but flagged in the result for
            visibility.
    """
    provenance: list[ProvenanceEntry] = []
    composites: list[float] = []
    patch_count = 0
    refusal_count = 0
    patch_at_threshold = 0
    parse_errors = 0

    # Per-scorer score samples. Keyed by scorer_name; only collects
    # entries where applies=True (excludes patcher-refusal scorers and
    # advisory ones unless they recorded a score).
    scorer_samples: dict[str, list[float]] = {}

    for path in report_paths:
        try:
            doc = json.loads(path.read_text())
        except (OSError, json.JSONDecodeError):
            parse_errors += 1
            continue

        # Composite: handle both canonical (composite.merge_ready_rate)
        # and hand-written (composite_merge_ready_rate) shapes.
        composite = _extract_composite(doc)
        patcher_kind = _extract_patcher_kind(doc)

        provenance.append(ProvenanceEntry(
            file=str(path),
            bundle_id=_pick(doc, "bundle_id"),
            invocation_id=_pick(doc, "patcher_invocation_id", "invocation_id"),
            prompt_sha=_pick(doc, "prompt_sha", "rescored_under_prompt_sha"),
            model_id=_pick(doc, "model_id"),
            patcher_kind=patcher_kind,
            composite_merge_ready_rate=composite,
        ))

        if composite is not None:
            composites.append(composite)
        if patcher_kind == "patch":
            patch_count += 1
            if composite is not None and composite >= PATCH_RATE_COMPOSITE_THRESHOLD:
                patch_at_threshold += 1
        elif patcher_kind == "refusal":
            refusal_count += 1

        for entry in doc.get("scorer_results") or doc.get("scorers") or []:
            if not isinstance(entry, dict):
                continue
            if entry.get("applies") is True and entry.get("score") is not None:
                name = entry.get("scorer_name")
                if isinstance(name, str):
                    scorer_samples.setdefault(name, []).append(float(entry["score"]))

    dispatchable = patch_count + refusal_count
    totals = {
        "scoring_reports": len(report_paths),
        "parse_errors": parse_errors,
        "dispatchable": dispatchable,
        "patches": patch_count,
        "refusals": refusal_count,
        "patches_at_threshold": patch_at_threshold,
    }
    patch_rate = (patch_at_threshold / dispatchable) if dispatchable > 0 else None
    merge_ready_rate_mean = statistics.mean(composites) if composites else None
    scorer_means = {
        name: (statistics.mean(samples) if samples else None)
        for name, samples in scorer_samples.items()
    }
    return AggregateResult(
        cohort=cohort,
        aggregated_at=_utc_now_iso(),
        totals=totals,
        patch_rate=patch_rate,
        merge_ready_rate_mean=merge_ready_rate_mean,
        scorer_means=scorer_means,
        provenance=provenance,
    )


def expand_glob(pattern: str, *, root: Path | None = None) -> list[Path]:
    """Expand a glob pattern into a list of paths. Sorted for stability."""
    base = root or Path.cwd()
    paths = sorted(Path(p) for p in glob.glob(pattern, recursive=True))
    if not paths:
        # Try relative-to-root.
        paths = sorted((base / p) for p in glob.glob(str(base / pattern), recursive=True))
    return [p for p in paths if p.is_file()]


# ─── extraction helpers ────────────────────────────────────────────────────


def _extract_composite(doc: dict) -> float | None:
    """Pull the composite merge-ready rate out of either the canonical
    shape (composite.merge_ready_rate) or the hand-written shape
    (composite_merge_ready_rate). Returns None if absent or null."""
    composite = doc.get("composite")
    if isinstance(composite, dict):
        v = composite.get("merge_ready_rate")
        if isinstance(v, (int, float)):
            return float(v)
    v = doc.get("composite_merge_ready_rate")
    if isinstance(v, (int, float)):
        return float(v)
    return None


def _extract_patcher_kind(doc: dict) -> str | None:
    """Read patcher_kind from canonical shape, hand-written shape, or
    composite.cohort_class. Returns 'patch' / 'refusal' / None."""
    for key in ("patcher_kind",):
        v = doc.get(key)
        if v in ("patch", "refusal"):
            return v
    composite = doc.get("composite")
    if isinstance(composite, dict):
        v = composite.get("cohort_class")
        if v in ("patch", "refusal"):
            return v
    return None


def _pick(doc: dict, *keys: str) -> str | None:
    """Return the first non-empty string value found at any of the keys."""
    for k in keys:
        v = doc.get(k)
        if isinstance(v, str) and v:
            return v
    return None


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


__all__ = [
    "AggregateResult",
    "ProvenanceEntry",
    "KNOWN_COHORT_LABELS",
    "PATCH_RATE_COMPOSITE_THRESHOLD",
    "aggregate_reports",
    "expand_glob",
]
