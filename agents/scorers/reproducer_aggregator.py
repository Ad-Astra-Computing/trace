"""Cohort-level aggregation over reproducer scoring reports.

Mirrors `agents/scorers/aggregator.py` (patcher) and
`agents/scorers/reviewer_aggregator.py` (reviewer) shapes. Reports the
v0 cohort metrics locked in `docs/REPRODUCER_V1.md` §9:

  reproducer_well_formed_rate     (repro-schema-valid mean)
  vuln_signal_recovered_rate      (both repro-unpatched-fails AND
                                   repro-patched-passes == 1.0,
                                   per non-proxy bundle)
  proxy_patched_passes_rate       (repro-patched-passes 1.0 across
                                   PROXY bundles only — measures
                                   whether proxies, when used, at
                                   least carry their narrower claim)
  passthru_coverage_mean          (repro-passthru-recorded mean)
  proxy_rate                      (fraction of reproducers labeled
                                   proxy; non-advisory; trend over
                                   time is the contract-drift signal)
  proxy_reason_distribution       (per-`proxy_reason` counts)
  refusal_rate                    (fraction of reproducer refusals)
  signal_specificity_mean         (advisory)
  provenance                      (per-run record list)

The aggregator reads scoring-report.json files of the shape produced
by run_reproducer_scorers (forthcoming) AND tolerates the inline
hand-written shape used during the first live runs. It is permissive
about the location of the proxy flag and proxy_reason — looks first in
each scorer's `details`, then falls back to a top-level field.
"""

from __future__ import annotations

import glob
import json
from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


KNOWN_REPRODUCER_COHORT_LABELS = (
    "synthetic", "real-single", "inner-loop", "full-corpus", "real-ci-smoke",
)


@dataclass(frozen=True)
class ReproducerProvenanceEntry:
    file: str
    bundle_id: str | None
    invocation_id: str | None
    patcher_invocation_id: str | None
    prompt_sha: str | None
    model_id: str | None
    is_proxy: bool
    proxy_reason: str | None
    refused: bool
    refusal_rule: int | None

    def to_dict(self) -> dict[str, Any]:
        return {
            "file": self.file,
            "bundle_id": self.bundle_id,
            "invocation_id": self.invocation_id,
            "patcher_invocation_id": self.patcher_invocation_id,
            "prompt_sha": self.prompt_sha,
            "model_id": self.model_id,
            "is_proxy": self.is_proxy,
            "proxy_reason": self.proxy_reason,
            "refused": self.refused,
            "refusal_rule": self.refusal_rule,
        }


@dataclass(frozen=True)
class ReproducerAggregateResult:
    cohort: str
    aggregated_at: str
    totals: dict[str, int]
    reproducer_well_formed_rate: float | None
    vuln_signal_recovered_rate: float | None
    proxy_patched_passes_rate: float | None
    passthru_coverage_mean: float | None
    proxy_rate: float | None
    proxy_reason_distribution: dict[str, int]
    refusal_rate: float | None
    signal_specificity_mean: float | None
    provenance: list[ReproducerProvenanceEntry] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "cohort": self.cohort,
            "aggregated_at": self.aggregated_at,
            "totals": dict(self.totals),
            "reproducer_well_formed_rate": self.reproducer_well_formed_rate,
            "vuln_signal_recovered_rate": self.vuln_signal_recovered_rate,
            "proxy_patched_passes_rate": self.proxy_patched_passes_rate,
            "passthru_coverage_mean": self.passthru_coverage_mean,
            "proxy_rate": self.proxy_rate,
            "proxy_reason_distribution": dict(self.proxy_reason_distribution),
            "refusal_rate": self.refusal_rate,
            "signal_specificity_mean": self.signal_specificity_mean,
            "provenance": [p.to_dict() for p in self.provenance],
        }


def aggregate_reproducer_reports(
    *,
    report_paths: list[Path],
    cohort: str,
) -> ReproducerAggregateResult:
    """Aggregate a list of repro-scoring-report.json files into a cohort report."""
    provenance: list[ReproducerProvenanceEntry] = []
    parse_errors = 0
    refusals = 0
    proxy_count = 0
    well_formed_samples: list[float] = []
    passthru_samples: list[float] = []
    specificity_samples: list[float] = []
    proxy_reason_counter: Counter[str] = Counter()

    # Per-bundle composite signals (load-bearing pair).
    vuln_signal_recovered_count = 0
    vuln_signal_eligible_count = 0  # non-proxy bundles where both scorers applied
    proxy_patched_passes_count = 0
    proxy_eligible_count = 0  # proxy bundles where repro-patched-passes applied

    for path in report_paths:
        try:
            doc = json.loads(path.read_text())
        except (OSError, json.JSONDecodeError):
            parse_errors += 1
            continue

        kind, refusal_rule = _extract_kind(doc)
        is_refusal = (kind == "refusal")
        if is_refusal:
            refusals += 1

        is_proxy, proxy_reason = _extract_proxy(doc)
        if is_proxy:
            proxy_count += 1
            if proxy_reason:
                proxy_reason_counter[proxy_reason] += 1

        provenance.append(ReproducerProvenanceEntry(
            file=str(path),
            bundle_id=_pick(doc, "bundle_id"),
            invocation_id=_pick(doc, "invocation_id"),
            patcher_invocation_id=_pick(doc, "patcher_invocation_id"),
            prompt_sha=_pick(doc, "prompt_sha", "rescored_under_prompt_sha"),
            model_id=_pick(doc, "model_id"),
            is_proxy=is_proxy,
            proxy_reason=proxy_reason,
            refused=is_refusal,
            refusal_rule=refusal_rule,
        ))

        scorers_by_name = _scorers_by_name(doc)

        # Schema-valid sample (always meaningful when applies=True).
        sv = scorers_by_name.get("repro-schema-valid")
        if sv and sv.get("applies") and sv.get("score") is not None:
            well_formed_samples.append(float(sv["score"]))

        # Passthru coverage sample (post-Builder).
        pt = scorers_by_name.get("repro-passthru-recorded")
        if pt and pt.get("applies") and pt.get("score") is not None:
            passthru_samples.append(float(pt["score"]))

        # Signal-specificity sample (advisory, post-Builder).
        spec = scorers_by_name.get("repro-signal-specificity")
        if spec and spec.get("applies") and spec.get("score") is not None:
            specificity_samples.append(float(spec["score"]))

        # vuln_signal_recovered_rate: per-bundle AND of two load-bearing
        # post-Builder scorers, restricted to non-proxy bundles.
        uf = scorers_by_name.get("repro-unpatched-fails")
        pp = scorers_by_name.get("repro-patched-passes")
        if not is_proxy and uf and pp and uf.get("applies") and pp.get("applies"):
            vuln_signal_eligible_count += 1
            if (uf.get("score") == 1.0) and (pp.get("score") == 1.0):
                vuln_signal_recovered_count += 1

        # proxy_patched_passes_rate: proxy bundles only.
        if is_proxy and pp and pp.get("applies"):
            proxy_eligible_count += 1
            if pp.get("score") == 1.0:
                proxy_patched_passes_count += 1

    totals = {
        "scoring_reports": len(report_paths),
        "parse_errors": parse_errors,
        "refusals": refusals,
        "proxy": proxy_count,
        "vuln_signal_eligible": vuln_signal_eligible_count,
        "proxy_eligible": proxy_eligible_count,
    }

    def _mean(samples: list[float]) -> float | None:
        return (sum(samples) / len(samples)) if samples else None

    reproducer_well_formed_rate = _mean(well_formed_samples)
    passthru_coverage_mean = _mean(passthru_samples)
    signal_specificity_mean = _mean(specificity_samples)

    vuln_signal_recovered_rate = (
        (vuln_signal_recovered_count / vuln_signal_eligible_count)
        if vuln_signal_eligible_count > 0 else None
    )
    proxy_patched_passes_rate = (
        (proxy_patched_passes_count / proxy_eligible_count)
        if proxy_eligible_count > 0 else None
    )

    n_reports = len(report_paths) - parse_errors
    proxy_rate = (proxy_count / n_reports) if n_reports > 0 else None
    refusal_rate = (refusals / n_reports) if n_reports > 0 else None

    return ReproducerAggregateResult(
        cohort=cohort,
        aggregated_at=_utc_now_iso(),
        totals=totals,
        reproducer_well_formed_rate=reproducer_well_formed_rate,
        vuln_signal_recovered_rate=vuln_signal_recovered_rate,
        proxy_patched_passes_rate=proxy_patched_passes_rate,
        passthru_coverage_mean=passthru_coverage_mean,
        proxy_rate=proxy_rate,
        proxy_reason_distribution=dict(proxy_reason_counter),
        refusal_rate=refusal_rate,
        signal_specificity_mean=signal_specificity_mean,
        provenance=provenance,
    )


def expand_reproducer_glob(pattern: str, *, root: Path | None = None) -> list[Path]:
    """Expand a glob pattern into a sorted list of paths."""
    base = root or Path.cwd()
    paths = sorted(Path(p) for p in glob.glob(pattern, recursive=True))
    if not paths:
        paths = sorted((base / p) for p in glob.glob(str(base / pattern), recursive=True))
    return [p for p in paths if p.is_file()]


# ─── extraction helpers ────────────────────────────────────────────────────


def _scorers_by_name(doc: dict) -> dict[str, dict]:
    out: dict[str, dict] = {}
    for entry in doc.get("scorers") or []:
        if isinstance(entry, dict):
            name = entry.get("scorer_name")
            if isinstance(name, str):
                out[name] = entry
    return out


def _extract_kind(doc: dict) -> tuple[str, int | None]:
    """Return ('reproducer' | 'refusal' | 'unknown', refusal_rule_or_None).

    Looks first at a top-level `kind`, then at any scorer's `details.refusal_rule`.
    """
    kind = doc.get("kind")
    refusal_rule_raw = doc.get("refusal_rule")
    if kind in ("reproducer", "refusal", "unknown"):
        rule = (
            int(refusal_rule_raw)
            if isinstance(refusal_rule_raw, int)
            else None
        )
        return kind, rule
    # Fallback: examine schema-valid scorer details (the schema-valid
    # scorer records details.refusal_rule on refusal-shape inputs).
    for entry in doc.get("scorers") or []:
        if not isinstance(entry, dict):
            continue
        if entry.get("scorer_name") != "repro-schema-valid":
            continue
        details = entry.get("details") or {}
        if isinstance(details, dict) and "refusal_rule" in details:
            try:
                return "refusal", int(details["refusal_rule"])
            except (TypeError, ValueError):
                pass
    return "unknown", None


def _extract_proxy(doc: dict) -> tuple[bool, str | None]:
    """Return (is_proxy, proxy_reason_or_None).

    Looks first at the schema-valid scorer's details (the canonical
    location), then at top-level `is_proxy` / `proxy_reason` fields,
    then falls back to False / None.
    """
    for entry in doc.get("scorers") or []:
        if not isinstance(entry, dict):
            continue
        if entry.get("scorer_name") != "repro-schema-valid":
            continue
        details = entry.get("details") or {}
        if isinstance(details, dict) and details.get("is_proxy") is True:
            reason = details.get("proxy_reason")
            return True, (reason if isinstance(reason, str) else None)
    if doc.get("is_proxy") is True:
        reason = doc.get("proxy_reason")
        return True, (reason if isinstance(reason, str) else None)
    return False, None


def _pick(doc: dict, *keys: str) -> str | None:
    for k in keys:
        v = doc.get(k)
        if isinstance(v, str) and v:
            return v
    return None


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


__all__ = [
    "KNOWN_REPRODUCER_COHORT_LABELS",
    "ReproducerAggregateResult",
    "ReproducerProvenanceEntry",
    "aggregate_reproducer_reports",
    "expand_reproducer_glob",
]
