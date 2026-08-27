"""trace report — pure roll-up of throughput + cost data on disk.

Step 1 of the cost/throughput reporting arc (see memory note 2026-05-08
"trace next-arc priority order"). Reads only existing artifacts:

  * data/scout-runs.jsonl       — per-run cron throughput records.
  * traces/example/CVE-*/       — frozen bundle directories with
                                  bundle.json, replay.json, and
                                  optional reproducer-refusal.json /
                                  patcher-invocation.json.

Does not estimate missing data. Emits three sections so the gap is
honest:

  * observed:    what came directly off disk.
  * derived:     simple counts on top of observed data.
  * unobserved:  instrumented fields with zero data points and why.

The Patcher CLI writes patcher-invocation.json with input/output tokens
and actual_cost_usd, but the seed corpus at traces/example/ predates
that path. So Step 1 is expected to report
unobserved.per_role_token_cost.data_points = 0. That's the value of
the report: it forces the decision about whether to instrument
Reviewer/Reproducer first or just re-run the existing Patcher bundles.

Writes:
  data/reports/throughput-<UTC-timestamp>.json
  data/reports/throughput-<UTC-timestamp>.md

With --format json: also prints the JSON to stdout.
With --format human: prints the Markdown to stdout.
"""

from __future__ import annotations

import argparse
import json
import subprocess
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable


SCHEMA_VERSION = "1.0.0"
REPORT_KIND = "throughput"


# ─── shapes ──────────────────────────────────────────────────────────────────


@dataclass
class ScoutRunsSummary:
    """Roll-up of data/scout-runs.jsonl. Counters are absent (None) when
    no record carried that key; missing keys are not the same as zero."""

    runs: int
    earliest_run_at: str | None
    latest_run_at: str | None
    totals_by_action: dict[str, int]
    totals_by_verdict: dict[str, int]
    discovered_total: int
    processed_total: int


@dataclass
class RoleWallTime:
    role: str
    invocations: int
    duration_seconds: float | None  # None when any invocation lacks timestamps


@dataclass
class BundleSummary:
    cve_id: str
    bundle_id: str | None
    kind: str | None
    kind_reason: str | None
    per_role: dict[str, RoleWallTime]
    total_wall_time_seconds: float | None
    has_reproducer_nix: bool
    has_reproducer_refusal: bool
    patcher_provenance: str  # "model-attested" | "deterministic-no-model" | "absent"
    # Per-role usage block from <role>-invocation.json sidecars. Each
    # value carries {input_tokens, output_tokens, actual_cost_usd,
    # model_id}; missing entries mean the sidecar isn't on disk yet
    # (the role didn't run, or pre-instrumentation seed bundle).
    role_usage: dict[str, dict[str, Any]]


@dataclass
class Provenance:
    generated_at: str
    git_rev: str | None
    traces_root: str
    scout_runs_path: str
    bundles_scanned: int
    scout_runs_scanned: int
    # Exactly where the telemetry was read from, so a report is never
    # silently built on stale data. One of: "<ref>:data/scout-runs.jsonl"
    # (live, from the scout-telemetry branch) or a description of the
    # working-tree fallback with an explicit staleness note.
    scout_runs_source: str = "working-tree"


@dataclass
class Report:
    schema_version: str
    report_kind: str
    provenance: Provenance
    observed: dict[str, Any]
    derived: dict[str, Any]
    unobserved: dict[str, Any]

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "report_kind": self.report_kind,
            "provenance": {
                "generated_at": self.provenance.generated_at,
                "git_rev": self.provenance.git_rev,
                "traces_root": self.provenance.traces_root,
                "scout_runs_path": self.provenance.scout_runs_path,
                "scout_runs_source": self.provenance.scout_runs_source,
                "bundles_scanned": self.provenance.bundles_scanned,
                "scout_runs_scanned": self.provenance.scout_runs_scanned,
            },
            "observed": self.observed,
            "derived": self.derived,
            "unobserved": self.unobserved,
        }


# ─── loaders ─────────────────────────────────────────────────────────────────


def _empty_scout_summary() -> ScoutRunsSummary:
    return ScoutRunsSummary(
        runs=0,
        earliest_run_at=None,
        latest_run_at=None,
        totals_by_action={},
        totals_by_verdict={},
        discovered_total=0,
        processed_total=0,
    )


def load_scout_runs(path: Path) -> ScoutRunsSummary:
    """Parse data/scout-runs.jsonl. Missing file is not an error: it
    means the cron never wrote, so all counters are zero and earliest/
    latest are None."""
    if not path.is_file():
        return _empty_scout_summary()
    return parse_scout_runs(path.read_text(encoding="utf-8"))


def parse_scout_runs(text: str) -> ScoutRunsSummary:
    """Roll up the JSONL telemetry text (from the working tree or a git
    ref). Unknown fields are ignored, so a newer writer schema (e.g. the
    added `main_sha`) parses fine."""
    runs = 0
    earliest: str | None = None
    latest: str | None = None
    totals_by_action: dict[str, int] = {}
    totals_by_verdict: dict[str, int] = {}
    discovered_total = 0
    processed_total = 0

    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            rec = json.loads(line)
        except json.JSONDecodeError:
            # Skip malformed lines rather than fail the whole report;
            # the cron writer is atomic, so a malformed line indicates
            # external tampering and should be surfaced as a counter,
            # not crash the rollup. Future iteration could expose a
            # parse-error counter.
            continue
        runs += 1
        run_at = rec.get("run_at")
        if isinstance(run_at, str):
            if earliest is None or run_at < earliest:
                earliest = run_at
            if latest is None or run_at > latest:
                latest = run_at
        discovered_total += int(rec.get("discovered") or 0)
        processed_total += int(rec.get("processed") or 0)
        for action, count in (rec.get("actions") or {}).items():
            totals_by_action[action] = totals_by_action.get(action, 0) + int(count)
        for verdict, count in (rec.get("resolver_verdicts") or {}).items():
            totals_by_verdict[verdict] = totals_by_verdict.get(verdict, 0) + int(count)

    return ScoutRunsSummary(
        runs=runs,
        earliest_run_at=earliest,
        latest_run_at=latest,
        totals_by_action=totals_by_action,
        totals_by_verdict=totals_by_verdict,
        discovered_total=discovered_total,
        processed_total=processed_total,
    )


_REAL_CVE_PREFIXES = ("CVE-2024-", "CVE-2025-", "CVE-2026-")


def scan_bundles(traces_root: Path) -> list[BundleSummary]:
    """Walk traces/example/CVE-*/ and return one BundleSummary per
    real-CVE bundle. Synthetic CVE-0000-* fixtures are excluded
    because they don't represent honest pipeline runs."""
    if not traces_root.is_dir():
        return []
    bundles: list[BundleSummary] = []
    for entry in sorted(traces_root.iterdir()):
        if not entry.is_dir():
            continue
        if not any(entry.name.startswith(p) for p in _REAL_CVE_PREFIXES):
            continue
        bundle_json = entry / "bundle.json"
        replay_json = entry / "replay.json"
        if not bundle_json.is_file() or not replay_json.is_file():
            continue
        try:
            bundle = json.loads(bundle_json.read_text())
            replay = json.loads(replay_json.read_text())
        except json.JSONDecodeError:
            continue
        bundles.append(_summarize_bundle(entry, bundle, replay))
    return bundles


def _summarize_bundle(
    bundle_dir: Path, bundle: dict[str, Any], replay: dict[str, Any]
) -> BundleSummary:
    per_role: dict[str, RoleWallTime] = {}
    total_seconds: float = 0.0
    total_known: bool = True

    for role_entry in replay.get("roles") or []:
        role_name = role_entry.get("role") or "<unknown-role>"
        invocations = role_entry.get("invocations") or []
        role_seconds = 0.0
        role_known = True
        for inv in invocations:
            d = _invocation_duration_seconds(inv)
            if d is None:
                role_known = False
                continue
            role_seconds += d
        per_role[role_name] = RoleWallTime(
            role=role_name,
            invocations=len(invocations),
            duration_seconds=role_seconds if role_known else None,
        )
        if role_known:
            total_seconds += role_seconds
        else:
            total_known = False

    role_usage: dict[str, dict[str, Any]] = {}
    for role in ("patcher", "reviewer", "reproducer"):
        usage = _read_role_invocation_sidecar(bundle_dir, role)
        if usage is not None:
            role_usage[role] = usage

    return BundleSummary(
        cve_id=bundle.get("cve_id") or bundle_dir.name,
        bundle_id=bundle.get("bundle_id"),
        kind=bundle.get("kind"),
        kind_reason=bundle.get("kind_reason"),
        per_role=per_role,
        total_wall_time_seconds=total_seconds if total_known else None,
        has_reproducer_nix=(bundle_dir / "reproducer.nix").is_file(),
        has_reproducer_refusal=(bundle_dir / "reproducer-refusal.json").is_file(),
        patcher_provenance=_patcher_provenance(replay),
        role_usage=role_usage,
    )


def _read_role_invocation_sidecar(
    bundle_dir: Path, role: str
) -> dict[str, Any] | None:
    """Read <role>-invocation.json sidecar if present. Returns the
    normalized usage block (uniform across all three roles), or None
    when the file is missing. Malformed sidecars are skipped silently
    so a broken file doesn't take out the whole report; future
    iteration could surface a parse-error counter."""
    path = bundle_dir / f"{role}-invocation.json"
    if not path.is_file():
        return None
    try:
        inv = json.loads(path.read_text())
    except (json.JSONDecodeError, OSError):
        return None
    if not isinstance(inv, dict):
        return None
    usage = inv.get("usage") or {}
    budget = inv.get("budget") or {}
    return {
        "input_tokens": usage.get("input_tokens"),
        "output_tokens": usage.get("output_tokens"),
        "actual_cost_usd": budget.get("actual_cost_usd"),
        "model_id": inv.get("model_id"),
        "attempts": usage.get("attempts"),
        "retry_count": inv.get("retry_count"),
        "first_attempt_conformant": inv.get("first_attempt_conformant"),
    }


def _invocation_duration_seconds(inv: dict[str, Any]) -> float | None:
    started = inv.get("started_at")
    ended = inv.get("ended_at")
    if not isinstance(started, str) or not isinstance(ended, str):
        return None
    try:
        s = datetime.fromisoformat(started.replace("Z", "+00:00"))
        e = datetime.fromisoformat(ended.replace("Z", "+00:00"))
    except ValueError:
        return None
    delta = (e - s).total_seconds()
    return delta if delta >= 0 else None


def _patcher_provenance(replay: dict[str, Any]) -> str:
    """Determine whether the bundle's Patcher invocation was model-
    attested or deterministic-no-model, based on the recorded model
    family. Bundles that don't ship a Patcher invocation (e.g. only
    upstream-ref-resolver) return 'absent'."""
    for role_entry in replay.get("roles") or []:
        if role_entry.get("role") != "patcher":
            continue
        for inv in role_entry.get("invocations") or []:
            family = (inv.get("model") or {}).get("family")
            if family == "deterministic-no-model":
                return "deterministic-no-model"
            if isinstance(family, str) and family:
                return "model-attested"
    return "absent"


# ─── report assembly ─────────────────────────────────────────────────────────


def build_report(
    scout: ScoutRunsSummary,
    bundles: list[BundleSummary],
    *,
    provenance: Provenance,
) -> Report:
    observed_cron = {
        "runs": scout.runs,
        "earliest_run_at": scout.earliest_run_at,
        "latest_run_at": scout.latest_run_at,
        "totals_by_action": scout.totals_by_action,
        "totals_by_verdict": scout.totals_by_verdict,
        "discovered_total": scout.discovered_total,
        "processed_total": scout.processed_total,
        "per_run_means": _per_run_means(scout),
    }

    observed_wall_time = [
        {
            "cve_id": b.cve_id,
            "bundle_id": b.bundle_id,
            "kind": b.kind,
            "total_wall_time_seconds": b.total_wall_time_seconds,
            "per_role": {
                role: {
                    "invocations": rwt.invocations,
                    "duration_seconds": rwt.duration_seconds,
                }
                for role, rwt in b.per_role.items()
            },
        }
        for b in bundles
    ]

    # Per-role usage rows: one row per (bundle, role) pair that has a
    # sidecar on disk. Caller can re-aggregate by role or by bundle.
    observed_role_usage: list[dict[str, Any]] = []
    for b in bundles:
        for role in ("patcher", "reviewer", "reproducer"):
            usage = b.role_usage.get(role)
            if usage is None:
                continue
            observed_role_usage.append({
                "cve_id": b.cve_id,
                "role": role,
                **usage,
            })

    kind_dist: dict[str, int] = {}
    repro_status: dict[str, int] = {"reproducer_nix": 0, "refusal": 0, "absent": 0}
    patcher_family: dict[str, int] = {}
    for b in bundles:
        if b.kind:
            kind_dist[b.kind] = kind_dist.get(b.kind, 0) + 1
        if b.has_reproducer_nix:
            repro_status["reproducer_nix"] += 1
        elif b.has_reproducer_refusal:
            repro_status["refusal"] += 1
        else:
            repro_status["absent"] += 1
        patcher_family[b.patcher_provenance] = (
            patcher_family.get(b.patcher_provenance, 0) + 1
        )

    derived = {
        "bundle_kind_distribution": kind_dist,
        "reproducer_status_distribution": repro_status,
        "patcher_provenance_distribution": patcher_family,
        "cost_per_merge_ready_bundle": _cost_per_merge_ready(bundles),
        "cost_by_kind": _cost_by_kind(bundles),
        "retry_summary": _retry_summary(bundles),
    }

    n_bundles = len(bundles)
    role_counts = {
        "patcher": sum(1 for b in bundles if "patcher" in b.role_usage),
        "reviewer": sum(1 for b in bundles if "reviewer" in b.role_usage),
        "reproducer": sum(1 for b in bundles if "reproducer" in b.role_usage),
    }
    n_total_invocations = sum(role_counts.values())
    unobserved = {
        "per_role_token_cost": {
            "data_points": n_total_invocations,
            "patcher_invocations_with_usage": role_counts["patcher"],
            "reviewer_invocations_with_usage": role_counts["reviewer"],
            "reproducer_invocations_with_usage": role_counts["reproducer"],
            "reason": _per_role_cost_reason(n_bundles, role_counts),
        },
    }

    return Report(
        schema_version=SCHEMA_VERSION,
        report_kind=REPORT_KIND,
        provenance=provenance,
        observed={
            "cron_throughput": observed_cron,
            "bundle_wall_time": observed_wall_time,
            "role_usage": observed_role_usage,
        },
        derived=derived,
        unobserved=unobserved,
    )


def _per_run_means(s: ScoutRunsSummary) -> dict[str, float | None]:
    if s.runs == 0:
        return {"discovered_per_run": None, "processed_per_run": None}
    return {
        "discovered_per_run": s.discovered_total / s.runs,
        "processed_per_run": s.processed_total / s.runs,
    }


def _per_role_cost_reason(
    n_bundles: int, role_counts: dict[str, int]
) -> str:
    if n_bundles == 0:
        return "no real-CVE bundles scanned under traces_root; nothing to report on"
    parts: list[str] = []
    for role in ("patcher", "reviewer", "reproducer"):
        parts.append(f"{role}={role_counts[role]}/{n_bundles}")
    return f"per-role sidecar coverage: {', '.join(parts)}"


def _bundle_realized_cost(b: BundleSummary) -> float | None:
    """Sum of whatever role sidecars carry a numeric actual_cost_usd for this
    bundle — the realized spend, whichever cross-family shape (Patcher+Reviewer
    or Patcher+Reproducer) the bundle used. Returns None unless the Patcher role
    reported a NUMERIC cost: both documented cross-family shapes include Patcher
    and it dominates spend, so a bundle without an observed Patcher cost (missing
    sidecar, null cost, or reviewer/reproducer-only telemetry) is cost-incomplete
    — counting it would understate the mean and inflate data_points. Mirrors the
    Patcher baseline in _cost_per_merge_ready."""
    patcher = b.role_usage.get("patcher") or {}
    if not isinstance(patcher.get("actual_cost_usd"), (int, float)):
        return None
    total = 0.0
    for u in b.role_usage.values():
        c = u.get("actual_cost_usd")
        if isinstance(c, (int, float)):
            total += float(c)
    return total


def _cost_by_kind(bundles: list[BundleSummary]) -> dict[str, Any]:
    """Realized agent cost grouped by the bundle's disposition `kind`
    (auto-merge / human-review-required / advisory-only). Uses the kind each
    bundle already carries — no per-bundle cohort tagging. Only bundles with an
    observed numeric cost contribute; a bundle with no numeric role cost is
    excluded rather than counted as $0 (see _bundle_realized_cost). This is the
    per-segment view the corpus's productivity claim rests on: auto-merge cost
    is the merge-ready cost, human-review/advisory cost is the honest-refusal
    cost."""
    groups: dict[str, list[float]] = {}
    for b in bundles:
        cost = _bundle_realized_cost(b)
        if cost is None:
            continue  # no observed numeric cost — not a $0 data point
        key = b.kind or "unclassified"
        groups.setdefault(key, []).append(cost)
    by_kind = {
        kind: {
            "data_points": len(costs),
            "mean_usd": round(sum(costs) / len(costs), 6) if costs else None,
            "total_usd": round(sum(costs), 6),
        }
        for kind, costs in sorted(groups.items())
    }
    return {
        "kinds": by_kind,
        "total_usd": round(sum(g["total_usd"] for g in by_kind.values()), 6),
    }


def _cost_per_merge_ready(bundles: list[BundleSummary]) -> dict[str, Any]:
    """Aggregate cost over auto-merge bundles whose Patcher invocation
    has on-disk usage data. The v0 cross-family contract is satisfied
    by Patcher + Reviewer OR Patcher + Reproducer (not both), so
    requiring all three sidecars excludes every real auto-merge
    bundle. The cost reported here sums whatever role sidecars are
    present per bundle — that's the actual realized cost. Patcher-
    only auto-merge bundles count too; they're a legitimate v0 shape
    even without cross-family attest (mbedtls).
    """
    rows: list[dict[str, Any]] = []
    for b in bundles:
        if b.kind != "auto-merge":
            continue
        bundle_cost = _bundle_realized_cost(b)
        if bundle_cost is None:
            continue  # no observed numeric Patcher cost — cost-incomplete
        rows.append({
            "cve_id": b.cve_id,
            "roles_present": sorted(b.role_usage.keys()),
            "total_usd": round(bundle_cost, 6),
        })
    if not rows:
        return {"data_points": 0, "mean_usd": None, "total_usd": 0.0, "rows": []}
    total = sum(r["total_usd"] for r in rows)
    return {
        "data_points": len(rows),
        "mean_usd": round(total / len(rows), 6),
        "total_usd": round(total, 6),
        "rows": rows,
    }


def _retry_summary(bundles: list[BundleSummary]) -> dict[str, Any]:
    """Observed aggregate over role-usage sidecars surfacing retry-driven
    model-call overhead. `usage.attempts` (all roles) counts the number of
    model calls a bundle's realized cost already covers (bounded auto-retry
    sums retried-attempt usage into the sidecar at write time — see
    execute.py `_write_role_invocation_sidecar`); this aggregate makes that
    extra spend visible in the report rather than leaving it folded silently
    into the dollar totals. This is a *model-call attempt* count, not a
    billed-call count: FakeAdapter / local-adapter sidecars carry attempts
    with null usage and cost, so they contribute attempts here without any
    dollar spend. `retry_count` / `first_attempt_conformant` are
    Reviewer-only fields, absent on Patcher/Reproducer sidecars. Older
    sidecars predate bounded auto-retry and carry no `attempts` field at
    all; those default to 1 (no retry), matching the "always >= 1" contract
    documented at the sidecar-write site."""
    roles_with_retry = 0
    roles_with_sampling = 0
    total_model_call_attempts = 0
    total_retry_extra_calls = 0
    total_sampling_extra_calls = 0
    reviewer_first_attempt_conformant = 0
    reviewer_first_attempt_nonconformant = 0
    for b in bundles:
        for role, usage in b.role_usage.items():
            attempts = usage.get("attempts")
            attempts = attempts if isinstance(attempts, int) else 1
            total_model_call_attempts += attempts
            extra = attempts - 1
            if extra > 0:
                # Only the Reviewer has a bounded auto-retry path. A Reproducer
                # with >1 attempt spent them on pass@K sampling DRAWS, not
                # retries (verifier-guided sampling bills every draw into the
                # sidecar). Attributing the two separately keeps the report
                # honest about WHY the extra spend happened rather than
                # mislabelling sampling overhead as retries.
                if role == "reproducer":
                    roles_with_sampling += 1
                    total_sampling_extra_calls += extra
                else:
                    roles_with_retry += 1
                    total_retry_extra_calls += extra
            if role == "reviewer":
                conformant = usage.get("first_attempt_conformant")
                if conformant is True:
                    reviewer_first_attempt_conformant += 1
                elif conformant is False:
                    reviewer_first_attempt_nonconformant += 1
    return {
        "roles_with_retry": roles_with_retry,
        "roles_with_sampling": roles_with_sampling,
        "total_model_call_attempts": total_model_call_attempts,
        # total_extra_calls stays the retry + sampling sum for continuity; the
        # split below says which is which.
        "total_extra_calls": total_retry_extra_calls + total_sampling_extra_calls,
        "total_retry_extra_calls": total_retry_extra_calls,
        "total_sampling_extra_calls": total_sampling_extra_calls,
        "reviewer_first_attempt_conformant": reviewer_first_attempt_conformant,
        "reviewer_first_attempt_nonconformant": reviewer_first_attempt_nonconformant,
    }


# ─── rendering ───────────────────────────────────────────────────────────────


def render_json(report: Report) -> str:
    return json.dumps(report.to_dict(), indent=2, sort_keys=True) + "\n"


def render_markdown(report: Report) -> str:
    lines: list[str] = []
    p = report.provenance
    lines.append(f"# Throughput report  ·  {p.generated_at}")
    lines.append("")
    lines.append(
        f"git: `{p.git_rev or 'unknown'}`  ·  traces: `{p.traces_root}`  ·  "
        f"scout-runs: `{p.scout_runs_path}`"
    )
    lines.append(
        f"bundles scanned: {p.bundles_scanned}  ·  "
        f"scout-runs scanned: {p.scout_runs_scanned}"
    )
    lines.append(f"scout-runs source: `{p.scout_runs_source}`")
    lines.append("")
    lines.append("## Observed")
    lines.append("")
    lines.append(_md_cron_section(report.observed["cron_throughput"]))
    lines.append("")
    lines.append(_md_wall_time_section(report.observed["bundle_wall_time"]))
    lines.append("")
    if report.observed["role_usage"]:
        lines.append(_md_role_usage_section(report.observed["role_usage"]))
        lines.append("")
    lines.append(_md_retry_summary_section(report.derived["retry_summary"]))
    lines.append("")
    lines.append("## Derived")
    lines.append("")
    lines.append(_md_derived_section(report.derived))
    lines.append("")
    lines.append("## Unobserved (instrumented but empty)")
    lines.append("")
    lines.append(_md_unobserved_section(report.unobserved))
    lines.append("")
    return "\n".join(lines)


def _md_cron_section(cron: dict[str, Any]) -> str:
    lines: list[str] = []
    lines.append("### Cron throughput")
    lines.append("")
    lines.append(f"- runs: {cron['runs']}")
    lines.append(f"- earliest: {cron['earliest_run_at'] or 'n/a'}")
    lines.append(f"- latest: {cron['latest_run_at'] or 'n/a'}")
    lines.append(
        f"- discovered total: {cron['discovered_total']}  ·  "
        f"processed total: {cron['processed_total']}"
    )
    means = cron["per_run_means"]
    lines.append(
        f"- per-run mean: discovered={_fmt_float(means['discovered_per_run'])}  ·  "
        f"processed={_fmt_float(means['processed_per_run'])}"
    )
    lines.append("")
    if cron["totals_by_action"]:
        lines.append("| action | count |")
        lines.append("|---|---|")
        for k in sorted(cron["totals_by_action"]):
            lines.append(f"| {k} | {cron['totals_by_action'][k]} |")
        lines.append("")
    if cron["totals_by_verdict"]:
        lines.append("| resolver verdict | count |")
        lines.append("|---|---|")
        for k in sorted(cron["totals_by_verdict"]):
            lines.append(f"| {k} | {cron['totals_by_verdict'][k]} |")
    return "\n".join(lines)


def _md_wall_time_section(bundles: list[dict[str, Any]]) -> str:
    lines: list[str] = []
    lines.append("### Bundle wall time")
    lines.append("")
    if not bundles:
        lines.append("(no bundles scanned)")
        return "\n".join(lines)
    all_roles: list[str] = []
    seen: set[str] = set()
    for b in bundles:
        for role in b["per_role"]:
            if role not in seen:
                seen.add(role)
                all_roles.append(role)
    header = ["CVE", "kind", "total (s)"] + all_roles
    lines.append("| " + " | ".join(header) + " |")
    lines.append("|" + "---|" * len(header))
    for b in bundles:
        row = [
            b["cve_id"],
            b["kind"] or "?",
            _fmt_float(b["total_wall_time_seconds"]),
        ]
        for role in all_roles:
            rec = b["per_role"].get(role)
            if rec is None:
                row.append("·")
            else:
                row.append(_fmt_float(rec["duration_seconds"]))
        lines.append("| " + " | ".join(row) + " |")
    return "\n".join(lines)


def _md_role_usage_section(usages: list[dict[str, Any]]) -> str:
    lines: list[str] = []
    lines.append("### Per-role usage")
    lines.append("")
    lines.append("| CVE | role | model | input tokens | output tokens | cost (USD) |")
    lines.append("|---|---|---|---|---|---|")
    for u in usages:
        lines.append(
            f"| {u['cve_id']} | {u['role']} | {u.get('model_id') or '?'} | "
            f"{u.get('input_tokens') if u.get('input_tokens') is not None else 'n/a'} | "
            f"{u.get('output_tokens') if u.get('output_tokens') is not None else 'n/a'} | "
            f"{_fmt_float(u.get('actual_cost_usd'))} |"
        )
    return "\n".join(lines)


def _md_retry_summary_section(retry: dict[str, Any]) -> str:
    lines: list[str] = []
    lines.append("## Retry & sampling overhead")
    lines.append("")
    if retry["total_extra_calls"] == 0:
        lines.append(
            "No extra model calls observed (no Reviewer retries, no pass@K "
            "sampling): every role ran a single call. The seed corpus predates "
            "both bounded Reviewer auto-retry and verifier-guided sampling, so "
            "0 extra calls is the expected current value."
        )
        lines.append("")
    lines.append(f"- total model-call attempts (all roles): {retry['total_model_call_attempts']}")
    lines.append(
        f"- reviewer retries: {retry['roles_with_retry']} role(s), "
        f"{retry['total_retry_extra_calls']} extra call(s)"
    )
    lines.append(
        f"- reproducer pass@K sampling: {retry.get('roles_with_sampling', 0)} role(s), "
        f"{retry.get('total_sampling_extra_calls', 0)} extra draw(s)"
    )
    lines.append(f"- total extra calls (retry + sampling): {retry['total_extra_calls']}")
    lines.append(
        f"- reviewer first-attempt conformant: {retry['reviewer_first_attempt_conformant']}"
    )
    lines.append(
        f"- reviewer first-attempt nonconformant: {retry['reviewer_first_attempt_nonconformant']}"
    )
    return "\n".join(lines)


def _md_derived_section(derived: dict[str, Any]) -> str:
    lines: list[str] = []
    if derived["bundle_kind_distribution"]:
        lines.append("**Bundle kind distribution**")
        lines.append("")
        lines.append("| kind | count |")
        lines.append("|---|---|")
        for k in sorted(derived["bundle_kind_distribution"]):
            lines.append(f"| {k} | {derived['bundle_kind_distribution'][k]} |")
        lines.append("")
    repro = derived["reproducer_status_distribution"]
    lines.append("**Reproducer status**")
    lines.append("")
    lines.append("| status | count |")
    lines.append("|---|---|")
    for k in ("reproducer_nix", "refusal", "absent"):
        lines.append(f"| {k} | {repro.get(k, 0)} |")
    lines.append("")
    if derived["patcher_provenance_distribution"]:
        lines.append("**Patcher provenance**")
        lines.append("")
        lines.append("| family | count |")
        lines.append("|---|---|")
        for k in sorted(derived["patcher_provenance_distribution"]):
            lines.append(
                f"| {k} | {derived['patcher_provenance_distribution'][k]} |"
            )
        lines.append("")
    cbk = (derived.get("cost_by_kind") or {}).get("kinds") or {}
    if cbk:
        lines.append("**Cost by bundle kind**")
        lines.append("")
        lines.append("| kind | bundles | mean (USD) | total (USD) |")
        lines.append("|---|---|---|---|")
        for kind in sorted(cbk):
            g = cbk[kind]
            mean = f"${g['mean_usd']:.4f}" if g.get("mean_usd") is not None else "—"
            lines.append(
                f"| {kind} | {g['data_points']} | {mean} | ${g['total_usd']:.4f} |"
            )
        lines.append("")
    cpb = derived.get("cost_per_merge_ready_bundle") or {}
    if cpb.get("data_points", 0) > 0:
        lines.append("**Cost per merge-ready bundle**")
        lines.append("")
        lines.append(f"- data points: {cpb['data_points']}")
        lines.append(f"- mean: ${cpb['mean_usd']:.4f}")
        lines.append(f"- total: ${cpb['total_usd']:.4f}")
        lines.append("")
        lines.append("| CVE | roles present | total (USD) |")
        lines.append("|---|---|---|")
        for r in cpb["rows"]:
            roles = ", ".join(r["roles_present"])
            lines.append(f"| {r['cve_id']} | {roles} | ${r['total_usd']:.4f} |")
    return "\n".join(lines)


def _md_unobserved_section(unobs: dict[str, Any]) -> str:
    lines: list[str] = []
    cost = unobs["per_role_token_cost"]
    lines.append("**per-role token / cost totals**")
    lines.append("")
    lines.append(f"- data points: {cost['data_points']}")
    lines.append(f"- patcher invocations with usage: {cost['patcher_invocations_with_usage']}")
    lines.append(f"- reviewer invocations with usage: {cost['reviewer_invocations_with_usage']}")
    lines.append(f"- reproducer invocations with usage: {cost['reproducer_invocations_with_usage']}")
    lines.append(f"- reason: {cost['reason']}")
    return "\n".join(lines)


def _fmt_float(v: float | int | None) -> str:
    if v is None:
        return "n/a"
    if isinstance(v, int) or float(v).is_integer():
        return str(int(v))
    return f"{v:.2f}"


# ─── CLI plumbing ────────────────────────────────────────────────────────────


def _git_rev_short(repo_root: Path) -> str | None:
    try:
        out = subprocess.run(
            ["git", "rev-parse", "--short=12", "HEAD"],
            cwd=str(repo_root),
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        )
    except (FileNotFoundError, subprocess.SubprocessError):
        return None
    if out.returncode != 0:
        return None
    rev = out.stdout.strip()
    return rev or None


def _read_scout_runs_ref(repo_root: Path, ref: str) -> str | None:
    """Read data/scout-runs.jsonl from a git ref (the scout-telemetry
    branch, where the cron now appends). Returns None if git is absent,
    the ref is unresolvable (branch not fetched), or the path is missing
    on that ref — the caller then falls back to the working tree with a
    visible staleness note."""
    try:
        out = subprocess.run(
            ["git", "show", f"{ref}:data/scout-runs.jsonl"],
            cwd=str(repo_root),
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
    except (FileNotFoundError, subprocess.SubprocessError):
        return None
    if out.returncode != 0:
        return None
    return out.stdout


def _resolve_scout_runs(
    args: argparse.Namespace, *, repo_root: Path
) -> tuple[ScoutRunsSummary, str]:
    """Resolve scout telemetry, preferring the scout-telemetry branch (the
    live source since the cron stopped pushing to protected main). Returns
    (summary, source_label). The label always states the true source so a
    report can never silently present stale working-tree data as current."""
    ref = (getattr(args, "scout_runs_ref", "") or "").strip()
    if ref:
        # A plain branch name resolves to the LOCAL ref only in a worktree
        # that has it checked out; on an ordinary main checkout `git fetch`
        # updates the remote-tracking `origin/<branch>` instead. Try the
        # remote-tracking ref FIRST — it's what `git fetch origin` freshens,
        # whereas a lingering local branch may be stale — then the bare name.
        candidates = [ref] if "/" in ref else [f"origin/{ref}", ref]
        for cand in candidates:
            text = _read_scout_runs_ref(repo_root, cand)
            if text is not None:
                # `report` never fetches (no surprise network I/O), so a
                # remote-tracking ref is only as current as the caller's last
                # fetch — say so rather than implying a guaranteed-live read.
                caveat = " (as of last fetch)" if cand.startswith("origin/") else ""
                return parse_scout_runs(text), f"{cand}:data/scout-runs.jsonl{caveat}"
        # Branch not reachable in this checkout — fall back, but say so.
        summary = load_scout_runs(args.scout_runs)
        return summary, (
            f"{args.scout_runs} (fallback; ref {ref!r} unavailable — "
            f"run `git fetch origin` for live telemetry)"
        )
    return load_scout_runs(args.scout_runs), f"{args.scout_runs} (working tree)"


def add_parser(subs: argparse._SubParsersAction) -> None:
    """Register `trace report throughput` on the report subparser."""
    rep = subs.add_parser(
        "throughput",
        help=(
            "roll up cron throughput + per-bundle wall time + Patcher "
            "token/cost data on disk; report observed / derived / "
            "unobserved sections to data/reports/."
        ),
    )
    rep.add_argument(
        "--traces-root",
        type=Path,
        default=Path("traces/example"),
        help="root directory containing CVE-* bundle directories (default: traces/example)",
    )
    rep.add_argument(
        "--scout-runs",
        type=Path,
        default=Path("data/scout-runs.jsonl"),
        help="working-tree path to scout-runs.jsonl, used when --scout-runs-ref "
        "is empty or unreachable (default: data/scout-runs.jsonl)",
    )
    rep.add_argument(
        "--scout-runs-ref",
        default="scout-telemetry",
        help="git ref to read live scout telemetry from (default: scout-telemetry, "
        "where the cron appends). Pass empty ('') to read the working-tree file instead.",
    )
    rep.add_argument(
        "--out-dir",
        type=Path,
        default=Path("data/reports"),
        help="output directory for the .json + .md report pair (default: data/reports)",
    )
    rep.add_argument(
        "--format",
        choices=("human", "json"),
        default="human",
        help="stdout format (default: human prints the Markdown; json prints the JSON)",
    )


def run(args: argparse.Namespace, *, repo_root: Path) -> int:
    scout, scout_source = _resolve_scout_runs(args, repo_root=repo_root)
    bundles = scan_bundles(args.traces_root)

    generated_at = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    provenance = Provenance(
        generated_at=generated_at,
        git_rev=_git_rev_short(repo_root),
        traces_root=str(args.traces_root),
        scout_runs_path=str(args.scout_runs),
        bundles_scanned=len(bundles),
        scout_runs_scanned=scout.runs,
        scout_runs_source=scout_source,
    )
    report = build_report(scout, bundles, provenance=provenance)

    args.out_dir.mkdir(parents=True, exist_ok=True)
    stem = f"throughput-{generated_at.replace(':', '').replace('-', '')}"
    json_path = args.out_dir / f"{stem}.json"
    md_path = args.out_dir / f"{stem}.md"
    json_path.write_text(render_json(report), encoding="utf-8")
    md_path.write_text(render_markdown(report), encoding="utf-8")

    if args.format == "json":
        print(render_json(report), end="")
    else:
        print(render_markdown(report), end="")
    print(f"\nwrote: {json_path}\nwrote: {md_path}")
    return 0
