#!/usr/bin/env python3
"""Reconstruct GitHub Actions billable minutes for this repository.

The `/actions/runs/{id}/timing` endpoint reports `billable.total_ms` as zero for
every run here while reporting a non-zero `run_duration_ms`, so the billable
figure has to be rebuilt from per-job timestamps. Billing rounds each job up to
the whole minute and sums parallel jobs, which is what `_billable_seconds` does.

The job walk is rate-limited by the GitHub REST quota. Runs whose jobs could not
be read are estimated from the measured billable-to-wall-clock ratio of their own
workflow, because that ratio is driven by job count and job count is a property
of the workflow rather than of the individual run.

Usage:
    scripts/ci_minutes.py --out data/reports/ci-minutes-<date>.json
"""

from __future__ import annotations

import argparse
import collections
import datetime as dt
import json
import math
import subprocess
import sys

LINUX_RATE_PER_MINUTE = 0.008
ALLOWANCES = {"2000-min plan": 2000, "3000-min plan": 3000}


def _gh(path: str) -> object | None:
    proc = subprocess.run(
        ["gh", "api", path], capture_output=True, text=True, check=False
    )
    if proc.returncode != 0:
        return None
    try:
        return json.loads(proc.stdout)
    except json.JSONDecodeError:
        return None


def _parse(stamp: str | None) -> dt.datetime | None:
    if not stamp:
        return None
    try:
        return dt.datetime.fromisoformat(stamp.replace("Z", "+00:00"))
    except ValueError:
        return None


def fetch_runs() -> list[dict]:
    runs: list[dict] = []
    page = 1
    while True:
        got = _gh(f"repos/:owner/:repo/actions/runs?per_page=100&page={page}")
        if not isinstance(got, dict):
            break
        batch = got.get("workflow_runs") or []
        if not batch:
            break
        for run in batch:
            started, updated = _parse(run.get("run_started_at")), _parse(
                run.get("updated_at")
            )
            created = _parse(run.get("created_at"))
            runs.append(
                {
                    "id": str(run["id"]),
                    "workflow": run.get("name") or "(unnamed)",
                    "month": created.strftime("%Y-%m") if created else "unknown",
                    "wall_seconds": max(0.0, (updated - started).total_seconds())
                    if started and updated
                    else 0.0,
                }
            )
        page += 1
    return runs


def _billable_seconds(jobs: list[dict]) -> float | None:
    """Whole-minute-rounded seconds across a run's jobs, or None if unreadable."""
    total = 0.0
    seen = False
    for job in jobs:
        started, done = _parse(job.get("started_at")), _parse(job.get("completed_at"))
        if not started or not done:
            continue
        seen = True
        total += math.ceil(max(0.0, (done - started).total_seconds()) / 60) * 60
    return total if seen else None


def fetch_billable(run_id: str) -> float | None:
    got = _gh(f"repos/:owner/:repo/actions/runs/{run_id}/jobs?per_page=100")
    if not isinstance(got, dict):
        return None
    return _billable_seconds(got.get("jobs") or [])


def build(runs: list[dict]) -> dict:
    measured: dict[str, float] = {}
    for run in runs:
        got = fetch_billable(run["id"])
        if got is not None:
            measured[run["id"]] = got

    num: collections.Counter = collections.Counter()
    den: collections.Counter = collections.Counter()
    for run in runs:
        if run["id"] in measured:
            num[run["workflow"]] += measured[run["id"]]
            den[run["workflow"]] += run["wall_seconds"]
    fallback = sum(num.values()) / max(1e-9, sum(den.values()))

    by_workflow: collections.Counter = collections.Counter()
    by_month: collections.Counter = collections.Counter()
    by_cell: collections.Counter = collections.Counter()
    runs_by_cell: collections.Counter = collections.Counter()
    total = 0.0
    for run in runs:
        if run["id"] in measured:
            seconds = measured[run["id"]]
        else:
            ratio = (
                num[run["workflow"]] / den[run["workflow"]]
                if den[run["workflow"]] > 0
                else fallback
            )
            seconds = run["wall_seconds"] * ratio
        by_workflow[run["workflow"]] += seconds
        by_month[run["month"]] += seconds
        by_cell[(run["month"], run["workflow"])] += seconds
        runs_by_cell[(run["month"], run["workflow"])] += 1
        total += seconds

    minutes = total / 60
    overage = {}
    for label, allowance in ALLOWANCES.items():
        billed = sum(max(0.0, v / 60 - allowance) for v in by_month.values())
        overage[label] = round(billed * LINUX_RATE_PER_MINUTE, 2)

    return {
        "generated_at": dt.datetime.now(dt.timezone.utc).isoformat(),
        "rate_per_minute_usd": LINUX_RATE_PER_MINUTE,
        "runs_total": len(runs),
        "runs_measured": len(measured),
        "runs_extrapolated": len(runs) - len(measured),
        "measured_billable_minutes": round(sum(measured.values()) / 60),
        "billable_to_wallclock_ratio": round(fallback, 3),
        "estimated_billable_minutes": round(minutes),
        "estimated_gross_usd": round(minutes * LINUX_RATE_PER_MINUTE, 2),
        "estimated_overage_usd": overage,
        "by_workflow_minutes": {
            k: round(v / 60) for k, v in by_workflow.most_common()
        },
        "by_month_minutes": {k: round(by_month[k] / 60) for k in sorted(by_month)},
        "by_month_workflow_minutes": {
            f"{month}/{workflow}": {
                "runs": runs_by_cell[(month, workflow)],
                "minutes": round(by_cell[(month, workflow)] / 60),
            }
            for month, workflow in sorted(by_cell)
        },
    }


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--out", required=True, help="path to write the JSON report")
    args = ap.parse_args()

    runs = fetch_runs()
    if not runs:
        print("no workflow runs read; is gh authenticated?", file=sys.stderr)
        return 1
    report = build(runs)
    with open(args.out, "w", encoding="utf-8") as handle:
        json.dump(report, handle, indent=2, sort_keys=True)
        handle.write("\n")
    print(
        f"{report['estimated_billable_minutes']} billable minutes, "
        f"${report['estimated_gross_usd']} gross "
        f"({report['runs_measured']}/{report['runs_total']} runs measured)"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
