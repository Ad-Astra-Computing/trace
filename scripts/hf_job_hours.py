#!/usr/bin/env python3
"""Reconstruct Hugging Face Jobs GPU spend for this project.

The Jobs API reports `durations.totalSecs` per job, which is scheduling plus
running time, and the flavor the job ran on. Billing is per second of wall
clock at the flavor's published hourly rate, so the spend is that duration
against `RATE_PER_HOUR`. Jobs still running are skipped: they have no
`finishedAt` and their duration is not final.

`HF_TOKEN` must be in the environment. Read it from the project `.env`:

    set -a; source .env; set +a
    scripts/hf_job_hours.py --namespace odoom --out data/reports/hf-jobs-<date>.json
"""

from __future__ import annotations

import argparse
import collections
import datetime as dt
import json
import os
import re
import sys
import urllib.error
import urllib.request

# huggingface.co/pricing, read 9 September 2026. A flavor absent here is
# reported under `unpriced_flavors` rather than silently costed at zero.
RATE_PER_HOUR = {
    "cpu-basic": 0.0,
    "cpu-upgrade": 0.03,
    "t4-small": 0.40,
    "t4-medium": 0.60,
    "l4x1": 0.80,
    "a10g-small": 1.00,
    "a10g-large": 1.50,
    "l40sx1": 1.80,
    "a100-large": 2.50,
}

API = "https://huggingface.co/api/jobs"


def _get(url: str, token: str) -> tuple[object, str | None]:
    req = urllib.request.Request(url, headers={"Authorization": f"Bearer {token}"})
    with urllib.request.urlopen(req) as resp:
        body = json.loads(resp.read().decode("utf-8"))
        link = resp.headers.get("link") or ""
    m = re.search(r'<([^>]+)>;\s*rel="next"', link)
    return body, m.group(1) if m else None


class WalkIncomplete(Exception):
    """The page walk stopped early, so any total built from it understates."""


def fetch_jobs(namespace: str, token: str) -> list[dict]:
    """Every job in the namespace, or an exception.

    A partial walk is not a smaller answer, it is a wrong one: the report it
    would produce reads as authoritative while understating the bill. So a
    failure part way through the pages raises rather than returning what it
    has.
    """
    jobs: list[dict] = []
    url = f"{API}/{namespace}"
    while url:
        try:
            batch, url = _get(url, token)
        except (urllib.error.URLError, json.JSONDecodeError) as e:
            raise WalkIncomplete(
                f"page walk failed after {len(jobs)} jobs: {e}") from e
        if not isinstance(batch, list):
            raise WalkIncomplete(f"unexpected response reading {url}")
        if not batch:
            break
        jobs.extend(batch)
    return jobs


def build(jobs: list[dict]) -> dict:
    by_flavor: collections.Counter = collections.Counter()
    runs_by_flavor: collections.Counter = collections.Counter()
    by_month: collections.Counter = collections.Counter()
    runs_by_month: collections.Counter = collections.Counter()
    by_stage: collections.Counter = collections.Counter()
    cost_by_flavor: collections.Counter = collections.Counter()
    cost_by_month: collections.Counter = collections.Counter()
    unpriced: set[str] = set()
    unpriced_jobs = 0
    unfinished = 0
    started_but_unmeasured = 0

    for job in jobs:
        if not job.get("finishedAt"):
            # A job with no `finishedAt` reports no duration. Most never left the
            # queue and cost nothing, but one that has a `startedAt` did hold a
            # GPU for an unrecorded stretch, so it is counted separately rather
            # than folded into the same "no spend" bucket.
            unfinished += 1
            if job.get("startedAt"):
                started_but_unmeasured += 1
            continue
        flavor = job.get("flavor") or "(unknown)"
        month = str(job.get("createdAt", ""))[:7] or "unknown"
        seconds = float((job.get("durations") or {}).get("totalSecs") or 0.0)
        rate = RATE_PER_HOUR.get(flavor)
        if rate is None:
            # A flavor with no published rate has an unknown cost, not a zero
            # one. Costing it at zero would publish an understated total that
            # reads as complete, so the job is left out of every dollar figure
            # and named instead.
            unpriced.add(flavor)
            unpriced_jobs += 1
            continue
        cost = seconds / 3600 * rate

        by_flavor[flavor] += seconds
        runs_by_flavor[flavor] += 1
        by_month[month] += seconds
        runs_by_month[month] += 1
        by_stage[(job.get("status") or {}).get("stage") or "(unknown)"] += 1
        cost_by_flavor[flavor] += cost
        cost_by_month[month] += cost

    return {
        "generated_at": dt.datetime.now(dt.timezone.utc).isoformat(),
        "rate_per_hour_usd": RATE_PER_HOUR,
        "jobs_total": len(jobs),
        "jobs_costed": len(jobs) - unfinished - unpriced_jobs,
        "jobs_unpriced": unpriced_jobs,
        "totals_complete": unpriced_jobs == 0,
        "jobs_unfinished": unfinished,
        "jobs_started_but_unmeasured": started_but_unmeasured,
        "unpriced_flavors": sorted(unpriced),
        "gpu_hours": round(sum(by_flavor.values()) / 3600, 2),
        "estimated_gross_usd": round(sum(cost_by_flavor.values()), 2),
        "by_stage_runs": dict(by_stage.most_common()),
        "by_flavor": {
            flavor: {
                "runs": runs_by_flavor[flavor],
                "hours": round(by_flavor[flavor] / 3600, 2),
                "usd": round(cost_by_flavor[flavor], 2),
            }
            for flavor, _ in by_flavor.most_common()
        },
        "by_month": {
            month: {
                "runs": runs_by_month[month],
                "hours": round(by_month[month] / 3600, 2),
                "usd": round(cost_by_month[month], 2),
            }
            for month in sorted(by_month)
        },
    }


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--namespace", default="odoom", help="HF namespace that owns the jobs")
    ap.add_argument("--out", required=True, help="path to write the JSON report")
    args = ap.parse_args()

    token = os.environ.get("HF_TOKEN")
    if not token:
        print("HF_TOKEN is not set; source the project .env first", file=sys.stderr)
        return 1

    try:
        jobs = fetch_jobs(args.namespace, token)
    except WalkIncomplete as e:
        print(f"{e}; refusing to write a partial report", file=sys.stderr)
        return 1
    if not jobs:
        print(f"no jobs read for {args.namespace}", file=sys.stderr)
        return 1
    report = build(jobs)
    with open(args.out, "w", encoding="utf-8") as handle:
        json.dump(report, handle, indent=2, sort_keys=True)
        handle.write("\n")
    print(
        f"{report['gpu_hours']} GPU hours, ${report['estimated_gross_usd']} "
        f"across {report['jobs_costed']} jobs"
    )
    if not report["totals_complete"]:
        print(
            f"INCOMPLETE: {report['jobs_unpriced']} jobs ran on unpriced flavors "
            f"{report['unpriced_flavors']} and are excluded from the total",
            file=sys.stderr,
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
