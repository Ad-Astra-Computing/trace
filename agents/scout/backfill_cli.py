"""Scout backfill CLI: catch-up over a wider window than the hourly cron.

Backfill is a deliberate, gated operation. Unlike the cron, it never
runs without an explicit window argument and rejects ranges that NVD
would refuse (>120 days). Within those guardrails it reuses the
existing list_recent_cves -> batch_cli pipeline and adds an
aggregate-counts.json summary so a single run produces both per-CVE
detail (run-summary.jsonl) and roll-up metrics.

  python -m agents.scout.backfill_cli \\
      --since-days 7 \\
      --graph-snapshot snapshot/nixpkgs-snapshot.json \\
      --inbox inbox \\
      --output-dir out/backfill-2026-04-30

Optional flags:
  --since/--until  ISO-8601 window (mutually exclusive with --since-days)
  --cap            limit number of CVEs processed (default: no cap)
  --cpe-index      product-keyed CPE index built by cpe_dictionary_cli

Exit codes:
  0   ok
  10  fetch-failed / transient
  20  rate-limited
  64  usage error
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from collections import Counter
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from agents.scout import batch_cli
from agents.scout.discovery import list_recent_cves
from agents.scout.feed_client import (
    FeedDecodeError,
    FeedNotFound,
    FeedRateLimit,
    FeedTransientError,
)


_EXIT_OK = 0
_EXIT_FETCH_FAILED = 10
_EXIT_RATE_LIMITED = 20
_EXIT_USAGE = 64

_NVD_MAX_WINDOW_DAYS = 120


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="trace-scout-backfill")
    parser.add_argument(
        "--since-days",
        type=int,
        default=None,
        help="Window in days, ending now. Mutually exclusive with --since/--until.",
    )
    parser.add_argument(
        "--since", help="ISO-8601 window start; required when --since-days absent."
    )
    parser.add_argument("--until", help="ISO-8601 window end; defaults to now.")
    parser.add_argument("--graph-snapshot", required=True, type=Path)
    parser.add_argument("--inbox", required=True, type=Path)
    parser.add_argument(
        "--output-dir",
        required=True,
        type=Path,
        help="Directory for run-summary.jsonl and aggregate-counts.json.",
    )
    parser.add_argument("--cpe-index", type=Path, default=None)
    parser.add_argument(
        "--nixpkgs-root",
        type=Path,
        default=None,
        help="Path to a nixpkgs checkout. With "
        "TRACE_REAL_PREFETCH=1 in env, enables "
        "auto-prefetch of plain-fetchurl src.hash.",
    )
    parser.add_argument(
        "--use-nix-eval",
        action="store_true",
        help="Allow path resolver `nix eval` fallback for non-by-name packages.",
    )
    parser.add_argument(
        "--cap",
        type=int,
        default=None,
        help="Hard limit on number of CVEs processed (defence against runaway scopes).",
    )
    args = parser.parse_args(argv)

    window = _resolve_window(args)
    if window is None:
        return _EXIT_USAGE
    since, until = window

    if not args.graph_snapshot.is_file():
        print(
            f"error: graph snapshot not found: {args.graph_snapshot}", file=sys.stderr
        )
        return _EXIT_USAGE
    if args.cpe_index is not None and not args.cpe_index.is_file():
        print(f"error: --cpe-index not found: {args.cpe_index}", file=sys.stderr)
        return _EXIT_USAGE

    api_key = os.environ.get("NVD_API_KEY") or None
    try:
        discovered = list_recent_cves(since=since, until=until, api_key=api_key)
    except FeedRateLimit as e:
        print(f"rate-limited; retry after {e.retry_after}s", file=sys.stderr)
        return _EXIT_RATE_LIMITED
    except (FeedNotFound, FeedTransientError, FeedDecodeError) as e:
        print(f"discovery failed: {e}", file=sys.stderr)
        return _EXIT_FETCH_FAILED

    cap_applied = args.cap is not None and len(discovered) > args.cap
    to_process = discovered[: args.cap] if args.cap is not None else list(discovered)

    args.output_dir.mkdir(parents=True, exist_ok=True)
    run_summary = args.output_dir / "run-summary.jsonl"
    ids_file = args.output_dir / "cve-ids.txt"
    ids_file.write_text("\n".join(to_process) + ("\n" if to_process else ""))

    if to_process:
        batch_argv = [
            "--cve-ids-file",
            str(ids_file),
            "--graph-snapshot",
            str(args.graph_snapshot),
            "--inbox",
            str(args.inbox),
            "--output-jsonl",
            str(run_summary),
        ]
        if args.cpe_index is not None:
            batch_argv += ["--cpe-index", str(args.cpe_index)]
        if args.nixpkgs_root is not None:
            batch_argv += [
                "--nixpkgs-root",
                str(args.nixpkgs_root),
                "--aggregate-counts",
                str(args.output_dir / "auto-prefetch-counts.json"),
            ]
            if args.use_nix_eval:
                batch_argv += ["--use-nix-eval"]
        rc = _run_batch(batch_argv)
        if rc != 0:
            print(f"batch_cli exited with {rc}", file=sys.stderr)
            # Continue anyway: aggregate whatever did make it to the summary.
    else:
        run_summary.write_text("")

    counts = _aggregate(
        run_summary=run_summary,
        discovered=len(discovered),
        cap_applied=cap_applied,
        since=since,
        until=until,
    )
    (args.output_dir / "aggregate-counts.json").write_text(
        json.dumps(counts, indent=2, sort_keys=True) + "\n"
    )
    _print_summary(counts)
    return _EXIT_OK


def _run_batch(argv: list[str]) -> int:
    return batch_cli.main(argv)


def _resolve_window(args: argparse.Namespace) -> tuple[datetime, datetime] | None:
    if args.since_days is not None and (args.since or args.until):
        print(
            "error: --since-days is mutually exclusive with --since/--until",
            file=sys.stderr,
        )
        return None
    if args.since_days is None and not args.since:
        print(
            "error: must pass --since-days or --since (no implicit default for backfill)",
            file=sys.stderr,
        )
        return None

    until = _parse_iso(args.until) if args.until else datetime.now(timezone.utc)
    if until is None:
        return None
    if args.since_days is not None:
        if args.since_days <= 0:
            print("error: --since-days must be positive", file=sys.stderr)
            return None
        since = until - timedelta(days=args.since_days)
    else:
        since = _parse_iso(args.since)
        if since is None:
            return None

    span = (until - since).total_seconds() / 86400
    if span > _NVD_MAX_WINDOW_DAYS:
        print(
            f"error: window is {span:.1f} days; NVD pubStart/pubEnd "
            f"caps at {_NVD_MAX_WINDOW_DAYS} days. Run multiple smaller "
            f"backfills if you need a longer history.",
            file=sys.stderr,
        )
        return None
    if since >= until:
        print(
            f"error: since ({since.isoformat()}) must be before until ({until.isoformat()})",
            file=sys.stderr,
        )
        return None
    return since, until


def _parse_iso(s: str) -> datetime | None:
    raw = s.replace("Z", "+00:00")
    try:
        dt = datetime.fromisoformat(raw)
    except ValueError:
        print(f"error: cannot parse ISO-8601 datetime: {s!r}", file=sys.stderr)
        return None
    if dt.tzinfo is None:
        print(f"error: timezone-aware datetime required: {s!r}", file=sys.stderr)
        return None
    return dt


def _aggregate(
    *,
    run_summary: Path,
    discovered: int,
    cap_applied: bool,
    since: datetime,
    until: datetime,
) -> dict[str, Any]:
    actions: Counter[str] = Counter()
    steward_states: Counter[str] = Counter()
    resolver_verdicts: Counter[str] = Counter()
    reason_codes: Counter[str] = Counter()
    finding_statuses: Counter[str] = Counter()
    processed = 0

    if run_summary.is_file():
        for line in run_summary.read_text().splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                row = json.loads(line)
            except json.JSONDecodeError:
                continue
            processed += 1
            if isinstance(row.get("action"), str):
                actions[row["action"]] += 1
            if isinstance(row.get("steward_state"), str):
                steward_states[row["steward_state"]] += 1
            if isinstance(row.get("resolver_status"), str):
                resolver_verdicts[row["resolver_status"]] += 1
            if isinstance(row.get("finding_status"), str):
                finding_statuses[row["finding_status"]] += 1
            for code in row.get("steward_reasons") or []:
                if isinstance(code, str):
                    reason_codes[code] += 1

    return {
        "schema_version": "1.0.0",
        "window": {
            "since": _zulu(since),
            "until": _zulu(until),
            "days": round((until - since).total_seconds() / 86400, 3),
        },
        "discovered": discovered,
        "processed": processed,
        "cap_applied": cap_applied,
        "actions": dict(actions),
        "finding_statuses": dict(finding_statuses),
        "resolver_verdicts": dict(resolver_verdicts),
        "steward_states": dict(steward_states),
        "reason_codes": dict(reason_codes),
    }


def _zulu(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _print_summary(counts: dict[str, Any]) -> None:
    print(
        f"backfill window {counts['window']['since']} to {counts['window']['until']} "
        f"({counts['window']['days']} days): "
        f"discovered={counts['discovered']} processed={counts['processed']}"
        + (" (capped)" if counts["cap_applied"] else ""),
        file=sys.stderr,
    )
    if counts["steward_states"]:
        print(f"steward_states: {counts['steward_states']}", file=sys.stderr)
    if counts["reason_codes"]:
        top = sorted(counts["reason_codes"].items(), key=lambda x: -x[1])[:10]
        print(f"top reason_codes: {top}", file=sys.stderr)


if __name__ == "__main__":
    sys.exit(main())
