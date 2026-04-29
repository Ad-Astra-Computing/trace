"""CLI wrapper for list_recent_cves.

  python -m agents.scout.discover_cli --lookback-hours 24
  python -m agents.scout.discover_cli --since 2026-04-28T00:00:00Z \\
                                      --until 2026-04-29T00:00:00Z

Prints one CVE id per line to stdout. Reads NVD_API_KEY from the
environment (anonymous-first; never required).

Exit codes:
  0   completed (zero or more ids printed)
  10  fetch-failed / transient
  20  rate-limited (server retry-after surfaced on stderr)
  64  usage error
"""

from __future__ import annotations

import argparse
import os
import sys
from datetime import datetime, timedelta, timezone

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


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="trace-scout-discover")
    parser.add_argument(
        "--since",
        help="Window start, ISO-8601 with timezone (e.g. 2026-04-28T00:00:00Z).",
    )
    parser.add_argument(
        "--until",
        help="Window end, ISO-8601 with timezone. Defaults to now (UTC).",
    )
    parser.add_argument(
        "--lookback-hours",
        type=float,
        default=None,
        help="Convenience: query the last N hours. Mutually exclusive with --since.",
    )
    args = parser.parse_args(argv)

    if args.since and args.lookback_hours is not None:
        print("error: --since and --lookback-hours are mutually exclusive", file=sys.stderr)
        return _EXIT_USAGE

    until = _parse_iso(args.until) if args.until else datetime.now(timezone.utc)
    if args.since:
        since = _parse_iso(args.since)
    elif args.lookback_hours is not None:
        since = until - timedelta(hours=args.lookback_hours)
    else:
        since = until - timedelta(hours=24)

    if since is None or until is None:
        return _EXIT_USAGE

    api_key = os.environ.get("NVD_API_KEY") or None

    try:
        cve_ids = list_recent_cves(since=since, until=until, api_key=api_key)
    except FeedRateLimit as e:
        print(f"rate-limited; retry after {e.retry_after}s", file=sys.stderr)
        return _EXIT_RATE_LIMITED
    except (FeedNotFound, FeedTransientError, FeedDecodeError) as e:
        print(f"discovery failed: {e}", file=sys.stderr)
        return _EXIT_FETCH_FAILED
    except ValueError as e:
        print(f"error: {e}", file=sys.stderr)
        return _EXIT_USAGE

    for cid in cve_ids:
        print(cid)
    return _EXIT_OK


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


if __name__ == "__main__":
    sys.exit(main())
