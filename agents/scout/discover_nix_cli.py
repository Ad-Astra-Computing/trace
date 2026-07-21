"""CLI wrapper for list_nixpkgs_cves — the vulnpatch /nix/cves seed source.

  python -m agents.scout.discover_nix_cli
  python -m agents.scout.discover_nix_cli --since 2026-07-10T00:00:00Z \\
                                          --until 2026-07-20T00:00:00Z
  python -m agents.scout.discover_nix_cli --lookback-hours 168

Prints one CVE id per line to stdout, exactly like `discover_cli`, so the
cron workflow can concatenate the two discovery sources into one poll queue.
Every id printed here still flows through the same poll -> process path
(graph lookup + relevance scoring), so the vulnpatch nixpkgs mapping is a
seed hint, never a merge decision (DECISIONS 2026-07-20 trust boundary).

The /nix/cves endpoint ignores server-side windowing and returns a fixed
~100-item snapshot, so any --since/--until/--lookback-hours filter is applied
CLIENT-SIDE on each entry's `published_at`. With no window flag the whole
snapshot is emitted (its natural mode — the pre-mapped fast path). An entry
may carry several cve ids (`cve_ids`); all of them are emitted, deduped in
first-seen order. No auth; NVD_API_KEY is not read here.

Exit codes (mirror discover_cli so the workflow treats both sources alike):
  0   completed (zero or more ids printed)
  10  fetch-failed / transient / decode
  20  rate-limited (server retry-after surfaced on stderr)
  64  usage error
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

from agents.scout.feed_client import (
    FeedDecodeError,
    FeedNotFound,
    FeedRateLimit,
    FeedTransientError,
)
from agents.scout.nix_discovery import list_nixpkgs_cves
from agents.scout.nix_seed_ledger import (
    aggregate_fingerprint,
    fingerprint_fields,
    read_ledger,
    should_emit,
)


_EXIT_OK = 0
_EXIT_FETCH_FAILED = 10
_EXIT_RATE_LIMITED = 20
_EXIT_USAGE = 64

_CVE_RE = re.compile(r"^CVE-[0-9]{4}-[0-9]{4,19}$")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="trace-scout-discover-nix")
    parser.add_argument(
        "--since",
        help="Client-side filter: keep entries published at/after this "
        "ISO-8601 (tz-aware) instant. The endpoint itself ignores windowing.",
    )
    parser.add_argument(
        "--until",
        help="Client-side filter: keep entries published at/before this ISO-8601 instant.",
    )
    parser.add_argument(
        "--lookback-hours",
        type=float,
        default=None,
        help="Convenience: keep entries published in the last N hours. "
        "Mutually exclusive with --since.",
    )
    parser.add_argument(
        "--seen-ledger",
        default=None,
        help="Path to the cross-run evaluation ledger (state/nix-seed-seen.jsonl). "
        "When set, a snapshot CVE is emitted only if it is new, previously "
        "retryable, its upstream record changed, or its last terminal outcome is "
        "older than --ttl-days. This is the intended cron mode (no window flag): "
        "drains the backlog once, then emits deltas.",
    )
    parser.add_argument(
        "--emit-sidecar",
        default=None,
        help="Path to write an ephemeral {cve_id, fingerprint} JSONL for each "
        "emitted id, so the post-run ledger update knows what fingerprint each "
        "id was evaluated at. Only meaningful with --seen-ledger.",
    )
    parser.add_argument(
        "--ttl-days",
        type=int,
        default=30,
        help="Re-emit a terminally-evaluated CVE after this many days even if "
        "unchanged (default 30). Only meaningful with --seen-ledger.",
    )
    args = parser.parse_args(argv)

    if args.since and args.lookback_hours is not None:
        print("error: --since and --lookback-hours are mutually exclusive", file=sys.stderr)
        return _EXIT_USAGE

    until: datetime | None = None
    since: datetime | None = None
    if args.until:
        until = _parse_iso(args.until)
        if until is None:
            return _EXIT_USAGE
    if args.since:
        since = _parse_iso(args.since)
        if since is None:
            return _EXIT_USAGE
    elif args.lookback_hours is not None:
        anchor = until or datetime.now(timezone.utc)
        since = anchor - timedelta(hours=args.lookback_hours)

    try:
        snapshot = list_nixpkgs_cves()
    except FeedRateLimit as e:
        print(f"rate-limited; retry after {e.retry_after}s", file=sys.stderr)
        return _EXIT_RATE_LIMITED
    except (FeedNotFound, FeedTransientError, FeedDecodeError) as e:
        print(f"nix discovery failed: {e}", file=sys.stderr)
        return _EXIT_FETCH_FAILED

    ledger = read_ledger(Path(args.seen_ledger)) if args.seen_ledger else {}
    now = datetime.now(timezone.utc)
    sidecar_lines: list[str] = []

    # First pass: collect every record's fingerprint per cve id, in first-seen
    # order. A CVE can span multiple snapshot records (separate affected attrs),
    # each with its own upstream state; the change signal must aggregate all of
    # them so a change on any record — not just the first seen — re-triggers
    # evaluation (codex audit 2026-07-21).
    order: list[str] = []
    fps_by_cid: dict[str, list[str]] = {}
    for entry in snapshot.entries:
        if not _in_window(entry.published_at, since, until):
            continue
        fp = fingerprint_fields(
            status=entry.status,
            fixed_version=entry.fixed_version,
            updated_at=entry.updated_at,
            has_pr=entry.has_pr,
            has_open_pr=entry.has_open_pr,
            has_merged_pr=entry.has_merged_pr,
        )
        # An entry's primary cve_id first, then any additional ids it groups.
        for cid in (entry.cve_id, *entry.cve_ids):
            if not _CVE_RE.match(cid):
                continue
            if cid not in fps_by_cid:
                fps_by_cid[cid] = []
                order.append(cid)
            fps_by_cid[cid].append(fp)

    # Second pass: gate each cve id on its AGGREGATE fingerprint.
    for cid in order:
        fp = aggregate_fingerprint(fps_by_cid[cid])
        if args.seen_ledger and not should_emit(
            ledger.get(cid),
            current_fingerprint=fp,
            now=now,
            ttl_days=args.ttl_days,
        ):
            continue
        print(cid)
        if args.emit_sidecar:
            sidecar_lines.append(
                json.dumps({"cve_id": cid, "fingerprint": fp}, sort_keys=True)
            )

    if args.emit_sidecar:
        sidecar = Path(args.emit_sidecar)
        sidecar.parent.mkdir(parents=True, exist_ok=True)
        sidecar.write_text("".join(s + "\n" for s in sidecar_lines))
    return _EXIT_OK


def _in_window(published_at: str, since: datetime | None, until: datetime | None) -> bool:
    """Client-side published_at window. An unparseable timestamp fails OPEN
    (kept) rather than silently dropping a real candidate — the poll loop is
    the authority that confirms or discards it."""
    if since is None and until is None:
        return True
    when = _parse_iso(published_at, quiet=True)
    if when is None:
        return True
    if since is not None and when < since:
        return False
    if until is not None and when > until:
        return False
    return True


def _parse_iso(s: str, *, quiet: bool = False) -> datetime | None:
    raw = s.replace("Z", "+00:00")
    try:
        dt = datetime.fromisoformat(raw)
    except ValueError:
        if not quiet:
            print(f"error: cannot parse ISO-8601 datetime: {s!r}", file=sys.stderr)
        return None
    if dt.tzinfo is None:
        if not quiet:
            print(f"error: timezone-aware datetime required: {s!r}", file=sys.stderr)
        return None
    return dt.astimezone(timezone.utc)


if __name__ == "__main__":
    sys.exit(main())
