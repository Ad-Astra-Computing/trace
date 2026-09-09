"""Scout poll CLI entrypoint.

  python -m agents.scout.poll_cli <CVE-ID> \\
      --graph-snapshot path/to/snapshot.json \\
      --inbox path/to/inbox

Snapshot format: a JSON array of records matching `GraphMatch` shape:

  [
    {"attr_path": "libtiff", "drv_path": "/nix/store/...", "pname": "libtiff",
     "version": "4.7.0", "cpes": ["cpe:2.3:a:libtiff:libtiff:..."],
     "purls": [], "src_url": null, "src_hash": null},
    ...
  ]

The CLI reads NVD_API_KEY from the environment but never requires it
(anonymous-first per the locked Scout decisions).

Exit codes mirror the PollOutcome action so the cron can branch:
  0  written
  0  skipped-irrelevant
  10 fetch-failed
  20 rate-limited
  64 usage error
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Any

from agents.scout.graph_lookup import CannedGraphLookup, GraphMatch
from agents.scout.poller import poll_one


_EXIT_OK = 0
_EXIT_FETCH_FAILED = 10
_EXIT_RATE_LIMITED = 20
_EXIT_USAGE = 64


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="trace-scout-poll")
    parser.add_argument("cve_id")
    parser.add_argument(
        "--graph-snapshot",
        required=True,
        type=Path,
        help="Path to a JSON snapshot of the nixpkgs graph (array of GraphMatch records).",
    )
    parser.add_argument(
        "--inbox",
        required=True,
        type=Path,
        help="Inbox directory; poll_one writes <inbox>/<CVE-ID>/... on success.",
    )
    args = parser.parse_args(argv)

    if not args.graph_snapshot.is_file():
        print(
            f"error: graph snapshot not found: {args.graph_snapshot}", file=sys.stderr
        )
        return _EXIT_USAGE

    try:
        graph = _load_snapshot(args.graph_snapshot)
    except (json.JSONDecodeError, KeyError, TypeError) as e:
        print(f"error: graph snapshot malformed: {e}", file=sys.stderr)
        return _EXIT_USAGE

    nvd_api_key = os.environ.get("NVD_API_KEY") or None

    try:
        outcome = poll_one(
            args.cve_id,
            graph=graph,
            root=args.inbox,
            nvd_api_key=nvd_api_key,
        )
    except ValueError as e:
        print(f"error: {e}", file=sys.stderr)
        return _EXIT_USAGE

    record = {
        "cve_id": outcome.cve_id,
        "action": outcome.action,
        "reason": outcome.reason,
        "feed_used": outcome.feed_used,
        "entry_path": str(outcome.entry_path) if outcome.entry_path else None,
        "retry_after_seconds": outcome.retry_after_seconds,
    }
    print(json.dumps(record))

    if outcome.action == "fetch-failed":
        return _EXIT_FETCH_FAILED
    if outcome.action == "rate-limited":
        return _EXIT_RATE_LIMITED
    return _EXIT_OK


def _load_snapshot(path: Path) -> CannedGraphLookup:
    raw = json.loads(path.read_text())
    if not isinstance(raw, list):
        raise TypeError("snapshot must be a JSON array")
    records: list[GraphMatch] = []
    for entry in raw:
        records.append(
            GraphMatch(
                attr_path=entry["attr_path"],
                drv_path=entry["drv_path"],
                pname=entry["pname"],
                version=entry["version"],
                cpes=tuple(entry.get("cpes") or ()),
                purls=tuple(entry.get("purls") or ()),
                src_url=entry.get("src_url"),
                src_hash=entry.get("src_hash"),
            )
        )
    return CannedGraphLookup(records)


if __name__ == "__main__":
    sys.exit(main())
