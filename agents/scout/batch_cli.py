"""Batch CLI: poll + process N CVEs in a single Python process.

The cron's per-CVE nix-shell + Python startup overhead was running
~5 s per CVE before the actual fetch began. For an hourly cron with
50 CVEs that's 4-5 minutes of pure boot. Collapsing the loop into one
Python invocation drops that to one boot total.

Usage:
  python -m agents.scout.batch_cli \\
      --cve-ids-file out/cve-ids.capped.txt \\
      --graph-snapshot snapshot/nixpkgs-snapshot.json \\
      --inbox inbox \\
      --output-jsonl out/run-summary.jsonl

Behaviour matches running poll_cli then (when written) process_cli for
each id, but in-process: one HTTP client, one CannedGraphLookup, one
sweep through scout.scan + upstream_ref_resolver.resolve. Each CVE
emits one JSON object to the --output-jsonl file (and stdout for
operator visibility); errors per-CVE are isolated and never stop the
batch.

Exit code is 0 unless the inputs are unusable (snapshot missing, file
unreadable). Per-CVE failures land in the JSONL as `action: error`.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Any

from agents.scout.graph_lookup import CannedGraphLookup
from agents.scout.poller import poll_one
from agents.scout.processor import process_entry
from agents.scout.snapshot_builder import snapshot_from_json


_EXIT_OK = 0
_EXIT_USAGE = 64


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="trace-scout-batch")
    parser.add_argument("--cve-ids-file", required=True, type=Path)
    parser.add_argument("--graph-snapshot", required=True, type=Path)
    parser.add_argument("--inbox", required=True, type=Path)
    parser.add_argument("--output-jsonl", required=True, type=Path)
    args = parser.parse_args(argv)

    if not args.cve_ids_file.is_file():
        print(f"error: cve-ids file not found: {args.cve_ids_file}", file=sys.stderr)
        return _EXIT_USAGE
    if not args.graph_snapshot.is_file():
        print(f"error: graph snapshot not found: {args.graph_snapshot}", file=sys.stderr)
        return _EXIT_USAGE

    try:
        records = snapshot_from_json(args.graph_snapshot.read_text())
    except (json.JSONDecodeError, KeyError, TypeError) as e:
        print(f"error: graph snapshot malformed: {e}", file=sys.stderr)
        return _EXIT_USAGE

    graph = CannedGraphLookup(records)
    nvd_api_key = os.environ.get("NVD_API_KEY") or None

    cve_ids = [
        line.strip()
        for line in args.cve_ids_file.read_text().splitlines()
        if line.strip()
    ]

    args.output_jsonl.parent.mkdir(parents=True, exist_ok=True)
    with args.output_jsonl.open("w") as out:
        for cve_id in cve_ids:
            record = _process_one(cve_id, graph=graph, inbox=args.inbox, nvd_api_key=nvd_api_key)
            line = json.dumps(record)
            print(line)
            out.write(line + "\n")

    return _EXIT_OK


def _process_one(
    cve_id: str,
    *,
    graph: CannedGraphLookup,
    inbox: Path,
    nvd_api_key: str | None,
) -> dict[str, Any]:
    """Run poll_one, and on `written` immediately run process_entry.
    Per-CVE exceptions are caught so one bad CVE doesn't kill the batch."""
    try:
        poll = poll_one(cve_id, graph=graph, root=inbox, nvd_api_key=nvd_api_key)
    except ValueError as e:
        return {"cve_id": cve_id, "action": "error", "reason": f"poll input error: {e}"}
    except Exception as e:
        return {"cve_id": cve_id, "action": "error", "reason": f"poll exception: {e}"}

    base: dict[str, Any] = {
        "cve_id": poll.cve_id,
        "action": poll.action,
        "reason": poll.reason,
        "feed_used": poll.feed_used,
        "entry_path": str(poll.entry_path) if poll.entry_path else None,
        "retry_after_seconds": poll.retry_after_seconds,
    }

    if poll.action != "written" or poll.entry_path is None:
        return base

    try:
        process = process_entry(poll.entry_path, graph=graph)
    except Exception as e:
        base["finding_status"] = "error"
        base["resolver_status"] = None
        base["process_error"] = f"process exception: {e}"
        return base

    base["finding_status"] = process.finding_status
    base["resolver_status"] = process.resolver_status
    return base


if __name__ == "__main__":
    sys.exit(main())
