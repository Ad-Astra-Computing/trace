"""Retry queue CLI: emit + update.

Two subcommands the cron workflow drives:

  emit   read state/scout-retry.jsonl and print one CVE id per line
         (in first_seen order) so the workflow can prepend them to
         the freshly-discovered window.

  update read out/run-summary.jsonl and the existing queue, write
         the new queue back to disk. Walks each record:
            written / skipped-irrelevant → drop
            fetch-failed / rate-limited / error → attempts++
            attempts > max_attempts → drop with ::warning::

Exit codes:
  0   ok
  64  usage error
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from agents.scout.retry_queue import (
    cve_ids_for_retry,
    enqueue_ids,
    read_queue,
    update_queue,
    write_queue,
)


_EXIT_OK = 0
_EXIT_USAGE = 64


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="trace-scout-retry")
    sub = parser.add_subparsers(dest="cmd", required=True)

    emit = sub.add_parser("emit", help="print CVE ids in the queue, one per line")
    emit.add_argument("--queue", required=True, type=Path)

    upd = sub.add_parser("update", help="update queue from a run summary")
    upd.add_argument("--queue", required=True, type=Path)
    upd.add_argument("--run-summary", required=True, type=Path)
    upd.add_argument(
        "--run-at", required=True, help="ISO-8601 UTC timestamp for this run"
    )
    upd.add_argument("--max-attempts", type=int, default=3)
    upd.add_argument(
        "--also-enqueue",
        type=Path,
        default=None,
        help="Optional file of CVE ids (one per line) that were discovered but "
        "not processed this run (displaced past the cap). They are added to the "
        "queue at attempts=0 so the next run picks them up instead of losing "
        "them to the advancing discovery cursor. Missing file is a no-op.",
    )

    args = parser.parse_args(argv)

    if args.cmd == "emit":
        for cve_id in cve_ids_for_retry(read_queue(args.queue)):
            print(cve_id)
        return _EXIT_OK

    if args.cmd == "update":
        if not args.run_summary.is_file():
            print(f"error: run-summary not found: {args.run_summary}", file=sys.stderr)
            return _EXIT_USAGE
        run_summary = []
        for line in args.run_summary.read_text().splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                run_summary.append(json.loads(line))
            except json.JSONDecodeError:
                continue
        existing = read_queue(args.queue)
        new_q = update_queue(
            existing=existing,
            run_summary=run_summary,
            run_at=args.run_at,
            max_attempts=args.max_attempts,
        )
        if args.also_enqueue is not None and args.also_enqueue.is_file():
            displaced = [
                ln.strip()
                for ln in args.also_enqueue.read_text().splitlines()
                if ln.strip()
            ]
            new_q = enqueue_ids(new_q, displaced, run_at=args.run_at)
        write_queue(args.queue, new_q)
        print(
            f"queue updated: {len(existing)} → {len(new_q)} entries",
            file=sys.stderr,
        )
        return _EXIT_OK

    return _EXIT_USAGE


if __name__ == "__main__":
    sys.exit(main())
