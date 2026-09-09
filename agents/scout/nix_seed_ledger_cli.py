"""nix_seed_ledger CLI: post-run update.

  update  read out/run-summary.jsonl + the emit sidecar + the existing ledger,
          fold this run's outcomes in, write the ledger back. Terminal outcomes
          (written / skipped-irrelevant) are recorded with last_evaluated=run_at;
          retryable/error outcomes are recorded but stay re-emittable; CVEs
          emitted but missing from the summary (crash before poll) are left
          untouched so they re-emit next run.

The ledger is written by THIS step only (single writer). Emission
(discover_nix_cli --seen-ledger) only reads it, so a crash mid-run never
marks a CVE seen without a real outcome.

Exit codes:
  0   ok
  64  usage error
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from agents.scout.nix_seed_ledger import read_ledger, update_ledger, write_ledger


_EXIT_OK = 0
_EXIT_USAGE = 64


def _read_jsonl(path: Path) -> list[dict]:
    out: list[dict] = []
    for line in path.read_text().splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            data = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(data, dict):
            out.append(data)
    return out


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="trace-scout-nix-seed-ledger")
    sub = parser.add_subparsers(dest="cmd", required=True)

    upd = sub.add_parser("update", help="fold a run summary into the ledger")
    upd.add_argument("--ledger", required=True, type=Path)
    upd.add_argument(
        "--sidecar",
        required=True,
        type=Path,
        help="emit sidecar written by discover_nix_cli --emit-sidecar",
    )
    upd.add_argument("--run-summary", required=True, type=Path)
    upd.add_argument(
        "--run-at", required=True, help="ISO-8601 UTC timestamp for this run"
    )

    args = parser.parse_args(argv)

    if args.cmd == "update":
        # A missing sidecar means the seed emitted nothing this run (or was
        # disabled) — nothing to fold, leave the ledger as-is.
        if not args.sidecar.is_file():
            print("no emit sidecar; ledger unchanged", file=sys.stderr)
            return _EXIT_OK
        if not args.run_summary.is_file():
            print(f"error: run-summary not found: {args.run_summary}", file=sys.stderr)
            return _EXIT_USAGE

        emitted_fingerprints: dict[str, str] = {}
        for rec in _read_jsonl(args.sidecar):
            cid = rec.get("cve_id")
            fp = rec.get("fingerprint")
            if isinstance(cid, str) and isinstance(fp, str):
                emitted_fingerprints[cid] = fp

        run_summary = _read_jsonl(args.run_summary)
        existing = read_ledger(args.ledger)
        new_ledger = update_ledger(
            existing=existing,
            emitted_fingerprints=emitted_fingerprints,
            run_summary=run_summary,
            run_at=args.run_at,
        )
        write_ledger(args.ledger, new_ledger.values())
        print(
            f"nix-seed ledger: {len(new_ledger)} entries "
            f"(+{len(new_ledger) - len(existing)} new this run)",
            file=sys.stderr,
        )
        return _EXIT_OK

    return _EXIT_USAGE


if __name__ == "__main__":
    sys.exit(main())
