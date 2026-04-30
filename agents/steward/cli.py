"""Steward routing CLI.

  python -m agents.steward.cli inbox/CVE-2026-42615

Reads the inbox entry and writes steward-decision.json. Prints the
decision JSON to stdout for cron / log capture.

Exit codes:
  0   decision written
  64  usage / inbox entry missing
  10  opa not available
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from agents.steward.agent import OpaUnavailable, route_inbox_entry


_EXIT_OK = 0
_EXIT_OPA_UNAVAILABLE = 10
_EXIT_USAGE = 64


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="trace-steward-route")
    parser.add_argument("entry", type=Path, help="Path to an inbox/<CVE-ID> directory.")
    args = parser.parse_args(argv)

    if not args.entry.is_dir():
        print(f"error: not a directory: {args.entry}", file=sys.stderr)
        return _EXIT_USAGE

    try:
        decision = route_inbox_entry(args.entry)
    except OpaUnavailable as e:
        print(f"error: {e}", file=sys.stderr)
        return _EXIT_OPA_UNAVAILABLE

    print(json.dumps(decision))
    return _EXIT_OK


if __name__ == "__main__":
    sys.exit(main())
