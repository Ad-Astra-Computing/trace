"""CLI: build a nixpkgs graph snapshot and write it to disk.

  python -m agents.scout.snapshot_cli --out snapshot.json
  python -m agents.scout.snapshot_cli --nixpkgs /path/to/nixpkgs --out snapshot.json

Writes a JSON array of records consumable by agents.scout.poll_cli's
--graph-snapshot flag and by snapshot_from_json().

Exit codes:
  0   wrote snapshot
  10  nix-env invocation / parse failed
  64  usage error
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from agents.scout.snapshot_builder import (
    SnapshotBuildError,
    build_snapshot,
    snapshot_to_json,
)


_EXIT_OK = 0
_EXIT_BUILD_FAILED = 10
_EXIT_USAGE = 64


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="trace-scout-snapshot")
    parser.add_argument(
        "--nixpkgs",
        default="<nixpkgs>",
        help="Nix expression for the nixpkgs source (default: <nixpkgs>).",
    )
    parser.add_argument(
        "--out",
        required=True,
        type=Path,
        help="Path to write the snapshot JSON.",
    )
    parser.add_argument(
        "--timeout-s",
        type=int,
        default=1800,
        help="Subprocess timeout in seconds (default: 1800 = 30 min).",
    )
    args = parser.parse_args(argv)

    try:
        records = build_snapshot(nixpkgs=args.nixpkgs, timeout_s=args.timeout_s)
    except SnapshotBuildError as e:
        print(f"snapshot build failed: {e}", file=sys.stderr)
        return _EXIT_BUILD_FAILED

    payload = snapshot_to_json(records)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(payload + "\n")
    print(f"wrote {len(records)} records to {args.out}", file=sys.stderr)
    return _EXIT_OK


if __name__ == "__main__":
    sys.exit(main())
