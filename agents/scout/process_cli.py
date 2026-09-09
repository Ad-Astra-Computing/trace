"""Run process_entry against a single inbox entry, using the snapshot
referenced by the GRAPH_SNAPSHOT env var. Helper for scout-cron.yml.

Required env:
  GRAPH_SNAPSHOT     path to graph-snapshot JSON
  PROCESS_CVE_ID     CVE id whose inbox entry to process
                     (the loop already wrote inbox/<CVE-ID>/scout-input.json)

Prints a single JSON line: {cve_id, finding_status, resolver_status}.
Exit codes: 0 ok; 64 missing env / inputs; 1 anything else.
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

from agents.scout.graph_lookup import CannedGraphLookup
from agents.scout.processor import process_entry
from agents.scout.snapshot_builder import snapshot_from_json


def main() -> int:
    snapshot = os.environ.get("GRAPH_SNAPSHOT", "")
    cve_id = os.environ.get("PROCESS_CVE_ID", "")
    if not snapshot or not cve_id:
        print(
            "error: GRAPH_SNAPSHOT and PROCESS_CVE_ID env vars required",
            file=sys.stderr,
        )
        return 64

    snap_path = Path(snapshot)
    if not snap_path.is_file():
        print(f"error: snapshot not found at {snap_path}", file=sys.stderr)
        return 64

    graph = CannedGraphLookup(snapshot_from_json(snap_path.read_text()))
    out = process_entry(Path("inbox") / cve_id, graph=graph)
    print(
        json.dumps(
            {
                "cve_id": out.cve_id,
                "finding_status": out.finding_status,
                "resolver_status": out.resolver_status,
            }
        )
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
