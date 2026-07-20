"""Dry-run source comparison: NVD walk vs vulnpatch /nix/cves.

Read-only. No model spend. No auto-merge path. Walks both discovery sources over
an overlapping recent window and reports overlap / freshness / unique-yield /
disagreement so we can judge whether cve.vulnpatch.dev's Nix-native feed earns a
place alongside (or ahead of) the NVD walk in Scout.

    python eval/compare_sources.py --since 2026-07-01 --until 2026-07-20 \
        --out data/reports/source-comparison.json

Key asymmetry the metrics quantify: the NVD walk returns raw CVE ids that Scout
must still graph-map to a nixpkgs attribute; vulnpatch /nix/cves returns that
join PRE-COMPUTED (attribute + current/fixed version + PR status). So beyond
overlap, we count vulnpatch's pre-joined nixpkgs mappings, its open-but-no-PR
entries (the beat-upstream signal), and its entries carrying an upstream
fixedVersion (bump/backport candidates) — none of which NVD surfaces directly.

Two axes that do NOT line up, handled explicitly:

  * Different clocks. NVD `pubStartDate` filters on CVE *publication* date over
    ALL CVEs; vulnpatch `publishedAt` is when the NixOS tracker ingested the
    nixpkgs advisory, over nixpkgs-affecting CVEs only. So we do NOT window
    vulnpatch by its own `publishedAt` and set-diff the two — that is
    apples-to-oranges. Instead we take vulnpatch's WHOLE snapshot (it is already
    "recent open nixpkgs CVEs") and measure how much of it the NVD walk over
    [since, until] covers. `overlap_in_nvd_window` is the decision metric;
    `vulnpatch_outside_nvd_window` are nixpkgs CVEs whose publication predates the
    window (widen --since to pull them in) or that the NVD walk did not return.

  * Snapshot cap. vulnpatch /nix/cves is a fixed ~100-item snapshot that ignores
    pagination params; `vulnpatch_snapshot_capped` flags when the snapshot is
    full (there may be older open entries it cannot show). Its tracker-time span
    is reported as `vulnpatch_published_range` for context.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

# Support the documented `python eval/compare_sources.py …` invocation from the
# repo root: put the repo root (not eval/) on sys.path so `agents` imports, as
# the other directly-executable eval scripts do.
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from agents.scout.discovery import list_recent_cves  # noqa: E402
from agents.scout.nix_discovery import (  # noqa: E402
    NixCvesSnapshot,
    NixpkgsCve,
    list_nixpkgs_cves,
)


@dataclass(frozen=True)
class Comparison:
    since: str
    until: str
    nvd_window_count: int
    vulnpatch_total: int
    overlap_in_nvd_window: int
    vulnpatch_outside_nvd_window: int
    vulnpatch_prejoined_nixpkgs: int
    vulnpatch_open_no_pr: int
    vulnpatch_fixed_version_present: int
    vulnpatch_snapshot_capped: bool
    vulnpatch_published_range: list[str | None]
    vulnpatch_outside_sample: list[str]

    def to_dict(self) -> dict[str, Any]:
        return {
            "scope": "source-comparison",
            "since": self.since,
            "until": self.until,
            # NVD walk = all CVEs published in window; Scout must graph-map each.
            "nvd_window_count": self.nvd_window_count,
            # vulnpatch = recent open nixpkgs CVEs, already attribute-mapped.
            "vulnpatch_total": self.vulnpatch_total,
            # decision metric: vulnpatch CVEs the NVD window also surfaced.
            "overlap_in_nvd_window": self.overlap_in_nvd_window,
            # vulnpatch nixpkgs CVEs NVD's window missed (older, or walk gap).
            "vulnpatch_outside_nvd_window": self.vulnpatch_outside_nvd_window,
            # vulnpatch's pre-joined value that NVD does not surface directly:
            "vulnpatch_prejoined_nixpkgs": self.vulnpatch_prejoined_nixpkgs,
            "vulnpatch_open_no_pr": self.vulnpatch_open_no_pr,
            "vulnpatch_fixed_version_present": self.vulnpatch_fixed_version_present,
            "vulnpatch_snapshot_capped": self.vulnpatch_snapshot_capped,
            "vulnpatch_published_range": self.vulnpatch_published_range,
            "vulnpatch_outside_sample": self.vulnpatch_outside_sample,
        }


def _parse_day(s: str) -> datetime:
    """Accept YYYY-MM-DD (or full ISO) as a UTC instant."""
    try:
        dt = datetime.fromisoformat(s)
    except ValueError as e:
        raise SystemExit(f"error: --since/--until must be ISO date/datetime, got {s!r}: {e}")
    # Promise a UTC instant: a naive input is read as UTC, an offset-aware one is
    # converted to UTC. The NVD walk formats wall-clock without the offset, so an
    # un-normalized +02:00 input would query the wrong interval (codex 2026-07-20).
    return dt.replace(tzinfo=timezone.utc) if dt.tzinfo is None else dt.astimezone(timezone.utc)


def _range(dates: list[str]) -> list[str | None]:
    ok = sorted(d for d in dates if d)
    return [ok[0], ok[-1]] if ok else [None, None]


def compute_comparison(
    nvd_ids: list[str],
    snapshot: NixCvesSnapshot,
    since: datetime,
    until: datetime,
) -> Comparison:
    """Pure metric computation — no I/O, so it unit-tests offline. `nvd_ids` is
    the NVD walk result for [since, until]; `snapshot` is the FULL vulnpatch
    snapshot (NOT windowed by its own tracker-time `publishedAt` — that clock
    differs from NVD's CVE-publication clock, so windowing it and set-diffing
    would be apples-to-oranges). We measure how much of vulnpatch's whole
    nixpkgs set the NVD window covers."""
    nvd_set = set(nvd_ids)

    entries: list[NixpkgsCve] = list(snapshot.entries)
    # A vulnpatch entry maps to one or more CVE ids; collect every real CVE id.
    vp_ids: set[str] = set()
    for e in entries:
        for cid in {e.cve_id, *e.cve_ids}:
            if cid.startswith("CVE-"):
                vp_ids.add(cid)

    outside = sorted(vp_ids - nvd_set)

    return Comparison(
        since=since.isoformat(),
        until=until.isoformat(),
        nvd_window_count=len(nvd_set),
        vulnpatch_total=len(vp_ids),
        overlap_in_nvd_window=len(vp_ids & nvd_set),
        vulnpatch_outside_nvd_window=len(outside),
        vulnpatch_prejoined_nixpkgs=sum(1 for e in entries if e.nixpkgs_attribute),
        vulnpatch_open_no_pr=sum(1 for e in entries if e.status == "open" and not e.has_pr),
        vulnpatch_fixed_version_present=sum(1 for e in entries if e.has_fixed_version),
        vulnpatch_snapshot_capped=snapshot.capped,
        vulnpatch_published_range=_range([e.published_at for e in entries]),
        vulnpatch_outside_sample=outside[:25],
    )


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Compare NVD vs vulnpatch /nix/cves discovery yield (dry-run).")
    ap.add_argument("--since", required=True, help="window start, ISO date (UTC)")
    ap.add_argument("--until", required=True, help="window end, ISO date (UTC)")
    ap.add_argument("--out", help="write JSON report here (default: stdout only)")
    args = ap.parse_args(argv)

    since = _parse_day(args.since)
    until = _parse_day(args.until)
    if since >= until:
        raise SystemExit(f"error: --since ({since}) must be before --until ({until})")

    api_key = os.environ.get("NVD_API_KEY") or None
    print(f"walking NVD {since.date()}..{until.date()} (anon={api_key is None})…", file=sys.stderr)
    nvd_ids = list_recent_cves(since, until, api_key=api_key)
    print(f"  NVD: {len(nvd_ids)} CVE ids", file=sys.stderr)

    print("fetching vulnpatch /nix/cves snapshot…", file=sys.stderr)
    snapshot = list_nixpkgs_cves()
    print(f"  vulnpatch: {len(snapshot.entries)} entries (capped={snapshot.capped})", file=sys.stderr)

    result = compute_comparison(nvd_ids, snapshot, since, until)
    report = result.to_dict()
    if result.vulnpatch_snapshot_capped:
        print("  NOTE: vulnpatch snapshot is capped at ~100; older open nixpkgs "
              "entries may exist beyond it.", file=sys.stderr)

    text = json.dumps(report, indent=2)
    if args.out:
        with open(args.out, "w") as f:
            f.write(text + "\n")
        print(f"wrote {args.out}", file=sys.stderr)
    print(text)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
