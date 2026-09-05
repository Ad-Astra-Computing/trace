"""Bucket beat-upstream screen rejections by WHY they missed the source-backport tier.

The 2026-09-01 14-day screen rejected all 984 nixpkgs-mapped CVEs as
`not-source-backport-tier`. That verdict is a single bucket for several
different situations, only some of which are real "no gap" outcomes:

  A  no-fix-commit        no candidate_refs: no reference URL matched the commit
                          regexes. Sub-count `regex-miss` when a reference still
                          looks like a fix (commit/pull/merge_request/.patch URL).
  B  release-nixpkgs-behind  a fix commit AND a derived fixed version, and the
                          nixpkgs snapshot version is BELOW it: the project fixed
                          it, nixpkgs has not shipped it. This is the window trace
                          exists for and the tier currently rejects it.
  C  release-nixpkgs-current  fix commit + fixed version, snapshot >= fixed. Not a gap.
  D  ambiguous-fixed-version  fix commit, bounds only lessThanOrEqual: fix exists,
                          version unknown. Currently rejected.
  E  source-backport      fix commit, no bounds: the only shape the tier accepts.
  U  unparseable          fix commit + fixed version but one side is not semver.

Reads a screen inbox (run `eval/beat_upstream_screen.py --inbox DIR`) and the
screen's `--out` verdict JSON; writes a counts summary plus per-CVE rows. No
network, no model spend.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from collections import Counter
from pathlib import Path

_FIXLIKE_RE = re.compile(r"/commit/|/commits/|/pull/|/-/merge_requests/|\.patch(\?|$)|/cgit/|;a=commit")


def _semver(v: str) -> tuple[int, ...] | None:
    m = re.match(r"^v?(\d+)\.(\d+)(?:\.(\d+))?(?:\.(\d+))?", v or "")
    if not m:
        return None
    return tuple(int(g) for g in m.groups() if g is not None)


def bucket_one(cve_dir: Path) -> dict:
    row: dict = {"cve_id": cve_dir.name}
    ri_path = cve_dir / "resolver-input.json"
    si_path = cve_dir / "scout-input.json"
    if not ri_path.exists():
        row["bucket"] = "no-resolver-input"
        return row
    ri = json.loads(ri_path.read_text())
    si = json.loads(si_path.read_text()) if si_path.exists() else {}
    row["attr_path"] = ri.get("attr_path")
    cur = ri.get("current_version") or ""
    row["current_version"] = cur
    refs = ri.get("candidate_refs") or []
    urls = [r.get("url", "") for r in (si.get("references") or [])]
    row["fixlike_urls"] = [u for u in urls if _FIXLIKE_RE.search(u)]

    if not refs:
        row["bucket"] = "A-no-fix-commit"
        row["regex_miss"] = bool(row["fixlike_urls"])
        return row

    ref = refs[0]
    row["fix_commits"] = ref.get("upstream_fix_commits", [])
    row["tier_hint"] = ref.get("tier_hint")
    reason = ref.get("requires_review_reason")
    row["requires_review_reason"] = reason
    fixed = ref.get("version") or ""
    row["fixed_version"] = fixed

    if ref.get("tier_hint") == "source-backport":
        row["bucket"] = "E-source-backport"
        return row
    if reason == "ambiguous-fixed-version":
        row["bucket"] = "D-ambiguous-fixed-version"
        return row
    c, f = _semver(cur), _semver(fixed)
    if c is None or f is None:
        row["bucket"] = "U-unparseable"
        return row
    row["bucket"] = "B-release-nixpkgs-behind" if c < f else "C-release-nixpkgs-current"
    return row


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--inbox", type=Path, required=True, help="persistent inbox dir from the screen run")
    ap.add_argument("--verdicts", type=Path, default=None,
                    help="screen --out JSON; restricts the audit to CVEs the screen mapped to nixpkgs")
    ap.add_argument("--out", type=Path, default=None, help="write per-CVE rows + counts here")
    args = ap.parse_args(argv)

    wanted: set[str] | None = None
    if args.verdicts is not None:
        vs = json.loads(args.verdicts.read_text())
        vs = vs.get("verdicts", vs) if isinstance(vs, dict) else vs
        wanted = {v["cve_id"] for v in vs if v.get("attr_path") or v.get("reject") == "not-source-backport-tier"}

    rows = []
    for d in sorted(args.inbox.iterdir()):
        if not d.is_dir() or not d.name.startswith("CVE-"):
            continue
        if wanted is not None and d.name not in wanted:
            continue
        if not (d / "resolver-input.json").exists():
            continue
        rows.append(bucket_one(d))

    counts = Counter(r["bucket"] for r in rows)
    regex_miss = sum(1 for r in rows if r.get("regex_miss"))
    summary = {
        "audited": len(rows),
        "buckets": dict(sorted(counts.items())),
        "A_regex_miss": regex_miss,
        "window_candidates_B_plus_D": counts.get("B-release-nixpkgs-behind", 0)
        + counts.get("D-ambiguous-fixed-version", 0),
    }
    print(json.dumps(summary, indent=2))
    if args.out:
        args.out.write_text(json.dumps({"summary": summary, "rows": rows}, indent=2) + "\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
