"""Beat-upstream screen: find a fresh CVE trace could fix before nixpkgs does.

The historical PR-accuracy harness (eval/pr_accuracy.py) proves trace produces the
*correct* fix retrospectively, on CVEs nixpkgs already fixed. This screen proves the
OPERATING MODE prospectively: it finds a freshly-published CVE where an upstream fix
commit EXISTS but nixpkgs master has not yet backported it — the genuine
"trace could beat upstream here" opportunity — so a live Patcher run can author the
backport and be graded same-day against the upstream commit as ground truth.

No model spend. Pure discovery + deterministic classification over the existing Scout
stages (discover -> poll -> process), plus optional nixpkgs negative-evidence checks.

Target shape (per reviewer, 2026-07-20): scout's `source-backport` tier — a fix commit
is present AND no fixed release version is derivable (placeholder-target-version). That is
scout's existing encoding of "upstream has a fix, no release carries it yet." A candidate
survives the screen only if, additionally:
  * it is NOT a linux-kernel CVE (nixpkgs fixes kernels via stable-branch bumps),
  * no open/merged NixOS/nixpkgs PR references the CVE id, and
  * (advisory) the fix commit is not already carried by a nixpkgs in-tree patch.
The last two are network checks (gh); they run only with --check-nixpkgs and never spend
model tokens. git-tag lag and symbol-reachability gates are surfaced as manual follow-ups
on survivors (they need the upstream repo + a build), not gates the screen can automate.

Usage:
  # screen the last 72h (discovers CVE ids from NVD, needs network):
  python3 eval/beat_upstream_screen.py --snapshot snapshot.json --lookback-hours 72 \
      --check-nixpkgs --out data/reports/beat-upstream-shortlist.json

  # screen an explicit id list (skip discovery):
  python3 eval/beat_upstream_screen.py --snapshot snapshot.json \
      --cve CVE-2026-64161 --cve CVE-2026-64170
"""
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path

# invoked by path (python3 eval/beat_upstream_screen.py), so put the repo root on
# sys.path before importing the agents package.
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from agents.scout.discovery import list_recent_cves
from agents.scout.graph_lookup import CannedGraphLookup
from agents.scout.poller import poll_one
from agents.scout.processor import process_entry
from agents.scout.snapshot_builder import snapshot_from_json

ROOT = Path(__file__).resolve().parents[1]

# kernel CVEs are bump-shaped in nixpkgs (stable-branch version bumps), so they are
# out of scope for a source-backport beat-upstream run regardless of tier.
_KERNEL_ATTR_PREFIXES = ("linux", "linuxKernel", "linuxPackages")


def _is_kernel(attr_path: str) -> bool:
    return any(attr_path == p or attr_path.startswith(p + ".") or attr_path.startswith(p + "_")
               for p in _KERNEL_ATTR_PREFIXES)


def _source_backport_ref(resolver_input: dict) -> dict | None:
    """Return the first candidate_ref tagged source-backport, else None."""
    for ref in resolver_input.get("candidate_refs") or []:
        if ref.get("tier_hint") == "source-backport":
            return ref
    return None


def _nixpkgs_pr_exists(cve_id: str) -> bool | None:
    """True/False if a NixOS/nixpkgs PR references the CVE id; None if the check failed.

    Any open OR merged PR mentioning the id means upstream nixpkgs is already on it, so
    this is not a beat-upstream opportunity.
    """
    try:
        r = subprocess.run(
            ["gh", "search", "prs", "--repo", "NixOS/nixpkgs", cve_id,
             "--state", "all", "--json", "number", "--limit", "5"],
            capture_output=True, text=True, timeout=60,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    if r.returncode != 0:
        return None
    try:
        return len(json.loads(r.stdout or "[]")) > 0
    except json.JSONDecodeError:
        return None


def _nixpkgs_code_mentions(cve_id: str) -> bool | None:
    """True/False if the CVE id already appears in NixOS/nixpkgs default-branch code."""
    try:
        r = subprocess.run(
            ["gh", "api", "-X", "GET", "search/code",
             "-f", f"q={cve_id} repo:NixOS/nixpkgs", "--jq", ".total_count"],
            capture_output=True, text=True, timeout=60,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    if r.returncode != 0:
        return None
    try:
        return int((r.stdout or "0").strip()) > 0
    except ValueError:
        return None


def screen_cve(cve_id: str, *, graph: CannedGraphLookup, inbox: Path,
               nvd_api_key: str | None, check_nixpkgs: bool) -> dict:
    """Run one CVE through poll -> process -> classify. Returns a verdict dict."""
    v: dict = {"cve_id": cve_id, "survives": False, "reject": None}
    outcome = poll_one(cve_id, graph=graph, root=inbox, nvd_api_key=nvd_api_key)
    v["poll_action"] = outcome.action
    if outcome.action != "written":
        v["reject"] = f"poll:{outcome.action}"  # skipped-irrelevant / fetch-failed / rate-limited
        return v

    proc = process_entry(inbox / cve_id, graph=graph)
    v["finding_status"] = proc.finding_status
    v["resolver_status"] = proc.resolver_status
    if proc.finding_status != "finding":
        v["reject"] = "no-nixpkgs-mapping"
        return v

    resolver_input = json.loads((inbox / cve_id / "resolver-input.json").read_text())
    attr = resolver_input.get("attr_path", "")
    v["attr_path"] = attr
    v["current_version"] = resolver_input.get("current_version")

    ref = _source_backport_ref(resolver_input)
    if ref is None:
        v["reject"] = "not-source-backport-tier"  # bump-shaped or no fix commit
        return v
    v["fix_commits"] = ref.get("upstream_fix_commits", [])

    if _is_kernel(attr):
        v["reject"] = "kernel-bump-shaped"
        return v

    if check_nixpkgs:
        pr = _nixpkgs_pr_exists(cve_id)
        code = _nixpkgs_code_mentions(cve_id)
        v["nixpkgs_pr_exists"] = pr
        v["nixpkgs_code_mentions"] = code
        if pr is True or code is True:
            v["reject"] = "already-in-nixpkgs"
            return v
        # pr/code None means the check couldn't run — surface, don't silently pass.
        if pr is None or code is None:
            v["nixpkgs_check_incomplete"] = True

    v["survives"] = True
    # manual gates the screen can't automate (need upstream repo + a build):
    v["followups"] = [
        "git tag --contains <fix-sha> on upstream: confirm no release carries the fix",
        "reachability: confirm the vulnerable symbol exists in the packaged version",
    ]
    return v


def _parse_iso(s: str) -> datetime:
    return datetime.fromisoformat(s.replace("Z", "+00:00"))


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--snapshot", type=Path, required=True, help="graph-snapshot JSON")
    ap.add_argument("--cve", action="append", default=[], help="explicit CVE id (repeatable); skips discovery")
    ap.add_argument("--lookback-hours", type=float, default=72.0)
    ap.add_argument("--since", help="ISO-8601 window start (overrides --lookback-hours)")
    ap.add_argument("--until", help="ISO-8601 window end (default: now)")
    ap.add_argument("--check-nixpkgs", action="store_true", help="run gh PR/code negative-evidence checks")
    ap.add_argument("--inbox", type=Path, default=None, help="inbox dir (default: a temp dir)")
    ap.add_argument("--out", type=Path, default=None, help="write full verdict JSON here")
    ap.add_argument("--limit", type=int, default=None, help="cap CVEs screened (discovery order)")
    args = ap.parse_args(argv)

    if not args.snapshot.is_file():
        print(f"error: snapshot not found: {args.snapshot}", file=sys.stderr)
        return 64
    graph = CannedGraphLookup(snapshot_from_json(args.snapshot.read_text()))
    nvd_api_key = os.environ.get("NVD_API_KEY") or None

    if args.cve:
        cve_ids = list(args.cve)
    else:
        until = _parse_iso(args.until) if args.until else datetime.now(timezone.utc)
        since = _parse_iso(args.since) if args.since else until - timedelta(hours=args.lookback_hours)
        cve_ids = list_recent_cves(since=since, until=until, api_key=nvd_api_key)
    if args.limit:
        cve_ids = cve_ids[: args.limit]

    tmp = None
    inbox = args.inbox
    if inbox is None:
        tmp = tempfile.TemporaryDirectory(prefix="beat-upstream-inbox-")
        inbox = Path(tmp.name)
    inbox.mkdir(parents=True, exist_ok=True)

    verdicts = []
    try:
        for cid in cve_ids:
            verdicts.append(screen_cve(
                cid, graph=graph, inbox=inbox,
                nvd_api_key=nvd_api_key, check_nixpkgs=args.check_nixpkgs,
            ))
    finally:
        if tmp is not None:
            tmp.cleanup()

    survivors = [v for v in verdicts if v["survives"]]
    print(f"beat-upstream screen — {len(cve_ids)} CVEs, {len(survivors)} survivor(s)")
    from collections import Counter
    reasons = Counter(v["reject"] for v in verdicts if v["reject"])
    for reason, n in reasons.most_common():
        print(f"  reject {reason:28} {n}")
    for v in survivors:
        print(f"  SURVIVOR {v['cve_id']}  {v.get('attr_path')}  {v.get('current_version')}")
        for fc in v.get("fix_commits", []):
            print(f"    fix: {fc.get('repo_url')} @ {fc.get('commit_sha')}")

    if args.out:
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(json.dumps({
            "screened": len(cve_ids), "survivors": len(survivors),
            "verdicts": verdicts,
        }, indent=2))
        print(f"wrote {args.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
