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
  * no STABLE upstream release tag already contains the fix commit (else nixpkgs fixes it
    by a version bump — the low-value bot path, not a source-backport),
  * no open/merged NixOS/nixpkgs PR references the CVE id, and
  * (advisory) the fix commit is not already carried by a nixpkgs in-tree patch.
These are network checks (gh); they run only with --check-nixpkgs and never spend model
tokens. The tag-lag gate is ancestry-based: for each upstream release tag newer than the
packaged version, `git compare fix...tag` reveals whether the tag contains the fix commit.
Containment in a STABLE tag is a hard reject (`fixed-release-exists`); containment only in
a pre-release tag is a flag (`fixed_prerelease_only`), not a reject — nixpkgs won't bump to
an rc. Known v1 blind spot: a fix cherry-picked onto a release branch has a different SHA,
so ancestry misses it and such a candidate survives wrongly (wastes a bootstrap, not spend
on a bad claim). Symbol-reachability stays a manual follow-up (needs a build).

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
import re
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


# --- git-tag-lag gate (ancestry-based): reject when a STABLE upstream release tag ---
# already contains the fix commit, because nixpkgs then fixes the CVE by bumping to that
# release (the low-value bot path), not by a model-authored source-backport.

_PRERELEASE_RE = re.compile(r"(?:^|[-._])(rc|beta|alpha|pre|dev|snapshot|nightly|preview|next|canary)", re.I)


def _is_prerelease(tag: str) -> bool:
    return bool(_PRERELEASE_RE.search(tag))


def _parse_ver(tag: str) -> tuple[int, ...] | None:
    """Leading numeric dotted version from a tag (v0.3.1 -> (0,3,1)); None if unparseable."""
    m = re.match(r"[vV]?(\d+(?:\.\d+)*)", (tag or "").strip())
    if not m:
        return None
    return tuple(int(x) for x in m.group(1).split("."))


def _repo_slug(repo_url: str) -> str | None:
    """github.com/owner/repo URL -> 'owner/repo'; None for non-GitHub (can't gh-ancestry)."""
    m = re.match(r"https?://github\.com/([^/]+/[^/]+?)(?:\.git)?/?$", (repo_url or "").strip())
    return m.group(1) if m else None


def _gh_list_tags(slug: str) -> list[str] | None:
    try:
        r = subprocess.run(
            ["gh", "api", f"repos/{slug}/tags", "--paginate", "--jq", ".[].name"],
            capture_output=True, text=True, timeout=120,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    if r.returncode != 0:
        return None
    return [ln.strip() for ln in r.stdout.splitlines() if ln.strip()]


def _gh_tag_contains(slug: str, fix_sha: str, tag: str) -> bool | None:
    """True if `tag` contains `fix_sha` (fix is an ancestor of tag), via compare fix...tag."""
    try:
        r = subprocess.run(
            ["gh", "api", f"repos/{slug}/compare/{fix_sha}...{tag}", "--jq", ".behind_by"],
            capture_output=True, text=True, timeout=60,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    if r.returncode != 0:
        return None
    try:
        # behind_by == 0: the fix has no commits absent from `tag` -> tag contains the fix.
        return int(r.stdout.strip()) == 0
    except ValueError:
        return None


def _fixed_release_status(ref: dict, current_version: str | None, *, tag_cache: dict,
                          list_tags=_gh_list_tags, tag_contains=_gh_tag_contains) -> tuple[str, str | None]:
    """Classify whether an upstream release already carries the fix commit.

    Returns (status, tag):
      'reject'     -> a STABLE release tag contains the fix (bump-shaped, not a backport)
      'prerelease' -> only a pre-release tag contains it (nixpkgs won't bump to an rc; survive+flag)
      'clear'      -> no release tag contains the fix
      'incomplete' -> the check could not run (non-GitHub upstream, API/parse failure)
    Only tags newer than the packaged version are checked (a bump can only go forward);
    unparseable tags are checked too (can't rule them out). Newest-first, early-exit on the
    first stable containment. list_tags/tag_contains are injectable for offline tests.
    """
    commits = ref.get("upstream_fix_commits") or []
    if not commits:
        return ("incomplete", None)
    slug = _repo_slug(commits[0].get("repo_url", ""))
    if slug is None:
        return ("incomplete", None)  # non-GitHub upstream: gh ancestry unavailable
    fix_sha = commits[0].get("commit_sha", "")
    if not fix_sha:
        return ("incomplete", None)

    if slug not in tag_cache:
        tag_cache[slug] = list_tags(slug)  # one fetch per repo per run
    tags = tag_cache[slug]
    if tags is None:
        return ("incomplete", None)

    pkg_ver = _parse_ver(current_version or "")
    # candidate tags: newer than the packaged version (semver prefilter), or unparseable.
    cands = []
    for t in tags:
        tv = _parse_ver(t)
        if tv is not None and pkg_ver is not None and tv <= pkg_ver:
            continue
        cands.append((tv or (), t))
    cands.sort(reverse=True)  # newest-first; the newest stable tag usually carries the fix

    prerelease_hit = None
    any_failed = False
    for _tv, tag in cands:
        contains = tag_contains(slug, fix_sha, tag)
        if contains is None:
            any_failed = True
            continue
        if contains:
            if _is_prerelease(tag):
                prerelease_hit = prerelease_hit or tag
            else:
                return ("reject", tag)  # stable release carries the fix
    if prerelease_hit:
        return ("prerelease", prerelease_hit)
    if any_failed:
        return ("incomplete", None)
    return ("clear", None)


def screen_cve(cve_id: str, *, graph: CannedGraphLookup, inbox: Path,
               nvd_api_key: str | None, check_nixpkgs: bool,
               tag_cache: dict | None = None) -> dict:
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
        # tag-lag gate first: if a stable upstream release already carries the fix, this is
        # bump-shaped and there is nothing to source-backport — decide it before the id checks.
        status, tag = _fixed_release_status(
            ref, v.get("current_version"), tag_cache=tag_cache if tag_cache is not None else {})
        v["fixed_release_status"] = status
        if status == "reject":
            v["fixed_release_tag"] = tag
            v["reject"] = "fixed-release-exists"
            return v
        if status == "prerelease":
            v["fixed_prerelease_only"] = tag  # survives; nixpkgs won't bump to a pre-release
        elif status == "incomplete":
            v["tag_lag_check_incomplete"] = True  # surface, don't silently pass

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
    # remaining manual gate the screen can't automate (needs a build):
    v["followups"] = [
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
    tag_cache: dict = {}  # one upstream tag-list fetch per repo, shared across candidates
    try:
        for cid in cve_ids:
            verdicts.append(screen_cve(
                cid, graph=graph, inbox=inbox,
                nvd_api_key=nvd_api_key, check_nixpkgs=args.check_nixpkgs,
                tag_cache=tag_cache,
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
