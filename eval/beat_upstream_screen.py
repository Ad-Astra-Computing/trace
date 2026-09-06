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
tokens. Two further no-spend annotations ride the same fetch:
  * fix-commit verification — the claimed fix commit must be a real source fix, not a
    mis-extracted release-prep / mechanical commit (scout surfaced a "Preparing for release"
    commit as the fix for proftpd CVE-2025-53994). A release-prep message, all-mechanical
    files, or zero overlap with the advisory's named symbols flags `fix-commit-unverified`
    and clears `gradeable` — the survivor stays (the CVE may be real) but its ground-truth
    pointer is suspect, so it is not gradeable same-day.
  * edit-shape tag — classify_diff labels the fix `canonical` (condition-fold/guard-clip/
    security-guard-add, ≤2 hunks; grades under pr_accuracy line-recall) vs `design-freedom`
    (multi-hunk/other; needs the Reviewer functional-equivalence grader). A preference tag
    for operator sequencing, NEVER a reject — design-freedom source-backports are the
    high-value thesis cases. The tag-lag gate is ancestry-based: for each upstream release tag newer than the
packaged version, `git compare fix...tag` reveals whether the tag contains the fix commit.
Containment in a STABLE tag tags the CVE `fix_available_as: release` (pass
--reject-when-fixed-release to make it a hard reject instead); containment only in
a pre-release tag is a flag (`fixed_prerelease_only`) — nixpkgs won't bump to
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
from eval.classify_edit_shape import classify_diff

ROOT = Path(__file__).resolve().parents[1]

# kernel CVEs are bump-shaped in nixpkgs (stable-branch version bumps), so they are
# out of scope for a source-backport beat-upstream run regardless of tier.
_KERNEL_ATTR_PREFIXES = ("linux", "linuxKernel", "linuxPackages")


def _is_kernel(attr_path: str) -> bool:
    return any(attr_path == p or attr_path.startswith(p + ".") or attr_path.startswith(p + "_")
               for p in _KERNEL_ATTR_PREFIXES)


def _source_backport_ref(resolver_input: dict) -> dict | None:
    """Return the candidate_ref to backport from, else None.

    A ref tagged `source-backport` wins when one exists. Otherwise any ref naming
    an upstream fix commit is accepted: Scout only tags source-backport when NO
    fixed version is derivable, which excludes the common and valuable case of a
    project that has released a fix nixpkgs has not shipped. The fix commit is
    what the Patcher needs; whether a release also exists is a routing tag, set by
    the tag-lag gate below, not a reason to drop the CVE.
    """
    refs = resolver_input.get("candidate_refs") or []
    for ref in refs:
        if ref.get("tier_hint") == "source-backport":
            return ref
    for ref in refs:
        if ref.get("upstream_fix_commits"):
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


_CVE_RECORD_URL = "https://cveawg.mitre.org/api/cve/{cve_id}"


def _fetch_cve_record(cve_id: str) -> dict | None:
    """The authoritative CVE record, or None when it cannot be fetched."""
    import urllib.request

    try:
        with urllib.request.urlopen(_CVE_RECORD_URL.format(cve_id=cve_id), timeout=30) as fh:
            return json.load(fh)
    except Exception:  # noqa: BLE001 - an unreachable record is data, not a crash
        return None


def _cmp_ver(a: str, b: str) -> int | None:
    """-1/0/1 comparing two dotted versions, None when either is unparseable."""
    pa, pb = _parse_ver(a), _parse_ver(b)
    if pa is None or pb is None:
        return None
    width = max(len(pa), len(pb))
    pa = pa + (0,) * (width - len(pa))
    pb = pb + (0,) * (width - len(pb))
    return (pa > pb) - (pa < pb)


def _packaged_version_verdict(record: dict | None, pname: str, current_version: str) -> str:
    """Does the packaged version fall inside the CVE's affected range?

    Returns 'in-range', 'out-of-range' or 'unknown'. This is the gate that catches
    a pname collision: nixpkgs `haskellPackages.zephyr` 0.5.3 matched the Zephyr
    RTOS CVEs, whose affected range is 3.6.0 to 4.4.2. Name matching cannot see
    that; the version range can. Undecidable inputs (non-numeric versions, no
    matching affected entry) stay 'unknown' and never reject on their own.
    """
    if not record or not pname or not current_version:
        return "unknown"
    cna = (record.get("containers") or {}).get("cna") or {}
    decided = False
    for aff in cna.get("affected") or []:
        names = {str(aff.get(k) or "").lower() for k in ("product", "packageName")}
        if pname.lower() not in names:
            continue
        for ver in aff.get("versions") or []:
            if ver.get("status") not in (None, "affected"):
                continue
            introduced = str(ver.get("version") or "")
            lt = ver.get("lessThan")
            lte = ver.get("lessThanOrEqual")
            # Records routinely put the whole range in the version field as
            # "< 2.0.5" rather than filling lessThan. PrivateBin CVE-2026-55891
            # does, and reading it as an introduced version made the gate blind.
            m = re.match(r"^\s*(<=?)\s*(.+?)\s*$", introduced)
            if m and not lt and not lte:
                if m.group(1) == "<":
                    lt = m.group(2)
                else:
                    lte = m.group(2)
                introduced = ""
            lower_ok = True
            if introduced and introduced not in ("0", "*", "unspecified"):
                c = _cmp_ver(current_version, introduced)
                if c is None:
                    continue
                lower_ok = c >= 0
            if lt:
                c = _cmp_ver(current_version, str(lt))
                if c is None:
                    continue
                decided = True
                if lower_ok and c < 0:
                    return "in-range"
            elif lte:
                c = _cmp_ver(current_version, str(lte))
                if c is None:
                    continue
                decided = True
                if lower_ok and c <= 0:
                    return "in-range"
            elif introduced:
                c = _cmp_ver(current_version, introduced)
                if c is None:
                    continue
                decided = True
                if c == 0:
                    return "in-range"
    return "out-of-range" if decided else "unknown"


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


def _packaged_release_carries_fix(ref: dict, current_version: str | None, *, tag_cache: dict,
                                  list_tags=_gh_list_tags,
                                  tag_contains=_gh_tag_contains) -> str | None:
    """The packaged version's own tag, when that tag already contains the fix.

    `_fixed_release_status` only looks at tags NEWER than the packaged version,
    which answers "is there a release to bump to" and not "is this tree already
    fixed". PrivateBin CVE-2026-55891 slipped through on exactly that: the fix
    shipped in 2.0.5, nixpkgs packages 2.0.6, and the CVE does not apply at all.
    """
    commits = ref.get("upstream_fix_commits") or []
    slug = _repo_slug(commits[0].get("repo_url", "")) if commits else None
    pkg_ver = _parse_ver(current_version or "")
    if slug is None or pkg_ver is None:
        return None
    if slug not in tag_cache:
        tag_cache[slug] = list_tags(slug)
    tags = tag_cache[slug] or []
    shas = [c.get("commit_sha", "") for c in commits if c.get("commit_sha")]
    for tag in tags:
        if _parse_ver(tag) != pkg_ver:
            continue
        if any(tag_contains(slug, sha, tag) is True for sha in shas):
            return tag
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
    first stable containment. Every sha in upstream_fix_commits is tested, since a fix is
    commonly cherry-picked per release branch under a different sha.
    list_tags/tag_contains are injectable for offline tests.
    """
    commits = ref.get("upstream_fix_commits") or []
    if not commits:
        return ("incomplete", None)
    slug = _repo_slug(commits[0].get("repo_url", ""))
    if slug is None:
        return ("incomplete", None)  # non-GitHub upstream: gh ancestry unavailable
    # Every fix sha, not just the first. A fix is routinely cherry-picked onto each
    # maintained release branch, so the main-branch commit is absent from a release
    # tag that nonetheless carries the same fix under a different sha. Checking only
    # commits[0] reported "clear" for openexr CVE-2026-59981 when v3.4.14 contains
    # the release-branch pick.
    fix_shas = [c.get("commit_sha", "") for c in commits if c.get("commit_sha")]
    if not fix_shas:
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
        results = [tag_contains(slug, sha, tag) for sha in fix_shas]
        if any(r is None for r in results):
            any_failed = True
        if any(r is True for r in results):
            if _is_prerelease(tag):
                prerelease_hit = prerelease_hit or tag
            else:
                return ("reject", tag)  # stable release carries the fix
    if prerelease_hit:
        return ("prerelease", prerelease_hit)
    if any_failed:
        return ("incomplete", None)
    return ("clear", None)


# --- fix-commit-verification gate: is scout's claimed fix commit a real fix, or did it ---
# mis-extract a release-prep / mechanical commit as the fix? A bogus ground-truth pointer
# makes a survivor ungradeable (proftpd CVE-2025-53994: scout surfaced a "Preparing for
# release" commit as the fix). This is a deterministic no-spend correctness check on scout's
# extraction, in the same class as the tag-lag gate.

_RELEASE_PREP_RE = re.compile(
    r"\b(prepar\w*\s+(?:for\s+)?(?:the\s+)?(?:next\s+)?release|"
    r"bump\w*\s+version|version\s+bump|back\s+to\s+\S*-?dev|post-?release|"
    r"begin\s+\S*\s*dev|release\s+v?\d)", re.I)
# files that carry no vulnerable code — a fix that touches ONLY these is not a source fix.
_MECHANICAL_FILE_RE = re.compile(
    r"(^|/)(ChangeLog\w*|NEWS|AUTHORS|COPYING|LICENSE\w*|VERSION|"
    r"configure\.ac|configure\.in|config\.h\.in|Makefile\.am|Makefile\.in|"
    r"\.github/|debian/changelog|[^/]+\.spec|version\.(h|c|py|go|rb|txt)|"
    r"__version__\.py|package\.json|Cargo\.toml)$", re.I)
# advisory-symbol extraction: function calls `foo_bar(` and source-file paths from the summary.
_FUNC_RE = re.compile(r"\b([a-z_][a-z0-9_]{3,})\s*\(")
_SRCFILE_RE = re.compile(r"\b([\w./-]+\.(?:c|h|cc|cpp|hpp|go|py|rb|rs|js|ts|php|java|pl))\b", re.I)
_STOPWORDS = frozenset({"this", "that", "when", "then", "with", "from", "into", "func",
                        "function", "call", "calls", "size", "used", "null", "true", "false"})
_CANONICAL_SHAPES = frozenset({"condition-fold", "guard-clip", "security-guard-add"})


def _gh_commit(slug: str, sha: str) -> dict | None:
    """Fetch a commit's message + changed files (filename, patch) via the GitHub API.

    Returns {"message": str, "files": [{"filename","patch"}]} or None on any failure.
    """
    try:
        r = subprocess.run(
            ["gh", "api", f"repos/{slug}/commits/{sha}",
             "--jq", "{message: .commit.message, files: [.files[] | {filename, patch}]}"],
            capture_output=True, text=True, timeout=60,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    if r.returncode != 0:
        return None
    try:
        return json.loads(r.stdout)
    except json.JSONDecodeError:
        return None


def _advisory_symbols(summary: str) -> set[str]:
    """Vulnerable-symbol / source-file tokens named in the advisory summary (lowercased)."""
    toks: set[str] = set()
    for m in _FUNC_RE.finditer(summary or ""):
        t = m.group(1).lower()
        if t not in _STOPWORDS:
            toks.add(t)
    for m in _SRCFILE_RE.finditer(summary or ""):
        path = m.group(1).lower()
        toks.add(path)
        toks.add(path.rsplit("/", 1)[-1])  # basename too
    return toks


def _verify_fix_commit(commit: dict, advisory_tokens: set[str]) -> tuple[str, str | None]:
    """Is the claimed fix commit a plausible source fix? (status, reason).

      'verified'   -> touches code and (if we have advisory symbols) overlaps them
      'unverified' -> release-prep message / only-mechanical files / no advisory overlap
    A release-prep or purely-mechanical commit is a mis-extraction; an advisory that names
    a symbol none of the commit's files/patch mention is a wrong-commit pointer. Either way
    the survivor is not gradeable same-day against this commit as ground truth.
    """
    msg = commit.get("message", "") or ""
    if _RELEASE_PREP_RE.search(msg):
        return ("unverified", "release-prep-message")
    files = commit.get("files") or []
    filenames = [f.get("filename", "") for f in files]
    code_files = [fn for fn in filenames if fn and not _MECHANICAL_FILE_RE.search(fn)]
    if filenames and not code_files:
        return ("unverified", "only-mechanical-files")
    if advisory_tokens:
        blob = (" ".join(filenames) + " "
                + " ".join(f.get("patch", "") or "" for f in files)).lower()
        if not any(tok in blob for tok in advisory_tokens):
            return ("unverified", "no-advisory-symbol-overlap")
    return ("verified", None)


def _fix_shape_class(commit: dict) -> dict:
    """Tag the fix's edit shape (via classify_diff) as canonical vs design-freedom.

    canonical fixes (condition-fold / guard-clip / security-guard-add, ≤2 hunks) grade well
    under pr_accuracy line-recall; design-freedom fixes (multi-hunk / other) do NOT — they
    need the Reviewer functional-equivalence grader. A preference tag for operator sequencing,
    NEVER a reject: design-freedom source-backports are the high-value thesis cases.
    """
    files = commit.get("files") or []
    patch = "\n".join(
        f"diff --git a/{f['filename']} b/{f['filename']}\n{f.get('patch','')}"
        for f in files if f.get("filename") and f.get("patch"))
    c = classify_diff(patch)
    c["fix_shape_class"] = (
        "canonical" if c["shape"] in _CANONICAL_SHAPES and c.get("n_hunks", 0) <= 2
        else "design-freedom")
    return c


def screen_cve(cve_id: str, *, graph: CannedGraphLookup, inbox: Path,
               nvd_api_key: str | None, check_nixpkgs: bool,
               tag_cache: dict | None = None,
               reject_when_fixed_release: bool = False,
               fetch_commit=_gh_commit,
               fetch_cve_record=_fetch_cve_record) -> dict:
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
        v["reject"] = "no-fix-commit"  # nothing to backport from
        return v
    v["fix_commits"] = ref.get("upstream_fix_commits", [])
    v["tier_hint"] = ref.get("tier_hint")

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
            # A stable release carrying the fix means nixpkgs' own remediation is
            # likely a version bump. That is a routing tag, not a reject: stable
            # NixOS branches backport rather than bump, and comparing trace's patch
            # against whichever shape nixpkgs lands is the measurement. Pass
            # --reject-when-fixed-release for the old bump-shaped-only behaviour.
            v["fixed_release_tag"] = tag
            v["fix_available_as"] = "release"
            if reject_when_fixed_release:
                v["reject"] = "fixed-release-exists"
                return v
        if status == "prerelease":
            v["fixed_prerelease_only"] = tag  # survives; nixpkgs won't bump to a pre-release
        elif status == "incomplete":
            v["tag_lag_check_incomplete"] = True  # surface, don't silently pass

        # Packaged-version-in-range gate. Scout maps by pname, so an unrelated
        # package sharing a name survives every other check: nixpkgs
        # haskellPackages.zephyr 0.5.3 matched 42 Zephyr RTOS CVEs in the
        # 2026-09-05 screen. Only a decisive out-of-range verdict rejects.
        record = fetch_cve_record(cve_id)
        pname = (attr or "").split(".")[-1]
        v["packaged_version_verdict"] = _packaged_version_verdict(
            record, pname, v.get("current_version") or "")
        if v["packaged_version_verdict"] == "out-of-range":
            v["reject"] = "packaged-version-out-of-range"
            return v

        already = _packaged_release_carries_fix(
            ref, v.get("current_version"), tag_cache=tag_cache if tag_cache is not None else {})
        if already:
            v["packaged_release_tag"] = already
            v["reject"] = "packaged-version-already-fixed"
            return v

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

        # fix-commit-verification + edit-shape: fetch the claimed fix commit once and
        # (a) verify it is a real source fix (not a mis-extracted release-prep commit) and
        # (b) tag its edit shape so the operator can prefer canonical (pr_accuracy-gradeable)
        # targets for a metric-validation run. Both need the upstream commit diff (gh).
        commits = ref.get("upstream_fix_commits") or []
        slug = _repo_slug(commits[0].get("repo_url", "")) if commits else None
        sha = commits[0].get("commit_sha", "") if commits else ""
        commit = fetch_commit(slug, sha) if (slug and sha) else None
        if commit is None:
            v["fix_commit_status"] = "incomplete"  # couldn't fetch — can't verify or shape
            v["gradeable"] = None
        else:
            summary = ""
            finding_path = inbox / cve_id / "finding.json"
            if finding_path.is_file():
                try:
                    summary = json.loads(finding_path.read_text()).get("summary", "") or ""
                except (json.JSONDecodeError, OSError):
                    summary = ""
            status, reason = _verify_fix_commit(commit, _advisory_symbols(summary))
            v["fix_commit_status"] = status
            if status == "unverified":
                v["fix_commit_unverified"] = reason  # ground truth suspect: not gradeable
            v["gradeable"] = status == "verified"
            v["fix_shape"] = _fix_shape_class(commit)

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
    ap.add_argument("--reject-when-fixed-release", action="store_true",
                    help="drop a CVE whose fix already ships in a stable upstream release "
                         "(the pre-2026-09-05 behaviour; by default such a CVE survives with "
                         "fix_available_as=release)")
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
                reject_when_fixed_release=args.reject_when_fixed_release,
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
