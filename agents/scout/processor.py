"""Scout inbox processor: scan + auto-resolve.

Closes the loop after the cron poller writes an inbox entry:

  inbox/<CVE-ID>/scout-input.json   (input)
       ↓
  scout.scan(scout_input, graph) → finding.json | mapping-failure.json
       ↓ (when finding)
  build resolver-input from finding + scout-input.references
       ↓
  upstream_ref_resolver.resolve → upstream-ref.json

Per locked decision (b): auto-resolve immediately. The resolver
records its own verdict (eligible / requires-human-review /
ineligible) and downstream agents read that as given truth.

candidate_refs extraction is deterministic and conservative:
  * references[] with kind='upstream-commit' that match
    github.com/<owner>/<repo>/commit/<sha> or the gitlab.com
    equivalent become candidate `upstream_fix_commits` entries.
  * No changelog scraping; the resolver itself defers that.
  * Empty candidates → resolver returns ineligible-no-fix-available,
    which is a perfectly valid recorded outcome.
"""

from __future__ import annotations

import json
import os
import re
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable

from agents.scout.auto_prefetch import AutoPrefetchStats
from agents.scout.graph_lookup import GraphLookup
from agents.scout.scout import scan
from agents.upstream_ref_resolver.resolver import resolve as resolve_upstream


_GITHUB_COMMIT_RE = re.compile(
    r"^https://github\.com/(?P<owner>[^/]+)/(?P<repo>[^/]+)/commit/(?P<sha>[0-9a-f]{7,40})/?$"
)
_GITLAB_COMMIT_RE = re.compile(
    r"^https://gitlab\.com/(?P<owner>[^/]+)/(?P<repo>[^/]+)/-/commit/(?P<sha>[0-9a-f]{7,40})/?$"
)
# git.kernel.org commit URL shapes. The Linux kernel CVE corpus
# overwhelmingly publishes patches as kernel.org cgit links rather
# than github mirrors; without this match, kernel CVEs land at
# resolver verdict ineligible-no-fix-available even when version
# bounds are derivable. v0 covers the four common forms:
#   * /stable/c/<sha>          (stable backports)
#   * /torvalds/c/<sha>        (mainline shorthand)
#   * /linus/<sha>             (mainline alternate shorthand)
#   * /pub/scm/.../linux.git/commit/?id=<sha>   (full cgit URL)
# Anything more exotic stays unmatched in v0 — we'd rather miss a
# rare form than build a fix-commit on a guessed repo_url.
_KERNEL_TREE_C_RE = re.compile(
    r"^https://git\.kernel\.org/(?P<tree>stable|torvalds)/c/(?P<sha>[0-9a-f]{7,40})/?$"
)
_KERNEL_LINUS_RE = re.compile(
    r"^https://git\.kernel\.org/linus/(?P<sha>[0-9a-f]{7,40})/?$"
)
_KERNEL_CGIT_RE = re.compile(
    r"^https://git\.kernel\.org/(?P<repo_path>pub/scm/[^?#]+\.git)/commit/\?id=(?P<sha>[0-9a-f]{7,40})$"
)
_KERNEL_TREE_REPO_URL = {
    "stable":   "https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux-stable.git",
    "torvalds": "https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git",
}


def match_commit_url(url: str) -> tuple[str, str] | None:
    """Recognize an upstream-commit URL and return (repo_url, commit_sha).
    Order is host-by-host so a URL that matches one shape doesn't
    accidentally fall through to a looser one."""
    m = _GITHUB_COMMIT_RE.match(url)
    if m:
        return f"https://github.com/{m.group('owner')}/{m.group('repo')}", m.group("sha")
    m = _GITLAB_COMMIT_RE.match(url)
    if m:
        return f"https://gitlab.com/{m.group('owner')}/{m.group('repo')}", m.group("sha")
    m = _KERNEL_TREE_C_RE.match(url)
    if m:
        return _KERNEL_TREE_REPO_URL[m.group("tree")], m.group("sha")
    m = _KERNEL_LINUS_RE.match(url)
    if m:
        return _KERNEL_TREE_REPO_URL["torvalds"], m.group("sha")
    m = _KERNEL_CGIT_RE.match(url)
    if m:
        return f"https://git.kernel.org/{m.group('repo_path')}", m.group("sha")
    return None


@dataclass(frozen=True)
class ProcessOutcome:
    cve_id: str
    entry_path: Path
    finding_status: str  # "finding" | "mapping-failure"
    resolver_status: str | None  # eligibility.verdict, or None for mapping-failure
    auto_prefetch: AutoPrefetchStats | None = None


# Callable that, given an inbox entry + attr_path, runs auto-prefetch
# and updates upstream-ref.json in place. Returns AutoPrefetchStats.
# `None` (default) means auto-prefetch is disabled for this run.
AutoPrefetchFn = Callable[[Path, str], AutoPrefetchStats]


def process_entry(
    entry_path: Path,
    *,
    graph: GraphLookup,
    auto_prefetch_fn: "AutoPrefetchFn | None" = None,
) -> ProcessOutcome:
    scout_input_path = entry_path / "scout-input.json"
    scout_input = json.loads(scout_input_path.read_text())

    scan_result = scan(scout_input, graph)

    if scan_result["status"] == "mapping-failure":
        _atomic_write_json(entry_path / "mapping-failure.json", scan_result["mapping_failure"])
        _remove_if_present(entry_path / "finding.json")
        _remove_if_present(entry_path / "resolver-input.json")
        _remove_if_present(entry_path / "upstream-ref.json")
        return ProcessOutcome(
            cve_id=scout_input["cve_id"],
            entry_path=entry_path,
            finding_status="mapping-failure",
            resolver_status=None,
        )

    finding = scan_result["finding"]
    _atomic_write_json(entry_path / "finding.json", finding)
    _remove_if_present(entry_path / "mapping-failure.json")

    resolver_input = _build_resolver_input(finding, scout_input)
    _atomic_write_json(entry_path / "resolver-input.json", resolver_input)

    upstream_ref = resolve_upstream(resolver_input)
    _atomic_write_json(entry_path / "upstream-ref.json", upstream_ref)

    auto_prefetch_stats: AutoPrefetchStats | None = None
    if auto_prefetch_fn is not None:
        try:
            auto_prefetch_stats = auto_prefetch_fn(
                entry_path, finding["affected"][0]["attr_path"],
            )
        except Exception:
            # Auto-prefetch is best-effort. A failure here must NOT
            # poison the inbox entry; surface as None and the caller
            # logs/aggregates absent stats as needed.
            auto_prefetch_stats = None

    return ProcessOutcome(
        cve_id=scout_input["cve_id"],
        entry_path=entry_path,
        finding_status="finding",
        resolver_status=upstream_ref["eligibility"]["verdict"],
        auto_prefetch=auto_prefetch_stats,
    )


def _build_resolver_input(
    finding: dict[str, Any],
    scout_input: dict[str, Any],
) -> dict[str, Any]:
    affected = finding["affected"][0]
    candidate_refs = _extract_candidate_refs(
        scout_input,
        current_version=affected["version"],
        matched_pname=affected.get("pname") or "",
    )
    return {
        "cve_id": finding["cve_id"],
        "current_version": affected["version"],
        "attr_path": affected["attr_path"],
        "candidate_refs": candidate_refs,
    }


_FIX_KIND_SYNTHESIZE = {"lessThan", "versionEndExcluding"}


def _extract_candidate_refs(
    scout_input: dict[str, Any],
    *,
    current_version: str,
    matched_pname: str,
) -> list[dict[str, Any]]:
    references = scout_input.get("references") or []
    advisory_urls = [
        r["url"] for r in references if r.get("kind") == "advisory"
    ]
    fix_commits: list[dict[str, str]] = []
    first_commit_url: str | None = None
    for ref in references:
        # `kind` comes from the feed's own tagging, which is frequently absent on
        # freshly disclosed CVEs (NVD adds the Patch tag days later, and the
        # aggregator does not tag at all). The URL shape is the stronger signal and
        # is what actually has to parse, so accept any reference whose URL is a
        # recognized commit URL and let _match_commit_url reject the rest.
        url = ref.get("url", "")
        match = match_commit_url(url)
        if match is None:
            continue
        repo_url, sha = match
        fix_commits.append({"repo_url": repo_url, "commit_sha": sha})
        if first_commit_url is None:
            first_commit_url = url

    if not fix_commits:
        return []

    # Derive concrete target versions from version_bounds when present
    # for the matched pname. lessThan / versionEndExcluding mean "the
    # fix landed at this version" so we can synthesize a real candidate
    # target. lessThanOrEqual / versionEndIncluding need next-semver
    # math we don't have yet, so they surface as a placeholder candidate
    # flagged with requires_review_reason for the resolver.
    bounds = scout_input.get("version_bounds") or []
    target_versions = _derive_target_versions(bounds, matched_pname=matched_pname)
    bounds_for_product = _bounds_for_pname(bounds, matched_pname=matched_pname)

    # Three target_version provenance classes, each routed differently:
    #   bounds + synthesizable     -> real derivation, no review flag
    #   bounds + not-synthesizable -> ambiguous-fixed-version
    #   no bounds at all           -> placeholder-target-version (NEW)
    # The placeholder case used to be detected downstream by target==current
    # equality. Making it explicit per the slice-5f review.
    flagged_ambiguous = bool(bounds_for_product) and not target_versions
    placeholder = False
    if not target_versions:
        target_versions = [current_version]  # placeholder = current_version
        if not flagged_ambiguous:
            placeholder = True

    out: list[dict[str, Any]] = []
    for v in target_versions:
        ref: dict[str, Any] = {
            "version": v,
            "release_url": first_commit_url,
            "advisory_urls": advisory_urls,
            "upstream_fix_commits": fix_commits,
            "delta": {
                "transitive_package_changes": 0,
                "new_direct_deps": [],
                "removed_direct_deps": [],
                "crosses_large_delta_threshold": False,
                "threshold_policy": "v0-default",
            },
            "tier_hint": "security-patch-release",
        }
        if flagged_ambiguous:
            ref["requires_review_reason"] = "ambiguous-fixed-version"
        elif placeholder:
            ref["requires_review_reason"] = "placeholder-target-version"
            # Source-backport PROPOSAL (additive, peer-reviewed 2026-06-11): a
            # fix commit exists but NO fixed release version was derivable — the
            # natural backport shape (fix the current version in place). Scout
            # proposes high-recall; the authoritative minimality decision is the
            # downstream `trace backport-patch` gate (rejects on conflict / multi-
            # file / non-apply), and the human reviews sufficiency. The
            # `requires_review_reason` above is KEPT, not replaced: "no fixed
            # release derivable" stays true regardless of the gate, so a clean-
            # applying-but-insufficient fix can't reach the human disguised as
            # done. (Conservative first cut: placeholder only — the clearest
            # no-fixed-release signal. The ambiguous-fixed-version case is a
            # follow-on, gated on the human-reject-rate of accepted backports.)
            ref["tier_hint"] = "source-backport"
        out.append(ref)
    return out


def _bounds_for_pname(
    bounds: list[dict[str, Any]],
    *,
    matched_pname: str,
) -> list[dict[str, Any]]:
    if not matched_pname:
        return []
    pname_lc = matched_pname.lower()
    return [b for b in bounds if b.get("product") == pname_lc]


def _derive_target_versions(
    bounds: list[dict[str, Any]],
    *,
    matched_pname: str,
) -> list[str]:
    """Pull synthesizable target versions from version_bounds for the
    matched product. Conservative: only lessThan/versionEndExcluding
    are mapped to a concrete fix version. lessThanOrEqual/
    versionEndIncluding skip (placeholder fallback fires)."""
    if not matched_pname:
        return []
    pname_lc = matched_pname.lower()
    out: list[str] = []
    seen: set[str] = set()
    for b in bounds:
        if b.get("product") != pname_lc:
            continue
        if b.get("fixed_kind") not in _FIX_KIND_SYNTHESIZE:
            continue
        v = b.get("fixed")
        if not isinstance(v, str) or v in seen:
            continue
        seen.add(v)
        out.append(v)
    return out


def _atomic_write_json(path: Path, data: Any) -> None:
    payload = json.dumps(data, indent=2, sort_keys=True).encode() + b"\n"
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix=path.name + ".", dir=str(path.parent))
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(payload)
        os.replace(tmp, path)
    except Exception:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def _remove_if_present(path: Path) -> None:
    try:
        path.unlink()
    except FileNotFoundError:
        pass
