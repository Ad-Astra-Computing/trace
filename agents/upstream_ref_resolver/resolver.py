"""UpstreamRefResolver — v0 stub.

Deterministic, table-driven. Reads a resolver-input document (which, in v0,
carries candidate upstream refs already surfaced by some upstream step) and
emits an `upstream-ref.json` shaped per `policy/upstream-ref-schema.json`.

No network. No changelog scraping. That complexity lives behind this same
interface later. This stub codifies the decision contract:

    input  -> candidate_refs[]
    output -> one of:
              { eligibility.verdict: "eligible",                     ... }
              { eligibility.verdict: "eligible-requires-human-review", ... }
              { eligibility.verdict: "ineligible-no-fix-available",  ... }

Per SPEC §2a and the resolver role contract:
  * no candidates              -> ineligible-no-fix-available
  * major version bump         -> eligible-requires-human-review (major-version-jump)
  * large sbom delta           -> eligible-requires-human-review (large-sbom-delta)
  * no changelog/advisory ref  -> eligible-requires-human-review (ambiguous-changelog)
  * otherwise                  -> eligible, tier driven by version delta + tier_hint

Patcher never re-litigates eligibility — it consumes this output as given truth.
"""

from __future__ import annotations

import re
from typing import Any


SCHEMA_VERSION = "1.0.0"


def resolve(input_doc: dict[str, Any]) -> dict[str, Any]:
    cve_id: str = input_doc["cve_id"]
    current_version: str = input_doc["current_version"]
    candidates: list[dict[str, Any]] = list(input_doc.get("candidate_refs", []))

    if not candidates:
        return _ineligible(
            cve_id=cve_id,
            current_version=current_version,
            verdict="ineligible-no-fix-available",
            verdict_reason="resolver received no candidate upstream refs",
        )

    chosen = _pick_smallest_upgrade(current_version, candidates)

    if chosen.get("requires_review_reason") == "ambiguous-fixed-version":
        return _eligible_requires_human_review(
            cve_id=cve_id,
            current_version=current_version,
            chosen=chosen,
            fix_tier=_classify_tier(current_version, chosen, input_doc),
            trigger="ambiguous-fixed-version",
            verdict_reason=(
                "candidate fix commit has no derivable target version "
                "(lessThanOrEqual / versionEndIncluding bound without "
                "next-semver math); human must confirm the actual fix "
                "version"
            ),
        )

    if chosen.get("delta", {}).get("crosses_large_delta_threshold"):
        return _eligible_requires_human_review(
            cve_id=cve_id,
            current_version=current_version,
            chosen=chosen,
            fix_tier=_classify_tier(current_version, chosen, input_doc),
            trigger="large-sbom-delta",
            verdict_reason=(
                "candidate upstream release crosses large-sbom-delta threshold; "
                "human must weigh dependency movement"
            ),
        )

    if not chosen.get("changelog_url") and not chosen.get("advisory_urls"):
        return _eligible_requires_human_review(
            cve_id=cve_id,
            current_version=current_version,
            chosen=chosen,
            fix_tier=_classify_tier(current_version, chosen, input_doc),
            trigger="ambiguous-changelog",
            verdict_reason=(
                "candidate upstream release has neither changelog nor advisory URL; "
                "delta unverifiable without human review"
            ),
        )

    if chosen["version"] == current_version:
        return _eligible_requires_human_review(
            cve_id=cve_id,
            current_version=current_version,
            chosen=chosen,
            fix_tier=_classify_tier(current_version, chosen, input_doc),
            trigger="no-target-version-derived",
            verdict_reason=(
                "candidate target_version equals current_version; "
                "no real upgrade was derived from the advisory. "
                "Auto-merge would produce a no-op patch. Human must "
                "confirm the actual fix version."
            ),
        )

    tier = _classify_tier(current_version, chosen, input_doc)
    if tier == "major-version-jump":
        return _eligible_requires_human_review(
            cve_id=cve_id,
            current_version=current_version,
            chosen=chosen,
            fix_tier=tier,
            trigger="major-version-jump",
            verdict_reason=(
                "fix is only present on a new major version; per §2a auto-merge "
                "is forbidden without explicit human sign-off"
            ),
        )

    return _eligible(
        cve_id=cve_id,
        current_version=current_version,
        chosen=chosen,
        fix_tier=tier,
    )


# ─── tier classification ─────────────────────────────────────────────────────

_SEMVER_RE = re.compile(r"^(\d+)\.(\d+)(?:\.(\d+))?")


def _parse_semver(v: str) -> tuple[int, int, int]:
    m = _SEMVER_RE.match(v)
    if not m:
        raise ValueError(f"resolver stub expects semver-ish versions; got {v!r}")
    major = int(m.group(1))
    minor = int(m.group(2))
    patch = int(m.group(3)) if m.group(3) else 0
    return major, minor, patch


def _classify_tier(current: str, chosen: dict[str, Any], input_doc: dict[str, Any]) -> str:
    cur = _parse_semver(current)
    tgt = _parse_semver(chosen["version"])
    if tgt[0] > cur[0]:
        return "major-version-jump"
    # Stub trusts the fixture's tier_hint when the bump is not major.
    hint = chosen.get("tier_hint")
    if hint in {"security-patch-release", "point-release-small-delta"}:
        return hint
    return "point-release-small-delta"


def _semver_distance(cur: str, tgt: str) -> tuple[int, int, int]:
    c = _parse_semver(cur)
    t = _parse_semver(tgt)
    return (t[0] - c[0], t[1] - c[1], t[2] - c[2])


def _pick_smallest_upgrade(current: str, candidates: list[dict[str, Any]]) -> dict[str, Any]:
    # Prefer the candidate whose semver distance from `current` is smallest.
    # Ties broken by original order, which preserves caller-supplied priority.
    return min(candidates, key=lambda c: _semver_distance(current, c["version"]))


# ─── output builders ─────────────────────────────────────────────────────────


def _base_eligible(
    cve_id: str,
    current_version: str,
    chosen: dict[str, Any],
    fix_tier: str,
) -> dict[str, Any]:
    out: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "cve_id": cve_id,
        "current_version": current_version,
        "target_version": chosen["version"],
        "fix_tier": fix_tier,
        "release_url": chosen["release_url"],
        "delta": {
            "transitive_package_changes": chosen["delta"]["transitive_package_changes"],
            "new_direct_deps": list(chosen["delta"].get("new_direct_deps", [])),
            "removed_direct_deps": list(chosen["delta"].get("removed_direct_deps", [])),
            "crosses_large_delta_threshold": bool(
                chosen["delta"].get("crosses_large_delta_threshold", False)
            ),
            "threshold_policy": chosen["delta"].get("threshold_policy", "v0-default"),
        },
        "replay_critical": True,
    }
    if "tag" in chosen:
        out["tag"] = chosen["tag"]
    if chosen.get("advisory_urls"):
        out["advisory_urls"] = list(chosen["advisory_urls"])
    if chosen.get("changelog_url"):
        out["changelog_url"] = chosen["changelog_url"]
    if chosen.get("upstream_fix_commits"):
        out["upstream_fix_commits"] = [
            {
                "repo_url": c["repo_url"],
                "commit_sha": c["commit_sha"],
                **({"message": c["message"]} if "message" in c else {}),
            }
            for c in chosen["upstream_fix_commits"]
        ]
    return out


def _eligible(
    cve_id: str,
    current_version: str,
    chosen: dict[str, Any],
    fix_tier: str,
) -> dict[str, Any]:
    out = _base_eligible(cve_id, current_version, chosen, fix_tier)
    out["eligibility"] = {"verdict": "eligible"}
    return out


def _eligible_requires_human_review(
    cve_id: str,
    current_version: str,
    chosen: dict[str, Any],
    fix_tier: str,
    trigger: str,
    verdict_reason: str,
) -> dict[str, Any]:
    out = _base_eligible(cve_id, current_version, chosen, fix_tier)
    out["eligibility"] = {
        "verdict": "eligible-requires-human-review",
        "verdict_reason": verdict_reason,
        "human_review_trigger": trigger,
    }
    return out


def _ineligible(
    cve_id: str,
    current_version: str,
    verdict: str,
    verdict_reason: str,
) -> dict[str, Any]:
    return {
        "schema_version": SCHEMA_VERSION,
        "cve_id": cve_id,
        "current_version": current_version,
        "eligibility": {
            "verdict": verdict,
            "verdict_reason": verdict_reason,
        },
        "replay_critical": True,
    }
