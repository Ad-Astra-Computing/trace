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

    # ─── source-backport (resolver-authorized contract for human-completed
    # backports) ─────────────────────────────────────────────────────────────
    # The harvest/Scout layer decides WHICH CVEs are backport cases (no fixed
    # release exists, or a small self-contained crash-class fix) and tags the
    # candidate; the resolver only formats + authorizes the contract. A backport
    # has target_version == current_version BY DESIGN (no version bump), so it
    # must be handled BEFORE the upgrade-candidate filter below strips it. The
    # resolver does NOT fetch/adapt upstream-fix.patch — that stays supplied
    # (harvest or hand) and the human-review verdict holds the gate; nothing
    # auto-advances a backport to assembly. The Patcher never self-selects the
    # strategy (see patcher.v3.md).
    # Monotonicity guard (peer security review 2026-06-11): only fire for a
    # GENUINE backport — version == current_version. A backport keeps the current
    # version by definition; a tagged candidate whose version != current is
    # malformed or a misrouting attempt, so we ignore the tag and fall through to
    # normal routing (which handles upgrades / downgrades / ineligible correctly).
    # This keeps the branch strictly inside the already-human-review territory
    # (target==current otherwise routes to no-target-version-derived) and prevents
    # the tag from PROMOTING a would-be hard-`ineligible` (e.g. downgrade-only)
    # CVE into a human-approvable state.
    backport_candidates = [
        c for c in candidates
        if _is_source_backport_signal(c) and c.get("version") == current_version
    ]
    if backport_candidates:
        chosen = backport_candidates[0]
        # A backport signal with no fix reference cannot be authored — never
        # emit an assemblable skeleton the human can't complete.
        if not chosen.get("upstream_fix_commits"):
            return _ineligible(
                cve_id=cve_id,
                current_version=current_version,
                verdict="ineligible-no-fix-available",
                verdict_reason=(
                    "candidate is tagged source-backport but carries no "
                    "upstream_fix_commits reference; a backport cannot be "
                    "authored without the upstream fix commit to transcribe."
                ),
            )
        # Carry through the harvest's "no fixed release derivable" fact, if any.
        # The source-backport strategy is layered ON TOP of that fact, never a
        # replacement (peer review 2026-06-11): a clean-applying backport may
        # still be a NECESSARY-BUT-NOT-SUFFICIENT fix, so the human must confirm
        # sufficiency — the reason the candidate had no derivable fixed release
        # must survive the strategy tag.
        review_reason = chosen.get("requires_review_reason")
        reason_note = (
            f" The harvest could not derive a fixed release version "
            f"(requires_review_reason={review_reason!r}); the human must confirm "
            f"the backport is the COMPLETE fix, not merely one necessary commit."
            if review_reason else ""
        )
        return _eligible_requires_human_review(
            cve_id=cve_id,
            current_version=current_version,
            chosen=chosen,
            fix_tier=_classify_tier(current_version, chosen, input_doc),
            trigger="source-backport-experimental",
            patch_strategy="source-backport",
            verdict_reason=(
                "source-backport (resolver-authorized): the harvest layer tagged "
                "this CVE as a backport case (e.g. no fixed release exists, or a "
                "small self-contained crash-class fix). The Patcher AUTHORS the "
                "upstream fix (upstream_fix_commits) as an in-tree patch against "
                "the current version; version is unchanged (target == current by "
                "design). Routed to human review (experimental); upstream-fix.patch "
                "must be supplied. The Patcher never self-selects this strategy."
                + reason_note
            ),
        )

    upgrade_candidates = [
        c for c in candidates
        if _is_upgrade_or_unparseable(current_version, c["version"])
    ]
    if not upgrade_candidates:
        return _ineligible(
            cve_id=cve_id,
            current_version=current_version,
            verdict="ineligible-no-fix-available",
            verdict_reason=(
                "every candidate target_version is <= current_version; "
                "the advisory has no upstream fix on the current major/minor "
                "line. Either downgrade is required (forbidden by auto-merge) "
                "or the package is already past the affected range."
            ),
        )
    chosen = _pick_smallest_upgrade(current_version, upgrade_candidates)

    # Dominating guard: if semver ordering between current and the chosen target
    # cannot be established (either side is a git-snapshot / unstable pin like
    # `0-unstable-2026-01-30`), we cannot prove this is an upgrade, so auto-merge
    # is off the table. This MUST precede every _eligible path — an unstable
    # TARGET does not match the pre-release regex and would otherwise fall through
    # to auto-merge. `_pick_smallest_upgrade` has already preferred any comparable
    # real upgrade, so reaching here means no semver-comparable candidate existed.
    if _semver_distance(current_version, chosen["version"]) is None:
        current_ok = _try_parse_semver(current_version) is not None
        target_ok = _try_parse_semver(chosen["version"]) is not None
        if not current_ok and not target_ok:
            side = "both current_version and target_version are"
        elif not current_ok:
            side = "current_version is"
        else:
            side = "target_version is"
        return _eligible_requires_human_review(
            cve_id=cve_id,
            current_version=current_version,
            chosen=chosen,
            fix_tier=_classify_tier(current_version, chosen, input_doc),
            trigger="unparseable-version-comparison",
            verdict_reason=(
                f"{side} not semver-shaped (e.g. a git-snapshot / unstable "
                "nixpkgs pin), so upgrade ordering cannot be established. The "
                "candidate was chosen by caller priority order, not by upgrade "
                "distance. Auto-merge is forbidden without a human confirming "
                "the target is genuinely the fixed release."
            ),
        )

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

    if _is_pre_release(chosen["version"]):
        return _eligible_requires_human_review(
            cve_id=cve_id,
            current_version=current_version,
            chosen=chosen,
            fix_tier=_classify_tier(current_version, chosen, input_doc),
            trigger="pre-release-target",
            verdict_reason=(
                "candidate target_version is a pre-release (alpha/beta/"
                "rc/dev/etc.); auto-merging to an unstable upstream is "
                "forbidden without explicit human sign-off."
            ),
        )

    if chosen.get("requires_review_reason") == "placeholder-target-version":
        return _eligible_requires_human_review(
            cve_id=cve_id,
            current_version=current_version,
            chosen=chosen,
            fix_tier=_classify_tier(current_version, chosen, input_doc),
            trigger="placeholder-target-version",
            verdict_reason=(
                "scout could not extract a fix-version signal from the "
                "advisory (no version_bounds, no lessThan/versionEndExcluding "
                "constraint). target_version is a placeholder fallback to "
                "current_version, not a real derivation. Human must confirm "
                "the actual fix version."
            ),
        )

    if chosen["version"] == current_version:
        # Backstop for callers that didn't tag the placeholder explicitly
        # (e.g. legacy resolver-input docs from before slice 5f). Same
        # routing outcome; less specific verdict_reason.
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


def _try_parse_semver(v: str) -> tuple[int, int, int] | None:
    """Parse a semver-ish version, or return None when it is not semver-shaped.

    nixpkgs pins some packages to a git snapshot (`0-unstable-2026-01-30`,
    `unstable-2026-01-30`, a bare commit date, …) that has no semver triple.
    Callers that must reason about version ORDERING treat None as "ordering
    cannot be established" and route to human review rather than crashing or,
    worse, silently auto-merging.
    """
    m = _SEMVER_RE.match(v)
    if not m:
        return None
    major = int(m.group(1))
    minor = int(m.group(2))
    patch = int(m.group(3)) if m.group(3) else 0
    return major, minor, patch


def _parse_semver(v: str) -> tuple[int, int, int]:
    parsed = _try_parse_semver(v)
    if parsed is None:
        raise ValueError(f"resolver stub expects semver-ish versions; got {v!r}")
    return parsed


def _classify_tier(current: str, chosen: dict[str, Any], input_doc: dict[str, Any]) -> str:
    # Tolerant by design: never raises. When either side is not semver-shaped the
    # resolver has ALREADY committed to human review (the unparseable-version
    # guard dominates before any auto-merge path), so the tier here is only a
    # label on a human-review bundle — a major-version jump can't be detected
    # without a semver triple, so we fall back to the tier_hint / neutral tier.
    cur = _try_parse_semver(current)
    tgt = _try_parse_semver(chosen["version"])
    if cur is not None and tgt is not None and tgt[0] > cur[0]:
        return "major-version-jump"
    # Stub trusts the fixture's tier_hint when the bump is not major.
    hint = chosen.get("tier_hint")
    if hint in {"security-patch-release", "point-release-small-delta"}:
        return hint
    return "point-release-small-delta"


def _semver_distance(cur: str, tgt: str) -> tuple[int, int, int] | None:
    """Distance between two semver triples, or None when either side is not
    semver-shaped (ordering is then unknowable, not zero)."""
    c = _try_parse_semver(cur)
    t = _try_parse_semver(tgt)
    if c is None or t is None:
        return None
    return (t[0] - c[0], t[1] - c[1], t[2] - c[2])


def _pick_smallest_upgrade(current: str, candidates: list[dict[str, Any]]) -> dict[str, Any]:
    # Rank in three tiers so precedence matches how much a candidate is worth:
    #   0. a STRICT semver upgrade (distance > 0)  — the real fix, smallest wins;
    #   1. an UNKNOWABLE-ordering candidate (current or target not semver-shaped)
    #      — a real candidate ref whose ordering we can't prove (unstable pin);
    #   2. an EQUAL-version placeholder (distance == 0) — a no-op / no-target-
    #      derived fallback that must NOT shadow tier 1 (codex review 2026-07-20).
    # Within a tier, original order breaks ties, preserving caller priority.
    def _key(item: tuple[int, dict[str, Any]]) -> tuple:
        idx, c = item
        dist = _semver_distance(current, c["version"])
        if dist is None:
            return (1, (), idx)
        if dist == (0, 0, 0):
            return (2, (), idx)
        return (0, dist, idx)

    return min(enumerate(candidates), key=_key)[1]


_PRE_RELEASE_RE = re.compile(r"[-+](?:rc|alpha|beta|dev|pre|preview|nightly|snapshot|m\d|a\d|b\d)", re.IGNORECASE)


def _is_pre_release(version: str) -> bool:
    """Detect pre-release / unstable target versions. Conservative: any
    semver build that names a pre-release identifier (rc, alpha, beta,
    dev, preview, nightly, snapshot, m, a, b) after the base triple is
    treated as unstable. Plain semver like 1.2.3 is not."""
    return bool(_PRE_RELEASE_RE.search(version))


def _is_upgrade_or_unparseable(current: str, target: str) -> bool:
    """True iff target >= current under semver, OR either side is
    unparseable. Equality is preserved so the existing
    no-target-version-derived safety net catches it; only strict
    downgrades (target < current) get filtered out, since auto-merging
    a downgrade is unsafe."""
    try:
        c = _parse_semver(current)
        t = _parse_semver(target)
    except ValueError:
        return True
    return t >= c


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
    patch_strategy: str | None = None,
) -> dict[str, Any]:
    out = _base_eligible(cve_id, current_version, chosen, fix_tier)
    out["eligibility"] = {
        "verdict": "eligible-requires-human-review",
        "verdict_reason": verdict_reason,
        "human_review_trigger": trigger,
    }
    # Source-backport authorization: the resolver records that the Patcher must
    # AUTHOR the upstream fix as an in-tree patch (not bump the version). The
    # Patcher never self-selects this — it reads it as given truth here.
    if patch_strategy is not None:
        out["eligibility"]["patch_strategy"] = patch_strategy
    return out


def _is_source_backport_signal(candidate: dict[str, Any]) -> bool:
    """True iff the harvest layer tagged this candidate as a source-backport.

    Precedence (per peer review 2026-06-11): `eligibility.patch_strategy` is
    authoritative; `tier_hint` is the lighter hint consulted ONLY when
    patch_strategy is absent. So an explicit `patch_strategy: "version-bump"`
    overrides a stale `tier_hint: "source-backport"`.
    """
    ps = (candidate.get("eligibility") or {}).get("patch_strategy")
    if ps is not None:
        return ps == "source-backport"
    return candidate.get("tier_hint") == "source-backport"


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
