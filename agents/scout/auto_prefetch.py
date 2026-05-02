"""Auto-prefetch orchestrator for the cron path.

Bridges three pieces:

  * agents.patcher.path_resolver — finds package.nix on disk
  * agents.upstream_ref_resolver.url_derivation — derives target URLs
  * agents.upstream_ref_resolver.prefetch — runs nix-prefetch-url

Scope (slice 5d, narrow):

  Only auto-prefetches **plain fetchurl** with a clean URL template
  at high confidence. Other fetcher classes are detected and counted
  for metrics, but not prefetched:

    plain-fetchurl       attempted via nix-prefetch-url
    fetchFromGitHub      detected, skipped (would need fetchzip-aware
                         prefetch via nix-build/fakeHash; gated by
                         TRACE_REAL_FETCHZIP)
    fetchzip             detected, skipped (same gate)
    go-mod-vendor        detected via vendorHash/cargoHash/npmDepsHash
                         (additive — co-occurs with src class)

The metrics that come out of this surface where the cron's auto-merge
volume actually lives. If most candidates are fetchFromGitHub, the
next slice opens the fetchzip-aware path; if plain fetchurl dominates,
this narrow slice was enough.

Live-call gating:

  TRACE_REAL_PREFETCH=1 must be set, AND nixpkgs_root must be supplied.
  Either missing → skip silently and report skip-stats.
"""

from __future__ import annotations

import json
import os
import re
import tempfile
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Callable

from agents.patcher.path_resolver import (
    PackageSourceNotFound,
    resolve_package_source,
)
from agents.upstream_ref_resolver.prefetch import PrefetchUrlFn
from agents.upstream_ref_resolver.url_derivation import (
    DerivationOutcome,
    auto_prefetch_high_confidence,
    derive_prefetch_targets,
)


_SRC_PRIMARY_CLASSES = (
    "plain-fetchurl",
    "fetchFromGitHub",
    "fetchzip",
    "other",
    "no-source-resolved",
)


# Vendor-style hash attributes whose presence flags an ecosystem-specific
# prefetch path that nix-prefetch-url cannot satisfy. Mirrors the
# NON_URL_HASH_ATTRS list in url_derivation.py.
_VENDOR_HASH_RE = re.compile(
    r"\b(vendorHash|vendorSha256|cargoHash|cargoSha256|npmDepsHash|"
    r"pnpmDepsHash|yarnDepsHash|yarnHash)\s*="
)

_SRC_FETCHURL_RE = re.compile(r"\bsrc\s*=\s*fetchurl\s*\{", re.DOTALL)
_SRC_FETCHZIP_RE = re.compile(r"\bsrc\s*=\s*fetchzip\s*\{", re.DOTALL)
_SRC_FETCHFROMGITHUB_RE = re.compile(r"\bsrc\s*=\s*fetchFromGitHub\s*\{", re.DOTALL)


@dataclass(frozen=True)
class AutoPrefetchStats:
    """Per-entry stats; aggregator sums these across a batch."""
    skipped_reason: str | None = None  # "env-not-set" | "no-nixpkgs-root" | "no-package-source" | None
    primary_src_class: str = "no-source-resolved"  # one of _SRC_PRIMARY_CLASSES
    has_vendor_style_hash: bool = False
    plain_fetchurl_attempted: int = 0
    plain_fetchurl_succeeded: int = 0
    plain_fetchurl_failed: int = 0
    fetchFromGitHub_present_but_skipped: int = 0
    fetchzip_present_but_skipped: int = 0
    go_mod_vendor_present_but_skipped: int = 0
    derived_targets: int = 0
    derived_skips: int = 0


def auto_prefetch_for_entry(
    entry_path: Path,
    *,
    attr_path: str,
    nixpkgs_root: Path | None,
    use_nix_eval: bool = False,
    prefetch_url_fn: PrefetchUrlFn | None = None,
    env_gate: bool = True,
) -> AutoPrefetchStats:
    """Drive auto-prefetch for one inbox entry, env-gated.

    Reads upstream-ref.json from the entry, resolves the package source
    on disk, runs derivation + prefetch (where in scope), and splices
    results back into upstream-ref.json atomically.

    Returns an AutoPrefetchStats describing what happened. Never raises
    on a per-entry failure: the stats record the diagnosis and the
    caller decides what to do.
    """
    if env_gate and os.environ.get("TRACE_REAL_PREFETCH") != "1":
        return AutoPrefetchStats(skipped_reason="env-not-set")
    if nixpkgs_root is None:
        return AutoPrefetchStats(skipped_reason="no-nixpkgs-root")

    upstream_ref_path = entry_path / "upstream-ref.json"
    if not upstream_ref_path.is_file():
        return AutoPrefetchStats(skipped_reason="no-upstream-ref")
    upstream_ref = json.loads(upstream_ref_path.read_text())

    # Don't re-prefetch already-populated bundles. Idempotent re-runs
    # should not double-call the network.
    if upstream_ref.get("prefetch_hashes"):
        return _classify_only(upstream_ref, package_source=None)

    try:
        pkg = resolve_package_source(
            attr_path,
            nixpkgs_root=nixpkgs_root,
            use_nix_eval=use_nix_eval,
        )
    except PackageSourceNotFound:
        return AutoPrefetchStats(
            skipped_reason="no-package-source",
            primary_src_class="no-source-resolved",
        )

    package_source = pkg.content
    primary, has_vendor = _classify_source(package_source)

    if primary == "plain-fetchurl":
        # Run the upstream auto-prefetch helper. It already filters to
        # high-confidence targets — for plain fetchurl that's the
        # package-url-template rule.
        derivation, prefetch, high = auto_prefetch_high_confidence(
            upstream_ref=upstream_ref,
            package_source=package_source,
            attr_path=attr_path,
            prefetch_url_fn=prefetch_url_fn,
        )
        attempted = len(prefetch.hashes) + len(prefetch.failures)
        succeeded = len(prefetch.hashes)
        failed = len(prefetch.failures)

        # Only splice fetchurl-derived hashes (i.e. package-url-template
        # rule). github-release-archive medium-confidence hashes are
        # already excluded by auto_prefetch_high_confidence's high-only
        # filter, but be defensive.
        new_hashes = []
        for s, t in zip(prefetch.hashes, high):
            if t.derivation_rule == "package-url-template":
                new_hashes.append(s.to_dict())
        new_failures = []
        for f, t in zip(prefetch.failures, high):
            if t.derivation_rule == "package-url-template":
                new_failures.append(f.to_dict())
        new_skips = [s.to_schema_dict() for s in derivation.skipped]

        if new_hashes:
            upstream_ref["prefetch_hashes"] = new_hashes
        if new_failures:
            upstream_ref["prefetch_failures"] = (
                upstream_ref.get("prefetch_failures", []) + new_failures
            )
        if new_skips:
            existing = upstream_ref.get("prefetch_skips", [])
            seen = {(s.get("name"), s.get("reason")) for s in existing}
            merged = list(existing) + [
                s for s in new_skips
                if (s["name"], s["reason"]) not in seen
            ]
            upstream_ref["prefetch_skips"] = merged

        _atomic_write_json(upstream_ref_path, upstream_ref)

        return AutoPrefetchStats(
            primary_src_class=primary,
            has_vendor_style_hash=has_vendor,
            plain_fetchurl_attempted=attempted,
            plain_fetchurl_succeeded=succeeded,
            plain_fetchurl_failed=failed,
            go_mod_vendor_present_but_skipped=1 if has_vendor else 0,
            derived_targets=len(derivation.targets),
            derived_skips=len(derivation.skipped),
        )

    # Out-of-scope src class. Run derivation only for diagnostic skips,
    # but no prefetch. Splice skips so Steward routes to human-review
    # with a structured patcher-not-ready reason.
    derivation = derive_prefetch_targets(
        upstream_ref=upstream_ref,
        package_source=package_source,
        attr_path=attr_path,
    )
    new_skips = [s.to_schema_dict() for s in derivation.skipped]
    if new_skips:
        existing = upstream_ref.get("prefetch_skips", [])
        seen = {(s.get("name"), s.get("reason")) for s in existing}
        merged = list(existing) + [
            s for s in new_skips
            if (s["name"], s["reason"]) not in seen
        ]
        upstream_ref["prefetch_skips"] = merged
        _atomic_write_json(upstream_ref_path, upstream_ref)

    return AutoPrefetchStats(
        primary_src_class=primary,
        has_vendor_style_hash=has_vendor,
        fetchFromGitHub_present_but_skipped=1 if primary == "fetchFromGitHub" else 0,
        fetchzip_present_but_skipped=1 if primary == "fetchzip" else 0,
        go_mod_vendor_present_but_skipped=1 if has_vendor else 0,
        derived_targets=len(derivation.targets),
        derived_skips=len(derivation.skipped),
    )


def _classify_source(package_source: str) -> tuple[str, bool]:
    """Return (primary_src_class, has_vendor_style_hash).

    Primary is decided by the first match in priority order:
      fetchFromGitHub > fetchzip > fetchurl > other.
    fetchFromGitHub wins over fetchurl because some packages have
    decoy fetchurl blocks for patches; the primary src is what
    nixpkgs builds.
    """
    has_vendor = bool(_VENDOR_HASH_RE.search(package_source))
    if _SRC_FETCHFROMGITHUB_RE.search(package_source):
        return "fetchFromGitHub", has_vendor
    if _SRC_FETCHZIP_RE.search(package_source):
        return "fetchzip", has_vendor
    if _SRC_FETCHURL_RE.search(package_source):
        return "plain-fetchurl", has_vendor
    return "other", has_vendor


def _classify_only(upstream_ref: dict, *, package_source: str | None) -> AutoPrefetchStats:
    """Idempotency path: return stats for an already-populated entry
    without re-running prefetch. Source-class is unknown without
    package text, so report 'other' to avoid double-counting."""
    return AutoPrefetchStats(
        skipped_reason="already-populated",
        primary_src_class="other",
    )


def _atomic_write_json(path: Path, data: Any) -> None:
    payload = json.dumps(data, indent=2, sort_keys=True).encode("utf-8") + b"\n"
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix=path.name + ".", dir=str(path.parent))
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(payload)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)
    except Exception:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def aggregate_stats(stats_list: list[AutoPrefetchStats]) -> dict[str, Any]:
    """Sum per-entry stats into a batch-level summary."""
    agg = {
        "plain-fetchurl-attempted": 0,
        "plain-fetchurl-succeeded": 0,
        "plain-fetchurl-failed": 0,
        "fetchFromGitHub-present-but-skipped": 0,
        "fetchzip-present-but-skipped": 0,
        "go-mod-vendor-present-but-skipped": 0,
        "skipped-no-source-resolved": 0,
        "skipped-env-not-set": 0,
        "skipped-no-nixpkgs-root": 0,
        "skipped-already-populated": 0,
        "skipped-no-upstream-ref": 0,
    }
    for s in stats_list:
        if s.skipped_reason == "env-not-set":
            agg["skipped-env-not-set"] += 1
            continue
        if s.skipped_reason == "no-nixpkgs-root":
            agg["skipped-no-nixpkgs-root"] += 1
            continue
        if s.skipped_reason == "already-populated":
            agg["skipped-already-populated"] += 1
            continue
        if s.skipped_reason == "no-upstream-ref":
            agg["skipped-no-upstream-ref"] += 1
            continue
        if s.skipped_reason == "no-package-source":
            agg["skipped-no-source-resolved"] += 1
            continue
        agg["plain-fetchurl-attempted"] += s.plain_fetchurl_attempted
        agg["plain-fetchurl-succeeded"] += s.plain_fetchurl_succeeded
        agg["plain-fetchurl-failed"] += s.plain_fetchurl_failed
        agg["fetchFromGitHub-present-but-skipped"] += s.fetchFromGitHub_present_but_skipped
        agg["fetchzip-present-but-skipped"] += s.fetchzip_present_but_skipped
        agg["go-mod-vendor-present-but-skipped"] += s.go_mod_vendor_present_but_skipped
    return agg


__all__ = [
    "AutoPrefetchStats",
    "auto_prefetch_for_entry",
    "aggregate_stats",
]
