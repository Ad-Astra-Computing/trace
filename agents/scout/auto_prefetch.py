"""Auto-prefetch orchestrator for the cron path.

Bridges four pieces:

  * agents.patcher.path_resolver — finds package.nix on disk
  * agents.upstream_ref_resolver.url_derivation — derives target URLs
  * agents.upstream_ref_resolver.prefetch — runs nix-prefetch-url
  * agents.upstream_ref_resolver.fetchzip_prefetch — fetchzip FOD via nix-build

Scope (slice 5d + 5e):

  plain-fetchurl       attempted via nix-prefetch-url
                       gate: TRACE_REAL_PREFETCH=1
  fetchFromGitHub      attempted via fetchzip_prefetch (nix-build with
                       fakeHash, FOD-mismatch parsing)
                       gate: TRACE_REAL_FETCHZIP=1 (NARROWED: only
                       fetchFromGitHub-shaped src; generic fetchzip stays
                       skipped)
  fetchzip (generic)   detected, skipped — separate fetcher class
  go-mod-vendor        detected via vendorHash/cargoHash/npmDepsHash
                       (additive — co-occurs with src class)

Live-call gating, both layered:

  TRACE_REAL_PREFETCH=1 enables plain-fetchurl path
  TRACE_REAL_FETCHZIP=1 enables fetchFromGitHub path
  Both ALSO require --nixpkgs-root to be supplied.
  Missing env or root → silent skip with classified stats.

The metrics partition cleanly so the operator can trace volume to the
specific fetcher class. Any prefetch failure produces a structured
prefetch_failures[] entry with required_for_patch=True; Steward then
routes the entry to human-review-required via the existing patcher-
not-ready rule. No Steward policy is loosened by this slice — the
bundle becomes more grounded, not the policy more permissive.
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
from agents.upstream_ref_resolver.fetchzip_prefetch import (
    CommandRunner as FetchzipCommandRunner,
    FetchzipFailure,
    FetchzipRequest,
    FetchzipSuccess,
    prefetch_fetchzip,
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
    # Diagnostic from path_resolver when skipped_reason="no-package-source".
    # Free-form short string surfaced from PackageSourceNotFound's message
    # (covers e.g. "no package.nix at pkgs/by-name/li/linux/...",
    # "nix eval did not return a meta.position for 'linux': nix-eval-timeout-120s",
    # "nix eval returned ... outside nixpkgs root"). Without this the cron
    # logs show only "no-package-source" with no signal as to which gap
    # broke; aggregator buckets these by reason-prefix for the run summary.
    path_resolver_diag: str | None = None
    # Per-entry truncated raw PackageSourceNotFound message. Only
    # surfaced in per-entry JSONL, not aggregated. Captures the
    # specific path/attr the resolver saw so debugging doesn't require
    # another round-trip.
    path_resolver_message: str | None = None
    has_vendor_style_hash: bool = False
    plain_fetchurl_attempted: int = 0
    plain_fetchurl_succeeded: int = 0
    plain_fetchurl_failed: int = 0
    fetchFromGitHub_attempted: int = 0
    fetchFromGitHub_succeeded: int = 0
    fetchFromGitHub_failed: int = 0
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
    fetchzip_command_runner: FetchzipCommandRunner | None = None,
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
    real_prefetch = os.environ.get("TRACE_REAL_PREFETCH") == "1"
    real_fetchzip = os.environ.get("TRACE_REAL_FETCHZIP") == "1"
    if env_gate and not (real_prefetch or real_fetchzip):
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
    except PackageSourceNotFound as e:
        msg = str(e)
        return AutoPrefetchStats(
            skipped_reason="no-package-source",
            primary_src_class="no-source-resolved",
            path_resolver_diag=_normalize_diag(msg),
            # Carry a truncated raw message for per-entry debugging.
            # Aggregator buckets by `path_resolver_diag` only; the raw
            # message is per-entry and helps identify which file path
            # the resolver actually saw — the bucket alone strips the
            # specific path that often is the actionable detail (e.g.
            # which alt-source store entry, which by-name shard).
            path_resolver_message=msg[:300],
        )

    package_source = pkg.content
    primary, has_vendor = _classify_source(package_source)

    # ── fetchFromGitHub: fetchzip-aware FOD-extraction ─────────────────
    if primary == "fetchFromGitHub":
        if env_gate and not real_fetchzip:
            # Detected but not in scope under the active gate.
            return AutoPrefetchStats(
                primary_src_class=primary,
                has_vendor_style_hash=has_vendor,
                fetchFromGitHub_present_but_skipped=1,
                go_mod_vendor_present_but_skipped=1 if has_vendor else 0,
            )
        target_version = upstream_ref.get("target_version") or ""
        if not target_version:
            # No target version → fetchzip_prefetch can't substitute the
            # tag template. Record as skip; Steward already routes
            # missing-target to review.
            return AutoPrefetchStats(
                primary_src_class=primary,
                has_vendor_style_hash=has_vendor,
                fetchFromGitHub_present_but_skipped=1,
                go_mod_vendor_present_but_skipped=1 if has_vendor else 0,
            )
        request = FetchzipRequest(
            attr_path=attr_path,
            target_version=target_version,
            current_version=upstream_ref.get("current_version") or "",
        )
        result = prefetch_fetchzip(
            request, command_runner=fetchzip_command_runner,
        )
        if isinstance(result, FetchzipSuccess):
            upstream_ref["prefetch_hashes"] = (
                upstream_ref.get("prefetch_hashes", []) + [result.to_schema_dict()]
            )
            _atomic_write_json(upstream_ref_path, upstream_ref)
            return AutoPrefetchStats(
                primary_src_class=primary,
                has_vendor_style_hash=has_vendor,
                fetchFromGitHub_attempted=1,
                fetchFromGitHub_succeeded=1,
                go_mod_vendor_present_but_skipped=1 if has_vendor else 0,
            )
        # FetchzipFailure: required_for_patch=True so Steward routes to
        # human-review per the existing patcher-not-ready rule.
        upstream_ref["prefetch_failures"] = (
            upstream_ref.get("prefetch_failures", []) + [result.to_schema_dict()]
        )
        _atomic_write_json(upstream_ref_path, upstream_ref)
        return AutoPrefetchStats(
            primary_src_class=primary,
            has_vendor_style_hash=has_vendor,
            fetchFromGitHub_attempted=1,
            fetchFromGitHub_failed=1,
            go_mod_vendor_present_but_skipped=1 if has_vendor else 0,
        )

    if primary == "plain-fetchurl":
        if env_gate and not real_prefetch:
            return AutoPrefetchStats(
                primary_src_class=primary,
                has_vendor_style_hash=has_vendor,
                go_mod_vendor_present_but_skipped=1 if has_vendor else 0,
            )
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


def _normalize_diag(message: str) -> str:
    """Map a PackageSourceNotFound message to a short bucket key.

    The aggregator counts entries per-bucket so the run summary stays
    readable across batches. Buckets cover the four gaps path_resolver
    can hit; anything unrecognized falls into "other" so we know to
    extend the mapping. Bucket key is what shows up in the cron's
    auto-prefetch-counts.json under path-resolver-diag.
    """
    msg = message or ""
    # Order matters: the by-name miss can co-occur with later eval errors
    # so we test for the more specific signatures first.
    if "nix-eval-timeout" in msg:
        return "nix-eval-timeout"
    if "nix-eval-empty-output" in msg:
        return "nix-eval-empty-output"
    if "nix-eval-exit-" in msg:
        return "nix-eval-exit-nonzero"
    if "nix-not-on-path" in msg:
        return "nix-not-on-path"
    if "outside nixpkgs root" in msg:
        return "outside-nixpkgs-root"
    if "is not a file" in msg:
        return "eval-position-not-a-file"
    if "no package.nix at" in msg:
        return "by-name-miss-no-eval-fallback"
    if "namespaced attr_path" in msg:
        return "namespaced-no-eval-fallback"
    if "too short for by-name shard" in msg:
        return "attr-path-too-short"
    if "nixpkgs root does not exist" in msg:
        return "nixpkgs-root-missing"
    return "other"


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
        "fetchFromGitHub-attempted": 0,
        "fetchFromGitHub-succeeded": 0,
        "fetchFromGitHub-failed": 0,
        "fetchFromGitHub-present-but-skipped": 0,
        "fetchzip-present-but-skipped": 0,
        "go-mod-vendor-present-but-skipped": 0,
        "skipped-no-source-resolved": 0,
        "skipped-env-not-set": 0,
        "skipped-no-nixpkgs-root": 0,
        "skipped-already-populated": 0,
        "skipped-no-upstream-ref": 0,
        # Per-cause breakdown of skipped-no-source-resolved. Surfaced from
        # path_resolver's PackageSourceNotFound diagnostic so we can tell
        # which structural gap blocked the resolve. Empty when no entry
        # hit no-package-source. Diagnostics are normalized to short
        # bucket keys; see _normalize_diag for the mapping.
        "path-resolver-diag": {},
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
            if s.path_resolver_diag:
                agg["path-resolver-diag"][s.path_resolver_diag] = (
                    agg["path-resolver-diag"].get(s.path_resolver_diag, 0) + 1
                )
            continue
        agg["plain-fetchurl-attempted"] += s.plain_fetchurl_attempted
        agg["plain-fetchurl-succeeded"] += s.plain_fetchurl_succeeded
        agg["plain-fetchurl-failed"] += s.plain_fetchurl_failed
        agg["fetchFromGitHub-attempted"] += s.fetchFromGitHub_attempted
        agg["fetchFromGitHub-succeeded"] += s.fetchFromGitHub_succeeded
        agg["fetchFromGitHub-failed"] += s.fetchFromGitHub_failed
        agg["fetchFromGitHub-present-but-skipped"] += s.fetchFromGitHub_present_but_skipped
        agg["fetchzip-present-but-skipped"] += s.fetchzip_present_but_skipped
        agg["go-mod-vendor-present-but-skipped"] += s.go_mod_vendor_present_but_skipped
    return agg


__all__ = [
    "AutoPrefetchStats",
    "auto_prefetch_for_entry",
    "aggregate_stats",
]
