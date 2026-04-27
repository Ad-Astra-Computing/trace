"""URL derivation layer above the prefetch module.

After the bind A/B (commit 756de73) the bottleneck moved from "can the
Patcher use grounded hashes" (yes) to "can the resolver derive the
URLs to prefetch without hand assembly" (until now: no). This module
takes `(upstream_ref, package_source, attr_path)` and emits structured
target candidates that `prefetch_targets()` can consume directly.

Scope (deliberately narrow per the design call):

  * Cover the patterns cohort-1 already needs: github-release-archive
    (mbedtls fetchFromGitHub), package-url-template (bind's
    downloads.isc.org template), gitlab-release-archive (bind's
    upstream commit_sha host).
  * High-confidence-only auto-prefetch: ambiguous cases are recorded
    as `SkippedTarget` with a structured reason so the bundle is still
    schema-valid and Patcher correctly rule-8 refuses for that hash
    slot.
  * vendorHash / cargoHash / npmDepsHash / yarnDepsHash / pnpmDepsHash
    are detected in `package.nix` and explicitly skipped with reason
    `ecosystem-not-url-derivable`. Go vendoring + Rust vendoring + JS
    deps need separate prefetch mechanisms (`prefetch_kind`-shaped, not
    URL-shaped); they will land in a follow-up module.

The derivation runs entirely on local strings — no network — so it is
deterministic and replay-safe. The actual prefetch (network call) is
a separate step done by `prefetch_targets()`.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Iterable
from urllib.parse import urlparse


# ─── result types ─────────────────────────────────────────────────────────


@dataclass(frozen=True)
class DerivedTarget:
    """A high/medium/low-confidence prefetch target derived locally."""

    name: str               # e.g. "src.hash"
    url: str
    derivation_rule: str    # see DERIVATION_RULES
    confidence: str         # "high" | "medium" | "low"
    algorithm: str = "sha256"


@dataclass(frozen=True)
class SkippedTarget:
    """A hash slot the derivation found but cannot URL-derive."""

    name: str
    reason: str  # see SKIP_REASONS
    detail: str | None = None


@dataclass(frozen=True)
class DerivationOutcome:
    targets: list[DerivedTarget] = field(default_factory=list)
    skipped: list[SkippedTarget] = field(default_factory=list)


# ─── enums (kept narrow) ──────────────────────────────────────────────────


DERIVATION_RULES: tuple[str, ...] = (
    "github-release-archive",      # fetchFromGitHub or upstream repo on github.com
    "gitlab-release-archive",      # upstream repo on a gitlab host
    "package-url-template",        # literal URL template in package.nix with ${version} placeholders
)


SKIP_REASONS: tuple[str, ...] = (
    "ecosystem-not-url-derivable",         # vendorHash / cargoHash / npmDepsHash family
    "url-template-too-complex",            # fetchurl with multiple competing placeholders
    "no-derivable-rule",                   # nothing in package.nix or upstream-ref hints at a URL
    "missing-target-version",              # upstream-ref doesn't have target_version
    "missing-tag",                         # github archive needs a tag and the bundle has none
)


# Hash-shaped attributes that are NOT URL-derivable in v0 — they need
# ecosystem-specific prefetch mechanisms (go-mod-vendor, cargo-vendor,
# npm-deps-prefetch, etc.). The derivation layer records these as skipped
# with reason ecosystem-not-url-derivable.
NON_URL_HASH_ATTRS: tuple[str, ...] = (
    "vendorHash", "vendorSha256",
    "cargoHash", "cargoSha256",
    "npmDepsHash", "pnpmDepsHash", "yarnDepsHash", "yarnHash",
)


# ─── regex toolkit ────────────────────────────────────────────────────────


# `fetchurl { ... url = "https://..."; ... }` — capture the URL string,
# not the rest of the block. Permissive on whitespace; multiline.
_FETCHURL_URL_RE = re.compile(
    r"fetchurl\s*\{[^}]*?url\s*=\s*\"(?P<url>[^\"]+)\"",
    re.DOTALL,
)

# `fetchzip { ... url = "..."; ... }` — same shape.
_FETCHZIP_URL_RE = re.compile(
    r"fetchzip\s*\{[^}]*?url\s*=\s*\"(?P<url>[^\"]+)\"",
    re.DOTALL,
)

# `fetchFromGitHub { owner = "..."; repo = "..."; rev = "..."; ... }` —
# capture all three. Order in nixpkgs is conventionally owner-repo-rev
# but we don't depend on it.
_FROMGITHUB_OWNER_RE = re.compile(r"fetchFromGitHub\s*\{[^}]*?owner\s*=\s*\"(?P<owner>[^\"]+)\"", re.DOTALL)
_FROMGITHUB_REPO_RE = re.compile(r"fetchFromGitHub\s*\{[^}]*?repo\s*=\s*\"(?P<repo>[^\"]+)\"", re.DOTALL)
_FROMGITHUB_REV_RE = re.compile(r"fetchFromGitHub\s*\{[^}]*?rev\s*=\s*\"(?P<rev>[^\"]+)\"", re.DOTALL)

# Hash-shaped attribute presence check, used for the skipped-target detector.
_HASH_ATTR_PRESENCE_RE = re.compile(
    r"^\s*(?P<name>" + "|".join(re.escape(n) for n in NON_URL_HASH_ATTRS) + r")\s*=",
    re.MULTILINE,
)

# Nix interpolation tokens we know how to substitute. `${version}` is
# the canonical form; nixpkgs idiom also uses `${finalAttrs.version}`,
# `${pname}`, and `${pname}-${version}`.
_VERSION_INTERP_RE = re.compile(r"\$\{(?:finalAttrs\.)?version\}")
_PNAME_INTERP_RE = re.compile(r"\$\{pname\}")


# ─── entry point ──────────────────────────────────────────────────────────


def derive_prefetch_targets(
    *,
    upstream_ref: dict,
    package_source: str,
    attr_path: str | None = None,
) -> DerivationOutcome:
    """Derive prefetch targets without touching the network.

    Args:
        upstream_ref: parsed upstream-ref.json. Must carry `target_version`
            for any URL-template rule to fire; `tag` is required for
            github/gitlab-release-archive rules.
        package_source: full text of package.nix (or equivalent) for
            the affected attr.
        attr_path: optional. The Nix attr the patch is for. Some rules
            use the attr path as a `pname` fallback when package.nix
            does not declare `pname` literally.

    Returns:
        DerivationOutcome(targets=[...], skipped=[...]).
    """
    targets: list[DerivedTarget] = []
    skipped: list[SkippedTarget] = []

    target_version = upstream_ref.get("target_version")
    tag = upstream_ref.get("tag")
    pname = _extract_pname(package_source) or attr_path

    if not isinstance(target_version, str) or not target_version:
        skipped.append(SkippedTarget(
            name="src.hash",
            reason="missing-target-version",
            detail="upstream-ref.json has no target_version; URL derivation requires it",
        ))
        # We still record skipped vendor-style hashes below.
    else:
        # ── 1. fetchurl / fetchzip with literal URL template → package-url-template
        # Try this first because when a package.nix DOES embed a fetcher
        # block, the literal URL template is the most authoritative
        # ground truth — it's what nixpkgs will actually request.
        tmpl = _try_url_template(package_source,
                                 target_version=target_version,
                                 pname=pname)
        if isinstance(tmpl, DerivedTarget):
            targets.append(tmpl)
        elif isinstance(tmpl, SkippedTarget):
            # Don't record the skip yet; we may still find a usable
            # github/gitlab-release-archive fallback below.
            url_template_skip: SkippedTarget | None = tmpl
        else:
            url_template_skip = None
        if isinstance(tmpl, DerivedTarget):
            url_template_skip = None

        # ── 2. fetchFromGitHub → github-release-archive ─────────────
        # Local fetchFromGitHub block in package.nix.
        if not _has_target_named(targets, "src.hash"):
            gh = _try_fetch_from_github(package_source, tag=tag, pname=pname,
                                        target_version=target_version)
            if gh is not None:
                targets.append(gh)

        # ── 3. github-release-archive fallback from upstream-ref ─────
        # Some packages (e.g. mbedtls 3.nix, which is a thin
        # callPackage wrapper) don't embed the fetcher locally. When
        # package.nix has no usable fetcher BUT upstream_fix_commits
        # points at a github.com repo, derive the archive URL from the
        # repo + tag. Confidence: medium because the package's actual
        # fetcher (in a sibling file) may use a different URL pattern.
        if not _has_target_named(targets, "src.hash"):
            gh_fb = _try_github_release_archive_from_upstream_ref(
                upstream_ref, tag=tag,
            )
            if gh_fb is not None:
                targets.append(gh_fb)

        # ── 4. gitlab-release-archive (narrow: fires only when
        # upstream_fix_commits[0].repo_url is on a gitlab host AND a
        # tag is present).
        if not _has_target_named(targets, "src.hash"):
            gl = _try_gitlab_release_archive(upstream_ref, tag=tag,
                                             target_version=target_version,
                                             pname=pname)
            if gl is not None:
                targets.append(gl)

        # If after all the above we still have no src.hash target,
        # record either the url-template-too-complex skip (preferred —
        # more specific) or a generic no-derivable-rule.
        if not _has_target_named(targets, "src.hash") and not _has_skipped_named(skipped, "src.hash"):
            if url_template_skip is not None:
                skipped.append(url_template_skip)
            else:
                skipped.append(SkippedTarget(
                    name="src.hash",
                    reason="no-derivable-rule",
                    detail="no fetchFromGitHub / fetchurl / fetchzip / gitlab-host / upstream-ref rule matched",
                ))

    # ── 4. vendor-style hashes detected in package.nix → skipped ─────────
    for m in _HASH_ATTR_PRESENCE_RE.finditer(package_source):
        attr_name = m.group("name")
        if _has_skipped_named(skipped, attr_name):
            continue
        skipped.append(SkippedTarget(
            name=attr_name,
            reason="ecosystem-not-url-derivable",
            detail=(
                f"{attr_name} is not URL-derivable in v0; needs an "
                f"ecosystem-specific prefetch mechanism (Go vendoring, "
                f"Cargo vendoring, npm/pnpm/yarn deps prefetch). Patcher "
                f"will rule-8 refuse for this slot until that lands."
            ),
        ))

    return DerivationOutcome(targets=targets, skipped=skipped)


# ─── per-rule helpers ─────────────────────────────────────────────────────


def _try_fetch_from_github(
    package_source: str,
    *,
    tag: str | None,
    pname: str | None,
    target_version: str,
) -> DerivedTarget | None:
    """github-release-archive rule.

    Fires when package.nix has a fetchFromGitHub block AND the bundle
    carries a `tag`. Confidence is high because the URL shape is
    deterministic.
    """
    owner_m = _FROMGITHUB_OWNER_RE.search(package_source)
    repo_m = _FROMGITHUB_REPO_RE.search(package_source)
    if not (owner_m and repo_m):
        return None
    owner = owner_m.group("owner")
    repo = repo_m.group("repo")

    # Resolve the rev the package will pin: prefer tag, then rev with
    # template substitution, then derive ${pname}-${version} as a
    # fallback (mbedtls-style).
    rev_for_archive = tag
    if not rev_for_archive:
        rev_m = _FROMGITHUB_REV_RE.search(package_source)
        if rev_m:
            rev_for_archive = _substitute_version_pname(
                rev_m.group("rev"), version=target_version, pname=pname,
            )
    if not rev_for_archive:
        return None

    url = f"https://github.com/{owner}/{repo}/archive/refs/tags/{rev_for_archive}.tar.gz"
    return DerivedTarget(
        name="src.hash",
        url=url,
        derivation_rule="github-release-archive",
        confidence="high",
    )


def _try_url_template(
    package_source: str,
    *,
    target_version: str,
    pname: str | None,
) -> DerivedTarget | SkippedTarget | None:
    """package-url-template rule.

    Walks fetchurl/fetchzip URL strings and substitutes ${version} /
    ${finalAttrs.version} / ${pname}. Confidence high if exactly one
    fetcher is present and the URL has at most one version placeholder
    family; medium if multiple version placeholders are interpolated;
    low if multiple competing fetchurl blocks are present (ambiguous).
    """
    candidates: list[str] = []
    for m in _FETCHURL_URL_RE.finditer(package_source):
        candidates.append(m.group("url"))
    for m in _FETCHZIP_URL_RE.finditer(package_source):
        candidates.append(m.group("url"))
    if not candidates:
        return None
    if len(candidates) > 1:
        return SkippedTarget(
            name="src.hash",
            reason="url-template-too-complex",
            detail=f"{len(candidates)} fetchurl/fetchzip URLs found; resolver only auto-derives single-fetcher packages",
        )

    raw = candidates[0]
    if "${" not in raw:
        # Already concrete — emit it as-is, high confidence.
        return DerivedTarget(
            name="src.hash",
            url=raw,
            derivation_rule="package-url-template",
            confidence="high",
        )

    substituted = _substitute_version_pname(raw, version=target_version, pname=pname)
    if "${" in substituted:
        return SkippedTarget(
            name="src.hash",
            reason="url-template-too-complex",
            detail=f"URL still contains unresolved interpolations after version+pname substitution: {substituted!r}",
        )
    # If the original raw URL had any non-version interpolation, mark
    # confidence medium (we substituted heuristically).
    confidence = "high"
    if _PNAME_INTERP_RE.search(raw):
        confidence = "medium"
    return DerivedTarget(
        name="src.hash",
        url=substituted,
        derivation_rule="package-url-template",
        confidence=confidence,
    )


def _try_github_release_archive_from_upstream_ref(
    upstream_ref: dict, *, tag: str | None,
) -> DerivedTarget | None:
    """github-release-archive fallback for packages whose fetcher lives
    in a sibling file (e.g. mbedtls 3.nix calling generic.nix).

    Fires when upstream_fix_commits[0].repo_url is on github.com AND a
    tag is set. Confidence: medium — the package's actual fetcher may
    use a different URL pattern.
    """
    if not tag:
        return None
    fixes = upstream_ref.get("upstream_fix_commits") or []
    if not fixes:
        return None
    repo_url = fixes[0].get("repo_url") if isinstance(fixes[0], dict) else None
    if not isinstance(repo_url, str):
        return None
    parsed = urlparse(repo_url)
    if (parsed.hostname or "").lower() != "github.com":
        return None
    path = parsed.path.rstrip("/")
    if path.endswith(".git"):
        path = path[: -len(".git")]
    # path is now /<owner>/<repo>
    parts = path.lstrip("/").split("/")
    if len(parts) < 2:
        return None
    owner, repo = parts[0], parts[1]
    url = f"https://github.com/{owner}/{repo}/archive/refs/tags/{tag}.tar.gz"
    return DerivedTarget(
        name="src.hash",
        url=url,
        derivation_rule="github-release-archive",
        confidence="medium",
    )


def _try_gitlab_release_archive(
    upstream_ref: dict,
    *,
    tag: str | None,
    target_version: str,
    pname: str | None,
) -> DerivedTarget | None:
    """gitlab-release-archive rule.

    Fires when upstream_fix_commits[0].repo_url is on a known gitlab
    host AND a tag is present. Confidence is medium because gitlab
    archive URL patterns vary by host config.
    """
    if not tag:
        return None
    fixes = upstream_ref.get("upstream_fix_commits") or []
    if not fixes:
        return None
    repo_url = fixes[0].get("repo_url") if isinstance(fixes[0], dict) else None
    if not isinstance(repo_url, str):
        return None
    parsed = urlparse(repo_url)
    host = (parsed.hostname or "").lower()
    if "gitlab" not in host:
        return None

    # Strip any trailing /-/ or .git from path. Conventional gitlab
    # archive URL: https://<host>/<group>/<repo>/-/archive/<tag>/<repo>-<tag>.tar.gz
    path = parsed.path.rstrip("/")
    if path.endswith(".git"):
        path = path[: -len(".git")]
    repo_name = path.rsplit("/", 1)[-1] if path else "unknown"
    url = f"https://{host}{path}/-/archive/{tag}/{repo_name}-{tag}.tar.gz"
    return DerivedTarget(
        name="src.hash",
        url=url,
        derivation_rule="gitlab-release-archive",
        confidence="medium",
    )


# ─── small utilities ──────────────────────────────────────────────────────


def _extract_pname(package_source: str) -> str | None:
    m = re.search(r'pname\s*=\s*"([^"]+)"', package_source)
    if m:
        return m.group(1)
    return None


def _substitute_version_pname(
    text: str, *, version: str, pname: str | None,
) -> str:
    out = _VERSION_INTERP_RE.sub(version, text)
    if pname is not None:
        out = _PNAME_INTERP_RE.sub(pname, out)
    return out


def _has_target_named(targets: Iterable[DerivedTarget], name: str) -> bool:
    return any(t.name == name for t in targets)


def _has_skipped_named(skipped: Iterable[SkippedTarget], name: str) -> bool:
    return any(s.name == name for s in skipped)


def auto_prefetch_high_confidence(
    *,
    upstream_ref: dict,
    package_source: str,
    attr_path: str | None = None,
    prefetch_url_fn=None,
):
    """Orchestration helper: derive → filter to high-confidence → prefetch.

    Per the user's URL-derivation design call: only high-confidence
    targets are auto-prefetched. Medium / low confidence targets remain
    in `DerivationOutcome.targets` for the caller to inspect, but they
    are NOT fed into the network-touching prefetch path. They surface
    as derived-but-not-attempted in the returned tuple.

    The mbedtls case (commit cd17e09) is the canonical example of why:
    the github-release-archive fallback derives a plausible URL from
    `upstream_fix_commits[0].repo_url` + `tag`, but the package's
    actual fetcher (in a sibling file) is `fetchFromGitHub` with
    `fetchSubmodules = true`, which produces a different hash. The
    derivation is correct; the attribution medium-confidence is
    correct; auto-prefetching it would write a hash that fails the
    build downstream. Better to surface the gap as "derived but not
    auto-prefetched" so the bundle assembler decides what to do
    (manual attestation, alternate prefetch mechanism, refuse the
    bundle, …).

    Returns:
        (DerivationOutcome, PrefetchOutcome, list[DerivedTarget])
        where the third element is the high-confidence subset that was
        sent to the prefetcher (for explicit attribution).
    """
    from agents.upstream_ref_resolver.prefetch import (
        PrefetchTarget,
        prefetch_targets,
    )
    derivation = derive_prefetch_targets(
        upstream_ref=upstream_ref,
        package_source=package_source,
        attr_path=attr_path,
    )
    high = [t for t in derivation.targets if t.confidence == "high"]
    prefetch_inputs = [
        PrefetchTarget(name=t.name, url=t.url, algorithm=t.algorithm)
        for t in high
    ]
    prefetch = prefetch_targets(prefetch_inputs, prefetch_url_fn=prefetch_url_fn)
    return derivation, prefetch, high


__all__ = [
    "DerivedTarget",
    "SkippedTarget",
    "DerivationOutcome",
    "DERIVATION_RULES",
    "SKIP_REASONS",
    "auto_prefetch_high_confidence",
    "derive_prefetch_targets",
]
