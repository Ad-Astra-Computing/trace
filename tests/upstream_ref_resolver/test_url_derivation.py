"""Tests for the URL-derivation layer.

The most valuable cases are anchored on the actual cohort-1 package.nix
files we already have on disk:

  * mbedtls 3.nix — fetchFromGitHub with rev = "${pname}-${version}"
    -> github-release-archive rule, high confidence.
  * bind package.nix — fetchurl with downloads.isc.org URL template
    interpolating ${finalAttrs.version} -> package-url-template rule,
    high confidence.
  * traefik package.nix — fetchzip with github.com URL template AND
    a vendorHash present -> package-url-template rule for src.hash,
    skipped vendorHash with reason ecosystem-not-url-derivable.

Synthetic cases cover the negative paths (missing target_version,
ambiguous fetcher, gitlab fallback, etc.).
"""

from __future__ import annotations

import json
from pathlib import Path

from agents.upstream_ref_resolver import (
    derive_prefetch_targets,
    DerivedTarget,
    SkippedTarget,
)
from tests.schema.validate import REPO_ROOT


# ─── cohort-1 anchor cases ─────────────────────────────────────────────────


def _bundle(name: str) -> Path:
    return REPO_ROOT / "traces" / "example" / name


def _read_bundle_inputs(bundle_dir: Path) -> tuple[dict, str]:
    upstream_ref = json.loads((bundle_dir / "upstream-ref.json").read_text())
    package_source = (bundle_dir / "package.nix").read_text()
    return upstream_ref, package_source


def test_mbedtls_derives_github_release_archive() -> None:
    bundle = _bundle("CVE-2024-49195--mbedtls")
    upstream_ref, package_source = _read_bundle_inputs(bundle)

    out = derive_prefetch_targets(
        upstream_ref=upstream_ref,
        package_source=package_source,
        attr_path="mbedtls",
    )
    assert len(out.targets) == 1, out
    t = out.targets[0]
    assert t.name == "src.hash"
    assert t.derivation_rule == "github-release-archive"
    # mbedtls 3.nix is a thin callPackage wrapper without fetchFromGitHub
    # locally; the rule fires from the upstream-ref-fallback path, which
    # is medium-confidence by design (the actual fetcher in a sibling
    # file may use a different URL pattern).
    assert t.confidence == "medium"
    assert "Mbed-TLS/mbedtls" in t.url
    assert "mbedtls-3.6.2" in t.url
    assert out.skipped == []


def test_bind_derives_package_url_template() -> None:
    bundle = _bundle("CVE-2025-13878--bind")
    upstream_ref, package_source = _read_bundle_inputs(bundle)

    out = derive_prefetch_targets(
        upstream_ref=upstream_ref,
        package_source=package_source,
        attr_path="bind",
    )
    assert len(out.targets) == 1, out
    t = out.targets[0]
    assert t.name == "src.hash"
    assert t.derivation_rule == "package-url-template"
    assert t.confidence == "high"
    # ${finalAttrs.version} -> 9.20.18; ISC tarball pattern.
    assert t.url == "https://downloads.isc.org/isc/bind9/9.20.18/bind-9.20.18.tar.xz"
    assert out.skipped == []


def test_bind_url_matches_run2_prefetch_url() -> None:
    """Cross-check: the URL the derivation layer produces for bind must
    match the URL the live nix-prefetch-url path used in commit 4668ebe.
    """
    bundle = _bundle("CVE-2025-13878--bind")
    upstream_ref, package_source = _read_bundle_inputs(bundle)
    out = derive_prefetch_targets(
        upstream_ref=upstream_ref, package_source=package_source,
    )
    derived_url = out.targets[0].url
    recorded_url = upstream_ref["prefetch_hashes"][0]["url"]
    assert derived_url == recorded_url, f"derived={derived_url!r} recorded={recorded_url!r}"


def test_traefik_skips_vendor_hash() -> None:
    bundle = _bundle("CVE-2026-25949--traefik")
    upstream_ref, package_source = _read_bundle_inputs(bundle)

    out = derive_prefetch_targets(
        upstream_ref=upstream_ref, package_source=package_source,
        attr_path="traefik",
    )
    # src.hash should be derived (traefik uses fetchzip with a github
    # release-download URL that interpolates ${finalAttrs.version}).
    src_targets = [t for t in out.targets if t.name == "src.hash"]
    assert len(src_targets) == 1, out
    assert src_targets[0].derivation_rule in (
        "package-url-template", "github-release-archive",
    )
    # vendorHash MUST be in skipped[] with reason ecosystem-not-url-derivable
    # AND required_for_patch=True.
    skipped_names = [s.name for s in out.skipped]
    assert "vendorHash" in skipped_names
    vendor = next(s for s in out.skipped if s.name == "vendorHash")
    assert vendor.reason == "ecosystem-not-url-derivable"
    assert vendor.required_for_patch is True


def test_skipped_target_serialises_to_schema_shape() -> None:
    """SkippedTarget.to_schema_dict() must match upstream-ref-schema's
    prefetch_skips[] entry shape: name, reason, required_for_patch
    required; detail optional; nothing else."""
    s = SkippedTarget(
        name="vendorHash",
        reason="ecosystem-not-url-derivable",
        required_for_patch=True,
        detail="needs go-mod-vendor prefetch path",
    )
    d = s.to_schema_dict()
    assert set(d) == {"name", "reason", "required_for_patch", "detail"}
    assert d["name"] == "vendorHash"
    assert d["reason"] == "ecosystem-not-url-derivable"
    assert d["required_for_patch"] is True
    assert d["detail"] == "needs go-mod-vendor prefetch path"


def test_skipped_target_serialised_validates_against_schema() -> None:
    """Round-trip: skipped[] from a real bundle must validate as
    upstream-ref-schema.json prefetch_skips[]."""
    from jsonschema import Draft202012Validator

    bundle = _bundle("CVE-2026-25949--traefik")
    upstream_ref, package_source = _read_bundle_inputs(bundle)
    out = derive_prefetch_targets(
        upstream_ref=upstream_ref, package_source=package_source,
        attr_path="traefik",
    )
    schema_path = REPO_ROOT / "policy" / "upstream-ref-schema.json"
    schema = json.loads(schema_path.read_text())
    enriched = {
        **{k: v for k, v in upstream_ref.items() if k != "prefetch_hashes"},
        "prefetch_skips": [s.to_schema_dict() for s in out.skipped],
    }
    validator = Draft202012Validator(schema)
    errors = ["/".join(str(p) for p in e.absolute_path) + ": " + e.message
             for e in validator.iter_errors(enriched)]
    assert not errors, errors


def test_missing_target_version_skip_is_not_required_for_patch() -> None:
    """When upstream-ref has no target_version, the resolver can't even
    tell whether the patch path is reachable. The src.hash skip is
    informational, not required_for_patch=True."""
    upstream_ref = dict(_MIN_UPSTREAM_REF)
    upstream_ref.pop("target_version")
    out = derive_prefetch_targets(
        upstream_ref=upstream_ref,
        package_source='fetchurl { url = "https://x.invalid/${version}.tar.gz"; }',
    )
    src_skip = next((s for s in out.skipped if s.name == "src.hash"), None)
    assert src_skip is not None
    assert src_skip.reason == "missing-target-version"
    assert src_skip.required_for_patch is False


# ─── synthetic / negative-path cases ───────────────────────────────────────


_MIN_UPSTREAM_REF = {
    "schema_version": "1.0.0",
    "cve_id": "CVE-0000-0000",
    "current_version": "1.0.0",
    "target_version": "1.0.1",
    "tag": "v1.0.1",
    "eligibility": {"verdict": "eligible"},
    "replay_critical": True,
}


def test_missing_target_version_is_skipped() -> None:
    upstream_ref = dict(_MIN_UPSTREAM_REF)
    upstream_ref.pop("target_version")
    out = derive_prefetch_targets(
        upstream_ref=upstream_ref,
        package_source='fetchurl { url = "https://x.invalid/${version}.tar.gz"; }',
    )
    assert out.targets == []
    reasons = [s.reason for s in out.skipped]
    assert "missing-target-version" in reasons


def test_multiple_fetchurl_blocks_too_complex() -> None:
    pkg = (
        'src = fetchurl { url = "https://a.invalid/${version}.tar"; };\n'
        'src2 = fetchurl { url = "https://b.invalid/${version}.tar"; };\n'
    )
    out = derive_prefetch_targets(
        upstream_ref=_MIN_UPSTREAM_REF, package_source=pkg,
    )
    skipped_reasons = [s.reason for s in out.skipped]
    assert "url-template-too-complex" in skipped_reasons


def test_gitlab_fallback_when_repo_url_is_gitlab() -> None:
    upstream_ref = {
        **_MIN_UPSTREAM_REF,
        "upstream_fix_commits": [
            {
                "repo_url": "https://gitlab.example.invalid/group/myproj",
                "commit_sha": "abc1234",
            },
        ],
    }
    # No fetchFromGitHub or fetchurl in the package source — only gitlab
    # rule should fire.
    out = derive_prefetch_targets(
        upstream_ref=upstream_ref,
        package_source='src = mkDerivation { /* no fetcher block here */ };',
    )
    targets = [t for t in out.targets if t.derivation_rule == "gitlab-release-archive"]
    assert len(targets) == 1
    assert targets[0].confidence == "medium"
    assert "gitlab.example.invalid" in targets[0].url
    assert "v1.0.1" in targets[0].url


def test_no_derivable_rule_records_skip() -> None:
    upstream_ref = dict(_MIN_UPSTREAM_REF)  # no upstream_fix_commits
    out = derive_prefetch_targets(
        upstream_ref=upstream_ref,
        package_source="# no fetcher of any kind\n{ stdenv }: stdenv.mkDerivation { }\n",
    )
    assert out.targets == []
    reasons = [s.reason for s in out.skipped]
    assert "no-derivable-rule" in reasons


def test_concrete_url_no_interpolation_high_confidence() -> None:
    pkg = 'src = fetchurl { url = "https://example.invalid/literal.tar.gz"; };'
    out = derive_prefetch_targets(
        upstream_ref=_MIN_UPSTREAM_REF, package_source=pkg,
    )
    assert len(out.targets) == 1
    t = out.targets[0]
    assert t.url == "https://example.invalid/literal.tar.gz"
    assert t.confidence == "high"


def test_pname_interpolation_lowers_confidence_to_medium() -> None:
    pkg = (
        'pname = "wibble";\n'
        'src = fetchurl { url = "https://x.invalid/${pname}-${version}.tar.gz"; };\n'
    )
    out = derive_prefetch_targets(
        upstream_ref=_MIN_UPSTREAM_REF, package_source=pkg, attr_path="wibble",
    )
    assert len(out.targets) == 1
    t = out.targets[0]
    assert t.url == "https://x.invalid/wibble-1.0.1.tar.gz"
    assert t.confidence == "medium"


def test_url_with_unresolved_interpolation_skipped() -> None:
    pkg = 'src = fetchurl { url = "https://x.invalid/${some_other_var}/x.tar"; };'
    out = derive_prefetch_targets(
        upstream_ref=_MIN_UPSTREAM_REF, package_source=pkg,
    )
    assert out.targets == []
    reasons = [s.reason for s in out.skipped]
    assert "url-template-too-complex" in reasons


def test_vendor_hash_alone_in_pkg_skipped_even_if_no_src() -> None:
    pkg = (
        '{ buildGoModule }: buildGoModule {\n'
        '  pname = "myapp";\n'
        '  version = "1.2.3";\n'
        '  vendorHash = "sha256-existing-vendor=";\n'
        '}\n'
    )
    out = derive_prefetch_targets(
        upstream_ref=_MIN_UPSTREAM_REF, package_source=pkg,
    )
    skipped_names = [s.name for s in out.skipped]
    assert "vendorHash" in skipped_names
    vendor = next(s for s in out.skipped if s.name == "vendorHash")
    assert vendor.reason == "ecosystem-not-url-derivable"


def test_auto_prefetch_filters_to_high_confidence_only() -> None:
    """auto_prefetch_high_confidence must NOT feed medium-confidence
    targets into the prefetcher. The mbedtls bundle is the anchor case:
    its github-release-archive URL is medium-confidence, so the
    orchestration helper must derive it but not attempt the fetch."""
    from agents.upstream_ref_resolver import auto_prefetch_high_confidence

    bundle = _bundle("CVE-2024-49195--mbedtls")
    upstream_ref, package_source = _read_bundle_inputs(bundle)
    upstream_ref_pre = {k: v for k, v in upstream_ref.items() if k != "prefetch_hashes"}

    # Inject a fake prefetcher that records every call. If the helper
    # sends mbedtls's medium-confidence URL through, this records it.
    seen_calls: list[tuple[str, str]] = []

    def fake_prefetcher(url: str, algorithm: str):
        seen_calls.append((url, algorithm))
        return ("ok", "sha256-fakeButShapedRightForTestPurposesOnlyXYZ=", "fake 1.0")

    derivation, prefetch, high_subset = auto_prefetch_high_confidence(
        upstream_ref=upstream_ref_pre,
        package_source=package_source,
        attr_path="mbedtls",
        prefetch_url_fn=fake_prefetcher,
    )
    # mbedtls's only target is medium-confidence; nothing gets auto-prefetched.
    assert seen_calls == [], f"mbedtls medium-confidence target was auto-prefetched: {seen_calls}"
    assert prefetch.hashes == []
    assert prefetch.failures == []
    assert high_subset == []
    # But the derivation is preserved for caller inspection.
    assert len(derivation.targets) == 1
    assert derivation.targets[0].confidence == "medium"


def test_auto_prefetch_runs_high_confidence_targets() -> None:
    """The bind bundle has a high-confidence target, so the helper must
    actually invoke the prefetcher for it."""
    from agents.upstream_ref_resolver import auto_prefetch_high_confidence

    bundle = _bundle("CVE-2025-13878--bind")
    upstream_ref, package_source = _read_bundle_inputs(bundle)
    upstream_ref_pre = {k: v for k, v in upstream_ref.items() if k != "prefetch_hashes"}

    seen_calls: list[tuple[str, str]] = []

    def fake_prefetcher(url: str, algorithm: str):
        seen_calls.append((url, algorithm))
        return ("ok", "sha256-livePrefetchedValueForBind=", "fake 1.0")

    derivation, prefetch, high_subset = auto_prefetch_high_confidence(
        upstream_ref=upstream_ref_pre,
        package_source=package_source,
        attr_path="bind",
        prefetch_url_fn=fake_prefetcher,
    )
    assert len(seen_calls) == 1
    assert seen_calls[0][0] == "https://downloads.isc.org/isc/bind9/9.20.18/bind-9.20.18.tar.xz"
    assert seen_calls[0][1] == "sha256"
    assert len(prefetch.hashes) == 1
    assert prefetch.hashes[0].name == "src.hash"
    assert len(high_subset) == 1
    assert high_subset[0].confidence == "high"


def test_outcome_feeds_directly_into_prefetch_targets() -> None:
    """The DerivedTargets must round-trip into PrefetchTarget without
    an adapter layer — same field names, compatible types."""
    from agents.upstream_ref_resolver import PrefetchTarget
    pkg = 'src = fetchurl { url = "https://x.invalid/literal.tar.gz"; };'
    out = derive_prefetch_targets(
        upstream_ref=_MIN_UPSTREAM_REF, package_source=pkg,
    )
    pts = [PrefetchTarget(name=t.name, url=t.url, algorithm=t.algorithm)
           for t in out.targets]
    assert len(pts) == 1
    assert pts[0].name == "src.hash"
    assert pts[0].algorithm == "sha256"
