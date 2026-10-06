"""Tests for the fetchzip prefetch path.

Mirrors tests/upstream_ref_resolver/test_go_mod_vendor.py's shape: the
runner shells out to `nix-build` and parses an FOD-mismatch error
from stderr. Tests inject fake command_runners so the unit suite is
deterministic and offline.

A network-gated end-to-end test (TRACE_REAL_FETCHZIP=1) exercises the
real path against `uriparser` 1.0.0 — the canonical fetchFromGitHub
case the v0 url_derivation got wrong.
"""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator

from agents.upstream_ref_resolver import (
    FetchzipFailure,
    FetchzipRequest,
    FetchzipSuccess,
    prefetch_fetchzip,
)
from tests.schema.validate import REPO_ROOT


def _fake_runner_ok(value: str, version: str = "nix-build (Nix) 2.33.3"):
    def runner(expression: str, request: FetchzipRequest):
        return ("ok", value, version, "nix-build --no-out-link -E ...")

    return runner


def _fake_runner_err(detail: str, version: str = "nix-build (Nix) 2.33.3"):
    def runner(expression: str, request: FetchzipRequest):
        return ("err", detail, version, "nix-build --no-out-link -E ...")

    return runner


def test_happy_path_records_full_attribution() -> None:
    request = FetchzipRequest(
        attr_path="uriparser", target_version="1.0.0", current_version="0.9.9"
    )
    out = prefetch_fetchzip(
        request,
        command_runner=_fake_runner_ok("sha256-Pr3F3tCh3dSrcValueShap3dRightForTest="),
    )
    assert isinstance(out, FetchzipSuccess)
    assert out.name == "src.hash"
    assert out.value == "sha256-Pr3F3tCh3dSrcValueShap3dRightForTest="
    assert out.source == "fetchzip-src-extract"
    assert out.prefetch_kind == "fetchzip"
    assert out.tool == "nix-build"
    assert out.tool_version
    assert out.fetched_at
    assert out.derivation_command
    assert out.replay_critical is True


def test_failure_path_returns_structured_failure() -> None:
    request = FetchzipRequest(
        attr_path="uriparser", target_version="1.0.0", current_version="0.9.9"
    )
    out = prefetch_fetchzip(
        request,
        command_runner=_fake_runner_err("nix-build: HTTP 404 fetching tarball"),
    )
    assert isinstance(out, FetchzipFailure)
    assert out.name == "src.hash"
    assert out.reason == "fetchzip-prefetch-failed"
    assert out.required_for_patch is True
    assert "404" in out.detail
    assert out.attempted_command
    assert out.attempted_at


def test_success_serialises_to_prefetch_hashes_schema_shape() -> None:
    request = FetchzipRequest(
        attr_path="uriparser", target_version="1.0.0", current_version="0.9.9"
    )
    out = prefetch_fetchzip(
        request,
        command_runner=_fake_runner_ok("sha256-V1d3oRoundtripValueForJSONsch3maT3st="),
    )
    assert isinstance(out, FetchzipSuccess)
    d = out.to_schema_dict()
    assert d["prefetch_kind"] == "fetchzip"
    assert d["source"] == "fetchzip-src-extract"
    schema_path = REPO_ROOT / "policy" / "upstream-ref-schema.json"
    schema = json.loads(schema_path.read_text())
    bundle = {
        "schema_version": "1.1.0",
        "cve_id": "CVE-0000-0000",
        "current_version": "0.9.9",
        "target_version": "1.0.0",
        "fix_tier": "major-version-jump",
        "release_url": "https://example.invalid/release",
        "delta": {
            "transitive_package_changes": 0,
            "new_direct_deps": [],
            "crosses_large_delta_threshold": False,
        },
        "prefetch_hashes": [d],
        "eligibility": {
            "verdict": "eligible-requires-human-review",
            "verdict_reason": "test",
            "human_review_trigger": "major-version-jump",
        },
        "replay_critical": True,
    }
    validator = Draft202012Validator(schema)
    errors = [
        "/".join(str(p) for p in e.absolute_path) + ": " + e.message
        for e in validator.iter_errors(bundle)
    ]
    assert not errors, errors


def test_failure_serialises_to_prefetch_failures_schema_shape() -> None:
    request = FetchzipRequest(
        attr_path="uriparser", target_version="1.0.0", current_version="0.9.9"
    )
    out = prefetch_fetchzip(
        request,
        command_runner=_fake_runner_err("nix-build: build timed out"),
    )
    assert isinstance(out, FetchzipFailure)
    d = out.to_schema_dict()
    schema_path = REPO_ROOT / "policy" / "upstream-ref-schema.json"
    schema = json.loads(schema_path.read_text())
    bundle = {
        "schema_version": "1.1.0",
        "cve_id": "CVE-0000-0000",
        "current_version": "0.9.9",
        "target_version": "1.0.0",
        "fix_tier": "major-version-jump",
        "release_url": "https://example.invalid/release",
        "delta": {
            "transitive_package_changes": 0,
            "new_direct_deps": [],
            "crosses_large_delta_threshold": False,
        },
        "prefetch_failures": [d],
        "eligibility": {
            "verdict": "eligible-requires-human-review",
            "verdict_reason": "test",
            "human_review_trigger": "major-version-jump",
        },
        "replay_critical": True,
    }
    validator = Draft202012Validator(schema)
    errors = [
        "/".join(str(p) for p in e.absolute_path) + ": " + e.message
        for e in validator.iter_errors(bundle)
    ]
    assert not errors, errors


def test_expression_includes_target_version_and_fakeHash() -> None:
    from agents.upstream_ref_resolver.fetchzip_prefetch import _build_expression

    request = FetchzipRequest(
        attr_path="uriparser", target_version="1.0.0", current_version="0.9.9"
    )
    expr = _build_expression(request)
    assert 'version = "1.0.0"' in expr
    assert "lib.fakeHash" in expr
    assert "uriparser" in expr
    # Re-invoke fetcher via src.override (post 2026-05-13 fix). The
    # previous shape (old.src.overrideAttrs with only outputHash) was
    # unsound because old.src was already evaluated against the OLD
    # version's rec binding; setting outputHash didn't change the URL
    # baked into the FOD. The new shape re-evaluates the fetcher with
    # a new tag/rev so the URL actually changes.
    assert "src = old.src.override (orig:" in expr
    assert "orig ? tag" in expr
    assert "orig ? rev" in expr
    # The version-substring substitution must reference BOTH versions.
    assert 'replaceStrings ["0.9.9"] ["1.0.0"]' in expr


def test_expression_rejects_nix_metacharacters_in_feed_sourced_fields() -> None:
    """attr_path and nixpkgs_rev come from the CVE feed / candidate row;
    a value carrying Nix syntax must be rejected, not interpolated."""
    import pytest

    from agents.upstream_ref_resolver.fetchzip_prefetch import _build_expression

    with pytest.raises(ValueError):
        _build_expression(
            FetchzipRequest(
                attr_path='uriparser"; } // { x = import <foo>; }; y = "',
                target_version="1.0.0",
                current_version="0.9.9",
            )
        )
    with pytest.raises(ValueError):
        _build_expression(
            FetchzipRequest(
                attr_path="uriparser",
                target_version="1.0.0",
                current_version="0.9.9",
                nixpkgs_rev='abc"); in builtins.exec',
            )
        )


def test_expression_escapes_quotes_in_versions() -> None:
    import json

    from agents.upstream_ref_resolver.fetchzip_prefetch import _build_expression

    poisoned = '1.0.0"; } // { pwned = true; } // { x = "'
    request = FetchzipRequest(
        attr_path="uriparser", target_version=poisoned, current_version="0.9.9"
    )
    expr = _build_expression(request)
    assert json.dumps(poisoned) in expr
    assert f'version = "{poisoned}"' not in expr


def test_expression_pins_nixpkgs_rev_when_supplied() -> None:
    from agents.upstream_ref_resolver.fetchzip_prefetch import _build_expression

    request = FetchzipRequest(
        attr_path="uriparser",
        target_version="1.0.0",
        current_version="0.9.9",
        nixpkgs_rev="20bb5d462943a0f38eba2372db9f7a6d9fd22be2",
    )
    expr = _build_expression(request)
    assert "20bb5d462943a0f38eba2372db9f7a6d9fd22be2" in expr


def test_expression_passes_allow_unsupported_system_for_linux_only_packages() -> None:
    """Regression for the 2026-04-27 systemd grounding failure.

    systemd's `meta.platforms` excludes darwin. On a darwin host,
    importing nixpkgs with no config flag makes evaluation refuse:
    "package is not available on the requested hostPlatform".

    Source hashes for fetchFromGitHub / fetchzip / fetchurl / fetchgit
    are platform-independent fixed-output derivations: the same URL
    and unpack semantics produce the same NAR hash on any host. So
    the prefetch evaluator imports nixpkgs with
    `config.allowUnsupportedSystem = true` to skip the meta-platforms
    eval-gate without claiming the package itself builds on darwin
    and without globally loosening unsupported-system checks (no env
    variable, no shared helper).

    An earlier draft used `system = "x86_64-linux"` here. That
    correctly bypassed the eval-time check but propagated the system
    attribute through the entire derivation graph, requiring a Linux
    builder to materialise even the platform-independent src FOD.
    `allowUnsupportedSystem` keeps the host system intact so the FOD
    builds locally where it actually runs."""
    from agents.upstream_ref_resolver.fetchzip_prefetch import (
        _build_expression,
        _PREFETCH_NIXPKGS_CONFIG,
    )

    assert "allowUnsupportedSystem = true" in _PREFETCH_NIXPKGS_CONFIG
    # Crucial: must NOT pin system — that would propagate to the FOD drv.
    assert "system =" not in _PREFETCH_NIXPKGS_CONFIG

    # No nixpkgs_rev — config still applied to the <nixpkgs> import.
    expr_unpinned = _build_expression(
        FetchzipRequest(
            attr_path="systemd", target_version="257.6", current_version="257.5"
        )
    )
    assert "config.allowUnsupportedSystem = true" in expr_unpinned
    assert "import <nixpkgs>" in expr_unpinned
    # We must NOT be pinning system; that's the whole point of the
    # B′ revision over the earlier x86_64-linux attempt.
    assert 'system = "x86_64-linux"' not in expr_unpinned

    # With nixpkgs_rev — config still applied to the fetchTarball import.
    expr_pinned = _build_expression(
        FetchzipRequest(
            attr_path="systemd",
            target_version="257.6",
            current_version="257.5",
            nixpkgs_rev="adfe0268d8b621c68f0b060fc2e801b5196b5f6a",
        )
    )
    assert "config.allowUnsupportedSystem = true" in expr_pinned
    assert "fetchTarball" in expr_pinned
    assert "adfe0268d8b621c68f0b060fc2e801b5196b5f6a" in expr_pinned
    assert 'system = "x86_64-linux"' not in expr_pinned
    # Must target src via the makeOverridable .override path (fix for
    # the 2026-05-13 wget2 prefetch-bug; see fetchzip_prefetch.py
    # _build_expression docstring).
    assert "src = old.src.override (orig:" in expr_pinned
    assert 'version = "257.6"' in expr_pinned


@pytest.mark.skipif(
    os.environ.get("TRACE_REAL_FETCHZIP") != "1",
    reason="real-network/build test; set TRACE_REAL_FETCHZIP=1 to enable",
)
def test_real_systemd_fetchzip_resolves_on_darwin_host() -> None:
    """End-to-end regression for the 2026-04-27 systemd grounding failure.

    systemd is Linux-only (`meta.platforms` excludes darwin). On a
    darwin host the prefetch evaluator must still recover the v257.6
    src.hash because the fix pins the eval `system` to x86_64-linux.

    The expected real value (per the historical nixpkgs fix at
    a68c049d03b8) is `sha256-Myb/ra7NQTDzN7B9jn8svbhTrLSfiqWaSxREe/nDyYo=`,
    which is what fetchFromGitHub demands at build time."""
    request = FetchzipRequest(
        attr_path="systemd",
        target_version="257.6",
        nixpkgs_rev="adfe0268d8b621c68f0b060fc2e801b5196b5f6a",
    )
    out = prefetch_fetchzip(request)
    assert isinstance(out, FetchzipSuccess), getattr(out, "detail", "")
    assert out.value == "sha256-Myb/ra7NQTDzN7B9jn8svbhTrLSfiqWaSxREe/nDyYo="
    assert out.tool == "nix-build"


def test_parse_fod_hash_mismatch_extracts_modern_format() -> None:
    from agents.upstream_ref_resolver.fetchzip_prefetch import _parse_fod_hash_mismatch

    stderr = (
        "error: hash mismatch in fixed-output derivation '/nix/store/...':\n"
        "         specified: sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\n"
        "              got:    sha256-Real4cqu1r3dSrcH4shFromActualBuild=\n"
    )
    sri = _parse_fod_hash_mismatch(stderr)
    assert sri == "sha256-Real4cqu1r3dSrcH4shFromActualBuild="


def test_parse_fod_hash_mismatch_returns_none_when_absent() -> None:
    from agents.upstream_ref_resolver.fetchzip_prefetch import _parse_fod_hash_mismatch

    stderr = "error: build failed for unrelated reason; exit code 2"
    assert _parse_fod_hash_mismatch(stderr) is None


@pytest.mark.skipif(
    os.environ.get("TRACE_REAL_FETCHZIP") != "1",
    reason="real-network/build test; set TRACE_REAL_FETCHZIP=1 to enable",
)
def test_real_uriparser_fetchzip_smoke() -> None:
    """End-to-end: actually run nix-build FOD extraction against
    uriparser 1.0.0. Asserts shape only — does not pin the hash value
    because upstream re-tags would otherwise turn this test flaky.

    The expected real value (per the historical nixpkgs fix at
    e9da914af2cd) is `sha256-k4hRy4kfsaxUNIITPNxzqVgl+AwiR1NpKcE9DtAbwxc=`,
    which is what fetchFromGitHub demands. Confirming this test passes
    is what the whole 'fetchFromGitHub != nix-prefetch-url' fix was for."""
    request = FetchzipRequest(
        attr_path="uriparser",
        target_version="1.0.0",
    )
    out = prefetch_fetchzip(request)
    assert isinstance(out, FetchzipSuccess), getattr(out, "detail", "")
    assert out.value.startswith("sha256-") and out.value.endswith("=")
    assert out.tool == "nix-build"
