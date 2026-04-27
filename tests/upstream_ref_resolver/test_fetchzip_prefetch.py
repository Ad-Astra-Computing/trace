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
    request = FetchzipRequest(attr_path="uriparser", target_version="1.0.0")
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
    request = FetchzipRequest(attr_path="uriparser", target_version="1.0.0")
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
    request = FetchzipRequest(attr_path="uriparser", target_version="1.0.0")
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
    errors = ["/".join(str(p) for p in e.absolute_path) + ": " + e.message
             for e in validator.iter_errors(bundle)]
    assert not errors, errors


def test_failure_serialises_to_prefetch_failures_schema_shape() -> None:
    request = FetchzipRequest(attr_path="uriparser", target_version="1.0.0")
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
    errors = ["/".join(str(p) for p in e.absolute_path) + ": " + e.message
             for e in validator.iter_errors(bundle)]
    assert not errors, errors


def test_expression_includes_target_version_and_fakeHash() -> None:
    from agents.upstream_ref_resolver.fetchzip_prefetch import _build_expression
    request = FetchzipRequest(attr_path="uriparser", target_version="1.0.0")
    expr = _build_expression(request)
    assert 'version = "1.0.0"' in expr
    assert "lib.fakeHash" in expr
    assert "uriparser" in expr
    # Critical: the override targets src, NOT vendorHash (that's the
    # go-mod-vendor module's territory).
    assert "src = old.src.overrideAttrs" in expr


def test_expression_pins_nixpkgs_rev_when_supplied() -> None:
    from agents.upstream_ref_resolver.fetchzip_prefetch import _build_expression
    request = FetchzipRequest(
        attr_path="uriparser", target_version="1.0.0",
        nixpkgs_rev="20bb5d462943a0f38eba2372db9f7a6d9fd22be2",
    )
    expr = _build_expression(request)
    assert "20bb5d462943a0f38eba2372db9f7a6d9fd22be2" in expr


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
        attr_path="uriparser", target_version="1.0.0",
    )
    out = prefetch_fetchzip(request)
    assert isinstance(out, FetchzipSuccess), getattr(out, "detail", "")
    assert out.value.startswith("sha256-") and out.value.endswith("=")
    assert out.tool == "nix-build"
