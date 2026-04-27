"""Tests for the go-mod-vendor prefetch path.

The runner shells out to `nix-build` and parses an FOD-hash-mismatch
error from stderr. Tests inject fake command_runners so the unit
suite is deterministic and offline.

A network-gated end-to-end test is included (TRACE_REAL_GO_VENDOR=1)
so the real path can be exercised against a known Go package, but it
is skipped by default — building all of traefik's vendored
dependencies on a fresh nix store can take many minutes and pull
significant network.
"""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator

from agents.upstream_ref_resolver import (
    GoModVendorFailure,
    GoModVendorRequest,
    GoModVendorSuccess,
    prefetch_go_mod_vendor,
)
from tests.schema.validate import REPO_ROOT


def _fake_runner_ok(value: str, version: str = "nix-build (Nix) 2.33.3"):
    def runner(expression: str, request: GoModVendorRequest):
        return ("ok", value, version, "nix-build --no-out-link -A goModules ...")
    return runner


def _fake_runner_err(detail: str, version: str = "nix-build (Nix) 2.33.3"):
    def runner(expression: str, request: GoModVendorRequest):
        return ("err", detail, version, "nix-build --no-out-link -A goModules ...")
    return runner


def test_happy_path_records_full_attribution() -> None:
    request = GoModVendorRequest(attr_path="traefik", target_version="3.6.8")
    out = prefetch_go_mod_vendor(
        request,
        command_runner=_fake_runner_ok("sha256-Pr3F3tCh3dV3nd0rV4lu3Sh4p3dRightForTest="),
    )
    assert isinstance(out, GoModVendorSuccess)
    assert out.name == "vendorHash"
    assert out.value == "sha256-Pr3F3tCh3dV3nd0rV4lu3Sh4p3dRightForTest="
    assert out.source == "go-mod-vendor"
    assert out.prefetch_kind == "go-mod-vendor"
    assert out.tool == "nix-build"
    assert out.tool_version  # non-empty
    assert out.fetched_at  # ISO-8601 string set
    assert "goModules" in out.derivation_command
    assert out.replay_critical is True


def test_failure_path_returns_structured_skip() -> None:
    request = GoModVendorRequest(attr_path="traefik", target_version="3.6.8")
    out = prefetch_go_mod_vendor(
        request,
        command_runner=_fake_runner_err("nix-build: error: network unreachable"),
    )
    assert isinstance(out, GoModVendorFailure)
    assert out.name == "vendorHash"
    assert out.reason == "go-mod-vendor-prefetch-failed"
    assert out.required_for_patch is True
    assert "network unreachable" in out.detail
    assert out.attempted_command  # non-empty
    assert out.attempted_at


def test_success_serialises_to_prefetch_hashes_schema_shape() -> None:
    request = GoModVendorRequest(attr_path="traefik", target_version="3.6.8")
    out = prefetch_go_mod_vendor(
        request,
        command_runner=_fake_runner_ok("sha256-V3nd0rValueShap3dRightForJSONsch3maT3st="),
    )
    assert isinstance(out, GoModVendorSuccess)
    d = out.to_schema_dict()
    assert d["name"] == "vendorHash"
    assert d["prefetch_kind"] == "go-mod-vendor"
    assert d["source"] == "go-mod-vendor"
    assert "derivation_command" in d
    assert d["replay_critical"] is True
    # Round-trip through upstream-ref-schema as a one-entry prefetch_hashes[].
    schema_path = REPO_ROOT / "policy" / "upstream-ref-schema.json"
    schema = json.loads(schema_path.read_text())
    bundle = {
        "schema_version": "1.1.0",
        "cve_id": "CVE-0000-0000",
        "current_version": "3.6.7",
        "target_version": "3.6.8",
        "fix_tier": "security-patch-release",
        "release_url": "https://example.invalid/release",
        "delta": {
            "transitive_package_changes": 0,
            "new_direct_deps": [],
            "crosses_large_delta_threshold": False,
        },
        "prefetch_hashes": [d],
        "eligibility": {"verdict": "eligible"},
        "replay_critical": True,
    }
    validator = Draft202012Validator(schema)
    errors = ["/".join(str(p) for p in e.absolute_path) + ": " + e.message
             for e in validator.iter_errors(bundle)]
    assert not errors, errors


def test_failure_serialises_to_prefetch_skips_schema_shape() -> None:
    request = GoModVendorRequest(attr_path="traefik", target_version="3.6.8")
    out = prefetch_go_mod_vendor(
        request,
        command_runner=_fake_runner_err("nix-build: build timed out after 1800s"),
    )
    assert isinstance(out, GoModVendorFailure)
    d = out.to_schema_dict()
    schema_path = REPO_ROOT / "policy" / "upstream-ref-schema.json"
    schema = json.loads(schema_path.read_text())
    bundle = {
        "schema_version": "1.1.0",
        "cve_id": "CVE-0000-0000",
        "current_version": "3.6.7",
        "target_version": "3.6.8",
        "fix_tier": "security-patch-release",
        "release_url": "https://example.invalid/release",
        "delta": {
            "transitive_package_changes": 0,
            "new_direct_deps": [],
            "crosses_large_delta_threshold": False,
        },
        "prefetch_skips": [d],
        "eligibility": {"verdict": "eligible"},
        "replay_critical": True,
    }
    validator = Draft202012Validator(schema)
    errors = ["/".join(str(p) for p in e.absolute_path) + ": " + e.message
             for e in validator.iter_errors(bundle)]
    assert not errors, errors


def test_expression_includes_target_version_and_fakeHash() -> None:
    """Sanity check the constructed Nix expression: the override must
    include the target_version and lib.fakeHash."""
    from agents.upstream_ref_resolver.go_mod_vendor import _build_expression
    request = GoModVendorRequest(attr_path="traefik", target_version="3.6.8")
    expr = _build_expression(request)
    assert 'version = "3.6.8"' in expr
    assert "lib.fakeHash" in expr
    assert "traefik" in expr


def test_expression_pins_nixpkgs_rev_when_supplied() -> None:
    from agents.upstream_ref_resolver.go_mod_vendor import _build_expression
    request = GoModVendorRequest(
        attr_path="traefik", target_version="3.6.8",
        nixpkgs_rev="55b908383f4d5bfee96f5cca0effc66c80893984",
    )
    expr = _build_expression(request)
    assert "55b908383f4d5bfee96f5cca0effc66c80893984" in expr


def test_parse_fod_hash_mismatch_extracts_modern_format() -> None:
    """Sanity check the regex against a realistic stderr excerpt."""
    from agents.upstream_ref_resolver.go_mod_vendor import _parse_fod_hash_mismatch
    stderr = (
        "error: hash mismatch in fixed-output derivation '/nix/store/...':\n"
        "         specified: sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\n"
        "              got:    sha256-Real4cqu1r3dV3nd0rH4shFromActualBuild=\n"
    )
    sri = _parse_fod_hash_mismatch(stderr)
    assert sri == "sha256-Real4cqu1r3dV3nd0rH4shFromActualBuild="


def test_parse_fod_hash_mismatch_returns_none_when_absent() -> None:
    from agents.upstream_ref_resolver.go_mod_vendor import _parse_fod_hash_mismatch
    stderr = "error: build failed for unrelated reason; exit code 2"
    assert _parse_fod_hash_mismatch(stderr) is None


@pytest.mark.skipif(
    os.environ.get("TRACE_REAL_GO_VENDOR") != "1",
    reason="real-network/build test; set TRACE_REAL_GO_VENDOR=1 to enable",
)
def test_real_traefik_go_vendor_smoke() -> None:
    """End-to-end: actually run the nix-build FOD-extraction against
    traefik 3.6.8. Asserts shape only — does not pin the hash value
    because the real value can shift if upstream re-releases."""
    request = GoModVendorRequest(
        attr_path="traefik", target_version="3.6.8",
    )
    out = prefetch_go_mod_vendor(request)
    assert isinstance(out, GoModVendorSuccess), getattr(out, "detail", "")
    assert out.value.startswith("sha256-") and out.value.endswith("=")
    assert out.tool == "nix-build"
