"""Tests for `trace bundle assemble`.

Unit coverage uses fake URL prefetchers + fake go-mod-vendor runners so
the suite is deterministic and offline. The real-network paths already
have their own gated tests under tests/upstream_ref_resolver/.

The end-to-end shape matters for downstream tools (Patcher / Steward),
so the schema-validity round-trip on the written upstream-ref.json is
the most load-bearing assertion.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator

from agents.upstream_ref_resolver import (
    GoModVendorRequest,
    GoModVendorSuccess,
)
from tools.trace_cli.bundle import (
    AssembleResult,
    FinalizeResult,
    assemble_bundle,
    emit_human_summary,
    finalize_bundle,
)
from tests.schema.validate import REPO_ROOT


# ─── shared fixtures ───────────────────────────────────────────────────────


def _resolver_input(tmp_path: Path, **overrides) -> Path:
    """Write a minimal resolver-input.json with a single eligible candidate."""
    doc = {
        "cve_id": "CVE-2026-25949",
        "current_version": "3.6.7",
        "attr_path": "traefik",
        "candidate_refs": [
            {
                "version": "3.6.8",
                "tag": "v3.6.8",
                "release_url": "https://github.com/traefik/traefik/releases/tag/v3.6.8",
                "changelog_url": "https://github.com/traefik/traefik/blob/v3.6.8/CHANGELOG.md",
                "advisory_urls": ["https://github.com/traefik/traefik/security/advisories/GHSA-89p3-4642-cr2w"],
                "upstream_fix_commits": [
                    {
                        "repo_url": "https://github.com/traefik/traefik",
                        "commit_sha": "2f215ab9a1068248669dacf77ec6901f21051c75",
                        "message": "Release v3.6.8",
                    },
                ],
                "delta": {
                    "transitive_package_changes": 0,
                    "new_direct_deps": [],
                    "removed_direct_deps": [],
                    "crosses_large_delta_threshold": False,
                    "threshold_policy": "v0-default",
                },
                "tier_hint": "security-patch-release",
            },
        ],
    }
    doc.update(overrides)
    p = tmp_path / "resolver-input.json"
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(doc, indent=2))
    return p


def _package_nix(tmp_path: Path, body: str | None = None) -> Path:
    """Write a minimal package.nix with a fetchzip + vendorHash."""
    p = tmp_path / "package.nix"
    if body is None:
        body = (
            '{ lib, fetchzip, buildGo124Module }:\n'
            'buildGo124Module (finalAttrs: {\n'
            '  pname = "traefik";\n'
            '  version = "3.6.7";\n'
            '  src = fetchzip {\n'
            '    url = "https://github.com/traefik/traefik/releases/download/v${finalAttrs.version}/traefik-v${finalAttrs.version}.src.tar.gz";\n'
            '    hash = "sha256-tfCVNfY2qqhTBv6nhHqcoZ5GP7xoCBJNBkEfoMFH5vI=";\n'
            '    stripRoot = false;\n'
            '  };\n'
            '  vendorHash = "sha256-B6H188VR9A4SSyMDh95Z3KqhtyWTo81f0ORxdXeCZu0=";\n'
            '  proxyVendor = true;\n'
            '})\n'
        )
    p.write_text(body)
    return p


def _fake_url_prefetcher(table: dict):
    def fn(url: str, algorithm: str):
        key = (url, algorithm)
        if key not in table:
            return ("fetch-error-other", f"unmocked url={url!r}", None)
        return table[key]
    return fn


def _fake_gmv_runner_ok(value: str):
    def runner(expression: str, request: GoModVendorRequest):
        return ("ok", value, "fake-nix-build 1.0",
                "nix-build --no-out-link -A goModules ...")
    return runner


# ─── tests ─────────────────────────────────────────────────────────────────


def test_assemble_writes_full_set_of_artifacts(tmp_path: Path) -> None:
    ri = _resolver_input(tmp_path)
    pkg = _package_nix(tmp_path)
    out = tmp_path / "out"

    result = assemble_bundle(
        resolver_input_path=ri,
        package_nix_path=pkg,
        out_dir=out,
        prefetch_url_fn=_fake_url_prefetcher({
            ("https://github.com/traefik/traefik/releases/download/v3.6.8/traefik-v3.6.8.src.tar.gz", "sha256"): (
                "ok", "sha256-Pr3F3tCH3dSrcValueShap3dRightForJSONsch3ma=",
                "fake-nix-prefetch-url 2.33.3",
            ),
        }),
    )
    assert isinstance(result, AssembleResult)
    assert result.eligibility_verdict == "eligible"
    assert result.target_version == "3.6.8"
    assert result.fix_tier == "security-patch-release"
    assert "src.hash" in result.prefetch_hashes_grounded
    # vendorHash is in the package.nix → recorded as a skip (run_go_mod_vendor=False).
    assert any(s.startswith("vendorHash=") for s in result.prefetch_skips)

    # All three required files written.
    assert (out / "upstream-ref.json").is_file()
    assert (out / "package.nix").is_file()
    assert (out / "resolver-input.json").is_file()
    # Nothing extra by default.
    assert not (out / "finding.json").exists()
    assert not (out / "impact.json").exists()
    assert not (out / "maintainers.json").exists()


def test_assemble_copies_optional_artifacts_when_supplied(tmp_path: Path) -> None:
    ri = _resolver_input(tmp_path)
    pkg = _package_nix(tmp_path)
    finding = tmp_path / "finding.json"
    finding.write_text('{"schema_version": "1.0.0"}')
    impact = tmp_path / "impact.json"
    impact.write_text('{"schema_version": "1.0.0"}')
    maintainers = tmp_path / "maintainers.json"
    maintainers.write_text('{"schema_version": "1.0.0"}')

    out = tmp_path / "out"
    assemble_bundle(
        resolver_input_path=ri,
        package_nix_path=pkg,
        out_dir=out,
        finding_path=finding,
        impact_path=impact,
        maintainers_path=maintainers,
        prefetch_url_fn=_fake_url_prefetcher({
            ("https://github.com/traefik/traefik/releases/download/v3.6.8/traefik-v3.6.8.src.tar.gz", "sha256"): (
                "ok", "sha256-Pr3F3tCH3dSrcValueShap3dRightForJSONsch3ma=",
                "fake-nix-prefetch-url 2.33.3",
            ),
        }),
    )
    assert (out / "finding.json").read_text() == '{"schema_version": "1.0.0"}'
    assert (out / "impact.json").read_text() == '{"schema_version": "1.0.0"}'
    assert (out / "maintainers.json").read_text() == '{"schema_version": "1.0.0"}'


def test_written_upstream_ref_validates_against_schema(tmp_path: Path) -> None:
    ri = _resolver_input(tmp_path)
    pkg = _package_nix(tmp_path)
    out = tmp_path / "out"
    assemble_bundle(
        resolver_input_path=ri,
        package_nix_path=pkg,
        out_dir=out,
        prefetch_url_fn=_fake_url_prefetcher({
            ("https://github.com/traefik/traefik/releases/download/v3.6.8/traefik-v3.6.8.src.tar.gz", "sha256"): (
                "ok", "sha256-Pr3F3tCH3dSrcValueShap3dRightForJSONsch3ma=",
                "fake-nix-prefetch-url 2.33.3",
            ),
        }),
    )

    schema = json.loads((REPO_ROOT / "policy" / "upstream-ref-schema.json").read_text())
    upstream_ref = json.loads((out / "upstream-ref.json").read_text())
    validator = Draft202012Validator(schema)
    errors = ["/".join(str(p) for p in e.absolute_path) + ": " + e.message
             for e in validator.iter_errors(upstream_ref)]
    assert not errors, errors

    # Every prefetch_hashes[] entry has prefetch_kind populated.
    for entry in upstream_ref.get("prefetch_hashes", []):
        assert "prefetch_kind" in entry


def test_assemble_runs_go_mod_vendor_when_flag_enabled(tmp_path: Path) -> None:
    ri = _resolver_input(tmp_path)
    pkg = _package_nix(tmp_path)
    out = tmp_path / "out"

    fake_url_calls: list[str] = []
    def url_fn(url: str, algorithm: str):
        fake_url_calls.append(url)
        return ("ok", "sha256-Pr3F3tCH3dSrcVal=", "fake 1.0")

    fake_gmv_calls: list[str] = []
    def gmv_runner(expression: str, request: GoModVendorRequest):
        fake_gmv_calls.append(request.attr_path)
        return ("ok", "sha256-V3nd0rValueFromFakeGmvRunner=", "fake-nix-build 1.0",
                "nix-build --no-out-link -A goModules ...")

    result = assemble_bundle(
        resolver_input_path=ri,
        package_nix_path=pkg,
        out_dir=out,
        run_go_mod_vendor=True,
        attr_path="traefik",
        prefetch_url_fn=url_fn,
        go_mod_vendor_runner=gmv_runner,
    )
    assert "src.hash" in result.prefetch_hashes_grounded
    assert "vendorHash" in result.prefetch_hashes_grounded
    assert result.prefetch_skips == []
    assert fake_gmv_calls == ["traefik"]

    # Written upstream-ref carries both prefetch_hashes entries.
    upstream_ref = json.loads((out / "upstream-ref.json").read_text())
    names = {e["name"] for e in upstream_ref["prefetch_hashes"]}
    assert names == {"src.hash", "vendorHash"}
    kinds = {e["prefetch_kind"] for e in upstream_ref["prefetch_hashes"]}
    assert kinds == {"url", "go-mod-vendor"}


def test_assemble_records_gmv_failure_as_prefetch_failure(tmp_path: Path) -> None:
    """A live go-mod-vendor attempt that fails should land in
    prefetch_failures[] (NOT prefetch_skips[]) with full attribution
    preserved: attempted_command, detail, attempted_at, and
    required_for_patch."""
    ri = _resolver_input(tmp_path)
    pkg = _package_nix(tmp_path)
    out = tmp_path / "out"

    def gmv_runner(expression: str, request: GoModVendorRequest):
        return ("err", "nix-build: build timed out after 1800s",
                "fake-nix-build 1.0",
                "nix-build --no-out-link -A goModules ...")

    result = assemble_bundle(
        resolver_input_path=ri,
        package_nix_path=pkg,
        out_dir=out,
        run_go_mod_vendor=True,
        attr_path="traefik",
        prefetch_url_fn=_fake_url_prefetcher({
            ("https://github.com/traefik/traefik/releases/download/v3.6.8/traefik-v3.6.8.src.tar.gz", "sha256"): (
                "ok", "sha256-Pr3F3tCH3dSrcVal=", "fake 1.0",
            ),
        }),
        go_mod_vendor_runner=gmv_runner,
    )
    assert "vendorHash" not in result.prefetch_hashes_grounded
    failure_descrs = result.prefetch_failures
    assert any(s == "vendorHash=go-mod-vendor-prefetch-failed" for s in failure_descrs)
    # vendorHash must NOT linger in prefetch_skips[] — the resolver did
    # attempt and failed, so the entry belongs in prefetch_failures[].
    assert not any(s.startswith("vendorHash=") for s in result.prefetch_skips)
    # Disk-side: prefetch_failures[] entry preserves attribution.
    upstream_ref = json.loads((out / "upstream-ref.json").read_text())
    pf = next(e for e in upstream_ref["prefetch_failures"] if e["name"] == "vendorHash")
    assert pf["reason"] == "go-mod-vendor-prefetch-failed"
    assert pf["required_for_patch"] is True
    assert pf["attempted_command"]
    assert pf["attempted_at"]
    assert "timed out" in pf["detail"]


def test_ineligible_verdict_writes_upstream_ref_and_skips_prefetch(tmp_path: Path) -> None:
    """Resolver returns an ineligible verdict (no candidates) → assemble
    must still write upstream-ref.json + package.nix + resolver-input.json,
    but no prefetch_hashes / prefetch_skips."""
    ri = _resolver_input(tmp_path, candidate_refs=[])
    pkg = _package_nix(tmp_path)
    out = tmp_path / "out"
    result = assemble_bundle(
        resolver_input_path=ri, package_nix_path=pkg, out_dir=out,
    )
    assert result.eligibility_verdict == "ineligible-no-fix-available"
    assert result.target_version is None
    assert result.prefetch_hashes_grounded == []
    assert result.prefetch_skips == []
    upstream_ref = json.loads((out / "upstream-ref.json").read_text())
    assert "prefetch_hashes" not in upstream_ref
    assert "prefetch_skips" not in upstream_ref


def test_human_summary_contains_load_bearing_fields(tmp_path: Path) -> None:
    ri = _resolver_input(tmp_path)
    pkg = _package_nix(tmp_path)
    out = tmp_path / "out"
    result = assemble_bundle(
        resolver_input_path=ri, package_nix_path=pkg, out_dir=out,
        prefetch_url_fn=_fake_url_prefetcher({
            ("https://github.com/traefik/traefik/releases/download/v3.6.8/traefik-v3.6.8.src.tar.gz", "sha256"): (
                "ok", "sha256-Pr3F3tCH3dSrcVal=", "fake 1.0",
            ),
        }),
    )
    summary = emit_human_summary(result)
    assert "eligible" in summary
    assert "3.6.8" in summary
    assert "src.hash" in summary
    assert "vendorHash" in summary  # in skips


def test_assemble_via_cli_entrypoint(tmp_path: Path, capsys) -> None:
    """End-to-end through tools.trace_cli.cli.main(['bundle', 'assemble', ...])."""
    ri = _resolver_input(tmp_path)
    pkg = _package_nix(tmp_path)
    out = tmp_path / "out"

    # Patch the prefetch_url_fn by monkey-patching via the bundle module
    # (the CLI doesn't expose an injection seam; but the test can verify
    # the command parses correctly + dispatches into the assembler).
    # Use the JSON output format so we can assert structured fields.
    from tools.trace_cli.cli import main as cli_main

    # Ensure the ineligible path works without network calls.
    ri_ineligible = _resolver_input(tmp_path / "ineligible", candidate_refs=[])
    rc = cli_main([
        "bundle", "assemble",
        "--input", str(ri_ineligible),
        "--package", str(pkg),
        "--out", str(out / "ineligible"),
        "--format", "json",
    ])
    assert rc == 0
    captured = capsys.readouterr()
    payload = json.loads(captured.out)
    assert payload["eligibility_verdict"] == "ineligible-no-fix-available"
    assert payload["target_version"] is None
    assert "upstream-ref.json" in payload["files_written"]


# ─── finalize tests ────────────────────────────────────────────────────────


def _assembled_bundle(tmp_path: Path) -> tuple[Path, Path]:
    """Run assemble against the bind exemplar fixture and return (out_dir, ri_path)."""
    ri = _resolver_input(tmp_path, **{
        "cve_id": "CVE-2025-13878",
        "current_version": "9.20.17",
        "attr_path": "bind",
        "candidate_refs": [{
            "version": "9.20.18",
            "tag": "v9.20.18",
            "release_url": "https://downloads.isc.org/isc/bind9/9.20.18/notes",
            "changelog_url": "https://downloads.isc.org/isc/bind9/9.20.18/changelog",
            "advisory_urls": ["https://kb.isc.org/docs/cve-2025-13878"],
            "upstream_fix_commits": [{
                "repo_url": "https://gitlab.isc.org/isc-projects/bind9",
                "commit_sha": "0d2e0d8fac7533145533c4e9942322c229a422c3",
            }],
            "delta": {
                "transitive_package_changes": 0,
                "new_direct_deps": [],
                "removed_direct_deps": [],
                "crosses_large_delta_threshold": False,
                "threshold_policy": "v0-default",
            },
            "tier_hint": "security-patch-release",
        }],
    })
    pkg = _package_nix(tmp_path, body=(
        '{ stdenv, fetchurl }:\n'
        'stdenv.mkDerivation (finalAttrs: {\n'
        '  pname = "bind";\n'
        '  version = "9.20.17";\n'
        '  src = fetchurl {\n'
        '    url = "https://downloads.isc.org/isc/bind9/${finalAttrs.version}/bind-${finalAttrs.version}.tar.xz";\n'
        '    hash = "sha256-OLDOLDOLDOLDOLDOLDOLDOLDOLDOLDOLDOLDOLDOLD0=";\n'
        '  };\n'
        '})\n'
    ))
    out = tmp_path / "out"
    assemble_bundle(
        resolver_input_path=ri, package_nix_path=pkg, out_dir=out,
        prefetch_url_fn=_fake_url_prefetcher({
            ("https://downloads.isc.org/isc/bind9/9.20.18/bind-9.20.18.tar.xz", "sha256"): (
                "ok", "sha256-FakeBindRunForFinalizeTestShap3dRightForJSON=", "fake 1.0",
            ),
        }),
    )
    return out, ri


def test_finalize_writes_bundle_json_and_replay_json(tmp_path: Path) -> None:
    bundle_dir, _ri = _assembled_bundle(tmp_path)

    result = finalize_bundle(bundle_dir=bundle_dir)
    assert isinstance(result, FinalizeResult)
    assert result.cve_id == "CVE-2025-13878"
    assert result.kind == "auto-merge"
    assert len(result.bundle_id) == 16
    assert all(c in "0123456789abcdef" for c in result.bundle_id)

    bundle_json = json.loads((bundle_dir / "bundle.json").read_text())
    replay_json = json.loads((bundle_dir / "replay.json").read_text())
    assert bundle_json["bundle_id"] == result.bundle_id
    assert replay_json["bundle_id"] == result.bundle_id
    # files that are on disk got real hashes; the rest got placeholders.
    real_files = set(result.files_real_hash)
    placeholder_files = set(result.files_placeholder)
    assert real_files & placeholder_files == set()
    assert "upstream-ref.json" in real_files
    assert "package.nix" not in bundle_json["files"], (
        "package.nix is not in the canonical bundle file set; finalize "
        "should not invent new bundle.json entries."
    )
    assert bundle_json["files"]["upstream-ref.json"]["sha256"] != "d" * 64


def test_finalize_uses_real_upstream_ref_sha(tmp_path: Path) -> None:
    """The bundle.json sha for upstream-ref.json must match the on-disk
    file's actual sha256, not a placeholder."""
    import hashlib
    bundle_dir, _ = _assembled_bundle(tmp_path)
    finalize_bundle(bundle_dir=bundle_dir)

    real_sha = hashlib.sha256(
        (bundle_dir / "upstream-ref.json").read_bytes()
    ).hexdigest()
    bundle_json = json.loads((bundle_dir / "bundle.json").read_text())
    assert bundle_json["files"]["upstream-ref.json"]["sha256"] == real_sha


def test_finalize_validates_against_bundle_schema(tmp_path: Path) -> None:
    bundle_dir, _ = _assembled_bundle(tmp_path)
    finalize_bundle(bundle_dir=bundle_dir)
    bundle_json = json.loads((bundle_dir / "bundle.json").read_text())
    schema = json.loads((REPO_ROOT / "policy" / "bundle-schema.json").read_text())
    validator = Draft202012Validator(schema)
    errors = ["/".join(str(p) for p in e.absolute_path) + ": " + e.message
             for e in validator.iter_errors(bundle_json)]
    assert not errors, errors


def test_finalize_replay_validates_against_replay_schema(tmp_path: Path) -> None:
    bundle_dir, _ = _assembled_bundle(tmp_path)
    finalize_bundle(bundle_dir=bundle_dir)
    replay_json = json.loads((bundle_dir / "replay.json").read_text())
    schema = json.loads((REPO_ROOT / "policy" / "replay-schema.json").read_text())
    validator = Draft202012Validator(schema)
    errors = ["/".join(str(p) for p in e.absolute_path) + ": " + e.message
             for e in validator.iter_errors(replay_json)]
    assert not errors, errors


def test_finalize_bundle_id_is_deterministic(tmp_path: Path) -> None:
    """Same (cve_id, nixpkgs_rev, created_at) -> same bundle_id."""
    bundle_dir, _ = _assembled_bundle(tmp_path)
    fixed_ts = "2026-04-27T20:00:00Z"
    r1 = finalize_bundle(bundle_dir=bundle_dir, created_at=fixed_ts,
                         nixpkgs_rev="0" * 40)
    r2 = finalize_bundle(bundle_dir=bundle_dir, created_at=fixed_ts,
                         nixpkgs_rev="0" * 40)
    assert r1.bundle_id == r2.bundle_id


def test_finalize_preserves_assemble_resolver_invocation(tmp_path: Path) -> None:
    """Assemble seeded an upstream-ref-resolver invocation. Finalize must
    keep it (not overwrite with a different fake one)."""
    bundle_dir, _ = _assembled_bundle(tmp_path)
    pre_replay = json.loads((bundle_dir / "replay.json").read_text())
    pre_resolver_inv = pre_replay["roles"][0]["invocations"][0]["invocation_id"]

    finalize_bundle(bundle_dir=bundle_dir)
    post_replay = json.loads((bundle_dir / "replay.json").read_text())
    post_resolver_inv = post_replay["roles"][0]["invocations"][0]["invocation_id"]
    assert pre_resolver_inv == post_resolver_inv


def test_finalize_via_cli_entrypoint(tmp_path: Path, capsys) -> None:
    bundle_dir, _ = _assembled_bundle(tmp_path)
    from tools.trace_cli.cli import main as cli_main
    rc = cli_main([
        "bundle", "finalize",
        "--bundle-dir", str(bundle_dir),
        "--format", "json",
    ])
    assert rc == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["cve_id"] == "CVE-2025-13878"
    assert len(payload["bundle_id"]) == 16
    assert "upstream-ref.json" in payload["files_real_hash"]


def test_finalize_missing_bundle_dir_returns_invalid(tmp_path: Path, capsys) -> None:
    from tools.trace_cli.cli import main as cli_main
    rc = cli_main([
        "bundle", "finalize",
        "--bundle-dir", str(tmp_path / "does-not-exist"),
    ])
    assert rc != 0
    assert "does not exist" in capsys.readouterr().err


def test_finalize_derives_blast_radius_kind_reason_from_impact(tmp_path: Path) -> None:
    """When impact.json has exceeds_threshold=true, finalize should pick
    `blast-radius-exceeds-threshold` automatically (no --kind-reason
    needed). Mirrors the openssl_3 case landed 2026-04-27 by hand."""
    bundle_dir, _ = _assembled_bundle(tmp_path)
    # Provide an impact.json with exceeds_threshold=true.
    impact = {
        "schema_version": "1.0.0",
        "cve_id": "CVE-2025-13878",
        "nixpkgs_rev": "0" * 40,
        "blast_radius_threshold": 500,
        "threshold_policy": "v0-default",
        "affected_attr_paths": ["bind"],
        "reverse_closure_count": 8742,
        "reverse_closure_bucket": ">5000",
        "reverse_closure_sample": ["x"],
        "critical_downstreams": [],
        "exceeds_threshold": True,
        "per_attr": [{
            "attr_path": "bind",
            "drv_path": "/nix/store/00000000000000000000000000000003-bind-9.20.17.drv",
            "reverse_closure_count": 8742,
            "reverse_closure_bucket": ">5000",
            "reverse_closure_sample": ["x"],
            "critical_downstreams": [],
            "exceeds_threshold": True,
        }],
        "replay_critical": True,
    }
    (bundle_dir / "impact.json").write_text(json.dumps(impact, indent=2))

    finalize_bundle(bundle_dir=bundle_dir, bundle_kind="human-review-required")
    bundle_json = json.loads((bundle_dir / "bundle.json").read_text())
    assert bundle_json["kind"] == "human-review-required"
    assert bundle_json["kind_reason"] == "blast-radius-exceeds-threshold"


def test_finalize_blast_radius_overrides_human_review_trigger(tmp_path: Path) -> None:
    """When BOTH impact.exceeds_threshold=true AND eligibility.
    human_review_trigger=major-version-jump are present, blast radius
    wins (it is the measurable cap signal)."""
    bundle_dir, _ = _assembled_bundle(tmp_path)
    # Make impact say exceeds.
    impact = {
        "schema_version": "1.0.0",
        "cve_id": "CVE-2025-13878",
        "nixpkgs_rev": "0" * 40,
        "blast_radius_threshold": 500,
        "threshold_policy": "v0-default",
        "affected_attr_paths": ["bind"],
        "reverse_closure_count": 8742,
        "reverse_closure_bucket": ">5000",
        "reverse_closure_sample": ["x"],
        "critical_downstreams": [],
        "exceeds_threshold": True,
        "per_attr": [{
            "attr_path": "bind",
            "drv_path": "/nix/store/00000000000000000000000000000003-bind-9.20.17.drv",
            "reverse_closure_count": 8742,
            "reverse_closure_bucket": ">5000",
            "reverse_closure_sample": ["x"],
            "critical_downstreams": [],
            "exceeds_threshold": True,
        }],
        "replay_critical": True,
    }
    (bundle_dir / "impact.json").write_text(json.dumps(impact, indent=2))
    # Make upstream-ref say major-version-jump-trigger.
    ur_path = bundle_dir / "upstream-ref.json"
    ur = json.loads(ur_path.read_text())
    ur["eligibility"] = {
        "verdict": "eligible-requires-human-review",
        "verdict_reason": "test",
        "human_review_trigger": "major-version-jump",
    }
    ur_path.write_text(json.dumps(ur, indent=2))

    finalize_bundle(bundle_dir=bundle_dir, bundle_kind="human-review-required")
    bundle_json = json.loads((bundle_dir / "bundle.json").read_text())
    # Blast radius wins.
    assert bundle_json["kind_reason"] == "blast-radius-exceeds-threshold"


def test_finalize_explicit_kind_reason_still_wins(tmp_path: Path) -> None:
    """The --kind-reason flag (in CLI) / kind_reason= kwarg overrides
    every derivation path. Operator escape hatch."""
    bundle_dir, _ = _assembled_bundle(tmp_path)
    finalize_bundle(
        bundle_dir=bundle_dir,
        bundle_kind="human-review-required",
        kind_reason="reviewer-verdict-escalate",
    )
    bundle_json = json.loads((bundle_dir / "bundle.json").read_text())
    assert bundle_json["kind_reason"] == "reviewer-verdict-escalate"


# ─── source-backport vendor-hash semantics ────────────────────────────────


def _backport_resolver_input(tmp_path: Path) -> Path:
    """A pinned source-backport row: the target version is the current one."""
    return _resolver_input(
        tmp_path,
        current_version="3.6.7",
        candidate_refs=[
            {
                "version": "3.6.7",
                "tag": "v3.6.7",
                "release_url": "https://github.com/traefik/traefik/releases/tag/v3.6.7",
                "changelog_url": "https://github.com/traefik/traefik/blob/v3.6.7/CHANGELOG.md",
                "advisory_urls": [
                    "https://github.com/traefik/traefik/security/advisories/GHSA-89p3-4642-cr2w"
                ],
                "upstream_fix_commits": [
                    {
                        "repo_url": "https://github.com/traefik/traefik",
                        "commit_sha": "2f215ab9a1068248669dacf77ec6901f21051c75",
                        "message": "Fix the thing",
                    },
                ],
                "delta": {
                    "transitive_package_changes": 0,
                    "new_direct_deps": [],
                    "removed_direct_deps": [],
                    "crosses_large_delta_threshold": False,
                    "threshold_policy": "v0-default",
                },
                "tier_hint": "source-backport",
            },
        ],
    )


def _assemble_backport(tmp_path: Path, patch_body: str) -> dict:
    patch = tmp_path / "upstream-fix.patch"
    patch.write_text(patch_body)
    out = tmp_path / "bundle"
    assemble_bundle(
        resolver_input_path=_backport_resolver_input(tmp_path),
        package_nix_path=_package_nix(tmp_path),
        out_dir=out,
        attr_path="traefik",
        upstream_fix_patch_path=patch,
        prefetch_url_fn=lambda *a, **k: ("error", None, "offline"),
    )
    return json.loads((out / "upstream-ref.json").read_text())


_SOURCE_ONLY_PATCH = (
    "diff --git a/pkg/server/x.go b/pkg/server/x.go\n"
    "--- a/pkg/server/x.go\n+++ b/pkg/server/x.go\n"
)
_LOCKFILE_PATCH = _SOURCE_ONLY_PATCH + (
    "diff --git a/go.sum b/go.sum\n--- a/go.sum\n+++ b/go.sum\n"
)


def test_assemble_clears_vendor_hash_for_a_source_only_backport(tmp_path):
    """The assembler must hand the ground-truth patch to the derivation.

    Without it every pinned backport of a vendored package draws a rule-8
    refusal citing a hash the patch never touches.
    """
    ref = _assemble_backport(tmp_path, _SOURCE_ONLY_PATCH)
    skips = {s["name"]: s for s in ref.get("prefetch_skips", [])}
    assert "vendorHash" in skips, skips
    assert skips["vendorHash"]["required_for_patch"] is False


def test_assemble_keeps_vendor_hash_for_a_lockfile_touching_backport(tmp_path):
    ref = _assemble_backport(tmp_path, _LOCKFILE_PATCH)
    skips = {s["name"]: s for s in ref.get("prefetch_skips", [])}
    assert skips["vendorHash"]["required_for_patch"] is True
