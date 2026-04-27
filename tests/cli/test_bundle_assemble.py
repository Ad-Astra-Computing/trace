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
    assemble_bundle,
    emit_human_summary,
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


def test_assemble_records_gmv_failure_as_prefetch_skip(tmp_path: Path) -> None:
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
    skip_descrs = result.prefetch_skips
    assert any(s == "vendorHash=go-mod-vendor-prefetch-failed" for s in skip_descrs)


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
