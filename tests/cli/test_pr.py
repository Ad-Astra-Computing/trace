"""Tests for `trace pr`.

Covers the validation / parse layer and dry-run path. Git + gh subprocess
calls are mocked; this is a unit-level suite — the integration path (real
clone + real PR) is exercised manually or in a dedicated e2e test.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from unittest import mock

import pytest

from tools.trace_cli import pr as pr_mod


# ─── fixture helpers ─────────────────────────────────────────────────────────


def _bundle_dir(
    tmp_path: Path,
    *,
    kind: str = "auto-merge",
    rekor_log_index: int | None = 9999999,
    signer: str = "https://github.com/Ad-Astra-Computing/trace/.github/workflows/steward.yml@refs/heads/main",
    with_patch_diff: bool = True,
) -> Path:
    d = tmp_path / "bundle"
    d.mkdir()
    bundle: dict = {
        "schema_version": "1.0.0",
        "bundle_id": "abcd1234ef567890",
        "cve_id": "CVE-2025-8176",
        "nixpkgs_rev": "d07af9b07a5fb0d212372f4d796f11d6267476ee",
        "kind": kind,
        "signed_manifest": {
            "algorithm": "sigstore-cosign-v1",
            "signer": signer,
            "identity_subject": signer,
            "identity_issuer": "https://token.actions.githubusercontent.com",
            "rekor_log_index": rekor_log_index,
            "rekor_uuid": "aabbcc",
        },
    }
    (d / "bundle.json").write_text(json.dumps(bundle))
    (d / "resolver-input.json").write_text(
        json.dumps({"cve_id": "CVE-2025-8176", "attr_path": "libtiff", "current_version": "4.7.0", "candidate_refs": []})
    )
    (d / "upstream-ref.json").write_text(
        json.dumps({"schema_version": "1.0.0", "cve_id": "CVE-2025-8176", "current_version": "4.7.0", "target_version": "4.7.1", "delta": {}, "tag": None, "release_url": None, "advisory_urls": [], "upstream_fix_commits": [], "eligibility": {}, "prefetch_hashes": [], "fix_tier": "patch", "replay_critical": True})
    )
    if with_patch_diff:
        (d / "patch.diff").write_text(
            "--- a/package.nix\n+++ b/package.nix\n@@ -1 +1 @@\n-version = \"4.7.0\";\n+version = \"4.7.1\";\n"
        )
    return d


def _policy_dir(tmp_path: Path) -> Path:
    pd = tmp_path / "policy"
    pd.mkdir()
    policy = {
        "schema_version": "1.0.0",
        "fork": {
            "owner": "Ad-Astra-Computing",
            "repo": "nixpkgs",
            "url": "https://github.com/Ad-Astra-Computing/nixpkgs",
            "ssh_url": "git@github.com:Ad-Astra-Computing/nixpkgs.git",
            "upstream": {"owner": "NixOS", "repo": "nixpkgs", "url": "https://github.com/NixOS/nixpkgs"},
            "default_branch": "master",
            "tracked_channels": ["nixos-unstable"],
        },
        "patch_branch_convention": {
            "format": "trace/{cve_id}--{attr_path}--{bundle_id_short}",
            "examples": [],
            "notes": "",
        },
        "pr_convention": {
            "title_format": "{cve_id}: {attr_path} -> {target_version}",
            "title_examples": [],
            "base_branch": "master",
            "labels": ["trace-bundle"],
            "body_includes": [],
        },
        "trust_boundary": {
            "trace_writes_to": "Ad-Astra-Computing/nixpkgs only",
            "never_writes_to": "NixOS/nixpkgs",
            "notes": "",
        },
    }
    (pd / "nixpkgs-fork.json").write_text(json.dumps(policy))
    return pd / "nixpkgs-fork.json"


def _args(
    bundle_dir: Path,
    policy_path: Path,
    *,
    dry_run: bool = False,
    nixpkgs_checkout: Path | None = None,
    fork: str | None = None,
    base: str | None = None,
    cert_run_url: str | None = None,
) -> argparse.Namespace:
    return argparse.Namespace(
        cmd="pr",
        bundle_dir=bundle_dir,
        nixpkgs_checkout=nixpkgs_checkout,
        fork=fork,
        base=base,
        cert_run_url=cert_run_url,
        dry_run=dry_run,
        policy=policy_path,
    )


# ─── validation tests ─────────────────────────────────────────────────────────


def test_rejects_non_auto_merge(tmp_path: Path, capsys) -> None:
    bd = _bundle_dir(tmp_path, kind="advisory-only")
    pp = _policy_dir(tmp_path)
    rc = pr_mod.run(_args(bd, pp))
    assert rc != 0
    err = capsys.readouterr().err
    assert "auto-merge" in err


def test_rejects_human_review_required(tmp_path: Path, capsys) -> None:
    bd = _bundle_dir(tmp_path, kind="human-review-required")
    pp = _policy_dir(tmp_path)
    rc = pr_mod.run(_args(bd, pp))
    assert rc != 0
    err = capsys.readouterr().err
    assert "auto-merge" in err


def test_rejects_unsigned_bundle(tmp_path: Path, capsys) -> None:
    bd = _bundle_dir(tmp_path, signer="ci-pending", rekor_log_index=None)
    pp = _policy_dir(tmp_path)
    rc = pr_mod.run(_args(bd, pp))
    assert rc != 0
    err = capsys.readouterr().err
    assert "signed" in err.lower() or "rekor" in err.lower()


def test_rejects_missing_rekor_index(tmp_path: Path, capsys) -> None:
    bd = _bundle_dir(tmp_path, rekor_log_index=None)
    pp = _policy_dir(tmp_path)
    rc = pr_mod.run(_args(bd, pp))
    assert rc != 0


def test_rejects_missing_patch_diff(tmp_path: Path, capsys) -> None:
    bd = _bundle_dir(tmp_path, with_patch_diff=False)
    pp = _policy_dir(tmp_path)
    rc = pr_mod.run(_args(bd, pp))
    assert rc != 0
    err = capsys.readouterr().err
    assert "patch.diff" in err


def test_rejects_missing_bundle_json(tmp_path: Path, capsys) -> None:
    empty = tmp_path / "empty"
    empty.mkdir()
    pp = _policy_dir(tmp_path)
    rc = pr_mod.run(_args(empty, pp))
    assert rc != 0
    err = capsys.readouterr().err
    assert "bundle.json" in err


def test_rejects_invalid_fork_format(tmp_path: Path, capsys) -> None:
    bd = _bundle_dir(tmp_path)
    pp = _policy_dir(tmp_path)
    rc = pr_mod.run(_args(bd, pp, fork="not-a-valid-fork-format"))
    assert rc != 0
    err = capsys.readouterr().err
    assert "owner/repo" in err


# ─── dry-run tests ────────────────────────────────────────────────────────────


def test_dry_run_prints_plan_on_valid_bundle(tmp_path: Path, capsys) -> None:
    """dry-run should reach the checkout+check stage. We mock subprocess
    so no real git calls happen."""
    bd = _bundle_dir(tmp_path)
    pp = _policy_dir(tmp_path)

    # Provide a fake nixpkgs checkout that has the expected package.nix
    nixpkgs_dir = tmp_path / "nixpkgs"
    pkg_dir = nixpkgs_dir / "pkgs" / "by-name" / "li" / "libtiff"
    pkg_dir.mkdir(parents=True)
    (pkg_dir / "package.nix").write_text('{ version = "4.7.0"; }')

    with mock.patch("subprocess.run") as mock_run:
        mock_run.return_value = mock.MagicMock(returncode=0, stdout="", stderr="")

        rc = pr_mod.run(_args(bd, pp, dry_run=True, nixpkgs_checkout=nixpkgs_dir))

    assert rc == 0
    out = capsys.readouterr().out
    assert "[dry-run]" in out
    assert "CVE-2025-8176" in out
    assert "Ad-Astra-Computing" in out


def test_dry_run_aborts_if_apply_check_fails(tmp_path: Path, capsys) -> None:
    bd = _bundle_dir(tmp_path)
    pp = _policy_dir(tmp_path)

    nixpkgs_dir = tmp_path / "nixpkgs"
    pkg_dir = nixpkgs_dir / "pkgs" / "by-name" / "li" / "libtiff"
    pkg_dir.mkdir(parents=True)
    (pkg_dir / "package.nix").write_text('{ version = "4.7.0"; }')

    with mock.patch("subprocess.run") as mock_run:
        mock_run.return_value = mock.MagicMock(returncode=1, stdout="", stderr="hunk failed")

        rc = pr_mod.run(_args(bd, pp, dry_run=True, nixpkgs_checkout=nixpkgs_dir))

    assert rc != 0
    err = capsys.readouterr().err
    assert "check" in err.lower() or "apply" in err.lower()


# ─── helper unit tests ────────────────────────────────────────────────────────


def test_resolve_attr_package_dir_finds_pkgs_by_name(tmp_path: Path) -> None:
    attr = "libtiff"
    pkg_dir = tmp_path / "pkgs" / "by-name" / "li" / "libtiff"
    pkg_dir.mkdir(parents=True)
    (pkg_dir / "package.nix").write_text("{ }")
    result = pr_mod._resolve_attr_package_dir(tmp_path, attr)
    assert result == "pkgs/by-name/li/libtiff"


def test_resolve_attr_package_dir_returns_none_when_missing(tmp_path: Path) -> None:
    result = pr_mod._resolve_attr_package_dir(tmp_path, "nonexistent")
    assert result is None


def test_build_pr_body_includes_cve_and_rekor(tmp_path: Path) -> None:
    bundle = {
        "cve_id": "CVE-2025-8176",
        "kind": "auto-merge",
        "bundle_id": "abcd1234ef567890",
        "nixpkgs_rev": "d07af9b07a5fb0d212372f4d796f11d6267476ee",
        "signed_manifest": {
            "rekor_log_index": 9999999,
            "identity_subject": "https://github.com/Ad-Astra-Computing/trace/.github/workflows/steward.yml@refs/heads/main",
            "identity_issuer": "https://token.actions.githubusercontent.com",
        },
    }
    bd = tmp_path / "b"
    bd.mkdir()
    body = pr_mod._build_pr_body(bundle, bd, cert_run_url=None)
    assert "CVE-2025-8176" in body
    assert "auto-merge" in body
    assert "abcd1234ef567890" in body
    assert "rekor.sigstore.dev" in body


def test_build_pr_body_includes_cert_run_url(tmp_path: Path) -> None:
    bundle = {
        "cve_id": "CVE-2025-8176",
        "kind": "auto-merge",
        "bundle_id": "abcd1234ef567890",
        "nixpkgs_rev": "d07af9b07a5fb0d212372f4d796f11d6267476ee",
        "signed_manifest": {
            "rekor_log_index": 9999999,
            "identity_subject": "",
            "identity_issuer": "",
        },
    }
    bd = tmp_path / "b"
    bd.mkdir()
    url = "https://github.com/Ad-Astra-Computing/trace/actions/runs/26647927663"
    body = pr_mod._build_pr_body(bundle, bd, cert_run_url=url)
    assert url in body


def test_load_attr_returns_attr_path(tmp_path: Path) -> None:
    ri = tmp_path / "resolver-input.json"
    ri.write_text(json.dumps({"attr_path": "mruby", "cve_id": "CVE-2025-7207", "current_version": "3.3.0", "candidate_refs": []}))
    attr, err = pr_mod._load_attr(tmp_path)
    assert attr == "mruby"
    assert err is None


def test_load_attr_fails_when_missing(tmp_path: Path) -> None:
    attr, err = pr_mod._load_attr(tmp_path)
    assert attr == ""
    assert err is not None
    assert "resolver-input.json" in err
