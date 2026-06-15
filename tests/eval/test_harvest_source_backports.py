"""Tests for the source-backport candidate harvester's pure parsing logic.

The git-driver (`harvest`) is exercised opportunistically against a real nixpkgs
clone when one is present; the parsing functions are unit-tested without a repo.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from eval.harvest_source_backports import (
    BackportCandidate,
    classify_keywords,
    harvest,
    package_from_patch_path,
    parse_commit_record,
)


# ─── package inference ────────────────────────────────────────────────────────


def test_package_from_by_name_path():
    assert package_from_patch_path(
        "pkgs/by-name/li/linux-pam/CVE-2025-6020.patch") == "linux-pam"


def test_package_from_legacy_path():
    assert package_from_patch_path(
        "pkgs/development/libraries/libxml2/CVE-2025-6170.patch") == "libxml2"


# ─── keyword classification ───────────────────────────────────────────────────


def test_classify_asan_class():
    tags = classify_keywords("libgit2: fix heap buffer overflow in SSH creds", [])
    assert "asan-class" in tags


def test_classify_testable():
    tags = classify_keywords(
        "litestream: fix CVE-2024-41254 by adding SSH host key verification", [])
    assert "testable" in tags


# ─── commit record parsing ────────────────────────────────────────────────────


def test_parse_pure_patch_add_is_candidate():
    c = parse_commit_record(
        commit="abc123", parent="parent456",
        subject="linux-pam: apply patch for CVE-2025-6020",
        added_patch_files=["pkgs/by-name/li/linux-pam/CVE-2025-6020.patch"],
        full_diff_added_lines=["+  patches = [ ./CVE-2025-6020.patch ];"],
    )
    assert c is not None
    assert c.cve_ids == ["CVE-2025-6020"]
    assert c.package == "linux-pam"
    assert c.nixpkgs_pre_fix_rev == "parent456"
    assert c.version_changed is False
    assert c.to_dict()["patch_strategy"] == "source-backport"


def test_parse_version_bump_flagged():
    c = parse_commit_record(
        commit="abc", parent="par",
        subject="foo: 1.0 -> 1.1 (also patches CVE-2025-9999)",
        added_patch_files=["pkgs/by-name/fo/foo/CVE-2025-9999.patch"],
        full_diff_added_lines=['+  version = "1.1";'],
    )
    assert c is not None
    assert c.version_changed is True  # bump+patch combo, bootstrap should skip


def test_parse_no_patch_added_returns_none():
    c = parse_commit_record(
        commit="abc", parent="par", subject="foo: 1.0 -> 1.1",
        added_patch_files=["pkgs/by-name/fo/foo/package.nix"],
        full_diff_added_lines=[],
    )
    assert c is None


def test_parse_cve_from_patch_filename_when_absent_in_subject():
    c = parse_commit_record(
        commit="abc", parent="par",
        subject="perlPackages.JSONXS: security patch",
        added_patch_files=["pkgs/development/perl-modules/JSON-XS-CVE-2025-40928.patch"],
        full_diff_added_lines=[],
    )
    assert c is not None
    assert "CVE-2025-40928" in c.cve_ids


# ─── opportunistic real-repo smoke ────────────────────────────────────────────


def test_harvest_against_real_clone_if_present():
    repo = Path.home() / "code" / "nixpkgs"
    if not (repo / ".git").is_dir():
        pytest.skip("no nixpkgs clone present")
    cands = harvest(repo, limit=500, ref="HEAD")
    # all results are well-formed source-backport leads
    for c in cands:
        assert isinstance(c, BackportCandidate)
        assert c.patch_files and all(p.endswith(".patch") for p in c.patch_files)
        assert c.nixpkgs_fix_commit and c.nixpkgs_pre_fix_rev
        assert c.cve_ids  # require_cve default True
