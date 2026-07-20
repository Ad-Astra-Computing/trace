"""Tests for eval/beat_upstream_screen classification logic (no network)."""
from __future__ import annotations

from eval.beat_upstream_screen import (
    _fixed_release_status,
    _is_kernel,
    _is_prerelease,
    _parse_ver,
    _repo_slug,
    _source_backport_ref,
)


def test_is_kernel_matches_kernel_attrs():
    assert _is_kernel("linux")
    assert _is_kernel("linuxPackages.nvidia_x11")
    assert _is_kernel("linux_6_6")
    assert _is_kernel("linuxKernel.kernels.linux_6_1")


def test_is_kernel_excludes_lookalikes():
    # substrings that merely start with "linux" but are ordinary packages
    assert not _is_kernel("linux-pam")
    assert not _is_kernel("linuxsampler")
    assert not _is_kernel("bzip2")


def test_source_backport_ref_picks_the_backport_tier():
    ri = {"candidate_refs": [
        {"tier_hint": "security-patch-release"},
        {"tier_hint": "source-backport", "upstream_fix_commits": [{"repo_url": "r", "commit_sha": "s"}]},
    ]}
    ref = _source_backport_ref(ri)
    assert ref is not None and ref["tier_hint"] == "source-backport"


def test_source_backport_ref_none_for_bump_only():
    assert _source_backport_ref({"candidate_refs": [{"tier_hint": "security-patch-release"}]}) is None


def test_source_backport_ref_none_for_empty():
    assert _source_backport_ref({}) is None
    assert _source_backport_ref({"candidate_refs": []}) is None


# --- git-tag-lag gate helpers ---

def test_parse_ver():
    assert _parse_ver("v0.3.1") == (0, 3, 1)
    assert _parse_ver("0.2.9") == (0, 2, 9)
    assert _parse_ver("1.3.9a") == (1, 3, 9)  # trailing non-numeric suffix dropped
    assert _parse_ver("release-nightly") is None


def test_is_prerelease():
    assert _is_prerelease("v1.0.0-rc1")
    assert _is_prerelease("2.0.0-beta")
    assert _is_prerelease("v3.0.0.dev2")
    assert not _is_prerelease("v0.3.1")
    assert not _is_prerelease("1.3.9a")


def test_repo_slug():
    assert _repo_slug("https://github.com/sipeed/picoclaw") == "sipeed/picoclaw"
    assert _repo_slug("https://github.com/proftpd/proftpd.git") == "proftpd/proftpd"
    assert _repo_slug("https://gitlab.com/x/y") is None  # non-GitHub: gh ancestry unavailable


def _ref(sha, repo="https://github.com/sipeed/picoclaw"):
    return {"upstream_fix_commits": [{"commit_sha": sha, "repo_url": repo}]}


def test_fixed_release_reject_when_stable_tag_carries_fix():
    # picoclaw SSRF (CVE-2026-16084): fix is contained in released v0.3.1 -> bump-shaped.
    tags = ["v0.3.1", "v0.3.0", "v0.2.9", "v0.2.8"]
    contains = {("SSRF", "v0.3.1"): True, ("SSRF", "v0.3.0"): False}
    status, tag = _fixed_release_status(
        _ref("SSRF"), "0.2.9", tag_cache={},
        list_tags=lambda slug: tags,
        tag_contains=lambda slug, sha, t: contains.get((sha, t), False),
    )
    assert status == "reject"
    assert tag == "v0.3.1"


def test_fixed_release_clear_when_fix_only_on_main():
    # picoclaw CSRF (CVE-2026-16081): fix is on main, not in any release tag -> genuine backport.
    tags = ["v0.3.1", "v0.3.0", "v0.2.9"]
    status, tag = _fixed_release_status(
        _ref("CSRF"), "0.2.9", tag_cache={},
        list_tags=lambda slug: tags,
        tag_contains=lambda slug, sha, t: False,
    )
    assert status == "clear"
    assert tag is None


def test_fixed_release_prerelease_only_survives_with_flag():
    tags = ["v0.4.0-rc1", "v0.3.0"]
    status, tag = _fixed_release_status(
        _ref("FIX"), "0.2.9", tag_cache={},
        list_tags=lambda slug: tags,
        tag_contains=lambda slug, sha, t: t == "v0.4.0-rc1",
    )
    assert status == "prerelease"
    assert tag == "v0.4.0-rc1"


def test_fixed_release_skips_tags_not_newer_than_packaged():
    # a tag <= packaged version can't be the bump target; it must not even be compared.
    compared = []

    def _contains(slug, sha, t):
        compared.append(t)
        return False

    _fixed_release_status(
        _ref("FIX"), "0.3.0", tag_cache={},
        list_tags=lambda slug: ["v0.3.1", "v0.3.0", "v0.2.9", "v0.2.8"],
        tag_contains=_contains,
    )
    assert compared == ["v0.3.1"]  # only the strictly-newer tag is checked


def test_fixed_release_incomplete_on_api_failure():
    status, tag = _fixed_release_status(
        _ref("FIX"), "0.2.9", tag_cache={},
        list_tags=lambda slug: None,  # tag-list fetch failed
        tag_contains=lambda slug, sha, t: False,
    )
    assert status == "incomplete"


def test_fixed_release_incomplete_for_non_github_upstream():
    status, _ = _fixed_release_status(
        _ref("FIX", repo="https://gitlab.com/x/y"), "0.2.9", tag_cache={},
        list_tags=lambda slug: ["v9.9.9"],
        tag_contains=lambda slug, sha, t: True,
    )
    assert status == "incomplete"


def test_fixed_release_incomplete_when_all_compares_fail_no_containment():
    status, _ = _fixed_release_status(
        _ref("FIX"), "0.2.9", tag_cache={},
        list_tags=lambda slug: ["v0.3.1"],
        tag_contains=lambda slug, sha, t: None,  # compare call failed
    )
    assert status == "incomplete"
