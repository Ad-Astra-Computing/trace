"""Tests for eval/beat_upstream_screen classification logic (no network)."""
from __future__ import annotations

from eval.beat_upstream_screen import _is_kernel, _source_backport_ref


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
