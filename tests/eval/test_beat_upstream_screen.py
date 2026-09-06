"""Tests for eval/beat_upstream_screen classification logic (no network)."""
from __future__ import annotations

import json
from types import SimpleNamespace

from eval.beat_upstream_screen import (
    _advisory_symbols,
    _fix_shape_class,
    _fixed_release_status,
    _is_kernel,
    _is_prerelease,
    _parse_ver,
    _repo_slug,
    _source_backport_ref,
    _verify_fix_commit,
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
    """A ref with no fix commit is nothing to backport from, whatever its tier."""
    assert _source_backport_ref({"candidate_refs": [{"tier_hint": "security-patch-release"}]}) is None


def test_source_backport_ref_accepts_a_fix_commit_on_a_bump_tier():
    """Scout tags source-backport only when no fixed version is derivable, which
    drops the common case of a released fix nixpkgs has not shipped. The fix
    commit is what matters."""
    ri = {"candidate_refs": [
        {"tier_hint": "security-patch-release",
         "upstream_fix_commits": [{"repo_url": "r", "commit_sha": "s"}]},
    ]}
    ref = _source_backport_ref(ri)
    assert ref is not None and ref["upstream_fix_commits"][0]["commit_sha"] == "s"


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


# --- fix-commit-verification gate ---

def test_advisory_symbols_extracts_functions_and_files():
    toks = _advisory_symbols(
        "Integer overflow in userauth_list() (src/userauth.c) via _libssh2_store_str().")
    assert "userauth_list" in toks
    assert "_libssh2_store_str" in toks
    assert "src/userauth.c" in toks
    assert "userauth.c" in toks  # basename too
    # short/stopword tokens are dropped
    assert "this" not in toks


def _commit(message, files):
    return {"message": message, "files": files}


def test_verify_flags_release_prep_message():
    # proftpd CVE-2025-53994 failure mode: scout extracted a release-prep commit.
    status, reason = _verify_fix_commit(
        _commit("Preparing for release of ProFTPD 1.3.9",
                [{"filename": "src/mod_sftp/packet.c", "patch": "@@ -1 +1 @@\n-a\n+b"}]),
        set())
    assert status == "unverified"
    assert reason == "release-prep-message"


def test_verify_flags_only_mechanical_files():
    status, reason = _verify_fix_commit(
        _commit("Update for 1.3.9", [
            {"filename": "ChangeLog", "patch": "@@ -1 +1 @@\n-x\n+y"},
            {"filename": "configure.ac", "patch": "@@ -1 +1 @@\n-1.3.8\n+1.3.9"},
        ]), set())
    assert status == "unverified"
    assert reason == "only-mechanical-files"


def test_verify_flags_no_advisory_symbol_overlap():
    # commit touches code, but not the file/symbol the advisory names -> wrong commit.
    status, reason = _verify_fix_commit(
        _commit("Fix unrelated thing",
                [{"filename": "src/other.c", "patch": "@@ -1 +1 @@\n-a\n+b"}]),
        {"userauth_list", "userauth.c"})
    assert status == "unverified"
    assert reason == "no-advisory-symbol-overlap"


def test_verify_passes_real_fix_touching_named_symbol():
    status, reason = _verify_fix_commit(
        _commit("Add bounds check in userauth_list",
                [{"filename": "src/userauth.c",
                  "patch": "@@ -1 +2 @@\n if (username_len > UINT32_MAX - 27)\n"}]),
        {"userauth_list", "src/userauth.c", "userauth.c"})
    assert status == "verified"
    assert reason is None


def test_verify_passes_when_no_advisory_symbols_and_code_touched():
    # no extractable advisory symbols -> fall back to "touches code, not release-prep".
    status, reason = _verify_fix_commit(
        _commit("Fix heap overflow", [{"filename": "auth.go", "patch": "@@ -1 +1 @@\n-a\n+b"}]),
        set())
    assert status == "verified"
    assert reason is None


# --- edit-shape tag ---

def test_fix_shape_class_canonical_for_condition_fold():
    commit = _commit("bounds fix", [{
        "filename": "src/foo.c",
        "patch": "@@ -1,3 +1,3 @@\n a\n-  if (n > MAX)\n+  if (n >= MAX)\n b",
    }])
    c = _fix_shape_class(commit)
    assert c["shape"] == "condition-fold"
    assert c["fix_shape_class"] == "canonical"


def test_fix_shape_class_design_freedom_for_multi_hunk():
    # picoclaw CSRF shape: several net-new function hunks -> design-freedom.
    patch = "\n".join(
        f"@@ -{i},0 +{i},3 @@\n+func helper{i}() bool {{\n+  return true\n+}}"
        for i in range(1, 4))
    c = _fix_shape_class(_commit("add CSRF defense", [{"filename": "auth.go", "patch": patch}]))
    assert c["n_hunks"] >= 3
    assert c["fix_shape_class"] == "design-freedom"


def test_fixed_release_is_a_tag_not_a_reject_by_default(tmp_path, monkeypatch):
    """A released fix nixpkgs has not shipped is still trace's work: stable
    branches backport, and the comparison against nixpkgs' eventual shape is the
    measurement. Only --reject-when-fixed-release drops it."""
    import eval.beat_upstream_screen as m

    resolver_input = {
        "attr_path": "demo",
        "current_version": "1.0.0",
        "candidate_refs": [{
            "tier_hint": "security-patch-release",
            "upstream_fix_commits": [{"repo_url": "https://github.com/o/r",
                                      "commit_sha": "a" * 40}],
        }],
    }
    entry = tmp_path / "CVE-2026-1"
    entry.mkdir()
    (entry / "resolver-input.json").write_text(json.dumps(resolver_input))

    monkeypatch.setattr(m, "poll_one", lambda cve_id, **kw: SimpleNamespace(action="written"))
    monkeypatch.setattr(m, "process_entry",
                        lambda p, **kw: SimpleNamespace(finding_status="finding",
                                                        resolver_status="eligible"))
    monkeypatch.setattr(m, "_fixed_release_status", lambda *a, **kw: ("reject", "v1.0.1"))
    monkeypatch.setattr(m, "_nixpkgs_pr_exists", lambda cve_id: False)
    monkeypatch.setattr(m, "_nixpkgs_code_mentions", lambda cve_id: False)
    monkeypatch.setattr(m, "_verify_fix_commit", lambda commit, adv: ("verified", ""))
    monkeypatch.setattr(m, "_fix_shape_class", lambda commit: {"fix_shape_class": "canonical"})

    kw = dict(graph=None, inbox=tmp_path, nvd_api_key=None, check_nixpkgs=True,
              fetch_commit=lambda slug, sha: {"files": [], "commit": {"message": "fix"}},
              fetch_cve_record=lambda cve_id: None)

    kept = m.screen_cve("CVE-2026-1", **kw)
    assert kept["reject"] is None
    assert kept["fix_available_as"] == "release"
    assert kept["fixed_release_tag"] == "v1.0.1"

    dropped = m.screen_cve("CVE-2026-1", reject_when_fixed_release=True, **kw)
    assert dropped["reject"] == "fixed-release-exists"


def test_fixed_release_checks_every_cherry_picked_sha():
    """A fix lands on main and is cherry-picked per release branch under different
    shas. Testing only the first sha reported 'clear' for openexr CVE-2026-59981
    when v3.4.14 carries the release-branch pick."""
    ref = {"upstream_fix_commits": [
        {"repo_url": "https://github.com/o/r", "commit_sha": "a" * 40},   # main
        {"repo_url": "https://github.com/o/r", "commit_sha": "b" * 40},   # release pick
    ]}
    contains = {("b" * 40, "v3.4.14"): True}
    status, tag = _fixed_release_status(
        ref, "3.4.13", tag_cache={},
        list_tags=lambda slug: ["v3.4.14"],
        tag_contains=lambda slug, sha, t: contains.get((sha, t), False))
    assert (status, tag) == ("reject", "v3.4.14")


def test_packaged_version_verdict_catches_pname_collision():
    """nixpkgs haskellPackages.zephyr 0.5.3 matched 42 Zephyr RTOS CVEs whose
    affected range is 3.6.0 to 4.4.2. Name matching cannot see that; the range can."""
    from eval.beat_upstream_screen import _packaged_version_verdict
    rec = {"containers": {"cna": {"affected": [
        {"product": "zephyr", "packageName": "zephyr",
         "versions": [{"version": "3.6.0", "status": "affected", "lessThan": "4.4.2"}]}]}}}
    assert _packaged_version_verdict(rec, "zephyr", "0.5.3") == "out-of-range"
    assert _packaged_version_verdict(rec, "zephyr", "4.0.0") == "in-range"


def test_packaged_version_verdict_is_unknown_when_undecidable():
    """An unparseable version, a missing record, or no matching affected entry must
    never reject on its own."""
    from eval.beat_upstream_screen import _packaged_version_verdict
    rec = {"containers": {"cna": {"affected": [
        {"product": "chirp", "versions": [{"version": "1.0", "lessThan": "2.0"}]}]}}}
    assert _packaged_version_verdict(rec, "chirp", "unstable-2026-05-18") == "unknown"
    assert _packaged_version_verdict(None, "chirp", "1.5") == "unknown"
    assert _packaged_version_verdict(rec, "other", "1.5") == "unknown"


def test_packaged_version_verdict_honours_lower_bound():
    from eval.beat_upstream_screen import _packaged_version_verdict
    rec = {"containers": {"cna": {"affected": [
        {"product": "p", "versions": [{"version": "2.0", "lessThanOrEqual": "2.9"}]}]}}}
    assert _packaged_version_verdict(rec, "p", "1.9") == "out-of-range"
    assert _packaged_version_verdict(rec, "p", "2.9") == "in-range"


def test_out_of_range_packaged_version_rejects(tmp_path, monkeypatch):
    """A collision reaching the nixpkgs checks would otherwise burn a bootstrap."""
    import eval.beat_upstream_screen as m

    entry = tmp_path / "CVE-2026-2"
    entry.mkdir()
    (entry / "resolver-input.json").write_text(json.dumps({
        "attr_path": "haskellPackages.zephyr",
        "current_version": "0.5.3",
        "candidate_refs": [{
            "tier_hint": "security-patch-release",
            "upstream_fix_commits": [{"repo_url": "https://github.com/o/r",
                                      "commit_sha": "a" * 40}]}]}))

    monkeypatch.setattr(m, "poll_one", lambda cve_id, **kw: SimpleNamespace(action="written"))
    monkeypatch.setattr(m, "process_entry",
                        lambda p, **kw: SimpleNamespace(finding_status="finding",
                                                        resolver_status="eligible"))
    monkeypatch.setattr(m, "_fixed_release_status", lambda *a, **kw: ("clear", None))

    record = {"containers": {"cna": {"affected": [
        {"product": "zephyr", "versions": [{"version": "3.6.0", "lessThan": "4.4.2"}]}]}}}
    out = m.screen_cve("CVE-2026-2", graph=None, inbox=tmp_path, nvd_api_key=None,
                       check_nixpkgs=True, fetch_cve_record=lambda cve_id: record,
                       fetch_commit=lambda slug, sha: None)
    assert out["reject"] == "packaged-version-out-of-range"
    assert out["survives"] is False


def test_inline_range_in_the_version_field_is_read():
    """Records routinely put the whole range in the version field as "< 2.0.5"
    rather than filling lessThan. Reading that as an introduced version made the
    gate blind, and PrivateBin CVE-2026-55891 reached the shortlist because of it,
    even though nixpkgs packages 2.0.6 and the fix shipped in 2.0.5."""
    from eval.beat_upstream_screen import _packaged_version_verdict
    rec = {"containers": {"cna": {"affected": [
        {"product": "privatebin", "versions": [{"version": "< 2.0.5", "status": "affected"}]}]}}}
    assert _packaged_version_verdict(rec, "privatebin", "2.0.6") == "out-of-range"
    assert _packaged_version_verdict(rec, "privatebin", "2.0.4") == "in-range"
    rec_lte = {"containers": {"cna": {"affected": [
        {"product": "p", "versions": [{"version": "<= 3.1", "status": "affected"}]}]}}}
    assert _packaged_version_verdict(rec_lte, "p", "3.1") == "in-range"
    assert _packaged_version_verdict(rec_lte, "p", "3.2") == "out-of-range"


def test_packaged_release_carrying_the_fix_is_detected():
    """The tag-lag gate only inspects tags NEWER than the packaged version, which
    answers "is there a release to bump to" and not "is this tree already fixed"."""
    from eval.beat_upstream_screen import _packaged_release_carries_fix
    ref = {"upstream_fix_commits": [
        {"repo_url": "https://github.com/o/r", "commit_sha": "a" * 40}]}
    tag = _packaged_release_carries_fix(
        ref, "2.0.6", tag_cache={},
        list_tags=lambda slug: ["2.0.7", "2.0.6", "2.0.5"],
        tag_contains=lambda slug, sha, t: t == "2.0.6")
    assert tag == "2.0.6"


def test_packaged_release_without_the_fix_is_not_flagged():
    from eval.beat_upstream_screen import _packaged_release_carries_fix
    ref = {"upstream_fix_commits": [
        {"repo_url": "https://github.com/o/r", "commit_sha": "a" * 40}]}
    assert _packaged_release_carries_fix(
        ref, "1.25.0", tag_cache={},
        list_tags=lambda slug: ["v1.25.0"],
        tag_contains=lambda slug, sha, t: False) is None
