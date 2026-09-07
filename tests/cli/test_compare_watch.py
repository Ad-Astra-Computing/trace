"""`trace compare watch`: notice when nixpkgs lands a fix for a live-lane bundle
and score ours against it. See docs/specs/upstream-comparison-watcher.md.

Every network call is injected. The suite makes none.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from tools.trace_cli.compare_watch import (
    classify_change,
    compare_bundle,
    parse_fork_branch,
    report,
    watch,
)

SHA = "e9697d98e7249b0f68a6be040a4f3dcc5bc101fa"


def _bundle(tmp_path: Path, name: str = "CVE-2026-16599--wget-ftp-opie-backport") -> Path:
    b = tmp_path / "traces" / "example" / name
    b.mkdir(parents=True)
    (b / "bundle.json").write_text(json.dumps({"bundle_id": "0599d03cf7b75fd2", "cve_id": "CVE-2026-16599",
                                              "nixpkgs_rev": "c" * 40}))
    (b / "finding.json").write_text(json.dumps({"cve_id": "CVE-2026-16599",
                                               "affected": [{"attr_path": "wget", "version": "1.25.0"}]}))
    (b / "upstream-ref.json").write_text(json.dumps({
        "eligibility": {"patch_strategy": "source-backport"},
        "upstream_fix_commits": [{"repo_url": "https://gitlab.com/gnuwget/wget", "commit_sha": SHA}]}))
    (b / "patch.diff").write_text(
        "diff --git a/CVE-2026-16599.patch b/CVE-2026-16599.patch\n--- /dev/null\n+++ b/CVE-2026-16599.patch\n"
        "@@ -0,0 +1,4 @@\n+--- a/src/ftp-basic.c\n++++ b/src/ftp-basic.c\n+-          skey_sequence = 10 * skey_sequence + *seed - '0';\n"
        "++          if (skey_sequence > 9999) return FTPLOGREFUSED;\n"
        "diff --git a/package.nix b/package.nix\n--- a/package.nix\n+++ b/package.nix\n@@ -1 +1,2 @@\n+    ./CVE-2026-16599.patch\n")
    return b


def test_parse_fork_branch():
    assert parse_fork_branch("trace/CVE-2026-16599--wget--0599d03cf7b75fd2") == \
        ("CVE-2026-16599", "wget", "0599d03cf7b75fd2")
    assert parse_fork_branch("trace/CVE-2021-28918--perlPackages.NetCIDRLite--ad030e70e8cdb2b5") == \
        ("CVE-2021-28918", "perlPackages.NetCIDRLite", "ad030e70e8cdb2b5")
    assert parse_fork_branch("main") is None


def test_classify_a_patch_file_added_under_the_package():
    files = [{"filename": "pkgs/by-name/wg/wget/CVE-2026-16599.patch", "status": "added",
              "patch": "@@ -0,0 +1,2 @@\n+-          skey_sequence = 10 * skey_sequence + *seed - '0';\n"
                       "++          if (skey_sequence > 9999) return FTPLOGREFUSED;\n"},
             {"filename": "pkgs/by-name/wg/wget/package.nix", "status": "modified", "patch": "+ ./CVE-2026-16599.patch"}]
    shape = classify_change(files, fix_shas=[SHA], current_version="1.25.0")
    assert shape["shape"] == "patch-file"
    assert shape["patch_files"] == ["pkgs/by-name/wg/wget/CVE-2026-16599.patch"]


def test_classify_a_fetchpatch_of_the_same_commit():
    files = [{"filename": "pkgs/by-name/wg/wget/package.nix", "status": "modified",
              "patch": f"+    (fetchpatch {{\n+      url = \"https://gitlab.com/gnuwget/wget/-/commit/{SHA}.patch\";\n"}]
    shape = classify_change(files, fix_shas=[SHA], current_version="1.25.0")
    assert shape["shape"] == "same-fix-commit"


def test_classify_a_version_bump():
    files = [{"filename": "pkgs/by-name/wg/wget/package.nix", "status": "modified",
              "patch": '-  version = "1.25.0";\n+  version = "1.26.0";\n'}]
    shape = classify_change(files, fix_shas=[SHA], current_version="1.25.0")
    assert shape["shape"] == "upstream-bumped"
    assert shape["fixed_version"] == "1.26.0"


def test_compare_scores_a_patch_file_with_the_existing_grader(tmp_path):
    b = _bundle(tmp_path)
    change = {"number": 4242, "merged_at": "2026-09-20T00:00:00Z",
              "files": [{"filename": "pkgs/by-name/wg/wget/CVE-2026-16599.patch", "status": "added",
                         "patch": "@@ -0,0 +1,2 @@\n+-          skey_sequence = 10 * skey_sequence + *seed - '0';\n"
                                  "++          if (skey_sequence > 9999) return FTPLOGREFUSED;\n"}]}
    result = compare_bundle(b, change, fetch_file=lambda pr, path: (
        "--- a/src/ftp-basic.c\n+++ b/src/ftp-basic.c\n"
        "-          skey_sequence = 10 * skey_sequence + *seed - '0';\n"
        "+          if (skey_sequence > 9999) return FTPLOGREFUSED;\n"))
    assert result["shape"] == "patch-file"
    assert result["scores"]["exact"] is True
    assert result["nixpkgs_pr"] == 4242
    saved = json.loads((b / "comparison.json").read_text())
    assert saved["scores"]["added_recall"] == 1.0
    assert "compared_at" in saved


def test_watch_leaves_an_unlanded_bundle_waiting_and_silent(tmp_path):
    b = _bundle(tmp_path)
    comments = []
    states = watch(
        fork_prs=[{"number": 45, "headRefName": "trace/CVE-2026-16599--wget--0599d03cf7b75fd2"}],
        bundles_root=tmp_path / "traces" / "example",
        find_merged_nixpkgs_pr=lambda cve: None,
        cve_in_tree=lambda cve: False,
        fetch_change=lambda number: None,
        fetch_file=lambda pr, path: "",
        comment=lambda pr, body: comments.append((pr, body)),
    )
    assert states == {"CVE-2026-16599": "waiting"}
    assert comments == []
    assert not (b / "comparison.json").exists()


def test_watch_compares_once_and_comments_once(tmp_path):
    b = _bundle(tmp_path)
    comments = []
    change = {"number": 4242, "merged_at": "2026-09-20T00:00:00Z",
              "files": [{"filename": "pkgs/by-name/wg/wget/package.nix", "status": "modified",
                         "patch": '-  version = "1.25.0";\n+  version = "1.26.0";\n'}]}
    kw = dict(
        fork_prs=[{"number": 45, "headRefName": "trace/CVE-2026-16599--wget--0599d03cf7b75fd2"}],
        bundles_root=tmp_path / "traces" / "example",
        find_merged_nixpkgs_pr=lambda cve: 4242,
        cve_in_tree=lambda cve: True,
        fetch_change=lambda number: change,
        fetch_file=lambda pr, path: "",
        comment=lambda pr, body: comments.append((pr, body)),
    )
    assert watch(**kw) == {"CVE-2026-16599": "landed"}
    assert len(comments) == 1 and comments[0][0] == 45
    assert "upstream-bumped" in comments[0][1] or "1.26.0" in comments[0][1]
    assert watch(**kw) == {"CVE-2026-16599": "landed"}
    assert len(comments) == 1


def test_report_groups_by_state_and_shape(tmp_path):
    b = _bundle(tmp_path)
    (b / "comparison.json").write_text(json.dumps({"shape": "patch-file", "scores": {"added_recall": 1.0, "exact": True}}))
    other = _bundle(tmp_path, "CVE-2026-78136--chirp-kenwood-eval-backport")
    table = report(tmp_path / "traces" / "example")
    assert table["waiting"] == 1
    assert table["landed"]["patch-file"] == 1
    assert table["exact_matches"] == 1


def test_multiple_patch_files_are_scored_individually_and_the_best_is_kept(tmp_path):
    """nixpkgs#412367 added four jq patches for four CVEs. Scoring our one-CVE
    payload against their union gave recall 0 and said nothing."""
    b = _bundle(tmp_path)
    change = {"number": 412367, "merged_at": "2025-05-30T16:58:38Z",
              "files": [{"filename": "pkgs/by-name/jq/jq/0001-other.patch", "status": "added", "patch": ""},
                        {"filename": "pkgs/by-name/jq/jq/0002-ours.patch", "status": "added", "patch": ""}]}
    texts = {
        "pkgs/by-name/jq/jq/0001-other.patch": "--- a/x\n+++ b/x\n-unrelated old\n+unrelated new\n",
        "pkgs/by-name/jq/jq/0002-ours.patch": ("--- a/src/ftp-basic.c\n+++ b/src/ftp-basic.c\n"
            "-          skey_sequence = 10 * skey_sequence + *seed - '0';\n"
            "+          if (skey_sequence > 9999) return FTPLOGREFUSED;\n"),
    }
    result = compare_bundle(b, change, fetch_file=lambda pr, path: texts[path])
    assert result["matched_patch_file"] == "pkgs/by-name/jq/jq/0002-ours.patch"
    assert result["scores"]["exact"] is True
    assert result["patch_files_in_pr"] == 2


def test_payload_recall_credits_a_minimal_patch_contained_in_a_larger_one(tmp_path):
    """nixpkgs's CVE-2024-12254.patch carried the upstream test and NEWS lines;
    ours carried the one code line. Recall of upstream lines calls that 9%. The
    reverse direction, how much of ours is in theirs, is the question that
    tells us whether we fixed the same thing."""
    b = _bundle(tmp_path)
    theirs = ("--- a/src/ftp-basic.c\n+++ b/src/ftp-basic.c\n"
              "-          skey_sequence = 10 * skey_sequence + *seed - '0';\n"
              "+          if (skey_sequence > 9999) return FTPLOGREFUSED;\n"
              "+# NEWS: fixed the OPIE loop\n+# test: added test_opie_bound\n")
    change = {"number": 1, "merged_at": "2026-01-01T00:00:00Z",
              "files": [{"filename": "pkgs/by-name/wg/wget/CVE-2026-16599.patch", "status": "added", "patch": ""}]}
    result = compare_bundle(b, change, fetch_file=lambda pr, path: theirs)
    assert result["scores"]["added_recall"] < 0.5
    assert result["scores"]["payload_added_recall"] == 1.0
    assert result["scores"]["payload_removed_recall"] == 1.0


def test_a_failed_nixpkgs_lookup_is_check_failed_not_waiting(tmp_path):
    """The dry run lost thirteen comparisons to transient gh failures that were
    recorded as waiting. A lookup that could not run is not evidence of waiting."""
    _bundle(tmp_path)

    def boom(cve):
        raise RuntimeError("gh: API rate limit exceeded")
    states = watch(
        fork_prs=[{"number": 45, "headRefName": "trace/CVE-2026-16599--wget--0599d03cf7b75fd2"}],
        bundles_root=tmp_path / "traces" / "example",
        find_merged_nixpkgs_pr=boom, cve_in_tree=lambda cve: False,
        fetch_change=lambda n: None, fetch_file=lambda pr, p: "", comment=lambda pr, b: None,
    )
    assert states == {"CVE-2026-16599": "check-failed"}


def test_report_counts_only_source_backport_bundles(tmp_path):
    """Version-bump bundles and synthetic fixtures are not live-lane work and
    must not inflate the waiting count."""
    b = _bundle(tmp_path)
    (b / "upstream-ref.json").write_text(json.dumps({"eligibility": {"patch_strategy": "source-backport"},
                                                    "upstream_fix_commits": [{"repo_url": "r", "commit_sha": SHA}]}))
    bump = _bundle(tmp_path, "CVE-2025-0001--bump")
    (bump / "upstream-ref.json").write_text(json.dumps({"eligibility": {"patch_strategy": "version-bump"}}))
    synth = _bundle(tmp_path, "CVE-0000-9002--fixture")
    (synth / "upstream-ref.json").write_text(json.dumps({"eligibility": {"patch_strategy": "source-backport"}}))
    table = report(tmp_path / "traces" / "example")
    assert table["waiting"] == 1


def test_a_failed_file_fetch_leaves_no_comparison_and_is_check_failed(tmp_path):
    """gh_fetch_file used to return an empty string on any failure, which
    compare_bundle recorded as a landed comparison with nothing to score, and the
    existence of comparison.json then blocked every later retry."""
    b = _bundle(tmp_path)
    comments = []
    change = {"number": 4242, "merged_at": "2026-09-20T00:00:00Z",
              "files": [{"filename": "pkgs/by-name/wg/wget/CVE-2026-16599.patch", "status": "added", "patch": ""}]}

    def failing_fetch(pr, path):
        raise RuntimeError("gh api: 503")
    states = watch(
        fork_prs=[{"number": 45, "headRefName": "trace/CVE-2026-16599--wget--0599d03cf7b75fd2"}],
        bundles_root=tmp_path / "traces" / "example",
        find_merged_nixpkgs_pr=lambda cve: 4242, cve_in_tree=lambda cve: True,
        fetch_change=lambda n: change, fetch_file=failing_fetch,
        comment=lambda pr, body: comments.append(body),
    )
    assert states == {"CVE-2026-16599": "check-failed"}
    assert not (b / "comparison.json").exists()
    assert comments == []


def test_cve_in_tree_failure_is_check_failed_not_waiting(tmp_path):
    _bundle(tmp_path)

    def boom(cve):
        raise RuntimeError("code search unavailable")
    states = watch(
        fork_prs=[{"number": 45, "headRefName": "trace/CVE-2026-16599--wget--0599d03cf7b75fd2"}],
        bundles_root=tmp_path / "traces" / "example",
        find_merged_nixpkgs_pr=lambda cve: None, cve_in_tree=boom,
        fetch_change=lambda n: None, fetch_file=lambda pr, p: "", comment=lambda pr, b: None,
    )
    assert states == {"CVE-2026-16599": "check-failed"}


def test_check_failed_reports_the_reason(tmp_path, capsys):
    _bundle(tmp_path)

    def boom(cve):
        raise RuntimeError("gh: HTTP 403 resource not accessible by integration")
    watch(
        fork_prs=[{"number": 45, "headRefName": "trace/CVE-2026-16599--wget--0599d03cf7b75fd2"}],
        bundles_root=tmp_path / "traces" / "example",
        find_merged_nixpkgs_pr=boom, cve_in_tree=lambda cve: False,
        fetch_change=lambda n: None, fetch_file=lambda pr, p: "", comment=lambda pr, b: None,
    )
    assert "resource not accessible" in capsys.readouterr().out


def test_code_search_failure_is_advisory_when_the_pr_search_worked(tmp_path, capsys):
    """GitHub's code search is not available to the default Actions token. A PR
    search that ran and found nothing is still a real answer, so the CVE stays
    waiting and the tree check is reported as skipped rather than failing it."""
    _bundle(tmp_path)

    def no_code_search(cve):
        raise RuntimeError("code search requires a user token")
    states = watch(
        fork_prs=[{"number": 45, "headRefName": "trace/CVE-2026-16599--wget--0599d03cf7b75fd2"}],
        bundles_root=tmp_path / "traces" / "example",
        find_merged_nixpkgs_pr=lambda cve: None, cve_in_tree=no_code_search,
        fetch_change=lambda n: None, fetch_file=lambda pr, p: "", comment=lambda pr, b: None,
    )
    assert states == {"CVE-2026-16599": "waiting"}
    assert "tree check skipped" in capsys.readouterr().out
