"""`trace compare watch`: notice when nixpkgs lands a fix for a live-lane bundle
and score ours against it. See docs/specs/upstream-comparison-watcher.md.

Every network call is injected. The suite makes none.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from tools.trace_cli.compare_watch import (
    change_touches_package,
    classify_change,
    compare_bundle,
    find_landed_in_tree,
    package_files,
    parse_fork_branch,
    report,
    watch,
)

SHA = "e9697d98e7249b0f68a6be040a4f3dcc5bc101fa"
BK = "CVE-2026-16599--wget-ftp-opie-backport"


def _bundle(
    tmp_path: Path, name: str = "CVE-2026-16599--wget-ftp-opie-backport"
) -> Path:
    b = tmp_path / "traces" / "example" / name
    b.mkdir(parents=True)
    (b / "bundle.json").write_text(
        json.dumps(
            {
                "bundle_id": "0599d03cf7b75fd2",
                "cve_id": "CVE-2026-16599",
                "nixpkgs_rev": "c" * 40,
            }
        )
    )
    (b / "finding.json").write_text(
        json.dumps(
            {
                "cve_id": "CVE-2026-16599",
                "affected": [{"attr_path": "wget", "version": "1.25.0"}],
            }
        )
    )
    (b / "upstream-ref.json").write_text(
        json.dumps(
            {
                "eligibility": {"patch_strategy": "source-backport"},
                "upstream_fix_commits": [
                    {"repo_url": "https://gitlab.com/gnuwget/wget", "commit_sha": SHA}
                ],
            }
        )
    )
    (b / "patch.diff").write_text(
        "diff --git a/CVE-2026-16599.patch b/CVE-2026-16599.patch\n--- /dev/null\n+++ b/CVE-2026-16599.patch\n"
        "@@ -0,0 +1,4 @@\n+--- a/src/ftp-basic.c\n++++ b/src/ftp-basic.c\n+-          skey_sequence = 10 * skey_sequence + *seed - '0';\n"
        "++          if (skey_sequence > 9999) return FTPLOGREFUSED;\n"
        "diff --git a/package.nix b/package.nix\n--- a/package.nix\n+++ b/package.nix\n@@ -1 +1,2 @@\n+    ./CVE-2026-16599.patch\n"
    )
    return b


def test_parse_fork_branch():
    assert parse_fork_branch("trace/CVE-2026-16599--wget--0599d03cf7b75fd2") == (
        "CVE-2026-16599",
        "wget",
        "0599d03cf7b75fd2",
    )
    assert parse_fork_branch(
        "trace/CVE-2021-28918--perlPackages.NetCIDRLite--ad030e70e8cdb2b5"
    ) == ("CVE-2021-28918", "perlPackages.NetCIDRLite", "ad030e70e8cdb2b5")
    assert parse_fork_branch("main") is None


def test_classify_a_patch_file_added_under_the_package():
    files = [
        {
            "filename": "pkgs/by-name/wg/wget/CVE-2026-16599.patch",
            "status": "added",
            "patch": "@@ -0,0 +1,2 @@\n+-          skey_sequence = 10 * skey_sequence + *seed - '0';\n"
            "++          if (skey_sequence > 9999) return FTPLOGREFUSED;\n",
        },
        {
            "filename": "pkgs/by-name/wg/wget/package.nix",
            "status": "modified",
            "patch": "+ ./CVE-2026-16599.patch",
        },
    ]
    shape = classify_change(files, fix_shas=[SHA], current_version="1.25.0")
    assert shape["shape"] == "patch-file"
    assert shape["patch_files"] == ["pkgs/by-name/wg/wget/CVE-2026-16599.patch"]


def test_classify_a_fetchpatch_of_the_same_commit():
    files = [
        {
            "filename": "pkgs/by-name/wg/wget/package.nix",
            "status": "modified",
            "patch": f'+    (fetchpatch {{\n+      url = "https://gitlab.com/gnuwget/wget/-/commit/{SHA}.patch";\n',
        }
    ]
    shape = classify_change(files, fix_shas=[SHA], current_version="1.25.0")
    assert shape["shape"] == "same-fix-commit"


def test_classify_a_version_bump():
    files = [
        {
            "filename": "pkgs/by-name/wg/wget/package.nix",
            "status": "modified",
            "patch": '-  version = "1.25.0";\n+  version = "1.26.0";\n',
        }
    ]
    shape = classify_change(files, fix_shas=[SHA], current_version="1.25.0")
    assert shape["shape"] == "upstream-bumped"
    assert shape["fixed_version"] == "1.26.0"


def test_compare_scores_a_patch_file_with_the_existing_grader(tmp_path):
    b = _bundle(tmp_path)
    change = {
        "number": 4242,
        "merged_at": "2026-09-20T00:00:00Z",
        "files": [
            {
                "filename": "pkgs/by-name/wg/wget/CVE-2026-16599.patch",
                "status": "added",
                "patch": "@@ -0,0 +1,2 @@\n+-          skey_sequence = 10 * skey_sequence + *seed - '0';\n"
                "++          if (skey_sequence > 9999) return FTPLOGREFUSED;\n",
            }
        ],
    }
    result = compare_bundle(
        b,
        change,
        fetch_file=lambda pr, path: (
            "--- a/src/ftp-basic.c\n+++ b/src/ftp-basic.c\n"
            "-          skey_sequence = 10 * skey_sequence + *seed - '0';\n"
            "+          if (skey_sequence > 9999) return FTPLOGREFUSED;\n"
        ),
    )
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
        fork_prs=[
            {
                "number": 45,
                "headRefName": "trace/CVE-2026-16599--wget--0599d03cf7b75fd2",
            }
        ],
        bundles_root=tmp_path / "traces" / "example",
        find_merged_nixpkgs_pr=lambda cve: None,
        find_landed_in_tree=lambda cve, b: None,
        fetch_change=lambda number: None,
        fetch_file=lambda pr, path: "",
        comment=lambda pr, body: comments.append((pr, body)),
    )
    assert states == {BK: "waiting"}
    assert comments == []
    assert not (b / "comparison.json").exists()


def test_watch_compares_once_and_comments_once(tmp_path):
    b = _bundle(tmp_path)
    comments = []
    change = {
        "number": 4242,
        "merged_at": "2026-09-20T00:00:00Z",
        "files": [
            {
                "filename": "pkgs/by-name/wg/wget/package.nix",
                "status": "modified",
                "patch": '-  version = "1.25.0";\n+  version = "1.26.0";\n',
            }
        ],
    }
    kw = dict(
        fork_prs=[
            {
                "number": 45,
                "headRefName": "trace/CVE-2026-16599--wget--0599d03cf7b75fd2",
            }
        ],
        bundles_root=tmp_path / "traces" / "example",
        find_merged_nixpkgs_pr=lambda cve: 4242,
        find_landed_in_tree=lambda cve, b: None,
        fetch_change=lambda number: change,
        fetch_file=lambda pr, path: "",
        comment=lambda pr, body: comments.append((pr, body)),
        post=True,  # the operator approved posting for this run
    )
    assert watch(**kw) == {BK: "landed"}
    assert len(comments) == 1 and comments[0][0] == 45
    assert "upstream-bumped" in comments[0][1] or "1.26.0" in comments[0][1]
    assert watch(**kw) == {BK: "landed"}
    assert len(comments) == 1


def test_report_groups_by_state_and_shape(tmp_path):
    b = _bundle(tmp_path)
    (b / "comparison.json").write_text(
        json.dumps(
            {"shape": "patch-file", "scores": {"added_recall": 1.0, "exact": True}}
        )
    )
    other = _bundle(tmp_path, "CVE-2026-78136--chirp-kenwood-eval-backport")
    table = report(tmp_path / "traces" / "example")
    assert table["waiting"] == 1
    assert table["landed"]["patch-file"] == 1
    assert table["exact_matches"] == 1


def test_multiple_patch_files_are_scored_individually_and_the_best_is_kept(tmp_path):
    """nixpkgs#412367 added four jq patches for four CVEs. Scoring our one-CVE
    payload against their union gave recall 0 and said nothing."""
    b = _bundle(tmp_path)
    change = {
        "number": 412367,
        "merged_at": "2025-05-30T16:58:38Z",
        "files": [
            {
                "filename": "pkgs/by-name/jq/jq/0001-other.patch",
                "status": "added",
                "patch": "",
            },
            {
                "filename": "pkgs/by-name/jq/jq/0002-ours.patch",
                "status": "added",
                "patch": "",
            },
        ],
    }
    texts = {
        "pkgs/by-name/jq/jq/0001-other.patch": "--- a/x\n+++ b/x\n-unrelated old\n+unrelated new\n",
        "pkgs/by-name/jq/jq/0002-ours.patch": (
            "--- a/src/ftp-basic.c\n+++ b/src/ftp-basic.c\n"
            "-          skey_sequence = 10 * skey_sequence + *seed - '0';\n"
            "+          if (skey_sequence > 9999) return FTPLOGREFUSED;\n"
        ),
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
    theirs = (
        "--- a/src/ftp-basic.c\n+++ b/src/ftp-basic.c\n"
        "-          skey_sequence = 10 * skey_sequence + *seed - '0';\n"
        "+          if (skey_sequence > 9999) return FTPLOGREFUSED;\n"
        "+# NEWS: fixed the OPIE loop\n+# test: added test_opie_bound\n"
    )
    change = {
        "number": 1,
        "merged_at": "2026-01-01T00:00:00Z",
        "files": [
            {
                "filename": "pkgs/by-name/wg/wget/CVE-2026-16599.patch",
                "status": "added",
                "patch": "",
            }
        ],
    }
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
        fork_prs=[
            {
                "number": 45,
                "headRefName": "trace/CVE-2026-16599--wget--0599d03cf7b75fd2",
            }
        ],
        bundles_root=tmp_path / "traces" / "example",
        find_merged_nixpkgs_pr=boom,
        find_landed_in_tree=lambda cve, b: None,
        fetch_change=lambda n: None,
        fetch_file=lambda pr, p: "",
        comment=lambda pr, b: None,
    )
    assert states == {BK: "check-failed"}


def test_report_counts_only_source_backport_bundles(tmp_path):
    """Version-bump bundles and synthetic fixtures are not live-lane work and
    must not inflate the waiting count."""
    b = _bundle(tmp_path)
    (b / "upstream-ref.json").write_text(
        json.dumps(
            {
                "eligibility": {"patch_strategy": "source-backport"},
                "upstream_fix_commits": [{"repo_url": "r", "commit_sha": SHA}],
            }
        )
    )
    bump = _bundle(tmp_path, "CVE-2025-0001--bump")
    (bump / "upstream-ref.json").write_text(
        json.dumps({"eligibility": {"patch_strategy": "version-bump"}})
    )
    synth = _bundle(tmp_path, "CVE-0000-9002--fixture")
    (synth / "upstream-ref.json").write_text(
        json.dumps({"eligibility": {"patch_strategy": "source-backport"}})
    )
    table = report(tmp_path / "traces" / "example")
    assert table["waiting"] == 1


def test_a_failed_file_fetch_leaves_no_comparison_and_is_check_failed(tmp_path):
    """gh_fetch_file used to return an empty string on any failure, which
    compare_bundle recorded as a landed comparison with nothing to score, and the
    existence of comparison.json then blocked every later retry."""
    b = _bundle(tmp_path)
    comments = []
    change = {
        "number": 4242,
        "merged_at": "2026-09-20T00:00:00Z",
        "files": [
            {
                "filename": "pkgs/by-name/wg/wget/CVE-2026-16599.patch",
                "status": "added",
                "patch": "",
            }
        ],
    }

    def failing_fetch(pr, path):
        raise RuntimeError("gh api: 503")

    states = watch(
        fork_prs=[
            {
                "number": 45,
                "headRefName": "trace/CVE-2026-16599--wget--0599d03cf7b75fd2",
            }
        ],
        bundles_root=tmp_path / "traces" / "example",
        find_merged_nixpkgs_pr=lambda cve: 4242,
        find_landed_in_tree=lambda cve, b: None,
        fetch_change=lambda n: change,
        fetch_file=failing_fetch,
        comment=lambda pr, body: comments.append(body),
    )
    assert states == {BK: "check-failed"}
    assert not (b / "comparison.json").exists()
    assert comments == []


def test_tree_check_failure_alone_does_not_fail_the_check(tmp_path):
    """Superseded expectation: an earlier version treated a code-search failure as
    check-failed. The default Actions token cannot run code search at all, so that
    made every CVE check-failed in CI. A PR search that ran is the real answer."""
    _bundle(tmp_path)

    def boom(cve, bundle_dir):
        raise RuntimeError("code search unavailable")

    states = watch(
        fork_prs=[
            {
                "number": 45,
                "headRefName": "trace/CVE-2026-16599--wget--0599d03cf7b75fd2",
            }
        ],
        bundles_root=tmp_path / "traces" / "example",
        find_merged_nixpkgs_pr=lambda cve: None,
        find_landed_in_tree=boom,
        fetch_change=lambda n: None,
        fetch_file=lambda pr, p: "",
        comment=lambda pr, b: None,
    )
    assert states == {BK: "waiting"}


def test_check_failed_reports_the_reason(tmp_path, capsys):
    _bundle(tmp_path)

    def boom(cve):
        raise RuntimeError("gh: HTTP 403 resource not accessible by integration")

    watch(
        fork_prs=[
            {
                "number": 45,
                "headRefName": "trace/CVE-2026-16599--wget--0599d03cf7b75fd2",
            }
        ],
        bundles_root=tmp_path / "traces" / "example",
        find_merged_nixpkgs_pr=boom,
        find_landed_in_tree=lambda cve, b: None,
        fetch_change=lambda n: None,
        fetch_file=lambda pr, p: "",
        comment=lambda pr, b: None,
    )
    assert "resource not accessible" in capsys.readouterr().out


def test_code_search_failure_is_advisory_when_the_pr_search_worked(tmp_path, capsys):
    """GitHub's code search is not available to the default Actions token. A PR
    search that ran and found nothing is still a real answer, so the CVE stays
    waiting and the tree check is reported as skipped rather than failing it."""
    _bundle(tmp_path)

    def no_code_search(cve, bundle_dir):
        raise RuntimeError("code search requires a user token")

    states = watch(
        fork_prs=[
            {
                "number": 45,
                "headRefName": "trace/CVE-2026-16599--wget--0599d03cf7b75fd2",
            }
        ],
        bundles_root=tmp_path / "traces" / "example",
        find_merged_nixpkgs_pr=lambda cve: None,
        find_landed_in_tree=no_code_search,
        fetch_change=lambda n: None,
        fetch_file=lambda pr, p: "",
        comment=lambda pr, b: None,
    )
    assert states == {BK: "waiting"}
    assert "tree check skipped" in capsys.readouterr().out


def test_a_landed_comparison_is_drafted_not_posted_without_approval(tmp_path):
    """The standard forbids posting anywhere public without the operator's
    explicit approval. The default writes the comment beside the bundle for
    review; posting is a separate, deliberate step."""
    b = _bundle(tmp_path)
    posted = []
    change = {
        "number": 4242,
        "merged_at": "2026-09-20T00:00:00Z",
        "files": [
            {
                "filename": "pkgs/by-name/wg/wget/package.nix",
                "status": "modified",
                "patch": '-  version = "1.25.0";\n+  version = "1.26.0";\n',
            }
        ],
    }
    states = watch(
        fork_prs=[
            {
                "number": 45,
                "headRefName": "trace/CVE-2026-16599--wget--0599d03cf7b75fd2",
            }
        ],
        bundles_root=tmp_path / "traces" / "example",
        find_merged_nixpkgs_pr=lambda cve: 4242,
        find_landed_in_tree=lambda cve, b: None,
        fetch_change=lambda n: change,
        fetch_file=lambda pr, p: "",
        comment=lambda pr, body: posted.append((pr, body)),
        post=False,
    )
    assert states == {BK: "landed"}
    assert posted == []
    draft = (b / "comparison-comment.md").read_text()
    assert "1.26.0" in draft and "#45" in draft


def test_tree_check_lands_a_cve_the_pr_search_missed(tmp_path):
    """A nixpkgs PR titled without the CVE id is invisible to the PR search. The
    tree check finds the CVE in the package directory and names the landing PR."""
    b = _bundle(tmp_path)
    fetched = []

    def fetch_change(number):
        fetched.append(number)
        return {
            "number": number,
            "merged_at": "2026-09-08T00:00:00Z",
            "files": [
                {
                    "filename": "pkgs/by-name/wg/wget/CVE-2026-16599.patch",
                    "status": "added",
                    "patch": "",
                }
            ],
        }

    states = watch(
        fork_prs=[
            {
                "number": 45,
                "headRefName": "trace/CVE-2026-16599--wget--0599d03cf7b75fd2",
            }
        ],
        bundles_root=tmp_path / "traces" / "example",
        find_merged_nixpkgs_pr=lambda cve: None,
        find_landed_in_tree=lambda cve, bd: 4343,
        fetch_change=fetch_change,
        fetch_file=lambda pr, p: "",
        comment=lambda pr, body: None,
    )
    assert states == {BK: "landed"}
    assert fetched == [4343]
    assert json.loads((b / "comparison.json").read_text())["nixpkgs_pr"] == 4343


def test_package_files_come_from_the_cert_record_then_the_by_name_attr(tmp_path):
    b = _bundle(tmp_path)
    (b / "resolver-input.json").write_text(json.dumps({"attr_path": "wget"}))
    assert package_files(b) == ["pkgs/by-name/wg/wget/package.nix"]
    (b / "build.json").write_text(
        json.dumps(
            {
                "patch_apply": {
                    "files_changed": [
                        "pkgs/tools/networking/wget/CVE-2026-16599.patch",
                        "pkgs/tools/networking/wget/default.nix",
                    ]
                }
            }
        )
    )
    assert package_files(b) == [
        "pkgs/tools/networking/wget/CVE-2026-16599.patch",
        "pkgs/tools/networking/wget/default.nix",
    ]


def test_find_landed_in_tree_walks_listing_file_and_commit_to_a_pr(tmp_path):
    """Contents API only: list the package directory, read the .nix file the bundle
    touched, find the commit naming the CVE, take its merged pull request."""
    b = _bundle(tmp_path)
    (b / "build.json").write_text(
        json.dumps(
            {
                "patch_apply": {
                    "files_changed": [
                        "pkgs/by-name/wg/wget/CVE-2026-16599.patch",
                        "pkgs/by-name/wg/wget/package.nix",
                    ]
                }
            }
        )
    )
    calls = []

    def gh(path):
        calls.append(path)
        if path == "repos/NixOS/nixpkgs/contents/pkgs/by-name/wg/wget?ref=master":
            return [{"name": "package.nix"}, {"name": "fix-ftp-opie.patch"}]
        if path.startswith("repos/NixOS/nixpkgs/commits?path=pkgs/by-name/wg/wget"):
            return [
                {"sha": "a" * 40, "commit": {"message": "wget: 1.25.0 -> 1.25.1"}},
                {
                    "sha": "b" * 40,
                    "commit": {"message": "wget: patch CVE-2026-16599\n\nbackport"},
                },
            ]
        if path == f"repos/NixOS/nixpkgs/commits/{'b' * 40}/pulls":
            return [{"number": 4343, "merged_at": "2026-09-08T00:00:00Z"}]
        raise AssertionError(path)

    def raw(path):
        assert (
            path
            == "repos/NixOS/nixpkgs/contents/pkgs/by-name/wg/wget/package.nix?ref=master"
        )
        return "  patches = [ ./fix-ftp-opie.patch ]; # CVE-2026-16599\n"

    assert find_landed_in_tree("CVE-2026-16599", b, gh_json=gh, gh_raw=raw) == 4343
    assert not any("search/code" in c for c in calls)


def test_find_landed_in_tree_is_none_when_the_package_does_not_mention_the_cve(
    tmp_path,
):
    b = _bundle(tmp_path)
    (b / "build.json").write_text(
        json.dumps(
            {"patch_apply": {"files_changed": ["pkgs/by-name/wg/wget/package.nix"]}}
        )
    )
    gh = lambda path: [{"name": "package.nix"}]
    raw = lambda path: '  version = "1.25.0";\n'
    assert find_landed_in_tree("CVE-2026-16599", b, gh_json=gh, gh_raw=raw) is None


def test_find_landed_in_tree_hit_without_a_naming_commit_stays_none(tmp_path, capsys):
    b = _bundle(tmp_path)
    (b / "build.json").write_text(
        json.dumps(
            {"patch_apply": {"files_changed": ["pkgs/by-name/wg/wget/package.nix"]}}
        )
    )

    def gh(path):
        if "contents" in path:
            return [{"name": "package.nix"}, {"name": "CVE-2026-16599.patch"}]
        return [{"sha": "a" * 40, "commit": {"message": "wget: add patch"}}]

    assert (
        find_landed_in_tree("CVE-2026-16599", b, gh_json=gh, gh_raw=lambda p: "")
        is None
    )
    assert "no commit names it" in capsys.readouterr().out


def test_package_files_drop_paths_that_could_rewrite_the_api_url(tmp_path):
    b = _bundle(tmp_path)
    (b / "build.json").write_text(
        json.dumps(
            {
                "patch_apply": {
                    "files_changed": [
                        "pkgs/by-name/wg/wget/package.nix",
                        "pkgs/../../repos/evil?ref=x",
                        "pkgs/by-name/wg/wget/a b.nix",
                    ]
                }
            }
        )
    )
    assert package_files(b) == ["pkgs/by-name/wg/wget/package.nix"]


def test_find_landed_in_tree_treats_a_moved_package_directory_as_absent(tmp_path):
    """putty's cert recorded pkgs/applications/networking/remote/putty; master no
    longer has that directory. A 404 on the listing is an answer, not a failure."""
    b = _bundle(tmp_path)
    (b / "build.json").write_text(
        json.dumps(
            {
                "patch_apply": {
                    "files_changed": [
                        "pkgs/applications/networking/remote/putty/default.nix"
                    ]
                }
            }
        )
    )

    def gh(path):
        raise RuntimeError("gh: Not Found (HTTP 404)")

    assert (
        find_landed_in_tree("CVE-2026-48850", b, gh_json=gh, gh_raw=lambda p: "")
        is None
    )


def test_a_bundle_without_a_fork_pr_is_still_compared(tmp_path):
    """Most live-lane bundles have no PR. Grading them locally needs no approval."""
    b = _bundle(tmp_path)
    comments = []
    change = {
        "number": 4242,
        "merged_at": "2026-09-20T00:00:00Z",
        "files": [
            {
                "filename": "pkgs/by-name/wg/wget/package.nix",
                "status": "modified",
                "patch": '-  version = "1.25.0";\n+  version = "1.26.0";\n',
            }
        ],
    }
    states = watch(
        fork_prs=[],
        bundles_root=tmp_path / "traces" / "example",
        find_merged_nixpkgs_pr=lambda cve: 4242,
        find_landed_in_tree=lambda cve, d: None,
        fetch_change=lambda number: change,
        fetch_file=lambda pr, path: "",
        comment=lambda pr, body: comments.append((pr, body)),
        post=True,
    )
    assert states == {BK: "landed"}
    assert json.loads((b / "comparison.json").read_text())["shape"] == "upstream-bumped"
    assert comments == []
    assert not (b / "comparison-comment.md").exists()


def test_a_bundle_without_a_fork_pr_can_be_waiting(tmp_path):
    b = _bundle(tmp_path)
    states = watch(
        fork_prs=[],
        bundles_root=tmp_path / "traces" / "example",
        find_merged_nixpkgs_pr=lambda cve: None,
        find_landed_in_tree=lambda cve, d: None,
        fetch_change=lambda number: None,
        fetch_file=lambda pr, path: "",
        comment=lambda pr, body: None,
    )
    assert states == {BK: "waiting"}
    assert not (b / "comparison.json").exists()


def test_a_fork_pr_without_its_bundle_is_still_no_bundle(tmp_path):
    root = tmp_path / "traces" / "example"
    root.mkdir(parents=True)
    states = watch(
        fork_prs=[
            {
                "number": 45,
                "headRefName": "trace/CVE-2026-16599--wget--0599d03cf7b75fd2",
            }
        ],
        bundles_root=root,
        find_merged_nixpkgs_pr=lambda cve: None,
        find_landed_in_tree=lambda cve, d: None,
        fetch_change=lambda number: None,
        fetch_file=lambda pr, path: "",
        comment=lambda pr, body: None,
    )
    assert states == {"CVE-2026-16599": "no-bundle"}


def test_a_bundle_is_compared_once_even_with_a_pr_pointing_at_it(tmp_path):
    """The PR-derived target and the bundle walk name the same directory."""
    b = _bundle(tmp_path)
    seen = []
    watch(
        fork_prs=[
            {
                "number": 45,
                "headRefName": "trace/CVE-2026-16599--wget--0599d03cf7b75fd2",
            }
        ],
        bundles_root=tmp_path / "traces" / "example",
        find_merged_nixpkgs_pr=lambda cve: seen.append(cve) or None,
        find_landed_in_tree=lambda cve, d: None,
        fetch_change=lambda number: None,
        fetch_file=lambda pr, path: "",
        comment=lambda pr, body: None,
    )
    assert seen == ["CVE-2026-16599"]


def test_two_bundles_for_one_cve_keep_their_own_verdicts(tmp_path):
    """A sibling's verdict must not overwrite the one before it, or the exit code lies."""
    a = _bundle(tmp_path)
    b = _bundle(tmp_path, "CVE-2026-16599--wget-ftp-opie-second")
    (a / "comparison.json").write_text(json.dumps({"shape": "upstream-bumped"}))
    states = watch(
        fork_prs=[],
        bundles_root=tmp_path / "traces" / "example",
        find_merged_nixpkgs_pr=lambda cve: (_ for _ in ()).throw(
            RuntimeError("rate limited")
        ),
        find_landed_in_tree=lambda cve, d: None,
        fetch_change=lambda number: None,
        fetch_file=lambda pr, path: "",
        comment=lambda pr, body: None,
    )
    assert states == {a.name: "landed", b.name: "check-failed"}


def test_one_search_serves_every_bundle_for_a_cve(tmp_path):
    """The search API's budget is small; two bundles ask nixpkgs the same question."""
    _bundle(tmp_path)
    _bundle(tmp_path, "CVE-2026-16599--wget-ftp-opie-second")
    asked = []
    states = watch(
        fork_prs=[],
        bundles_root=tmp_path / "traces" / "example",
        find_merged_nixpkgs_pr=lambda cve: asked.append(cve) or None,
        find_landed_in_tree=lambda cve, d: None,
        fetch_change=lambda number: None,
        fetch_file=lambda pr, path: "",
        comment=lambda pr, body: None,
    )
    assert asked == ["CVE-2026-16599"]
    assert set(states.values()) == {"waiting"}


def test_the_search_throttle_spaces_requests_out():
    from tools.trace_cli import compare_watch as cw

    clock = [100.0]
    slept = []

    def pause(seconds):
        slept.append(seconds)
        clock[0] += seconds

    cw._last_search = 0.0
    cw._search_throttle(now=lambda: clock[0], pause=pause)
    assert slept == []  # the first request in a long while waits for nothing
    clock[0] += 0.2
    cw._search_throttle(now=lambda: clock[0], pause=pause)
    assert slept and abs(slept[0] - (cw._SEARCH_INTERVAL - 0.2)) < 1e-9
    cw._last_search = 0.0


def _wget_change(filename="pkgs/by-name/wg/wget/package.nix"):
    return {
        "number": 4242,
        "merged_at": "2026-09-20T00:00:00Z",
        "files": [
            {
                "filename": filename,
                "status": "modified",
                "patch": '-  version = "1.25.0";\n+  version = "1.26.0";\n',
            }
        ],
    }


def test_a_pr_that_touches_another_package_is_not_a_landing(tmp_path):
    """The search matches the CVE id anywhere, a comment on an unrelated PR included."""
    b = _bundle(tmp_path)
    (b / "resolver-input.json").write_text(json.dumps({"attr_path": "wget"}))
    states = watch(
        fork_prs=[],
        bundles_root=tmp_path / "traces" / "example",
        find_merged_nixpkgs_pr=lambda cve: 4242,
        find_landed_in_tree=lambda cve, d: None,
        fetch_change=lambda number: _wget_change(
            "pkgs/applications/misc/golden-cheetah-bin/default.nix"
        ),
        fetch_file=lambda pr, path: "",
        comment=lambda pr, body: None,
    )
    assert states == {BK: "waiting"}
    assert not (b / "comparison.json").exists()


def test_a_pr_that_touches_the_package_directory_lands(tmp_path):
    b = _bundle(tmp_path)
    (b / "resolver-input.json").write_text(json.dumps({"attr_path": "wget"}))
    states = watch(
        fork_prs=[],
        bundles_root=tmp_path / "traces" / "example",
        find_merged_nixpkgs_pr=lambda cve: 4242,
        find_landed_in_tree=lambda cve, d: None,
        fetch_change=lambda number: _wget_change(
            "pkgs/by-name/wg/wget/CVE-2026-16599.patch"
        ),
        fetch_file=lambda pr, path: "",
        comment=lambda pr, body: None,
    )
    assert states == {BK: "landed"}
    assert (b / "comparison.json").is_file()


def test_relevance_is_unknown_when_the_bundle_names_no_package(tmp_path):
    """Without a cert record or an attr there is nothing to match, so the
    comparison runs as it did before rather than refusing on a guess."""
    b = _bundle(tmp_path)
    assert (
        change_touches_package(_wget_change("pkgs/by-name/zz/zzz/package.nix"), b)
        is None
    )
    states = watch(
        fork_prs=[],
        bundles_root=tmp_path / "traces" / "example",
        find_merged_nixpkgs_pr=lambda cve: 4242,
        find_landed_in_tree=lambda cve, d: None,
        fetch_change=lambda number: _wget_change("pkgs/by-name/zz/zzz/package.nix"),
        fetch_file=lambda pr, path: "",
        comment=lambda pr, body: None,
    )
    assert states == {BK: "landed"}


def test_a_registry_attr_matches_the_registry_file(tmp_path):
    """perlPackages lives in one file; the attr's own name never appears in a path."""
    b = _bundle(tmp_path)
    (b / "resolver-input.json").write_text(
        json.dumps({"attr_path": "perlPackages.BytesRandomSecure"})
    )
    assert (
        change_touches_package(_wget_change("pkgs/top-level/perl-packages.nix"), b)
        is True
    )


def test_a_package_that_moved_directory_still_matches(tmp_path):
    """A bundle records the paths of its own pinned revision; nixpkgs moves them."""
    b = _bundle(tmp_path)
    (b / "build.json").write_text(
        json.dumps(
            {"patch_apply": {"files_changed": ["pkgs/by-name/gr/grub2/package.nix"]}}
        )
    )
    assert (
        change_touches_package(_wget_change("pkgs/tools/misc/grub/default.nix"), b)
        is True
    )


def test_a_different_package_entirely_does_not_match(tmp_path):
    b = _bundle(tmp_path)
    (b / "resolver-input.json").write_text(json.dumps({"attr_path": "libwebp"}))
    assert (
        change_touches_package(
            _wget_change("pkgs/applications/misc/golden-cheetah-bin/default.nix"), b
        )
        is False
    )
