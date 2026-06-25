"""Tests for `trace export authoring` (tools/trace_cli/export.py).

The authoring exporter turns cert-green source-backport bundles into
(CVE-vuln-only + pre-fix source) -> upstream-fix training pairs. The load-bearing
property is LEAKAGE CONTROL: the input must never name what the fix changes. These
tests pin the scrub (`_fix_symbols` / `_scrub_summary`) and the end-to-end record
shape, using a cached `authoring-example.json` so no network fetch is needed.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from tools.trace_cli import export as ex


# A realistic source-backport fix: removing a type-gate so an existing bounds
# check applies to all proxy types (mirrors the proxychains CVE-2025-34451 shape).
_FIX_DIFF = (
    "diff --git a/src/libproxychains.c b/src/libproxychains.c\n"
    "--- a/src/libproxychains.c\n"
    "+++ b/src/libproxychains.c\n"
    "@@ -241,7 +241,7 @@ static int proxy_from_string(const char *proxystring,\n"
    " \t\tpl = at-p;\n"
    "-\t\tif(proxytype == RS_PT_SOCKS5 && (ul > 255 || pl > 255))\n"
    "+\t\tif(ul > 255 || pl > 255)\n"
    " \t\t\treturn 0;\n"
)


def _cached_bundle(root: Path, name: str, *, cve: str, attr: str, summary: str,
                   fix_diff: str = _FIX_DIFF, kind: str = "human-review-required",
                   rekor: int | None = 1796253004) -> Path:
    bd = root / name
    bd.mkdir(parents=True)
    bundle = {"bundle_id": "deadbeef", "cve_id": cve, "kind": kind}
    if rekor is not None:
        bundle["signed_manifest"] = {"rekor_log_index": rekor}
    (bd / "bundle.json").write_text(json.dumps(bundle))
    (bd / "finding.json").write_text(json.dumps(
        {"cve_id": cve, "summary": summary, "affected": [{"attr_path": attr}]}))
    (bd / "upstream-ref.json").write_text(json.dumps({"cve_id": cve}))
    # Pre-built cache so _authoring_pair returns offline.
    (bd / "authoring-example.json").write_text(json.dumps({
        "cve_id": cve, "attr_path": attr, "vuln_raw": summary,
        "file": "src/libproxychains.c",
        "pre_fix_source": "static int proxy_from_string(...) {\n  /* vulnerable body */\n}",
        "fix_diff": fix_diff,
        "fix_commit": {"repo_url": "https://github.com/rofl0r/proxychains-ng",
                       "commit_sha": "cc005b713281"},
    }))
    return bd


def _args(out: Path, root: Path) -> argparse.Namespace:
    return argparse.Namespace(export_scope="authoring", out=out, traces_root=root,
                              format="json")


# --- pure scrub functions -------------------------------------------------

def test_fix_symbols_only_from_changed_lines():
    syms = ex._fix_symbols(_FIX_DIFF)
    assert "RS_PT_SOCKS5" in syms          # on a removed line
    assert "proxytype" in syms             # changed line (len>=6, no '_': proxytype is 9)
    assert "proxy_from_string" not in syms  # only in the @@ hunk header (context)


def test_fix_symbols_skips_generic_short_tokens():
    syms = ex._fix_symbols("--- a/x\n+++ b/x\n@@ -1 +1 @@\n-if (a > b)\n+if (a >= b)\n")
    assert "if" not in syms  # too short / generic
    assert syms == set()     # nothing distinctive changed


def test_fix_symbols_extracts_only_moved_numeric_literal():
    # a bound that moved (10 -> 8) is a tell; an unchanged constant is not.
    diff = "--- a/x\n+++ b/x\n@@ -1 +1 @@\n-if (n > 10 && cap == 256)\n+if (n > 8 && cap == 256)\n"
    syms = ex._fix_symbols(diff)
    assert "10" in syms and "8" not in syms  # 8 is single-digit (too generic)
    assert "256" not in syms                 # unchanged on both sides — a vuln fact


def test_fix_symbols_ignores_single_digit_offbyone():
    # bzip2 shape: `MAX` -> `MAX - 1`. The `1` is too generic; the identifier carries it.
    diff = ("--- a/x\n+++ b/x\n@@ -1 +1 @@\n"
            "-if (c >= BZ_MAX_HANDLED_BLOCKS)\n+if (c >= BZ_MAX_HANDLED_BLOCKS - 1)\n")
    syms = ex._fix_symbols(diff)
    assert "BZ_MAX_HANDLED_BLOCKS" in syms
    assert "1" not in syms


def test_mentions_word_boundary_for_numbers():
    assert ex._mentions("the limit is 50 blocks", "50")
    assert not ex._mentions("version 1.0.8 is affected", "50")  # 50 not inside 5000/1.0.8
    assert not ex._mentions("more than 50000 magics", "50")     # boundary, not substring
    assert ex._mentions("calls slotat() directly", "slotat")    # identifier substring


def test_scrub_summary_drops_sentence_naming_the_fix_symbol():
    summary = ("Stack overflow in proxy_from_string when a credential exceeds 255 bytes. "
               "The bounds check was gated on proxytype == RS_PT_SOCKS5, excluding HTTP.")
    scrubbed = ex._scrub_summary(summary, _FIX_DIFF)
    assert "RS_PT_SOCKS5" not in scrubbed         # the leaky sentence is gone
    assert "Stack overflow" in scrubbed           # the vuln description survives


def test_scrub_summary_drops_remediation_language():
    summary = "Heap overflow in foo(). Fixed upstream in commit abc1234 by adding a length check."
    scrubbed = ex._scrub_summary(summary, "--- a/x\n+++ b/x\n@@ -1 +1 @@\n-a\n+b\n")
    assert "Fixed upstream" not in scrubbed
    assert "Heap overflow" in scrubbed


# --- end-to-end export ----------------------------------------------------

def test_authoring_export_builds_clean_pair(tmp_path, capsys):
    root = tmp_path / "traces"
    summary = ("Stack-based buffer overflow in proxy_from_string when a username exceeds "
               "255 bytes. It was gated on proxytype == RS_PT_SOCKS5.")
    _cached_bundle(root, "CVE-2025-34451--proxychains-ng-backport",
                   cve="CVE-2025-34451", attr="proxychains-ng", summary=summary)
    rc = ex.run(_args(tmp_path / "out", root))
    assert rc == 0
    lines = (tmp_path / "out" / "authoring.jsonl").read_text().splitlines()
    assert len(lines) == 1
    ex_rec = json.loads(lines[0])
    roles = [m["role"] for m in ex_rec["messages"]]
    assert roles == ["system", "user", "assistant"]
    user = ex_rec["messages"][1]["content"]
    assert "RS_PT_SOCKS5" not in user           # fix symbol scrubbed from input
    assert "buffer overflow" in user            # vuln preserved
    assert ex_rec["messages"][2]["content"].startswith("diff --git")  # label = the fix
    assert ex_rec["task"] == "author-from-vuln"
    assert ex_rec["provenance"]["cve_id"] == "CVE-2025-34451"
    assert ex_rec["provenance"]["steward_signed"] is True


def test_authoring_export_excludes_unscrubbable_summary(tmp_path):
    """If every sentence names a fix symbol, the summary scrubs to empty and the
    bundle is excluded rather than shipping a leaky/empty input."""
    root = tmp_path / "traces"
    _cached_bundle(root, "CVE-2025-34451--leaky-backport", cve="CVE-2025-34451",
                   attr="leaky", summary="proxytype RS_PT_SOCKS5 gate removed.")
    rc = ex.run(_args(tmp_path / "out", root))
    assert rc == 0
    manifest = json.loads((tmp_path / "out" / "manifest.json").read_text())
    assert manifest["eligible_examples"] == 0
    assert manifest["excluded"]
    assert "scrub" in manifest["excluded"][0]["reason"]


def test_authoring_manifest_records_leakage_partition(tmp_path):
    root = tmp_path / "traces"
    _cached_bundle(root, "CVE-2025-34451--proxychains-ng-backport",
                   cve="CVE-2025-34451", attr="proxychains-ng",
                   summary="Stack overflow in proxy_from_string with long credentials.")
    ex.run(_args(tmp_path / "out", root))
    manifest = json.loads((tmp_path / "out" / "manifest.json").read_text())
    assert manifest["scope"] == "authoring"
    assert "author-from-vuln" in manifest["note"]
    assert "leakage" in manifest["note"].lower()
    assert manifest["families"] == ["proxychains-ng"]


# ── input-file selection for multi-file fix commits (CVE-2026-0989 shape) ──────

def test_pick_input_file_prefers_highest_churn_impl_over_header():
    # libxml2 CVE-2026-0989: header listed first, but the vuln (and the bulk of
    # the change) is in relaxng.c. The input window must center on the impl.
    churn = {"include/libxml/relaxng.h": 2, "relaxng.c": 37}
    assert ex._pick_authoring_input_file(churn) == "relaxng.c"


def test_pick_input_file_deterministic_tie_break():
    assert ex._pick_authoring_input_file({"b.c": 5, "a.c": 5}) == "a.c"
    assert ex._pick_authoring_input_file({}) is None


def test_pick_input_file_skips_newly_added_high_churn_file():
    # A new file (absent from parent) has the most churn, but the input is a
    # PRE-fix parent window, so we pick the highest-churn parent-existing file.
    churn = {"newfile.c": 99, "relaxng.c": 30, "include/libxml/relaxng.h": 2}
    parent_existing = {"relaxng.c", "include/libxml/relaxng.h"}  # newfile.c is status A
    assert ex._pick_authoring_input_file(churn, parent_existing) == "relaxng.c"


def test_pick_input_file_allows_deleted_vulnerable_file():
    # A fix that DELETES the vulnerable file (status D) while editing a companion:
    # the deleted file exists in the parent, so it's a valid (highest-churn) input.
    churn = {"vuln.c": 40, "companion.c": 6}
    parent_existing = {"vuln.c", "companion.c"}  # both exist in parent (D + M)
    assert ex._pick_authoring_input_file(churn, parent_existing) == "vuln.c"


def test_pick_input_file_falls_back_when_none_parent_existing():
    # All changed files are new -> fall back to overall max (the blob fetch in
    # _authoring_pair still guards a genuinely-absent parent).
    churn = {"a.c": 10, "b.c": 4}
    assert ex._pick_authoring_input_file(churn, set()) == "a.c"


def test_file_diff_starts_only_for_named_file():
    diff = (
        "diff --git a/include/libxml/relaxng.h b/include/libxml/relaxng.h\n"
        "--- a/include/libxml/relaxng.h\n+++ b/include/libxml/relaxng.h\n"
        "@@ -10,3 +10,4 @@\n+ int x;\n"
        "diff --git a/relaxng.c b/relaxng.c\n"
        "--- a/relaxng.c\n+++ b/relaxng.c\n"
        "@@ -820,6 +820,9 @@\n+ guard;\n"
        "@@ -1200,3 +1200,5 @@\n+ more;\n"
    )
    assert ex._file_diff_starts(diff, "relaxng.c") == [820, 1200]
    assert ex._file_diff_starts(diff, "include/libxml/relaxng.h") == [10]
    assert ex._file_diff_starts(diff, "nonexistent.c") == []


def test_authoring_pair_skips_nixpkgs_repo_commit(tmp_path):
    """A bundle whose upstream_fix_commit points at nixpkgs (the packaging commit
    that adds the backport .patch) is NOT an authoring candidate — the fix is .nix
    packaging, not vulnerable upstream source. _authoring_pair must return None."""
    bd = tmp_path / "CVE-2025-6170--libxml2-backport"
    bd.mkdir(parents=True)
    (bd / "finding.json").write_text(json.dumps({"cve_id": "CVE-2025-6170"}))
    (bd / "upstream-ref.json").write_text(json.dumps({
        "eligibility": {"patch_strategy": "source-backport"},
        "upstream_fix_commits": [{
            "repo_url": "https://github.com/NixOS/nixpkgs",
            "commit_sha": "2da008e2ee4eda00000000000000000000000000",
        }],
    }))
    assert ex._authoring_pair(bd) is None


def test_authoring_pair_skips_cached_nixpkgs_pair(tmp_path):
    """The nixpkgs skip must apply to CACHED pairs too — a stale cache built from a
    nixpkgs packaging commit must not export (the guard runs before cache-return)."""
    bd = tmp_path / "CVE-2025-6170--libxml2-backport"
    bd.mkdir(parents=True)
    (bd / "authoring-example.json").write_text(json.dumps({
        "cve_id": "CVE-2025-6170", "file": "pkgs/development/libraries/libxml2/default.nix",
        "pre_fix_source": "{ ... }", "fix_diff": "diff --git a/default.nix b/default.nix\n",
        "fix_commit": {"repo_url": "https://github.com/NixOS/nixpkgs", "commit_sha": "2da008e2"},
    }))
    assert ex._authoring_pair(bd) is None


def test_is_nixpkgs_repo_url_forms():
    assert ex._is_nixpkgs_repo("https://github.com/NixOS/nixpkgs")
    assert ex._is_nixpkgs_repo("https://github.com/NixOS/nixpkgs.git")
    assert ex._is_nixpkgs_repo("https://github.com/NixOS/nixpkgs/")
    assert ex._is_nixpkgs_repo("git@github.com:NixOS/nixpkgs.git")   # scp-style
    assert not ex._is_nixpkgs_repo("https://github.com/NixOS/nixpkgs-tools")  # anchored
    assert not ex._is_nixpkgs_repo("https://gitlab.gnome.org/GNOME/libxml2")
    assert not ex._is_nixpkgs_repo(None)    # malformed: no crash, treated as not-nixpkgs
    assert not ex._is_nixpkgs_repo(1234)


def test_hunk_windows_single_region():
    lines = [f"L{i}" for i in range(100)]
    out = ex._hunk_windows(lines, [50], radius=5)
    assert out.splitlines() == [f"L{i}" for i in range(45, 55)]  # lines[50-5:50+5]
    assert "/* ... */" not in out  # single region, no elision


def test_hunk_windows_merges_overlap_and_elides_gaps():
    lines = [f"L{i}" for i in range(1000)]
    out = ex._hunk_windows(lines, [10, 12, 800], radius=5)  # 10&12 overlap; 800 distant
    assert out.count("/* ... */") == 1          # one gap (merged 10/12 vs 800)
    assert "L5" in out.splitlines() and "L16" in out.splitlines()  # merged first region (lines[5:17])
    assert "L4" not in out.splitlines()           # just outside the first window
    assert "L799" in out.splitlines()             # distant hunk region present (label-consistent)
    # bounded by hunk count, not the 1000-line file span
    assert len(out.splitlines()) < 60


# ── curated upstream-fix.patch as the authoring LABEL ─────────────────────────
# The label is the MINIMAL upstream source fix. Prefer the curated
# upstream-fix.patch (Reviewer ground truth) over `git show <fix-sha>`, which can
# carry release-commit noise (pyjwt version bump) or drop hunks (python-multipart).

def test_strip_ab_prefix():
    assert ex._strip_ab_prefix("a/jwt/algorithms.py") == "jwt/algorithms.py"
    assert ex._strip_ab_prefix("b/jwt/algorithms.py") == "jwt/algorithms.py"
    assert ex._strip_ab_prefix("bzip2recover.c") == "bzip2recover.c"   # bare, untouched
    assert ex._strip_ab_prefix("  a/x.c \n") == "x.c"                   # whitespace tidy


def test_label_from_patch_diff_git_format():
    patch = (
        "From abc Mon Sep 17 00:00:00 2001\nSubject: [PATCH] fix\n\n"
        "diff --git a/jwt/algorithms.py b/jwt/algorithms.py\n"
        "--- a/jwt/algorithms.py\n+++ b/jwt/algorithms.py\n"
        "@@ -325,3 +325,6 @@ def prepare_key(self, key):\n"
        " key_bytes = force_bytes(key)\n"
        "+        if len(key_bytes) == 0:\n+            raise InvalidKeyError('empty')\n"
        "+\n if is_pem_format(key_bytes):\n"
    )
    r = ex._authoring_label_from_patch(patch)
    assert list(r["churn"]) == ["jwt/algorithms.py"]
    assert r["added"] == set()
    assert "__version__" not in r["fix_diff"]                    # release noise excluded
    assert r["fix_diff"].startswith("diff --git a/jwt/algorithms.py b/jwt/algorithms.py")


def test_label_from_patch_bare_and_a_slash_headers():
    # `--- a/X` (no diff --git) and `--- X` (bare, bzip2-style) both parse.
    for header in ("--- a/src/x.c\n+++ b/src/x.c\n", "--- src/x.c\n+++ src/x.c\n"):
        patch = header + "@@ -10,2 +10,2 @@\n-old line\n+new line\n"
        r = ex._authoring_label_from_patch(patch)
        assert list(r["churn"]) == ["src/x.c"]
        assert "diff --git a/src/x.c b/src/x.c" in r["fix_diff"]   # canonicalized


def test_label_from_patch_keeps_all_hunks():
    # python-multipart shape: a 2-hunk fix. git-show dropped the 2nd; the curated
    # patch keeps both. The parser must preserve every hunk.
    patch = (
        "--- a/multipart.py\n+++ b/multipart.py\n"
        "@@ -1105,2 +1105,5 @@\n-    i += 1\n+    i = data.find(b'-', i)\n+    if i == -1:\n+        break\n"
        "@@ -1414,4 +1418,2 @@\n-    self.logger.warning('skip')\n-    i += 2\n+    i = length\n+    break\n"
    )
    r = ex._authoring_label_from_patch(patch)
    assert ex._file_diff_starts(r["fix_diff"], "multipart.py") == [1105, 1414]  # both hunks
    assert r["churn"]["multipart.py"] == 8                        # 3 removed + 5 added


def test_label_from_patch_drops_non_source_files():
    # A curated patch that bundled a test must not leak the test into the label.
    patch = (
        "diff --git a/src/parser.c b/src/parser.c\n--- a/src/parser.c\n+++ b/src/parser.c\n"
        "@@ -10,2 +10,2 @@\n-bad\n+good\n"
        "diff --git a/tests/test_parser.c b/tests/test_parser.c\n"
        "--- a/tests/test_parser.c\n+++ b/tests/test_parser.c\n"
        "@@ -1,1 +1,2 @@\n test\n+more test\n"
    )
    r = ex._authoring_label_from_patch(patch)
    assert list(r["churn"]) == ["src/parser.c"]                  # test file dropped
    assert "tests/test_parser.c" not in r["fix_diff"]


def test_label_from_patch_detects_added_file_and_none_when_all_nonsource():
    added = ("diff --git a/new.c b/new.c\n--- /dev/null\n+++ b/new.c\n"
             "@@ -0,0 +1,2 @@\n+int x;\n+int y;\n")
    r = ex._authoring_label_from_patch(added)
    assert r["added"] == {"new.c"}
    # all-non-source -> nothing to author from
    assert ex._authoring_label_from_patch(
        "--- a/docs/README.md\n+++ b/docs/README.md\n@@ -1 +1 @@\n-a\n+b\n") is None


def test_label_from_patch_preserves_dev_null_headers():
    # An added source file keeps `--- /dev/null`; a deleted one keeps `+++ /dev/null`
    # so the label is a faithful add/delete diff, not a spurious modify.
    added = ("diff --git a/new.c b/new.c\n--- /dev/null\n+++ b/new.c\n@@ -0,0 +1,1 @@\n+int x;\n")
    r = ex._authoring_label_from_patch(added)
    assert "--- /dev/null" in r["fix_diff"] and "+++ b/new.c" in r["fix_diff"]
    deleted = ("diff --git a/old.c b/old.c\n--- a/old.c\n+++ /dev/null\n@@ -1,1 +0,0 @@\n-int y;\n")
    r2 = ex._authoring_label_from_patch(deleted)
    assert "--- a/old.c" in r2["fix_diff"] and "+++ /dev/null" in r2["fix_diff"]


def test_label_file_has_removed_is_file_scoped():
    # x.c is pure-addition; y.c has a deletion. has-removed for x.c must be False
    # (another file's deletion must not vouch for a suffix-resolved x.c).
    fix = ("diff --git a/x.c b/x.c\n--- a/x.c\n+++ b/x.c\n@@ -10,1 +10,2 @@\n ctx;\n+added;\n"
           "diff --git a/y.c b/y.c\n--- a/y.c\n+++ b/y.c\n@@ -5,2 +5,1 @@\n-gone;\n ctx2;\n")
    assert ex._label_file_has_removed(fix, "y.c")
    assert not ex._label_file_has_removed(fix, "x.c")


def test_patch_grounded_removed_lines_present_vs_absent():
    fix = ("diff --git a/x.c b/x.c\n--- a/x.c\n+++ b/x.c\n"
           "@@ -10,2 +10,2 @@\n-    int bad = 1;\n+    int good = 1;\n")
    assert ex._patch_grounded(fix, "x.c", "void f() {\n    int bad = 1;\n}")       # removed line present
    assert not ex._patch_grounded(fix, "x.c", "void f() {\n    int other = 1;\n}")  # absent -> ungrounded


def test_patch_grounded_pure_addition_uses_context():
    # No removed lines -> require the hunk CONTEXT to appear in the window.
    fix = ("diff --git a/x.c b/x.c\n--- a/x.c\n+++ b/x.c\n"
           "@@ -10,2 +10,3 @@\n context anchor;\n+    int added;\n trailing;\n")
    assert ex._patch_grounded(fix, "x.c", "context anchor;\ntrailing;\nmore;")     # context present
    assert not ex._patch_grounded(fix, "x.c", "unrelated;\nlines;")                # context absent


def test_patch_grounded_scopes_to_named_file():
    # A removed line belonging to ANOTHER file must not be required in fpath's window.
    fix = ("diff --git a/x.c b/x.c\n--- a/x.c\n+++ b/x.c\n@@ -10,2 +10,2 @@\n-here;\n+now;\n"
           "diff --git a/y.c b/y.c\n--- a/y.c\n+++ b/y.c\n@@ -5,2 +5,2 @@\n-elsewhere;\n+changed;\n")
    assert ex._patch_grounded(fix, "x.c", "here;\nrest;")   # only x.c's `here;` checked


# ── offline integration: patch-preferred, version-bump excluded, divergent fallback ──

def _git(repo: Path, *a: str):
    import subprocess
    return subprocess.run(["git", "-C", str(repo), *a], capture_output=True, text=True,
                          env={"GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@t",
                               "GIT_COMMITTER_NAME": "t", "GIT_COMMITTER_EMAIL": "t@t",
                               "PATH": __import__("os").environ.get("PATH", "")})


def _fix_repo(tmp_path: Path, parent_src: str, fix_src: str, *, extra_commit_file=None):
    """A local git repo with a vulnerable parent commit and a fix commit. When
    `extra_commit_file` is given, the FIX COMMIT also touches it (release noise the
    curated patch must exclude)."""
    repo = tmp_path / "upstream"
    repo.mkdir()
    _git(repo, "init", "-q")
    (repo / "impl.c").write_text(parent_src)
    _git(repo, "add", "-A"); _git(repo, "commit", "-qm", "parent")
    (repo / "impl.c").write_text(fix_src)
    if extra_commit_file:
        (repo / extra_commit_file).write_text("__version__ = '2.0'\n")
    _git(repo, "add", "-A"); _git(repo, "commit", "-qm", "fix")
    return repo, _git(repo, "rev-parse", "HEAD").stdout.strip()


def _bundle(tmp_path, repo, sha, patch_body):
    bd = tmp_path / "CVE-2099-0001--local-backport"
    bd.mkdir()
    (bd / "bundle.json").write_text(json.dumps({"bundle_id": "x", "cve_id": "CVE-2099-0001"}))
    (bd / "finding.json").write_text(json.dumps(
        {"cve_id": "CVE-2099-0001", "summary": "Overflow when input is large.",
         "affected": [{"attr_path": "local"}]}))
    (bd / "upstream-ref.json").write_text(json.dumps({
        "eligibility": {"patch_strategy": "source-backport"},
        "upstream_fix_commits": [{"repo_url": str(repo), "commit_sha": sha}]}))
    (bd / "upstream-fix.patch").write_text(patch_body)
    return bd


def _allow_file_proto(monkeypatch):
    """The offline integration repos are local paths; the production
    `GIT_ALLOW_PROTOCOL=https:git:ssh` hardening blocks `file`. These tests
    exercise the LABEL logic, not the protocol guard, so widen it locally."""
    bp = ex_bp()
    monkeypatch.setattr(bp, "_validate_repo_url", lambda u: u)
    monkeypatch.setattr(bp, "_HARDENED_ENV",
                        {**bp._HARDENED_ENV, "GIT_ALLOW_PROTOCOL": "file:https:git:ssh"})


def test_authoring_prefers_curated_patch_over_noisy_git_show(tmp_path, monkeypatch):
    # Fix commit bumps a version file (release noise); curated patch is 1-file minimal.
    _allow_file_proto(monkeypatch)
    parent = "int f() {\n    int n = read();\n    use(n);\n    return 0;\n}\n"
    fixed = "int f() {\n    int n = read();\n    if (n > 255) return -1;\n    use(n);\n    return 0;\n}\n"
    repo, sha = _fix_repo(tmp_path, parent, fixed, extra_commit_file="version.py")
    patch = ("--- a/impl.c\n+++ b/impl.c\n@@ -2,3 +2,4 @@\n"
             "     int n = read();\n+    if (n > 255) return -1;\n     use(n);\n     return 0;\n")
    bd = _bundle(tmp_path, repo, sha, patch)
    pair = ex._authoring_pair(bd)
    assert pair is not None
    assert pair["label_source"] == "upstream-fix.patch"
    assert "__version__" not in pair["fix_diff"]            # release noise excluded
    assert "n > 255" in pair["fix_diff"]
    assert "if (n > 255) return -1;" in pair["pre_fix_source"] or "use(n)" in pair["pre_fix_source"]


def test_authoring_falls_back_when_patch_base_diverges(tmp_path, monkeypatch):
    # Curated patch removes a line that is NOT in the fix-commit's parent (authored
    # against a different base) -> ungrounded -> git-show fallback (procps shape).
    _allow_file_proto(monkeypatch)
    parent = "int f() {\n    int n = read();\n    use(n);\n}\n"
    fixed = "int f() {\n    int n = read();\n    if (n > 255) return -1;\n    use(n);\n}\n"
    repo, sha = _fix_repo(tmp_path, parent, fixed)
    # patch claims to remove a line absent from this parent:
    patch = ("--- a/impl.c\n+++ b/impl.c\n@@ -2,2 +2,2 @@\n"
             "-    int n = scanf_unbounded();\n+    int n = read_bounded();\n")
    bd = _bundle(tmp_path, repo, sha, patch)
    pair = ex._authoring_pair(bd)
    assert pair is not None
    assert pair["label_source"] == "git-show-fallback"      # diverged -> git-show
    assert "n > 255" in pair["fix_diff"]                    # the REAL commit's fix


def ex_bp():
    from tools.trace_cli import backport_patch as bp
    return bp
