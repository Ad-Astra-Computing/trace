"""Tests for eval/pr_accuracy — the corpus PR-accuracy harness."""

from __future__ import annotations

from eval.pr_accuracy import (
    extract_authored_patch,
    parse_change_lines,
    score,
)

# A realistic bundle patch.diff: a new *.patch (the authored source fix) + a .nix wire-in.
PATCH_DIFF = """\
diff --git a/pkgs/tools/compression/bzip2/CVE-2026-42250.patch b/pkgs/tools/compression/bzip2/CVE-2026-42250.patch
new file mode 100644
--- /dev/null
+++ b/pkgs/tools/compression/bzip2/CVE-2026-42250.patch
@@ -0,0 +1,9 @@
+--- bzip2recover.c
++++ bzip2recover.c
+@@ -402,5 +402,5 @@
+             rbCtr++;
+          }
+-         if (currBlock >= BZ_MAX_HANDLED_BLOCKS)
++         if (currBlock >= BZ_MAX_HANDLED_BLOCKS - 1)
+             tooManyBlocks(BZ_MAX_HANDLED_BLOCKS);
+          currBlock++;
diff --git a/pkgs/tools/compression/bzip2/default.nix b/pkgs/tools/compression/bzip2/default.nix
--- a/pkgs/tools/compression/bzip2/default.nix
+++ b/pkgs/tools/compression/bzip2/default.nix
@@ -32,6 +32,7 @@
     patches = [
       ./patches/bzip2-1.0.6.2-autoconfiscated.patch
+      ./CVE-2026-42250.patch
     ];
"""

UPSTREAM_FIX = """\
--- bzip2recover.c
+++ bzip2recover.c
@@ -402,5 +402,5 @@
            rbCtr++;
         }
-        if (currBlock >= BZ_MAX_HANDLED_BLOCKS)
+        if (currBlock >= BZ_MAX_HANDLED_BLOCKS - 1)
           tooManyBlocks(BZ_MAX_HANDLED_BLOCKS);
         currBlock++;
"""

NIX_ONLY_DIFF = """\
diff --git a/pkgs/by-name/mi/micropython/package.nix b/pkgs/by-name/mi/micropython/package.nix
--- a/pkgs/by-name/mi/micropython/package.nix
+++ b/pkgs/by-name/mi/micropython/package.nix
@@ -10,6 +10,7 @@
-  version = "1.26.0";
+  version = "1.27.0";
"""


def test_extract_authored_patch_recovers_inner_diff():
    inner = extract_authored_patch(PATCH_DIFF)
    assert inner is not None
    # the outer '+' is stripped; inner +/- payload survives, .nix wire-in excluded
    assert "if (currBlock >= BZ_MAX_HANDLED_BLOCKS - 1)" in inner
    assert "./CVE-2026-42250.patch" not in inner
    assert "patches = [" not in inner


def test_extract_returns_none_for_nix_only_bump():
    assert extract_authored_patch(NIX_ONLY_DIFF) is None


def test_parse_change_lines_ignores_headers_and_context():
    removed, added = parse_change_lines(UPSTREAM_FIX)
    assert removed == ["if (currBlock >= BZ_MAX_HANDLED_BLOCKS)"]
    assert added == ["if (currBlock >= BZ_MAX_HANDLED_BLOCKS - 1)"]


def test_score_exact_match_across_whitespace_and_context():
    # authored (from the bundle) and upstream differ only in leading indentation of
    # context lines + hunk line numbers, yet the CHANGED lines are identical.
    inner = extract_authored_patch(PATCH_DIFF)
    s = score(inner, UPSTREAM_FIX)
    assert s["exact"] is True
    assert s["added_recall"] == 1.0
    assert s["removed_recall"] == 1.0


def test_score_partial_when_authored_misses_an_added_line():
    upstream = "@@ -1,2 +1,3 @@\n a\n+guard_one\n+guard_two\n"
    authored = "@@ -1,2 +1,2 @@\n a\n+guard_one\n"
    s = score(authored, upstream)
    assert s["exact"] is False
    assert s["added_recall"] == 0.5  # 1 of 2 upstream added-lines reproduced


def test_score_wrong_edit_shape_scores_low():
    # deletes the right line but writes a different addition (the documented failure mode)
    upstream = "@@ -1,1 +1,1 @@\n-old_guard\n+correct_new_guard\n"
    authored = "@@ -1,1 +1,1 @@\n-old_guard\n+different_wrong_guard\n"
    s = score(authored, upstream)
    assert s["removed_recall"] == 1.0
    assert s["added_recall"] == 0.0
    assert s["exact"] is False
