"""Tests for the source-context writer (tools/trace_cli/source_context.py).

Slice 2 of the semantic-backport-adaptation arc. The load-bearing cases are the
path-traversal guards (`test_*_rejects_*`): feed-sourced diff paths must never
escape the pinned source tree or the source-context destination. The base-mismatch
guard (`test_write_missing_file_raises`) is the same failure class the preflight
catches, surfaced here so a slice-2 assemble refuses rather than silently omitting
an affected file.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from tools.trace_cli import source_context as sc


# ─── parse_touched_paths ─────────────────────────────────────────────────────

_GIT_DIFF = """\
diff --git a/libarchive/archive_read_support_format_tar.c b/libarchive/archive_read_support_format_tar.c
index 1111111..2222222 100644
--- a/libarchive/archive_read_support_format_tar.c
+++ b/libarchive/archive_read_support_format_tar.c
@@ -3517,7 +3517,7 @@ tar_atol_base_n(const char *p, size_t char_cnt, int base)
-	old
+	new
"""

_MULTI_FILE = """\
--- a/src/foo.c
+++ b/src/foo.c
@@ -1 +1 @@
-a
+b
--- a/include/foo.h
+++ b/include/foo.h
@@ -1 +1 @@
-a
+b
"""

_ADDS_FILE = """\
--- /dev/null
+++ b/src/newfile.c
@@ -0,0 +1 @@
+brand new
--- a/src/existing.c
+++ b/src/existing.c
@@ -1 +1 @@
-a
+b
"""


def test_parse_single_file() -> None:
    assert sc.parse_touched_paths(_GIT_DIFF) == [
        "libarchive/archive_read_support_format_tar.c"
    ]


def test_parse_multi_file_sorted_unique() -> None:
    assert sc.parse_touched_paths(_MULTI_FILE) == ["include/foo.h", "src/foo.c"]


def test_parse_skips_dev_null_old_side() -> None:
    """A file the fix ADDS (old side /dev/null) has no pre-patch source."""
    assert sc.parse_touched_paths(_ADDS_FILE) == ["src/existing.c"]


def test_parse_trims_timestamp() -> None:
    patch = "--- a/foo.c\t2026-07-27 12:00:00.000000000 +0000\n+++ b/foo.c\n"
    assert sc.parse_touched_paths(patch) == ["foo.c"]


def test_parse_rejects_absolute_path() -> None:
    with pytest.raises(sc.SourceContextError, match="absolute"):
        sc.parse_touched_paths("--- a//etc/passwd\n+++ b//etc/passwd\n")


def test_parse_rejects_traversal() -> None:
    with pytest.raises(sc.SourceContextError, match="traversal"):
        sc.parse_touched_paths("--- a/../../etc/passwd\n+++ b/../../etc/passwd\n")


def test_parse_ignores_removed_line_that_looks_like_header() -> None:
    """A removed source line `-- comment` renders as `--- comment` in the diff
    body; it must NOT be read as a file header (codex P2a). The single real file
    header is the one paired with a `+++ ` line outside any hunk."""
    patch = (
        "--- a/mod.lua\n"
        "+++ b/mod.lua\n"
        "@@ -1,2 +1,2 @@\n"
        "--- old behavior\n"     # removed line whose content is "-- old behavior"
        "+-- new behavior\n"     # added line whose content is "-- new behavior"
        " context\n"
    )
    assert sc.parse_touched_paths(patch) == ["mod.lua"]


def test_parse_multi_file_git_diff() -> None:
    """Multi-file git diff: both headers found, hunk bodies skipped."""
    patch = (
        "diff --git a/one.c b/one.c\n"
        "--- a/one.c\n+++ b/one.c\n@@ -1 +1 @@\n-a\n+b\n"
        "diff --git a/two.c b/two.c\n"
        "--- a/two.c\n+++ b/two.c\n@@ -1 +1 @@\n---x\n+--y\n"
    )
    assert sc.parse_touched_paths(patch) == ["one.c", "two.c"]


# ─── write_source_context ────────────────────────────────────────────────────

def _tree(root: Path, files: dict[str, str]) -> Path:
    for rel, content in files.items():
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(content)
    return root


def test_write_copies_touched_files(tmp_path: Path) -> None:
    src = _tree(tmp_path / "src", {
        "src/foo.c": "int foo;\n",
        "include/foo.h": "extern int foo;\n",
        "src/unrelated.c": "int bar;\n",
    })
    dest = tmp_path / "bundle" / "source-context"
    written = sc.write_source_context(_MULTI_FILE, src, dest)
    assert written == ["include/foo.h", "src/foo.c"]
    assert (dest / "src/foo.c").read_text() == "int foo;\n"
    assert (dest / "include/foo.h").read_text() == "extern int foo;\n"
    # Only the touched files are copied — unrelated source is not leaked in.
    assert not (dest / "src/unrelated.c").exists()


def test_write_missing_file_raises(tmp_path: Path) -> None:
    """Base mismatch: the fix touches a file absent from the pinned source."""
    src = _tree(tmp_path / "src", {"src/foo.c": "int foo;\n"})  # foo.h absent
    dest = tmp_path / "bundle" / "source-context"
    with pytest.raises(sc.SourceContextError, match="base mismatch"):
        sc.write_source_context(_MULTI_FILE, src, dest)


def test_write_rejects_symlinked_dest_root(tmp_path: Path) -> None:
    """A symlinked source-context root must be refused before resolve() follows it
    out of the bundle (codex P1)."""
    src = _tree(tmp_path / "src", {"src/foo.c": "x\n", "include/foo.h": "y\n"})
    external = tmp_path / "external"
    external.mkdir()
    dest = tmp_path / "bundle" / "source-context"
    dest.parent.mkdir(parents=True)
    dest.symlink_to(external)
    with pytest.raises(sc.SourceContextError, match="root is a symlink"):
        sc.write_source_context(_MULTI_FILE, src, dest)
    # nothing was written through the link
    assert list(external.iterdir()) == []


def test_write_rejects_symlinked_dest_leaf(tmp_path: Path) -> None:
    """A pre-existing destination leaf symlink must be refused before copyfile
    follows it and overwrites the external target (codex P1)."""
    src = _tree(tmp_path / "src", {"src/foo.c": "real\n", "include/foo.h": "y\n"})
    dest = tmp_path / "bundle" / "source-context"
    (dest / "src").mkdir(parents=True)
    external = tmp_path / "victim.c"
    external.write_text("do-not-overwrite\n")
    (dest / "src" / "foo.c").symlink_to(external)
    with pytest.raises(sc.SourceContextError, match="symlink"):
        sc.write_source_context(_MULTI_FILE, src, dest)
    assert external.read_text() == "do-not-overwrite\n"


def test_write_rejects_symlink_escape(tmp_path: Path) -> None:
    """A symlink in the source tree must not be followed out of the tree."""
    src = tmp_path / "src"
    (src / "src").mkdir(parents=True)
    secret = tmp_path / "secret.txt"
    secret.write_text("top secret\n")
    (src / "src" / "foo.c").symlink_to(secret)
    dest = tmp_path / "bundle" / "source-context"
    patch = "--- a/src/foo.c\n+++ b/src/foo.c\n@@ -1 +1 @@\n-a\n+b\n"
    with pytest.raises(sc.SourceContextError, match="symlink"):
        sc.write_source_context(patch, src, dest)
