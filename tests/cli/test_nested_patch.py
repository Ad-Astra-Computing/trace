"""Tests for `tools/trace_cli/nested_patch.py` — extracting the model's own
source patch out of a bundle's `patch.diff` (the nested `CVE-*.patch`
addition, or the flat direct-edit shape)."""

from __future__ import annotations

from tools.trace_cli import nested_patch


_NESTED_PATCH_DIFF = """\
diff --git a/CVE-2026-40356.patch b/CVE-2026-40356.patch
new file mode 100644
--- /dev/null
+++ b/CVE-2026-40356.patch
@@ -0,0 +1,8 @@
+Backport note line one.
+
+diff --git a/src/lib/gssapi/spnego/negoex_util.c b/src/lib/gssapi/spnego/negoex_util.c
+--- a/src/lib/gssapi/spnego/negoex_util.c
++++ b/src/lib/gssapi/spnego/negoex_util.c
+@@ -1,3 +1,3 @@
+-old line
++new line
diff --git a/package.nix b/package.nix
--- a/package.nix
+++ b/package.nix
@@ -10,3 +10,4 @@
   ];
+  extra = true;
"""

_FLAT_PATCH_DIFF = """\
diff --git a/lib/foo.c b/lib/foo.c
--- a/lib/foo.c
+++ b/lib/foo.c
@@ -1,3 +1,3 @@
-old line
+new line
diff --git a/package.nix b/package.nix
--- a/package.nix
+++ b/package.nix
@@ -10,3 +10,4 @@
   ];
+  extra = true;
"""


def test_extracts_nested_patch_body_verbatim() -> None:
    inner, names = nested_patch.extract_nested_source_patch(_NESTED_PATCH_DIFF)
    assert names == ["CVE-2026-40356.patch"]
    assert "diff --git a/src/lib/gssapi/spnego/negoex_util.c" in inner
    assert "--- a/src/lib/gssapi/spnego/negoex_util.c" in inner
    assert "+++ b/src/lib/gssapi/spnego/negoex_util.c" in inner
    assert "-old line" in inner
    assert "+new line" in inner
    # The outer "+" prefix (from the addition) must be fully stripped — no
    # double-prefixed lines should survive.
    assert "++diff --git" not in inner
    assert "++--- a/" not in inner
    # package.nix is NOT part of the nested addition; must not leak in.
    assert "package.nix" not in inner


def test_nested_patch_excludes_package_nix_section() -> None:
    inner, _names = nested_patch.extract_nested_source_patch(_NESTED_PATCH_DIFF)
    assert "extra = true" not in inner


def test_flat_shape_falls_back_and_drops_package_nix() -> None:
    inner, names = nested_patch.extract_nested_source_patch(_FLAT_PATCH_DIFF)
    assert names == []  # empty names signals "flat shape" to the caller
    assert "diff --git a/lib/foo.c" in inner
    assert "-old line" in inner
    assert "+new line" in inner
    assert "package.nix" not in inner
    assert "extra = true" not in inner


def test_raises_when_nothing_to_extract() -> None:
    only_package_nix = """\
diff --git a/package.nix b/package.nix
--- a/package.nix
+++ b/package.nix
@@ -1,1 +1,1 @@
-a
+b
"""
    import pytest

    with pytest.raises(nested_patch.NestedPatchError):
        nested_patch.extract_nested_source_patch(only_package_nix)


def test_raises_on_modified_existing_patch_file() -> None:
    """A `patch.diff` that MODIFIES an existing `*.patch` (not a new-file add)
    is a nested source patch we can't reconstruct without its base — fail
    closed rather than misclassify it as a flat edit and patch the `.patch`
    path itself (a false preflight failure)."""
    modifies_existing_patch = """\
diff --git a/fix-CVE.patch b/fix-CVE.patch
--- a/fix-CVE.patch
+++ b/fix-CVE.patch
@@ -1,3 +1,3 @@
-old guard
+new guard
diff --git a/package.nix b/package.nix
--- a/package.nix
+++ b/package.nix
@@ -10,3 +10,4 @@
   ];
+  extra = true;
"""
    import pytest

    with pytest.raises(
        nested_patch.NestedPatchError, match="modifies existing nested patch"
    ):
        nested_patch.extract_nested_source_patch(modifies_existing_patch)


def test_raises_on_mixed_added_and_modified_patch_files() -> None:
    """Even when a new `*.patch` IS added, a co-located MODIFY of another
    `*.patch` must fail closed: returning only the added body would silently
    omit a build-affecting patch, so the gate could pass without validating
    the complete change."""
    mixed = """\
diff --git a/CVE-NEW.patch b/CVE-NEW.patch
new file mode 100644
--- /dev/null
+++ b/CVE-NEW.patch
@@ -0,0 +1,4 @@
+diff --git a/lib/foo.c b/lib/foo.c
+--- a/lib/foo.c
++++ b/lib/foo.c
diff --git a/existing.patch b/existing.patch
--- a/existing.patch
+++ b/existing.patch
@@ -1,1 +1,1 @@
-old
+new
"""
    import pytest

    with pytest.raises(
        nested_patch.NestedPatchError, match="modifies existing nested patch"
    ):
        nested_patch.extract_nested_source_patch(mixed)


def test_unwrap_preserves_no_trailing_newline() -> None:
    """A nested added `*.patch` with no trailing newline emits a
    `\\ No newline at end of file` marker; it must be dropped (not treated as
    content) and the recovered body must not gain a synthetic newline."""
    no_newline = (
        "diff --git a/CVE.patch b/CVE.patch\n"
        "new file mode 100644\n"
        "--- /dev/null\n"
        "+++ b/CVE.patch\n"
        "@@ -0,0 +1,2 @@\n"
        "+line one\n"
        "+line two\n"
        "\\ No newline at end of file\n"
    )
    inner, names = nested_patch.extract_nested_source_patch(no_newline)
    assert names == ["CVE.patch"]
    assert inner == "line one\nline two"  # no trailing newline, no marker
    assert "No newline" not in inner


def test_unwrap_keeps_trailing_newline_by_default() -> None:
    with_newline = (
        "diff --git a/CVE.patch b/CVE.patch\n"
        "new file mode 100644\n"
        "--- /dev/null\n"
        "+++ b/CVE.patch\n"
        "@@ -0,0 +1,2 @@\n"
        "+line one\n"
        "+line two\n"
    )
    inner, _ = nested_patch.extract_nested_source_patch(with_newline)
    assert inner == "line one\nline two\n"


def test_raises_on_multiple_added_nested_patches() -> None:
    """Two added `*.patch` files can't be ordered from patch.diff alone (the
    order is the package's patches=[] wiring) — fail closed."""
    two_added = """\
diff --git a/CVE-A.patch b/CVE-A.patch
new file mode 100644
--- /dev/null
+++ b/CVE-A.patch
@@ -0,0 +1,3 @@
+diff --git a/lib/a.c b/lib/a.c
+--- a/lib/a.c
++++ b/lib/a.c
diff --git a/CVE-B.patch b/CVE-B.patch
new file mode 100644
--- /dev/null
+++ b/CVE-B.patch
@@ -0,0 +1,3 @@
+diff --git a/lib/b.c b/lib/b.c
+--- a/lib/b.c
++++ b/lib/b.c
"""
    import pytest

    with pytest.raises(nested_patch.NestedPatchError, match="multiple nested patch"):
        nested_patch.extract_nested_source_patch(two_added)
