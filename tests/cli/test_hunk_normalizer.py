"""Unit tests for the adaptation-lane hunk-header normalizer.

Covers the codex-confirmed guardrails (slice 4, DECISIONS 2026-07-27):
  * metadata-only rewrite (body never mutated),
  * exact + unique old-side match against source-context (fail on zero/ambiguous),
  * new-side starts derived from prior-hunk deltas,
  * idempotency on a byte-correct verbatim patch,
  * out-of-context hunks (package.nix, .patch wrapper) untouched,
  * the real libarchive CVE-2026-15028 regression case.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from tools.trace_cli.hunk_normalizer import (
    HunkNormalizationError,
    NormalizationResult,
    normalize_backport_patch,
)

REPO_ROOT = Path(__file__).resolve().parents[2]
LIBARCHIVE = REPO_ROOT / "traces/example/CVE-2026-15028--libarchive-tar-atol-oob-backport"


def _load_source_context(bundle: Path) -> dict[str, str]:
    scd = bundle / "source-context"
    return {
        p.relative_to(scd).as_posix(): p.read_text()
        for p in scd.rglob("*")
        if p.is_file()
    }


# A minimal flat source file for synthetic cases.
FLAT_SOURCE = "\n".join(
    [
        "int f(void) {",
        "\tint x = 0;",
        "\tif (bad) {",
        "\t\tx = compute();",
        "\t}",
        "\treturn x;",
        "}",
        "",
    ]
)


def _flat_patch(header: str) -> str:
    """A one-file, one-hunk flat diff against FLAT_SOURCE's `if (bad)` region."""
    return "\n".join(
        [
            "diff --git a/src/f.c b/src/f.c",
            "--- a/src/f.c",
            "+++ b/src/f.c",
            header,
            " \tif (bad) {",
            "-\t\tx = compute();",
            "+\t\tx = compute_safe();",
            " \t}",
            "",
        ]
    )


def test_flat_wrong_start_and_count_recomputed():
    ctx = {"src/f.c": FLAT_SOURCE}
    # Correct header is `@@ -3,3 +3,3 @@` (region starts at source line 3).
    patch = _flat_patch("@@ -99,2 +99,2 @@")
    res = normalize_backport_patch(patch, ctx)
    assert res.changed
    assert "@@ -3,3 +3,3 @@" in res.text
    assert "@@ -99,2 +99,2 @@" not in res.text
    assert len(res.rewrites) == 1
    assert res.rewrites[0]["file"] == "src/f.c"
    assert res.rewrites[0]["to"] == "@@ -3,3 +3,3 @@"


def test_body_lines_never_mutated():
    ctx = {"src/f.c": FLAT_SOURCE}
    patch = _flat_patch("@@ -1,1 +1,1 @@")
    res = normalize_backport_patch(patch, ctx)
    body = [ln for ln in res.text.split("\n") if ln[:1] in {" ", "+", "-"} and not ln.startswith("@@")]
    assert " \tif (bad) {" in body
    assert "-\t\tx = compute();" in body
    assert "+\t\tx = compute_safe();" in body


def test_correct_header_is_idempotent_no_rewrite():
    ctx = {"src/f.c": FLAT_SOURCE}
    patch = _flat_patch("@@ -3,3 +3,3 @@")
    res = normalize_backport_patch(patch, ctx)
    assert not res.changed
    assert res.rewrites == []
    assert res.text == patch


def test_ungroundable_body_fails_loudly():
    ctx = {"src/f.c": FLAT_SOURCE}
    patch = "\n".join(
        [
            "diff --git a/src/f.c b/src/f.c",
            "--- a/src/f.c",
            "+++ b/src/f.c",
            "@@ -3,3 +3,3 @@",
            " \tif (nonexistent) {",  # not in FLAT_SOURCE
            "-\t\tx = compute();",
            "+\t\tx = compute_safe();",
            " \t}",
            "",
        ]
    )
    with pytest.raises(HunkNormalizationError, match="does not match the pinned source"):
        normalize_backport_patch(patch, ctx)


def test_ambiguous_match_fails_loudly():
    # Source with the target region appearing twice.
    dup = "\n".join(["\tping();", "\tping();", "\tping();", ""])
    ctx = {"src/f.c": dup}
    patch = "\n".join(
        [
            "diff --git a/src/f.c b/src/f.c",
            "--- a/src/f.c",
            "+++ b/src/f.c",
            "@@ -1,1 +1,2 @@",
            "-\tping();",
            "+\tpong();",
            "+\tpong();",
            "",
        ]
    )
    with pytest.raises(HunkNormalizationError, match="ambiguous"):
        normalize_backport_patch(patch, ctx)


def test_multi_hunk_new_start_uses_prior_delta():
    # Two hunks in one file; the first adds a net +2 lines, so the second hunk's
    # new_start must be its old_start + 2.
    source = "\n".join([f"L{i}" for i in range(1, 21)] + [""])  # L1..L20
    ctx = {"src/f.c": source}
    patch = "\n".join(
        [
            "diff --git a/src/f.c b/src/f.c",
            "--- a/src/f.c",
            "+++ b/src/f.c",
            "@@ -1,1 +1,1 @@",       # hunk 1 at L2, net +2
            " L2",
            "+A",
            "+B",
            "@@ -1,1 +1,1 @@",       # hunk 2 at L15, expect new_start 15+2=17
            " L15",
            "+C",
            "",
        ]
    )
    res = normalize_backport_patch(patch, ctx)
    headers = [ln for ln in res.text.split("\n") if ln.startswith("@@")]
    # `,1` is omitted per GNU/git convention (git never emits it).
    assert headers[0] == "@@ -2 +2,3 @@"
    assert headers[1] == "@@ -15 +17,2 @@"


def test_package_nix_and_wrapper_untouched():
    # Out-of-context files (not in source_context) pass through byte-for-byte,
    # including a wrong-looking header that we must NOT touch.
    ctx = {"src/f.c": FLAT_SOURCE}
    patch = "\n".join(
        [
            "diff --git a/package.nix b/package.nix",
            "--- a/package.nix",
            "+++ b/package.nix",
            "@@ -999,1 +999,5 @@ stdenv.mkDerivation (finalAttrs: {",
            " x",
            "+  patches = [ ./cve.patch ];",
            "",
        ]
    )
    res = normalize_backport_patch(patch, ctx)
    assert not res.changed
    assert res.text == patch


# ─── nested (canonical) shape ────────────────────────────────────────────────


def _nested_patch(inner_header: str, outer_count: int) -> str:
    inner = [
        "diff --git a/src/f.c b/src/f.c",
        "--- a/src/f.c",
        "+++ b/src/f.c",
        inner_header,
        " \tif (bad) {",
        "-\t\tx = compute();",
        "+\t\tx = compute_safe();",
        " \t}",
    ]
    outer = [
        "diff --git a/cve.patch b/cve.patch",
        "new file mode 100644",
        "--- /dev/null",
        "+++ b/cve.patch",
        f"@@ -0,0 +1,{outer_count} @@",
        *["+" + ln for ln in inner],
        "diff --git a/package.nix b/package.nix",
        "--- a/package.nix",
        "+++ b/package.nix",
        "@@ -1,1 +1,2 @@",
        " a",
        "+  patches = [ ./cve.patch ];",
        "",
    ]
    return "\n".join(outer)


def test_nested_embedded_inner_header_normalized():
    ctx = {"src/f.c": FLAT_SOURCE}
    patch = _nested_patch("@@ -50,2 +50,2 @@", outer_count=8)
    res = normalize_backport_patch(patch, ctx)
    assert res.changed
    # Inner header fixed and re-embedded with the outer `+` prefix.
    assert "+@@ -3,3 +3,3 @@" in res.text
    assert "+@@ -50,2 +50,2 @@" not in res.text
    # Outer new-file count line preserved/recomputed (8 content lines).
    assert "@@ -0,0 +1,8 @@" in res.text
    # package.nix hunk untouched.
    assert "@@ -1,1 +1,2 @@" in res.text


def test_nested_correct_inner_header_idempotent():
    ctx = {"src/f.c": FLAT_SOURCE}
    patch = _nested_patch("@@ -3,3 +3,3 @@", outer_count=8)
    res = normalize_backport_patch(patch, ctx)
    assert not res.changed
    assert res.text == patch


# ─── real regression case ────────────────────────────────────────────────────


@pytest.mark.skipif(
    not (LIBARCHIVE / "source-context").is_dir(),
    reason="libarchive source-context fixture not present",
)
def test_libarchive_real_case_fixed_and_applies():
    ctx = _load_source_context(LIBARCHIVE)
    patch = (LIBARCHIVE / "patch.diff").read_text()
    res = normalize_backport_patch(patch, ctx)
    assert res.changed
    # Two arithmetic defects in the model output: the inner hunk header AND the
    # outer new-file line count (declared 32, actually 40 lines).
    assert len(res.rewrites) == 2
    by_file = {r["file"]: r for r in res.rewrites}
    inner = by_file["libarchive/archive_read_support_format_tar.c"]
    assert inner["from"].startswith("@@ -3517,13 +3517,13 @@")
    assert inner["to"].startswith("@@ -3443,16 +3443,16 @@")
    outer = by_file["CVE-2026-15028.patch"]
    assert outer["from"] == "@@ -0,0 +1,32 @@"
    assert outer["to"] == "@@ -0,0 +1,40 @@"
    # Second pass is a no-op.
    assert not normalize_backport_patch(res.text, ctx).changed


def test_deletion_line_beginning_with_dashdash_kept_in_body():
    # A deleted source line `-- keep` renders as `--- keep` in the diff and must
    # NOT be mistaken for a file header (codex slice-4 P1). The `--- ` boundary is
    # a file header only when the NEXT line is `+++ `; here it is followed by a
    # context line, so it stays in the body.
    source = "\n".join(["int g(void) {", "-- keep", "\treturn 0;", "}", ""])
    ctx = {"src/g.c": source}
    patch = "\n".join(
        [
            "diff --git a/src/g.c b/src/g.c",
            "--- a/src/g.c",
            "+++ b/src/g.c",
            "@@ -99,9 +99,9 @@",       # wrong start; recompute to line 1
            " int g(void) {",
            "--- keep",                # deletion of the `-- keep` source line
            " \treturn 0;",            # context (NOT a +++ header)
            "",
        ]
    )
    res = normalize_backport_patch(patch, ctx)
    # old-side = ["int g(void) {", "-- keep", "\treturn 0;"] matches at line 1;
    # new-side = the two context lines. => @@ -1,3 +1,2 @@
    assert "@@ -1,3 +1,2 @@" in res.text
    # The ambiguous deletion line is preserved verbatim in the body.
    assert "--- keep" in res.text


def test_embedded_outer_count_wrong_is_recorded_as_rewrite():
    # Inner headers correct, but the outer new-file count is wrong. The recompute
    # must be recorded so `changed`/provenance reflect it (codex slice-4 P2).
    ctx = {"src/f.c": FLAT_SOURCE}
    inner = [
        "--- a/src/f.c",
        "+++ b/src/f.c",
        "@@ -3,3 +3,3 @@",
        " \tif (bad) {",
        "-\t\tx = compute();",
        "+\t\tx = compute_safe();",
        " \t}",
    ]
    patch = "\n".join(
        [
            "diff --git a/cve.patch b/cve.patch",
            "new file mode 100644",
            "--- /dev/null",
            "+++ b/cve.patch",
            "@@ -0,0 +1,999 @@",  # WRONG count (should be 7)
            *["+" + ln for ln in inner],
            "",
        ]
    )
    res = normalize_backport_patch(patch, ctx)
    assert res.changed
    assert "@@ -0,0 +1,7 @@" in res.text
    assert any(r["to"] == "@@ -0,0 +1,7 @@" for r in res.rewrites)


def test_empty_patch_is_noop():
    assert normalize_backport_patch("", {}).text == ""
    assert not normalize_backport_patch("", {}).changed
