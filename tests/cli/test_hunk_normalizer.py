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
    CanonicalizationResult,
    HunkNormalizationError,
    NormalizationResult,
    canonicalize_backport_patch,
    normalize_backport_patch,
)

REPO_ROOT = Path(__file__).resolve().parents[2]
LIBARCHIVE = REPO_ROOT / "traces/example/CVE-2026-15028--libarchive-tar-atol-oob-backport"
MAXIMA = REPO_ROOT / "traces/drafts/CVE-2024-34490--maxima-plot-tempfile-backport"


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


# ─── bare / rangeless hunk headers (maxima CVE-2024-34490 shape) ──────────────
#
# opus-4-7 on the adaptation lane emitted a nested in-tree `.patch` whose inner
# hunk headers were BARE `@@` with no `-l,s +l,s` ranges at all. `_HUNK_HEADER_RE`
# requires numeric ranges, so before this the normalizer did not recognize the
# lines as headers: nested detection failed (`has_hunk` False), the content passed
# through untouched, and GNU `patch` rejected the artifact ("only garbage"). The
# normalizer must synthesize the full header from the body + pinned source.


def _flat_patch_bare(header: str = "@@") -> str:
    """FLAT_SOURCE one-hunk diff whose hunk header is bare/rangeless."""
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


def test_flat_bare_header_synthesized():
    ctx = {"src/f.c": FLAT_SOURCE}
    res = normalize_backport_patch(_flat_patch_bare("@@"), ctx)
    assert res.changed
    assert "@@ -3,3 +3,3 @@" in res.text
    # The bare marker is gone.
    assert not any(ln.strip() == "@@" for ln in res.text.split("\n"))
    assert res.rewrites[0]["from"] == "@@"
    assert res.rewrites[0]["to"] == "@@ -3,3 +3,3 @@"


def test_flat_bare_double_at_header_synthesized():
    # Some models emit `@@ @@` (empty range block). Same synthesis path.
    ctx = {"src/f.c": FLAT_SOURCE}
    res = normalize_backport_patch(_flat_patch_bare("@@ @@"), ctx)
    assert res.changed
    assert "@@ -3,3 +3,3 @@" in res.text


def test_nested_bare_inner_header_synthesized():
    # The real maxima shape: nested `.patch`, inner header bare `@@`.
    ctx = {"src/f.c": FLAT_SOURCE}
    inner = [
        "--- a/src/f.c",
        "+++ b/src/f.c",
        "@@",
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
            f"@@ -0,0 +1,{len(inner)} @@",
            *["+" + ln for ln in inner],
            "",
        ]
    )
    res = normalize_backport_patch(patch, ctx)
    assert res.changed
    assert "+@@ -3,3 +3,3 @@" in res.text
    # No bare inner header survives.
    assert "+@@\n" in patch  # sanity: the input really had a bare inner header
    assert not any(ln == "+@@" for ln in res.text.split("\n"))
    # Second pass is a no-op (idempotent once ranges are synthesized).
    assert not normalize_backport_patch(res.text, ctx).changed


def test_bare_header_ungroundable_still_fails_loud():
    # A bare header whose body is not in the pinned source must still fail closed,
    # not silently synthesize a bogus range.
    ctx = {"src/f.c": FLAT_SOURCE}
    patch = "\n".join(
        [
            "diff --git a/src/f.c b/src/f.c",
            "--- a/src/f.c",
            "+++ b/src/f.c",
            "@@",
            " \tif (nonexistent) {",
            "-\t\tx = compute();",
            "+\t\tx = compute_safe();",
            " \t}",
            "",
        ]
    )
    with pytest.raises(HunkNormalizationError, match="does not match the pinned source"):
        normalize_backport_patch(patch, ctx)


# ─── canonical compilation ───────────────────────────────────────────────────
#
# The model authors non-canonical bodies (redundant delete+re-add of unchanged
# lines, missing trailing context) that GNU patch rejects at default fuzz even
# with correct headers. canonicalize_backport_patch reconstructs the postimage from
# the model's body and re-diffs against the pinned source, producing an applying
# patch. It never changes meaning — only representation.

# Source where two change sites are separated by >2*context unchanged lines, so a
# single model spanning-hunk must re-split into two canonical hunks (maxima shape).
SPANNED_SOURCE = "\n".join(
    [
        "int f(void) {",     # 1
        "\tint a = bad1();",  # 2  <- change site 1
        "\tint b = 0;",       # 3
        "\tint c = 0;",       # 4
        "\tint d = 0;",       # 5
        "\tint e = 0;",       # 6
        "\tint g = 0;",       # 7
        "\treturn bad2();",   # 8  <- change site 2
        "}",                  # 9
        "",
    ]
)


def test_canonicalize_redundant_deladd_and_missing_trailing_context():
    # The exact defect class from maxima: a single model hunk that (a) uses a BARE
    # header, (b) redundantly deletes+re-adds an identical line, (c) has no trailing
    # context. Canonicalization must drop the redundant del/readd and split as needed.
    ctx = {"src/f.c": SPANNED_SOURCE}
    inner = [
        "--- a/src/f.c",
        "+++ b/src/f.c",
        "@@",                       # bare header
        " int f(void) {",
        "-\tint a = bad1();",
        "+\tint a = safe1();",
        " \tint b = 0;",
        " \tint c = 0;",
        " \tint d = 0;",
        " \tint e = 0;",
        " \tint g = 0;",
        "-\treturn bad2();",        # change site 2
        "+\treturn safe2();",
        "-}",                       # redundant: `}` deleted AND re-added identically
        "+}",
    ]
    patch = "\n".join(
        [
            "diff --git a/cve.patch b/cve.patch",
            "new file mode 100644",
            "--- /dev/null",
            "+++ b/cve.patch",
            f"@@ -0,0 +1,{len(inner)} @@",
            *["+" + ln for ln in inner],
            "",
        ]
    )
    res = canonicalize_backport_patch(patch, ctx)
    assert res.changed
    assert len(res.files) == 1
    assert res.files[0]["file"] == "src/f.c"
    # The redundant `}` del/readd is eliminated — no `+-}` / `++}` pair survives.
    text = res.text
    assert "+-}" not in text
    # Both real changes are present, re-embedded under the outer `+`.
    assert "+-\tint a = bad1();" in text
    assert "++\tint a = safe1();" in text
    assert "+-\treturn bad2();" in text
    # Idempotent: recompiling the canonical output is a fixpoint.
    assert canonicalize_backport_patch(res.text, ctx).text == res.text


def test_canonicalize_flat_shape():
    ctx = {"src/f.c": FLAT_SOURCE}
    patch = "\n".join(
        [
            "diff --git a/src/f.c b/src/f.c",
            "--- a/src/f.c",
            "+++ b/src/f.c",
            "@@",  # bare header, flat (no wrapper .patch)
            " \tif (bad) {",
            "-\t\tx = compute();",
            "+\t\tx = compute_safe();",
            " \t}",
            "",
        ]
    )
    res = canonicalize_backport_patch(patch, ctx)
    assert res.changed
    assert "diff --git a/src/f.c b/src/f.c" in res.text
    # Canonical header carries real ranges.
    assert any(ln.startswith("@@ -") and " +" in ln for ln in res.text.split("\n"))


def test_canonicalize_package_nix_passthrough():
    ctx = {"src/f.c": FLAT_SOURCE}
    patch = "\n".join(
        [
            "diff --git a/package.nix b/package.nix",
            "--- a/package.nix",
            "+++ b/package.nix",
            "@@ -1,1 +1,2 @@",
            " a",
            "+  patches = [ ./cve.patch ];",
            "",
        ]
    )
    res = canonicalize_backport_patch(patch, ctx)
    assert not res.changed
    assert res.text == patch


def test_canonicalize_addition_line_not_mistaken_for_file_header():
    # A package.nix section adds a line whose CONTENT begins with `++` (rendered as
    # `+++ src/f.c`). It must not be mistaken for a source-file header and misrouted;
    # the section targets package.nix (out of source-context) and passes through.
    ctx = {"src/f.c": FLAT_SOURCE}
    patch = "\n".join(
        [
            "diff --git a/package.nix b/package.nix",
            "--- a/package.nix",
            "+++ b/package.nix",
            "@@ -1,1 +1,2 @@",
            " a",
            "+++ src/f.c",  # body addition of a line whose content is `++ src/f.c`
            "",
        ]
    )
    res = canonicalize_backport_patch(patch, ctx)
    assert not res.changed
    assert res.text == patch


def test_canonicalize_ungroundable_fails_loud():
    ctx = {"src/f.c": FLAT_SOURCE}
    patch = "\n".join(
        [
            "diff --git a/src/f.c b/src/f.c",
            "--- a/src/f.c",
            "+++ b/src/f.c",
            "@@",
            " \tif (nonexistent) {",
            "-\t\tx = compute();",
            "+\t\tx = compute_safe();",
            " \t}",
            "",
        ]
    )
    with pytest.raises(HunkNormalizationError, match="does not match the pinned source"):
        canonicalize_backport_patch(patch, ctx)


def test_canonicalize_empty_is_noop():
    assert canonicalize_backport_patch("", {}).text == ""
    assert not canonicalize_backport_patch("", {}).changed


def test_canonicalize_rejects_non_newline_terminated_source():
    # A pinned source without a trailing newline cannot be canonicalized losslessly
    # (EOF-newline state) — fail closed rather than risk postimage drift.
    ctx = {"src/f.c": "    l = l * base;"}  # no trailing newline
    patch = "\n".join(
        [
            "diff --git a/src/f.c b/src/f.c",
            "--- a/src/f.c",
            "+++ b/src/f.c",
            "@@ -1 +1 @@",
            "-    l = l * base;",
            "+    l = safe(l);",
            "",
        ]
    )
    with pytest.raises(HunkNormalizationError, match="not newline-terminated"):
        canonicalize_backport_patch(patch, ctx)


def test_canonicalize_flat_repeated_same_file_sections_grouped():
    # Two separate `diff --git` sections target the same file with changes at
    # different sites. Compiled together they must both survive in one postimage;
    # compiled independently the second would still expect the original preimage.
    ctx = {"src/f.c": SPANNED_SOURCE}
    patch = "\n".join(
        [
            "diff --git a/src/f.c b/src/f.c",
            "--- a/src/f.c",
            "+++ b/src/f.c",
            "@@",  # bare header, change site 1
            " int f(void) {",
            "-\tint a = bad1();",
            "+\tint a = safe1();",
            " \tint b = 0;",
            "diff --git a/src/f.c b/src/f.c",  # SECOND section, same file
            "--- a/src/f.c",
            "+++ b/src/f.c",
            "@@",  # change site 2
            " \tint g = 0;",
            "-\treturn bad2();",
            "+\treturn safe2();",
            " }",
            "",
        ]
    )
    res = canonicalize_backport_patch(patch, ctx)
    assert res.changed
    # One combined provenance record for the file (not two independent compiles).
    assert len(res.files) == 1
    assert res.files[0]["file"] == "src/f.c"
    # Both changes present in the single canonical output.
    assert "+\tint a = safe1();" in res.text
    assert "+\treturn safe2();" in res.text
    # Exactly one `diff --git` for the file (headers derived from the compiled diff).
    assert res.text.count("diff --git a/src/f.c b/src/f.c") == 1
    # Idempotent fixpoint.
    assert canonicalize_backport_patch(res.text, ctx).text == res.text


def test_canonicalize_context_only_overlap_is_merged():
    # Two hunks change distinct lines (b, d) but each repeats the shared line c as
    # context, so their matched old-side ranges overlap. This is a non-conflicting
    # representation: the cores are disjoint and both edits must survive.
    src = "\n".join(["a", "b", "c", "d", "e", ""])
    ctx = {"src/f.c": src}
    inner = [
        "--- a/src/f.c",
        "+++ b/src/f.c",
        "@@",
        " a",
        "-b",
        "+B",
        " c",
        "--- a/src/f.c",
        "+++ b/src/f.c",
        "@@",
        " c",
        "-d",
        "+D",
        " e",
    ]
    patch = "\n".join(
        [
            "diff --git a/cve.patch b/cve.patch",
            "new file mode 100644",
            "--- /dev/null",
            "+++ b/cve.patch",
            f"@@ -0,0 +1,{len(inner)} @@",
            *["+" + ln for ln in inner],
            "",
        ]
    )
    res = canonicalize_backport_patch(patch, ctx)
    assert res.changed
    assert "+-b" in res.text and "++B" in res.text
    assert "+-d" in res.text and "++D" in res.text
    assert canonicalize_backport_patch(res.text, ctx).text == res.text


def test_canonicalize_boundary_insertion_and_replacement_order_independent():
    # A replacement of a line and an insertion immediately before it are compatible.
    # The model authored them replacement-first (the order that naively conflicts):
    # a zero-length insertion must order before the same-start replacement.
    src = "\n".join(["a", "b", "c", ""])
    ctx = {"src/f.c": src}
    inner = [
        "--- a/src/f.c",
        "+++ b/src/f.c",
        "@@",  # replacement: b -> B
        " a",
        "-b",
        "+B",
        " c",
        "--- a/src/f.c",
        "+++ b/src/f.c",
        "@@",  # insertion: I before b
        " a",
        "+I",
        " b",
    ]
    patch = "\n".join(
        [
            "diff --git a/cve.patch b/cve.patch",
            "new file mode 100644",
            "--- /dev/null",
            "+++ b/cve.patch",
            f"@@ -0,0 +1,{len(inner)} @@",
            *["+" + ln for ln in inner],
            "",
        ]
    )
    res = canonicalize_backport_patch(patch, ctx)
    assert res.changed
    # Both edits survive: I inserted before b, b replaced by B.
    assert "++I" in res.text
    assert "++B" in res.text
    assert "+-b" in res.text
    assert canonicalize_backport_patch(res.text, ctx).text == res.text


def test_canonicalize_conflicting_edits_rejected():
    # Two hunks both change the SAME source line to different values — a real
    # conflict. Cores overlap, so canonicalization fails closed.
    src = "\n".join(["a", "b", "c", ""])
    ctx = {"src/f.c": src}
    inner = [
        "--- a/src/f.c",
        "+++ b/src/f.c",
        "@@",
        " a",
        "-b",
        "+B",
        " c",
        "--- a/src/f.c",
        "+++ b/src/f.c",
        "@@",
        " a",
        "-b",
        "+X",
        " c",
    ]
    patch = "\n".join(
        [
            "diff --git a/cve.patch b/cve.patch",
            "new file mode 100644",
            "--- /dev/null",
            "+++ b/cve.patch",
            f"@@ -0,0 +1,{len(inner)} @@",
            *["+" + ln for ln in inner],
            "",
        ]
    )
    with pytest.raises(HunkNormalizationError, match="conflicting"):
        canonicalize_backport_patch(patch, ctx)


def test_canonicalize_rejects_git_metadata_directive():
    # A mode change / rename carries semantics canonicalization can't reconstruct
    # (it emits only ---/+++/@@). Fail closed rather than silently drop it.
    ctx = {"src/f.c": FLAT_SOURCE}
    patch = "\n".join(
        [
            "diff --git a/src/f.c b/src/f.c",
            "old mode 100644",
            "new mode 100755",
            "--- a/src/f.c",
            "+++ b/src/f.c",
            "@@ -3,3 +3,3 @@",
            " \tif (bad) {",
            "-\t\tx = compute();",
            "+\t\tx = compute_safe();",
            " \t}",
            "",
        ]
    )
    with pytest.raises(HunkNormalizationError, match="git metadata directive"):
        canonicalize_backport_patch(patch, ctx)


def test_canonicalize_rejects_no_newline_marker():
    # A `\ No newline at end of file` marker in the model's diff is an EOF-newline
    # change canonicalization can't model — fail closed.
    ctx = {"src/f.c": FLAT_SOURCE}
    patch = "\n".join(
        [
            "diff --git a/src/f.c b/src/f.c",
            "--- a/src/f.c",
            "+++ b/src/f.c",
            "@@ -3,3 +3,3 @@",
            " \tif (bad) {",
            "-\t\tx = compute();",
            "+\t\tx = compute_safe();",
            "\\ No newline at end of file",
            " \t}",
            "",
        ]
    )
    with pytest.raises(HunkNormalizationError, match="No newline at end of file"):
        canonicalize_backport_patch(patch, ctx)


@pytest.mark.skipif(
    not (MAXIMA / "patch.diff").is_file() or not (MAXIMA / "source-context").is_dir(),
    reason="maxima draft fixture not present",
)
def test_canonicalize_maxima_real_case_applies():
    # The real opus-4-7 adaptation: bare inner headers + redundant del/readd +
    # missing trailing context + a merged spanning hunk. Canonicalization must
    # produce a patch that applies (verified by the compiler's own fuzz-0 self-apply
    # invariant, which raises on any mismatch).
    ctx = _load_source_context(MAXIMA)
    patch = (MAXIMA / "patch.diff").read_text()
    res = canonicalize_backport_patch(patch, ctx)
    assert res.changed
    by_file = {r["file"]: r for r in res.files}
    # All three touched lisp files compiled.
    assert set(by_file) == {"src/plot.lisp", "src/gnuplot_def.lisp", "src/xmaxima_def.lisp"}
    # The merged spanning hunk in plot.lisp re-splits into multiple canonical hunks.
    assert by_file["src/plot.lisp"]["canonical_hunks"] >= 2
    # Idempotent fixpoint.
    assert canonicalize_backport_patch(res.text, ctx).text == res.text
