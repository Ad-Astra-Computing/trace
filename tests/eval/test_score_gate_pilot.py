"""Tests for eval/score_gate_pilot.py diagnostics."""

from __future__ import annotations

import importlib.util
from pathlib import Path

_spec = importlib.util.spec_from_file_location(
    "score_gate_pilot",
    Path(__file__).resolve().parents[2] / "eval" / "score_gate_pilot.py",
)
sgp = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(sgp)


def _pilot_rec(patch_diff_body: str) -> dict:
    """A minimal pilot record whose user turn carries a `# patch.diff` block."""
    user = (
        "# finding.json\n{...}\n"
        "# patch.diff\n"
        f"{patch_diff_body}\n"
        "# upstream-fix.patch\n+ j = 0;\n++ k = 0;\n"
    )
    return {"messages": [{"role": "user", "content": user}]}


# patch.diff has j=0 (context) THEN k=0 (added) — the libxmp shape.
_PATCH = "@@ -232,5 +231,6 @@\n  j = 0;\n++ k = 0;\n  for (i = 0;...) {"


def test_extraction_order_error_flagged_when_added_listed_before_context():
    # Model lists `+ k = 0;` BEFORE ` j = 0;` — reversed from file order.
    generated = (
        "## patch.diff extraction\n"
        "hunk 3:\n"
        "- `+ k = 0;`\n"
        "- ` j = 0;`\n"
        "- critical token window: `k = 0;` (reset)\n"
        "## upstream-fix.patch extraction\n"
    )
    err = sgp.check_pc_extraction_order(generated, _pilot_rec(_PATCH))
    assert err is not None
    assert "out of file order" in err
    assert "j = 0;" in err


def test_extraction_in_file_order_is_clean():
    # Model lists ` j = 0;` THEN `+ k = 0;` — matches file order.
    generated = (
        "## patch.diff extraction\n"
        "hunk 3:\n"
        "- ` j = 0;`\n"
        "- `+ k = 0;`\n"
        "- critical token window: `j = 0;` (reset)\n"
        "## upstream-fix.patch extraction\n"
    )
    assert sgp.check_pc_extraction_order(generated, _pilot_rec(_PATCH)) is None


def test_extraction_order_no_section_returns_none():
    generated = "## Verdict\naccept\n## Reasoning\nlooks fine\n"
    assert sgp.check_pc_extraction_order(generated, _pilot_rec(_PATCH)) is None


def _pilot_rec_block(patch_diff_body: str) -> dict:
    user = f"# finding.json\n{{...}}\n# patch.diff\n{patch_diff_body}\n# upstream-fix.patch\n+ guard;\n"
    return {"messages": [{"role": "user", "content": user}]}


def test_role_grounding_flags_removed_line_quoted_as_added():
    # Embedded patch DELETES the guard (`+-` = embedded removed). Model quotes it
    # under a `+` extraction marker as if the patch applied it.
    patch = (
        "@@ -0,0 +1,4 @@\n"
        "+@@ -764,3 +764,2 @@\n"
        "+ if (copy) {\n"
        "+-        (len = x) < extra_max) {\n"
        "++        unguarded;\n"
    )
    generated = (
        "## patch.diff extraction\n"
        "- `+ (len = x) < extra_max) {`\n"
        "## upstream-fix.patch extraction\n"
    )
    err = sgp.check_pc_role_grounding(generated, _pilot_rec_block(patch))
    assert err is not None
    assert "REMOVED" in err


def test_role_grounding_clean_when_line_is_genuinely_added():
    patch = (
        "@@ -0,0 +1,3 @@\n"
        "+@@ -764,2 +764,3 @@\n"
        "+ if (copy) {\n"
        "++        (len = x) < extra_max) {\n"
    )
    generated = (
        "## patch.diff extraction\n"
        "- `+ (len = x) < extra_max) {`\n"
        "## upstream-fix.patch extraction\n"
    )
    assert sgp.check_pc_role_grounding(generated, _pilot_rec_block(patch)) is None


def test_extraction_order_absent_line_not_flagged_as_order():
    # A quoted line absent from patch.diff is a grounding concern, not an order
    # one — check_pc_extraction_order must stay silent on it.
    generated = (
        "## patch.diff extraction\n"
        "- ` j = 0;`\n"
        "- `+ totally_absent_line();`\n"
        "## upstream-fix.patch extraction\n"
    )
    assert sgp.check_pc_extraction_order(generated, _pilot_rec(_PATCH)) is None


# --- check_pc_omission_claim (v1.11 quote-then-contradict) -------------------
#
# Reproduces the v1.10 held-out compound-guard probe failure: the model quotes
# the full multi-conjunct guard in its own patch.diff extraction, then asserts
# in prose that patch.diff omits one conjunct -> FALSE REJECT on a clean
# unseen-family positive (ffmpeg CVE-2023-49502).

_FFMPEG_GUARD = (
    "AV_CEIL_RSHIFT(link->w, desc->log2_chroma_w) < 3 || "
    "AV_CEIL_RSHIFT(link->h, desc->log2_chroma_h) < 4"
)


def test_omission_claim_flags_quote_then_contradict():
    generated = (
        "## patch.diff extraction\n"
        f"- `+    if ({_FFMPEG_GUARD})`\n"
        "## upstream-fix extraction\n"
        f"- `+    if ({_FFMPEG_GUARD})`\n"
        "## Patch comparison\n"
        "comparison: mismatch — patch.diff omits the height conjunct "
        "`AV_CEIL_RSHIFT(link->h, desc->log2_chroma_h) < 4`\n"
        "## Findings\nverdict: reject\n"
    )
    err = sgp.check_pc_omission_claim(generated)
    assert err is not None
    assert "omits" in err


def test_omission_claim_silent_on_genuine_dropped_conjunct():
    # The conjunct really is absent from the extraction: a true negative that
    # must still reject. The check must NOT fire here.
    generated = (
        "## patch.diff extraction\n"
        "- `+    if (AV_CEIL_RSHIFT(link->w, desc->log2_chroma_w) < 3)`\n"
        "## Patch comparison\n"
        "comparison: mismatch — patch.diff omits "
        "`AV_CEIL_RSHIFT(link->h, desc->log2_chroma_h) < 4`\n"
        "## Findings\nverdict: reject\n"
    )
    assert sgp.check_pc_omission_claim(generated) is None


def test_omission_claim_silent_on_clean_accept():
    generated = (
        "## patch.diff extraction\n"
        "- `+    if (a && b)`\n"
        "## Patch comparison\ncomparison: match\n"
        "## Findings\nverdict: accept\n"
    )
    assert sgp.check_pc_omission_claim(generated) is None


def test_omission_claim_silent_on_unquoted_hedged_claim():
    # No backticked token -> conservative: never flag.
    generated = (
        "## patch.diff extraction\n"
        "- `+    if (a && b)`\n"
        "## Patch comparison\n"
        "comparison: mismatch — the patch appears to omit a conjunct\n"
        "## Findings\nverdict: reject\n"
    )
    assert sgp.check_pc_omission_claim(generated) is None


def test_omission_claim_silent_without_extraction_section():
    assert sgp.check_pc_omission_claim("no sections here; omits `x && y`") is None
