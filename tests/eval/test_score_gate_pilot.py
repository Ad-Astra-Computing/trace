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
