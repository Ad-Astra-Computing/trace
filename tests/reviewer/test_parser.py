"""Tests for agents.reviewer.parser.

Contract from prompts/reviewer.v1.md: exactly one of two response shapes.
The parser is strict — anything off-contract raises
ReviewerOutputMalformed with a specific diagnosis.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator

from agents.reviewer import (
    ReviewerOutputMalformed,
    parse_equivalence_verdict,
    parse_reviewer_output,
)
from tests.schema.validate import REPO_ROOT


SCHEMA_PATH = REPO_ROOT / "policy" / "reviewer-output-schema.json"


def _accept_review() -> str:
    return (
        "=== BEGIN review.md ===\n"
        "## Verdict\n"
        "accept\n"
        "\n"
        "## Reasoning\n"
        "The patch updates traefik 3.6.7 to 3.6.8 per upstream-ref.json.target_version. "
        "Both src.hash and vendorHash match prefetch_hashes[].value byte-for-byte.\n"
        "\n"
        "## Findings\n"
        "(none)\n"
        "\n"
        "## Cited evidence\n"
        "- upstream-ref.json:target_version=3.6.8\n"
        "- patch.diff\n"
        "- patch-rationale.md\n"
        "\n"
        "## Cross-family attestation\n"
        "reviewer_family: anthropic-sonnet\n"
        "patcher_family_observed: anthropic-opus\n"
        "rule_honored: true\n"
        "=== END review.md ==="
    )


def _reject_review() -> str:
    return (
        "=== BEGIN review.md ===\n"
        "## Verdict\n"
        "reject\n"
        "\n"
        "## Reasoning\n"
        "patch.diff emits a vendorHash value that does not appear in "
        "upstream-ref.json.prefetch_hashes; this would fail the build.\n"
        "\n"
        "## Findings\n"
        "- severity: blocking — vendorHash ungrounded — patch.diff:hunk=2\n"
        "- severity: medium — rationale claims sha256-Real... without quoting prefetch_hashes — patch-rationale.md:## Why minimal\n"
        "\n"
        "## Cited evidence\n"
        "- upstream-ref.json:prefetch_hashes\n"
        "- patch.diff:hunk=2\n"
        "\n"
        "## Cross-family attestation\n"
        "reviewer_family: anthropic-sonnet\n"
        "patcher_family_observed: anthropic-opus\n"
        "rule_honored: true\n"
        "=== END review.md ==="
    )


# ─── happy path ────────────────────────────────────────────────────────────


def test_accept_review_parses_clean() -> None:
    r = parse_reviewer_output(_accept_review())
    assert r.kind == "review"
    assert r.verdict == "accept"
    assert r.findings == []
    assert "patch.diff" in r.cited_evidence
    assert r.cross_family is not None
    assert r.cross_family.reviewer_family == "anthropic-sonnet"
    assert r.cross_family.patcher_family_observed == "anthropic-opus"
    assert r.cross_family.rule_honored is True
    assert r.raw_review_md is not None
    assert r.raw_review_md.endswith("\n")


def test_reject_review_parses_findings_with_severities() -> None:
    r = parse_reviewer_output(_reject_review())
    assert r.kind == "review"
    assert r.verdict == "reject"
    assert len(r.findings) == 2
    severities = [f.severity for f in r.findings]
    assert severities == ["blocking", "medium"]
    assert r.findings[0].title == "vendorHash ungrounded"
    assert r.findings[0].citation == "patch.diff:hunk=2"


def test_parsed_review_validates_against_schema() -> None:
    r = parse_reviewer_output(_reject_review())
    schema = json.loads(SCHEMA_PATH.read_text())
    validator = Draft202012Validator(schema)
    errors = ["/".join(str(p) for p in e.absolute_path) + ": " + e.message
             for e in validator.iter_errors(r.to_schema_dict())]
    assert not errors, errors


def test_accept_review_with_low_severity_findings_is_allowed() -> None:
    raw = _accept_review().replace(
        "## Findings\n(none)\n",
        "## Findings\n- severity: low — minor whitespace shift — patch.diff:line=14\n",
    )
    r = parse_reviewer_output(raw)
    assert r.verdict == "accept"
    assert len(r.findings) == 1
    assert r.findings[0].severity == "low"


def test_refusal_response_parses() -> None:
    raw = (
        "=== BEGIN refusal ===\n"
        "rule: 1\n"
        "reason: patch.diff missing from bundle dir\n"
        "=== END refusal ==="
    )
    r = parse_reviewer_output(raw)
    assert r.kind == "refusal"
    assert r.refusal_rule == 1
    assert "patch.diff missing" in r.refusal_reason


# ─── parser strictness — every off-contract output must fail loudly ────────


def test_rejects_empty_input() -> None:
    with pytest.raises(ReviewerOutputMalformed, match="empty"):
        parse_reviewer_output("")


def test_rejects_no_begin_marker() -> None:
    with pytest.raises(ReviewerOutputMalformed, match="no '=== BEGIN"):
        parse_reviewer_output("just some prose with no markers")


def test_rejects_preamble_before_begin_marker() -> None:
    raw = "Here is my review:\n" + _accept_review()
    with pytest.raises(ReviewerOutputMalformed, match="content before"):
        parse_reviewer_output(raw)


def test_rejects_trailing_prose_after_end_marker() -> None:
    raw = _accept_review() + "\n\nHope that helps!"
    with pytest.raises(ReviewerOutputMalformed, match="content after"):
        parse_reviewer_output(raw)


def test_rejects_invalid_verdict() -> None:
    raw = _accept_review().replace("accept\n", "approve\n", 1)
    with pytest.raises(ReviewerOutputMalformed, match="verdict must be one of"):
        parse_reviewer_output(raw)


def test_rejects_missing_required_heading() -> None:
    raw = _accept_review().replace(
        "## Cross-family attestation\n"
        "reviewer_family: anthropic-sonnet\n"
        "patcher_family_observed: anthropic-opus\n"
        "rule_honored: true\n",
        "",
    )
    with pytest.raises(ReviewerOutputMalformed, match="missing required level-2 headings"):
        parse_reviewer_output(raw)


def test_rejects_finding_with_invalid_severity() -> None:
    raw = _reject_review().replace("severity: blocking", "severity: critical")
    with pytest.raises(ReviewerOutputMalformed, match="severity must be one of"):
        parse_reviewer_output(raw)


def test_rejects_non_accept_verdict_with_none_findings() -> None:
    raw = _reject_review().replace(
        "## Findings\n"
        "- severity: blocking — vendorHash ungrounded — patch.diff:hunk=2\n"
        "- severity: medium — rationale claims sha256-Real... without quoting prefetch_hashes — patch-rationale.md:## Why minimal\n",
        "## Findings\n(none)\n",
    )
    with pytest.raises(ReviewerOutputMalformed, match="non-accept verdicts"):
        parse_reviewer_output(raw)


def test_rejects_accept_with_blocking_finding() -> None:
    raw = _accept_review().replace(
        "## Findings\n(none)\n",
        "## Findings\n- severity: blocking — sneaky issue — patch.diff:hunk=1\n",
    )
    with pytest.raises(ReviewerOutputMalformed, match="must trigger reject or escalate"):
        parse_reviewer_output(raw)


def test_rejects_empty_cited_evidence() -> None:
    raw = _accept_review().replace(
        "## Cited evidence\n"
        "- upstream-ref.json:target_version=3.6.8\n"
        "- patch.diff\n"
        "- patch-rationale.md\n",
        "## Cited evidence\n",
    )
    with pytest.raises(ReviewerOutputMalformed, match="at least one artifact"):
        parse_reviewer_output(raw)


def test_rejects_missing_cross_family_key() -> None:
    raw = _accept_review().replace(
        "patcher_family_observed: anthropic-opus\n",
        "",
    )
    with pytest.raises(ReviewerOutputMalformed, match="missing keys"):
        parse_reviewer_output(raw)


def test_rejects_invalid_rule_honored_value() -> None:
    raw = _accept_review().replace("rule_honored: true", "rule_honored: yes")
    with pytest.raises(ReviewerOutputMalformed, match="rule_honored must be"):
        parse_reviewer_output(raw)


def test_rejects_refusal_rule_out_of_range() -> None:
    raw = (
        "=== BEGIN refusal ===\n"
        "rule: 99\n"
        "reason: off-scale\n"
        "=== END refusal ==="
    )
    with pytest.raises(ReviewerOutputMalformed, match=r"\[1, 5\]"):
        parse_reviewer_output(raw)


def test_rejects_level_1_heading_in_review() -> None:
    raw = _accept_review().replace(
        "## Verdict\n", "# Big Heading\n## Verdict\n"
    )
    with pytest.raises(ReviewerOutputMalformed, match="level-1 heading"):
        parse_reviewer_output(raw)


def test_tolerates_wrapping_code_fence() -> None:
    """Some models (sonnet 4.6) wrap their entire response in ```...```.
    The fence is a formatting artifact; the parser strips it iff it
    wraps the whole response. Surfaced by the first live reviewer run
    on traefik 2026-04-27."""
    raw = "```\n" + _accept_review() + "\n```"
    r = parse_reviewer_output(raw)
    assert r.kind == "review"
    assert r.verdict == "accept"


def test_does_not_strip_unbalanced_code_fence() -> None:
    """An unbalanced wrap (only opening ```) must still be rejected;
    the regex requires both fences."""
    with pytest.raises(ReviewerOutputMalformed):
        parse_reviewer_output("```\n" + _accept_review())


def test_rejects_findings_out_of_order() -> None:
    """Sections must appear in the contracted order."""
    raw = (
        "=== BEGIN review.md ===\n"
        "## Verdict\naccept\n\n"
        "## Findings\n(none)\n\n"  # out of order: should be after Reasoning
        "## Reasoning\nthe patch is fine.\n\n"
        "## Cited evidence\n- patch.diff\n\n"
        "## Cross-family attestation\n"
        "reviewer_family: a\npatcher_family_observed: b\nrule_honored: true\n"
        "=== END review.md ==="
    )
    with pytest.raises(ReviewerOutputMalformed, match="out of contracted order"):
        parse_reviewer_output(raw)


# ─── parse_equivalence_verdict ──────────────────────────────────────────────


def test_parse_equivalence_verdict_extracts_token() -> None:
    section = "- equivalence: equivalent — same overflow invariant established"
    assert parse_equivalence_verdict(section) == "equivalent"


def test_parse_equivalence_verdict_lowercases() -> None:
    section = "- equivalence: Equivalent — mixed-case token"
    assert parse_equivalence_verdict(section) == "equivalent"


def test_parse_equivalence_verdict_strips_bold_emphasis() -> None:
    # Models routinely bold the value; the token is unambiguous.
    section = "- equivalence: **not-equivalent** — unresolved construct"
    assert parse_equivalence_verdict(section) == "not-equivalent"


def test_parse_equivalence_verdict_strips_code_and_italic() -> None:
    assert parse_equivalence_verdict("- equivalence: `equivalent` — x") == "equivalent"
    assert parse_equivalence_verdict("- equivalence: *indeterminate* — y") == "indeterminate"


def test_parse_equivalence_verdict_returns_none_for_none() -> None:
    assert parse_equivalence_verdict(None) is None


def test_parse_equivalence_verdict_returns_none_for_empty_string() -> None:
    assert parse_equivalence_verdict("") is None


def test_parse_equivalence_verdict_returns_none_when_no_equivalence_line() -> None:
    section = (
        "- unsafe operation: unchecked multiply\n"
        "- behavior preserved: yes\n"
    )
    assert parse_equivalence_verdict(section) is None


def test_parse_equivalence_verdict_takes_first_line() -> None:
    """A section with two `equivalence:` lines (malformed input, but the
    helper doesn't validate structure) returns the FIRST one."""
    section = (
        "- equivalence: equivalent — first token\n"
        "- equivalence: not-equivalent — should not be picked\n"
    )
    assert parse_equivalence_verdict(section) == "equivalent"


def test_parse_equivalence_verdict_returns_raw_token_for_unrecognized_value() -> None:
    """The helper does not validate against VALID_EQUIVALENCE_VALUES; the
    caller decides what to do with an out-of-enum token."""
    section = "- equivalence: maybe — unrecognized token"
    assert parse_equivalence_verdict(section) == "maybe"


def test_parse_equivalence_verdict_ignores_substring_field() -> None:
    """A different field that merely CONTAINS 'equivalence:' as a substring
    (e.g. `non-equivalence:`) is not an equivalence declaration."""
    assert parse_equivalence_verdict("- non-equivalence: equivalent — trap") is None
    assert parse_equivalence_verdict("summary of equivalence: equivalent") is None


def test_parse_equivalence_verdict_bare_field_no_bullet() -> None:
    """The list-marker prefix is optional."""
    assert parse_equivalence_verdict("equivalence: not-equivalent") == "not-equivalent"


def test_parse_equivalence_verdict_field_with_no_value() -> None:
    assert parse_equivalence_verdict("- equivalence:") is None
