"""Review rubric: schema validation + aggregation tests.

Two layers:

1. Shape: schema well-formed; example-review.json validates; conditional
   requirements fire (primary_rejection_reason required when decision != merge;
   example_reason required when is_example=true).

2. Aggregation: summarize() on canned inputs produces the documented fields
   with deterministic values. Covers decision counts, confidence mean, time
   median, external-access percent, rejection-reason counts, pairwise percent
   agreement on decision. Example-exclusion behavior tested directly on
   load_reviews().
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
from jsonschema import Draft202012Validator

from tests.schema.validate import REPO_ROOT
from tools.trace_cli.review import emit_summary, load_reviews, summarize


SCHEMA_PATH = REPO_ROOT / "policy" / "review-rubric-schema.json"
EXAMPLE_REVIEW_PATH = REPO_ROOT / "eval" / "reviews" / "example-review.json"


@pytest.fixture(scope="module")
def schema() -> dict[str, Any]:
    return json.loads(SCHEMA_PATH.read_text())


@pytest.fixture(scope="module")
def validator(schema) -> Draft202012Validator:
    return Draft202012Validator(schema)


# ─── shape ──────────────────────────────────────────────────────────────────


def test_schema_is_well_formed(schema):
    Draft202012Validator.check_schema(schema)


def test_example_review_validates(validator):
    doc = json.loads(EXAMPLE_REVIEW_PATH.read_text())
    errors = [e.message for e in validator.iter_errors(doc)]
    assert not errors, f"example review failed schema: {errors}"


def test_merge_decision_rejects_rejection_reason(validator):
    doc = {
        "schema_version": "1.0.0",
        "cve_id": "CVE-2026-12345",
        "bundle_id": "0123456789abcdef",
        "panelist_id": "p1",
        "reviewed_at": "2026-04-23T00:00:00Z",
        "decision": "merge",
        "confidence": 5,
        "time_to_decision_seconds": 30,
        "needed_external_access": False,
        "missing_evidence": [],
        "primary_rejection_reason": "patch-incorrect",
        "is_example": False,
    }
    errors = list(validator.iter_errors(doc))
    assert errors, "schema should forbid primary_rejection_reason on merge decision"


def test_non_merge_decision_requires_rejection_reason(validator):
    doc = {
        "schema_version": "1.0.0",
        "cve_id": "CVE-2026-12345",
        "bundle_id": "0123456789abcdef",
        "panelist_id": "p1",
        "reviewed_at": "2026-04-23T00:00:00Z",
        "decision": "reject",
        "confidence": 4,
        "time_to_decision_seconds": 120,
        "needed_external_access": True,
        "missing_evidence": ["no reproducer"],
        "is_example": False,
    }
    errors = [e.message for e in validator.iter_errors(doc)]
    assert any("primary_rejection_reason" in m for m in errors), (
        f"schema should require primary_rejection_reason on non-merge decisions; got errors={errors}"
    )


def test_is_example_requires_example_reason(validator):
    doc = json.loads(EXAMPLE_REVIEW_PATH.read_text())
    del doc["example_reason"]
    errors = [e.message for e in validator.iter_errors(doc)]
    assert any("example_reason" in m for m in errors)


# ─── load_reviews: example exclusion ────────────────────────────────────────


def _write(tmp_path: Path, name: str, doc: dict[str, Any]) -> Path:
    p = tmp_path / name
    p.write_text(json.dumps(doc))
    return p


def _mk_review(**overrides: Any) -> dict[str, Any]:
    base = {
        "schema_version": "1.0.0",
        "cve_id": "CVE-2026-12345",
        "bundle_id": "0123456789abcdef",
        "panelist_id": "p1",
        "reviewed_at": "2026-04-23T00:00:00Z",
        "decision": "merge",
        "confidence": 4,
        "time_to_decision_seconds": 60,
        "needed_external_access": False,
        "missing_evidence": [],
        "is_example": False,
    }
    base.update(overrides)
    return base


def test_load_reviews_skips_examples_by_default(tmp_path):
    _write(tmp_path, "real.json", _mk_review(panelist_id="p1"))
    _write(tmp_path, "example.json", _mk_review(
        panelist_id="px", is_example=True, example_reason="seed"
    ))
    loaded = load_reviews(tmp_path)
    assert len(loaded) == 1
    assert loaded[0]["panelist_id"] == "p1"


def test_load_reviews_include_examples_flag(tmp_path):
    _write(tmp_path, "real.json", _mk_review(panelist_id="p1"))
    _write(tmp_path, "example.json", _mk_review(
        panelist_id="px", is_example=True, example_reason="seed"
    ))
    loaded = load_reviews(tmp_path, include_examples=True)
    assert len(loaded) == 2


def test_load_reviews_bundle_filter(tmp_path):
    _write(tmp_path, "a.json", _mk_review(panelist_id="p1", bundle_id="aaaaaaaaaaaaaaaa"))
    _write(tmp_path, "b.json", _mk_review(panelist_id="p2", bundle_id="bbbbbbbbbbbbbbbb"))
    loaded = load_reviews(tmp_path, bundle_filter="aaaaaaaaaaaaaaaa")
    assert len(loaded) == 1
    assert loaded[0]["bundle_id"] == "aaaaaaaaaaaaaaaa"


def test_load_reviews_missing_directory_raises(tmp_path):
    with pytest.raises(FileNotFoundError):
        load_reviews(tmp_path / "does-not-exist")


# ─── summarize: deterministic aggregation ───────────────────────────────────


def test_summarize_empty_is_safe():
    summary = summarize([])
    assert summary["count"] == 0
    assert summary["confidence_mean"] is None
    assert summary["time_to_decision_seconds_median"] is None
    assert summary["percent_needed_external_access"] is None
    assert summary["percent_agreement_on_decision"] is None
    assert summary["decisions"] == {"merge": 0, "reject": 0, "escalate": 0}


def test_summarize_counts_decisions_and_means():
    reviews = [
        _mk_review(panelist_id="p1", confidence=5, time_to_decision_seconds=30,
                   needed_external_access=False, decision="merge"),
        _mk_review(panelist_id="p2", confidence=3, time_to_decision_seconds=90,
                   needed_external_access=True, decision="reject",
                   primary_rejection_reason="reproducer-unconvincing"),
        _mk_review(panelist_id="p3", confidence=4, time_to_decision_seconds=60,
                   needed_external_access=True, decision="escalate",
                   primary_rejection_reason="blast-radius"),
        _mk_review(panelist_id="p4", confidence=2, time_to_decision_seconds=120,
                   needed_external_access=False, decision="reject",
                   primary_rejection_reason="reproducer-unconvincing"),
    ]
    s = summarize(reviews)
    assert s["count"] == 4
    assert s["decisions"] == {"merge": 1, "reject": 2, "escalate": 1}
    assert s["confidence_mean"] == pytest.approx((5 + 3 + 4 + 2) / 4)
    # Median of [30, 60, 90, 120] = (60+90)/2 = 75
    assert s["time_to_decision_seconds_median"] == pytest.approx(75)
    # 2 of 4 needed external access
    assert s["percent_needed_external_access"] == pytest.approx(50.0)
    assert s["primary_rejection_reasons"] == {
        "reproducer-unconvincing": 2,
        "blast-radius": 1,
    }


def test_summarize_agreement_per_bundle():
    """Agreement is computed per-bundle over pairs of reviews; bundles with only one review contribute zero pairs."""
    reviews = [
        # bundle A: 3 reviewers, 2 merge + 1 reject -> 3 pairs, 1 agreeing
        _mk_review(panelist_id="p1", bundle_id="aaaaaaaaaaaaaaaa", decision="merge"),
        _mk_review(panelist_id="p2", bundle_id="aaaaaaaaaaaaaaaa", decision="merge"),
        _mk_review(panelist_id="p3", bundle_id="aaaaaaaaaaaaaaaa", decision="reject",
                   primary_rejection_reason="patch-incorrect"),
        # bundle B: 2 reviewers, both escalate -> 1 pair, 1 agreeing
        _mk_review(panelist_id="p1", bundle_id="bbbbbbbbbbbbbbbb", decision="escalate",
                   primary_rejection_reason="other"),
        _mk_review(panelist_id="p2", bundle_id="bbbbbbbbbbbbbbbb", decision="escalate",
                   primary_rejection_reason="other"),
        # bundle C: 1 reviewer, no pair, ignored
        _mk_review(panelist_id="p1", bundle_id="cccccccccccccccc", decision="merge"),
    ]
    s = summarize(reviews)
    # total pairs = 3 (bundle A) + 1 (bundle B) = 4. Agreeing = 1 + 1 = 2. 50%.
    assert s["bundles_with_multiple_reviews"] == 2
    assert s["percent_agreement_on_decision"] == pytest.approx(50.0)


def test_summarize_agreement_none_when_no_multi_review_bundles():
    reviews = [
        _mk_review(panelist_id="p1", bundle_id="aaaaaaaaaaaaaaaa", decision="merge"),
        _mk_review(panelist_id="p2", bundle_id="bbbbbbbbbbbbbbbb", decision="reject",
                   primary_rejection_reason="patch-incorrect"),
    ]
    s = summarize(reviews)
    assert s["bundles_with_multiple_reviews"] == 0
    assert s["percent_agreement_on_decision"] is None


# ─── CLI integration (smoke) ────────────────────────────────────────────────


def test_cli_summarize_on_seed_directory(tmp_path):
    from tools.trace_cli.cli import main

    # With only the seed example review present and --include-examples NOT set,
    # aggregation produces a zero-count summary without failing.
    rc = main(["review", "summarize", str(REPO_ROOT / "eval" / "reviews"), "--format", "json"])
    assert rc == 0


def test_cli_summarize_include_examples(capsys):
    from tools.trace_cli.cli import main

    rc = main([
        "review", "summarize", str(REPO_ROOT / "eval" / "reviews"),
        "--include-examples", "--format", "json",
    ])
    assert rc == 0
    out = capsys.readouterr().out
    summary = json.loads(out)
    assert summary["count"] == 1
    assert summary["decisions"]["escalate"] == 1


def test_cli_summarize_missing_path_errors(capsys, tmp_path):
    from tools.trace_cli.cli import main

    rc = main(["review", "summarize", str(tmp_path / "missing")])
    assert rc != 0
    err = capsys.readouterr().err
    assert "not found" in err


def test_emit_summary_human_format_shape():
    s = summarize([
        _mk_review(panelist_id="p1", decision="merge"),
        _mk_review(panelist_id="p2", decision="reject",
                   primary_rejection_reason="patch-incorrect"),
    ])
    text = emit_summary(s, "human")
    assert "reviews aggregated:" in text
    assert "merge / reject / escalate:" in text
    assert "primary rejection reasons:" in text
    assert "patch-incorrect" in text
