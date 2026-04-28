"""Tests for the three Reviewer scorers."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from agents.scorers.reviewer_scorers import (
    CANONICAL_BUNDLE_ARTIFACTS,
    ReviewDisagreementScorer,
    ReviewEvidenceCitedScorer,
    ReviewSchemaValidScorer,
    reviewer_scorer_names,
)


# ─── shared fixtures ───────────────────────────────────────────────────────


def _accept_review_md() -> str:
    return (
        "## Verdict\n"
        "accept\n"
        "\n"
        "## Reasoning\n"
        "Patch updates 3.6.7 to 3.6.8 per upstream-ref.json.target_version. Hashes match prefetch_hashes.\n"
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
    )


def _reject_review_md() -> str:
    return (
        "## Verdict\n"
        "reject\n"
        "\n"
        "## Reasoning\n"
        "patch.diff emits an ungrounded vendorHash value.\n"
        "\n"
        "## Findings\n"
        "- severity: blocking — vendorHash ungrounded — patch.diff:hunk=2\n"
        "\n"
        "## Cited evidence\n"
        "- patch.diff:hunk=2\n"
        "- upstream-ref.json:prefetch_hashes\n"
        "\n"
        "## Cross-family attestation\n"
        "reviewer_family: anthropic-sonnet\n"
        "patcher_family_observed: anthropic-opus\n"
        "rule_honored: true\n"
    )


def _build_bundle(tmp_path: Path, *,
                  bundle_kind: str = "auto-merge",
                  verdict: str | None = "eligible",
                  exceeds_threshold: bool = False) -> Path:
    bd = tmp_path / "bundle"
    bd.mkdir()
    bundle = {"kind": bundle_kind}
    (bd / "bundle.json").write_text(json.dumps(bundle))
    eligibility = {"verdict": verdict} if verdict else {}
    (bd / "upstream-ref.json").write_text(json.dumps({"eligibility": eligibility}))
    (bd / "impact.json").write_text(json.dumps({"exceeds_threshold": exceeds_threshold}))
    return bd


def _review_invocation(outputs: list[str]) -> dict:
    return {
        "invocation_id": "00000000-0000-4000-8000-000000000099",
        "outputs": [{"path": p, "sha256": "0" * 64} for p in outputs],
    }


# ─── meta ──────────────────────────────────────────────────────────────────


def test_reviewer_scorer_names_are_locked() -> None:
    assert reviewer_scorer_names() == (
        "review-schema-valid",
        "review-evidence-cited",
        "review-disagreement",
    )


# ─── review-schema-valid ───────────────────────────────────────────────────


def test_schema_valid_passes_clean_review(tmp_path: Path) -> None:
    bd = _build_bundle(tmp_path)
    (bd / "review.md").write_text(_accept_review_md())
    r = ReviewSchemaValidScorer().score(
        bundle_dir=bd, invocation=_review_invocation(["review.md"]),
    )
    assert r.applies is True and r.advisory is False
    assert r.score == 1.0
    assert r.details["verdict"] == "accept"


def test_schema_valid_fails_malformed_review(tmp_path: Path) -> None:
    bd = _build_bundle(tmp_path)
    # Missing the required ## Cross-family attestation section.
    (bd / "review.md").write_text(_accept_review_md().replace(
        "## Cross-family attestation\n"
        "reviewer_family: anthropic-sonnet\n"
        "patcher_family_observed: anthropic-opus\n"
        "rule_honored: true\n",
        "",
    ))
    r = ReviewSchemaValidScorer().score(
        bundle_dir=bd, invocation=_review_invocation(["review.md"]),
    )
    assert r.score == 0.0
    assert "fails strict parser" in r.notes


def test_schema_valid_passes_well_formed_refusal(tmp_path: Path) -> None:
    bd = _build_bundle(tmp_path)
    (bd / "review-refusal.json").write_text(json.dumps({"rule": 1, "reason": "x"}))
    r = ReviewSchemaValidScorer().score(
        bundle_dir=bd, invocation=_review_invocation(["review-refusal.json"]),
    )
    assert r.score == 1.0


def test_schema_valid_fails_refusal_without_rule(tmp_path: Path) -> None:
    bd = _build_bundle(tmp_path)
    (bd / "review-refusal.json").write_text(json.dumps({"reason": "x"}))
    r = ReviewSchemaValidScorer().score(
        bundle_dir=bd, invocation=_review_invocation(["review-refusal.json"]),
    )
    assert r.score == 0.0


# ─── review-evidence-cited ─────────────────────────────────────────────────


def test_evidence_cited_perfect_when_all_canonical(tmp_path: Path) -> None:
    bd = _build_bundle(tmp_path)
    (bd / "review.md").write_text(_accept_review_md())
    r = ReviewEvidenceCitedScorer().score(
        bundle_dir=bd, invocation=_review_invocation(["review.md"]),
    )
    assert r.applies is True
    assert r.score == 1.0
    assert r.details["unrecognised"] == []


def test_evidence_cited_partial_when_one_unrecognised(tmp_path: Path) -> None:
    bd = _build_bundle(tmp_path)
    body = _accept_review_md().replace(
        "- patch.diff\n",
        "- patch.diff\n- some-imaginary-file.json\n",
    )
    (bd / "review.md").write_text(body)
    r = ReviewEvidenceCitedScorer().score(
        bundle_dir=bd, invocation=_review_invocation(["review.md"]),
    )
    assert r.applies is True
    assert 0 < r.score < 1
    assert "some-imaginary-file.json" in r.details["unrecognised"]


def test_evidence_cited_skipped_on_refusal(tmp_path: Path) -> None:
    bd = _build_bundle(tmp_path)
    (bd / "review-refusal.json").write_text(json.dumps({"rule": 1, "reason": "x"}))
    r = ReviewEvidenceCitedScorer().score(
        bundle_dir=bd, invocation=_review_invocation(["review-refusal.json"]),
    )
    assert r.applies is False


def test_canonical_artifact_set_is_stable() -> None:
    """If this set grows, the evidence-cited scorer's denominator changes;
    locked here to make the change visible."""
    assert CANONICAL_BUNDLE_ARTIFACTS == (
        "finding.json",
        "upstream-ref.json",
        "impact.json",
        "maintainers.json",
        "package.nix",
        "patch.diff",
        "patch-rationale.md",
    )


# ─── review-disagreement (advisory) ────────────────────────────────────────


def test_disagreement_aligned_when_verdict_matches_steward(tmp_path: Path) -> None:
    """Clean auto-merge bundle, reviewer says accept → aligned (1.0)."""
    bd = _build_bundle(tmp_path, bundle_kind="auto-merge", verdict="eligible")
    (bd / "review.md").write_text(_accept_review_md())
    r = ReviewDisagreementScorer().score(
        bundle_dir=bd, invocation=_review_invocation(["review.md"]),
    )
    assert r.advisory is True
    assert r.applies is True
    assert r.score == 1.0
    assert r.details["steward_signal"] == "accept"
    assert r.details["verdict"] == "accept"


def test_disagreement_contradicts_when_reject_on_clean_auto_merge(tmp_path: Path) -> None:
    bd = _build_bundle(tmp_path, bundle_kind="auto-merge", verdict="eligible")
    (bd / "review.md").write_text(_reject_review_md())
    r = ReviewDisagreementScorer().score(
        bundle_dir=bd, invocation=_review_invocation(["review.md"]),
    )
    assert r.advisory is True
    assert r.score == 0.0
    assert r.details["steward_signal"] == "accept"


def test_disagreement_adjacent_when_escalate_on_clean_auto_merge(tmp_path: Path) -> None:
    """escalate ↔ accept counts as adjacent (0.5)."""
    bd = _build_bundle(tmp_path, bundle_kind="auto-merge", verdict="eligible")
    body = _accept_review_md().replace(
        "## Verdict\naccept\n",
        "## Verdict\nescalate\n",
    ).replace("(none)\n", "- severity: medium — adjacent escalate test — patch.diff\n")
    (bd / "review.md").write_text(body)
    r = ReviewDisagreementScorer().score(
        bundle_dir=bd, invocation=_review_invocation(["review.md"]),
    )
    assert r.score == 0.5


def test_disagreement_aligned_on_human_review_bundle(tmp_path: Path) -> None:
    """human-review-required bundle, reviewer says escalate → aligned."""
    bd = _build_bundle(tmp_path, bundle_kind="human-review-required",
                       verdict="eligible-requires-human-review")
    body = _accept_review_md().replace(
        "## Verdict\naccept\n", "## Verdict\nescalate\n"
    ).replace("(none)\n", "- severity: medium — major-jump triggers escalate — upstream-ref.json\n")
    (bd / "review.md").write_text(body)
    r = ReviewDisagreementScorer().score(
        bundle_dir=bd, invocation=_review_invocation(["review.md"]),
    )
    assert r.score == 1.0


def test_disagreement_skipped_on_refusal(tmp_path: Path) -> None:
    bd = _build_bundle(tmp_path)
    (bd / "review-refusal.json").write_text(json.dumps({"rule": 1, "reason": "x"}))
    r = ReviewDisagreementScorer().score(
        bundle_dir=bd, invocation=_review_invocation(["review-refusal.json"]),
    )
    assert r.applies is False
    assert r.advisory is True
