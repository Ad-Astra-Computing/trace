"""Tests for the three Reviewer scorers."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from agents.scorers.reviewer_scorers import (
    CANONICAL_BUNDLE_ARTIFACTS,
    ReviewCrossFamilyAttestationScorer,
    ReviewDisagreementScorer,
    ReviewEvidenceCitedScorer,
    ReviewPatchComparisonPresentScorer,
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


def _review_invocation(outputs: list[str], *,
                      reviewer_model_id: str = "claude-sonnet-4-6") -> dict:
    return {
        "invocation_id": "00000000-0000-4000-8000-000000000099",
        "outputs": [{"path": p, "sha256": "0" * 64} for p in outputs],
        "model": {
            "family": "anthropic-sonnet",
            "vendor": "anthropic",
            "model_id": reviewer_model_id,
            "version": "x",
            "sampling": {"temperature": 0.0, "top_p": 1.0, "max_tokens": 1024},
        },
    }


# ─── meta ──────────────────────────────────────────────────────────────────


def test_reviewer_scorer_names_are_locked() -> None:
    assert reviewer_scorer_names() == (
        "review-schema-valid",
        "review-evidence-cited",
        "review-cross-family-attestation",
        "review-patch-comparison-present",
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


def test_schema_valid_passes_review_with_patch_comparison(tmp_path: Path) -> None:
    """Source-backport reviews carry a ## Patch comparison section (reviewer.v5+);
    the parser emits `patch_comparison`, so the schema must allow it. Regression
    guard for 9bd5b98, which added the field without updating the schema."""
    bd = _source_backport_bundle(tmp_path)
    (bd / "review.md").write_text(_accept_review_with_patch_comparison())
    r = ReviewSchemaValidScorer().score(
        bundle_dir=bd, invocation=_review_invocation(["review.md"]),
    )
    assert r.applies is True and r.advisory is False
    assert r.score == 1.0, r.notes
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


def test_evidence_cited_recognises_source_context(tmp_path: Path) -> None:
    # Adaptation-lane reviews cite the pinned source-context/* they ground on.
    bd = _build_bundle(tmp_path)
    (bd / "source-context" / "src").mkdir(parents=True)
    (bd / "source-context" / "src" / "plot.lisp").write_text("(in-package :maxima)\n")
    body = _accept_review_md().replace(
        "- patch.diff\n",
        "- patch.diff\n- source-context/src/plot.lisp\n",
    )
    (bd / "review.md").write_text(body)
    r = ReviewEvidenceCitedScorer().score(
        bundle_dir=bd, invocation=_review_invocation(["review.md"]),
    )
    assert r.score == 1.0
    assert r.details["unrecognised"] == []


def test_evidence_cited_recognises_cve_patch_alias(tmp_path: Path) -> None:
    # The authored patch is cited by its in-tree <cve>.patch name (= patch.diff).
    bd = _build_bundle(tmp_path)
    (bd / "bundle.json").write_text(json.dumps({"kind": "human-review-required", "cve_id": "CVE-2024-34490"}))
    (bd / "patch.diff").write_text("--- a\n+++ b\n")
    body = _accept_review_md().replace(
        "- patch.diff\n",
        "- CVE-2024-34490.patch\n",
    )
    (bd / "review.md").write_text(body)
    r = ReviewEvidenceCitedScorer().score(
        bundle_dir=bd, invocation=_review_invocation(["review.md"]),
    )
    assert "CVE-2024-34490.patch" not in r.details["unrecognised"]


def test_evidence_cited_rejects_source_context_traversal(tmp_path: Path) -> None:
    # A citation from model prose must not escape the bundle via `..`.
    bd = _build_bundle(tmp_path)
    (bd / "source-context").mkdir()
    (tmp_path / "outside.txt").write_text("secret\n")
    body = _accept_review_md().replace(
        "- patch.diff\n",
        "- patch.diff\n- source-context/../outside.txt\n",
    )
    (bd / "review.md").write_text(body)
    r = ReviewEvidenceCitedScorer().score(
        bundle_dir=bd, invocation=_review_invocation(["review.md"]),
    )
    assert "source-context/../outside.txt" in r.details["unrecognised"]


def test_evidence_cited_rejects_symlinked_source_context_root(tmp_path: Path) -> None:
    # A bundle whose `source-context` is a symlink to an external dir must not
    # launder host files into recognized citations.
    bd = _build_bundle(tmp_path)
    external = tmp_path / "external"
    (external / "src").mkdir(parents=True)
    (external / "src" / "secret.c").write_text("int leak;\n")
    (bd / "source-context").symlink_to(external, target_is_directory=True)
    body = _accept_review_md().replace(
        "- patch.diff\n",
        "- patch.diff\n- source-context/src/secret.c\n",
    )
    (bd / "review.md").write_text(body)
    r = ReviewEvidenceCitedScorer().score(
        bundle_dir=bd, invocation=_review_invocation(["review.md"]),
    )
    assert "source-context/src/secret.c" in r.details["unrecognised"]


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


# ─── review-cross-family-attestation (non-advisory, low-weight) ────────────


def _seed_replay_with_patcher(bd: Path, patcher_model_id: str) -> None:
    """Seed replay.json with a single patcher invocation pointing at a
    given model_id. Used to set up the scorer's reference family."""
    replay = {
        "schema_version": "1.0.0",
        "bundle_id": "0" * 16,
        "cve_id": "CVE-0000-0000",
        "nixpkgs_rev": "0" * 40,
        "policy_version": "0" * 64,
        "bundle_schema_sha256": "1" * 64,
        "routing_config_sha256": "2" * 64,
        "tool_manifest": {"flake_lock_sha256": "3" * 64, "tools": [{"name": "trace-cli", "version": "0"}]},
        "cross_family_rule_honored": True,
        "roles": [{
            "role": "patcher",
            "invocations": [{
                "invocation_id": "11111111-1111-4111-8111-111111111111",
                "role": "patcher",
                "started_at": "2026-04-27T00:00:00Z",
                "ended_at": "2026-04-27T00:00:01Z",
                "model": {
                    "family": "anthropic",
                    "vendor": "anthropic",
                    "model_id": patcher_model_id,
                    "version": "x",
                    "sampling": {"temperature": 0.0, "top_p": 1.0, "max_tokens": 1024},
                },
                "prompt": {"path": "prompts/patcher.v2.md", "sha256": "f" * 64},
                "inputs": [{"path": "finding.json", "sha256": "0" * 64}],
                "outputs": [{"path": "patch.diff", "sha256": "0" * 64}],
                "rng_seed": None,
                "validators_passed": ["schema-valid-output"],
                "network_policy_applied": "none",
            }],
        }],
    }
    (bd / "replay.json").write_text(json.dumps(replay, indent=2))


def test_attestation_matches_when_all_three_fields_correct(tmp_path: Path) -> None:
    """All three deterministic fields match the model's claims. The
    default _accept_review_md asserts reviewer_family=anthropic-sonnet,
    patcher_family_observed=anthropic-opus, rule_honored=true. Pair
    with a sonnet reviewer model_id + opus patcher → all three match."""
    bd = _build_bundle(tmp_path)
    _seed_replay_with_patcher(bd, "claude-opus-4-7")
    (bd / "review.md").write_text(_accept_review_md())
    r = ReviewCrossFamilyAttestationScorer().score(
        bundle_dir=bd,
        invocation=_review_invocation(["review.md"], reviewer_model_id="claude-sonnet-4-6"),
    )
    assert r.applies is True
    assert r.advisory is False
    assert r.score == 1.0
    assert r.details["match"] is True
    assert r.details["fabricated_fields"] == []
    assert r.details["patcher_family_recorded"] == "anthropic-opus"
    assert r.details["reviewer_family_recorded"] == "anthropic-sonnet"
    assert r.details["rule_honored_recorded"] is True


def test_attestation_fabricated_patcher_family_yields_zero(tmp_path: Path) -> None:
    """Reproduces the first wget2 live-run failure mode: model emits
    patcher_family_observed=openai-gpt despite the recorded patcher
    being claude-opus-4-7."""
    bd = _build_bundle(tmp_path)
    _seed_replay_with_patcher(bd, "claude-opus-4-7")
    review = _accept_review_md().replace(
        "patcher_family_observed: anthropic-opus",
        "patcher_family_observed: openai-gpt",
    )
    (bd / "review.md").write_text(review)
    r = ReviewCrossFamilyAttestationScorer().score(
        bundle_dir=bd,
        invocation=_review_invocation(["review.md"], reviewer_model_id="claude-sonnet-4-6"),
    )
    assert r.applies is True
    assert r.score == 0.0
    assert r.details["match"] is False
    assert r.details["fabricated_fields"] == ["patcher_family_observed"]
    assert r.details["patcher_family_observed"] == "openai-gpt"
    assert r.details["patcher_family_recorded"] == "anthropic-opus"


def test_attestation_fabricated_reviewer_family_yields_zero(tmp_path: Path) -> None:
    """Reproduces the second wget2 live-run failure mode: model emits
    reviewer_family=anthropic-claude (not a real family label) despite
    the reviewer model_id resolving to anthropic-sonnet. The older
    scorer would not have caught this; the widened scorer must."""
    bd = _build_bundle(tmp_path)
    _seed_replay_with_patcher(bd, "claude-opus-4-7")
    review = _accept_review_md().replace(
        "reviewer_family: anthropic-sonnet",
        "reviewer_family: anthropic-claude",
    )
    (bd / "review.md").write_text(review)
    r = ReviewCrossFamilyAttestationScorer().score(
        bundle_dir=bd,
        invocation=_review_invocation(["review.md"], reviewer_model_id="claude-sonnet-4-6"),
    )
    assert r.applies is True
    assert r.score == 0.0
    assert r.details["fabricated_fields"] == ["reviewer_family"]
    assert r.details["reviewer_family_observed"] == "anthropic-claude"
    assert r.details["reviewer_family_recorded"] == "anthropic-sonnet"


def test_attestation_fabricated_rule_honored_yields_zero(tmp_path: Path) -> None:
    """Reproduces the third wget2 run failure mode: model emits
    rule_honored=false despite reviewer_family and patcher_family
    being genuinely different (so rule SHOULD be honored=true). The
    older scorer didn't consult rule_honored at all."""
    bd = _build_bundle(tmp_path)
    _seed_replay_with_patcher(bd, "claude-opus-4-7")
    review = _accept_review_md().replace(
        "rule_honored: true",
        "rule_honored: false",
    )
    (bd / "review.md").write_text(review)
    r = ReviewCrossFamilyAttestationScorer().score(
        bundle_dir=bd,
        invocation=_review_invocation(["review.md"], reviewer_model_id="claude-sonnet-4-6"),
    )
    assert r.applies is True
    assert r.score == 0.0
    assert r.details["fabricated_fields"] == ["rule_honored"]
    assert r.details["rule_honored_observed"] is False
    assert r.details["rule_honored_recorded"] is True


def test_attestation_same_family_pair_is_rule_violation(tmp_path: Path) -> None:
    """If the routing/replay genuinely pairs same-family models
    (configuration error or eval-time pairing), rule_honored should be
    false. A model claiming rule_honored=true in that case is fabricating."""
    bd = _build_bundle(tmp_path)
    _seed_replay_with_patcher(bd, "claude-sonnet-4-5-20250929")
    # default _accept_review_md claims rule_honored=true. With patcher
    # AND reviewer both anthropic-sonnet, recorded rule_honored=false.
    review = _accept_review_md().replace(
        "patcher_family_observed: anthropic-opus",
        "patcher_family_observed: anthropic-sonnet",
    )
    (bd / "review.md").write_text(review)
    r = ReviewCrossFamilyAttestationScorer().score(
        bundle_dir=bd,
        invocation=_review_invocation(["review.md"], reviewer_model_id="claude-sonnet-4-6"),
    )
    assert r.applies is True
    assert r.score == 0.0
    # rule_honored is the only fabricated field: the model claims
    # honored=true, but reviewer_family == patcher_family == sonnet
    # means the rule is NOT honored.
    assert r.details["fabricated_fields"] == ["rule_honored"]
    assert r.details["rule_honored_recorded"] is False


def test_attestation_skipped_on_refusal(tmp_path: Path) -> None:
    bd = _build_bundle(tmp_path)
    _seed_replay_with_patcher(bd, "claude-opus-4-7")
    (bd / "review-refusal.json").write_text(json.dumps({"rule": 1, "reason": "x"}))
    r = ReviewCrossFamilyAttestationScorer().score(
        bundle_dir=bd, invocation=_review_invocation(["review-refusal.json"]),
    )
    assert r.applies is False
    assert r.advisory is False  # non-advisory by design
    assert r.score is None


def test_attestation_skipped_when_no_patcher_in_replay(tmp_path: Path) -> None:
    """No patcher invocation on file → cannot verify; applies=False."""
    bd = _build_bundle(tmp_path)
    # No replay.json at all.
    (bd / "review.md").write_text(_accept_review_md())
    r = ReviewCrossFamilyAttestationScorer().score(
        bundle_dir=bd, invocation=_review_invocation(["review.md"]),
    )
    assert r.applies is False
    assert r.score is None
    assert "no patcher invocation" in r.notes


def test_attestation_skipped_when_reviewer_model_id_unresolvable(tmp_path: Path) -> None:
    """If the reviewer's invocation has a model_id that doesn't map to
    a known family, we can't verify reviewer_family — skip rather
    than score 0.0 (mirrors the same-shape skip for missing patcher)."""
    bd = _build_bundle(tmp_path)
    _seed_replay_with_patcher(bd, "claude-opus-4-7")
    (bd / "review.md").write_text(_accept_review_md())
    r = ReviewCrossFamilyAttestationScorer().score(
        bundle_dir=bd,
        invocation=_review_invocation(["review.md"], reviewer_model_id="mystery-vendor-0.1"),
    )
    assert r.applies is False
    assert r.score is None
    assert "no resolvable model family" in r.notes


# ─── review-patch-comparison-present ──────────────────────────────────────


def _source_backport_bundle(tmp_path: Path) -> Path:
    """Bundle with patch_strategy=source-backport in upstream-ref.json."""
    bd = tmp_path / "bundle"
    bd.mkdir()
    (bd / "bundle.json").write_text(json.dumps({"kind": "human-review-required"}))
    (bd / "upstream-ref.json").write_text(json.dumps({
        "eligibility": {
            "verdict": "eligible-requires-human-review",
            "patch_strategy": "source-backport",
        }
    }))
    (bd / "impact.json").write_text(json.dumps({"exceeds_threshold": False}))
    return bd


def _accept_review_with_patch_comparison() -> str:
    return (
        "## Verdict\n"
        "accept\n"
        "\n"
        "## Reasoning\n"
        "Patch implements the same functional change as upstream-fix.patch.\n"
        "\n"
        "## Patch comparison\n"
        "hunk 1 — shell.c:safeModeAuth:\n"
        "- upstream-fix.patch:\n"
        "  - `- UNUSED_PARAMETER(zA2);`\n"
        "  - `+ UNUSED_PARAMETER(zA1);`\n"
        "- patch.diff:\n"
        "  - `- UNUSED_PARAMETER(zA2);`\n"
        "  - `+ UNUSED_PARAMETER(zA1);`\n"
        "- comparison: match\n"
        "\n"
        "conclusion: accept — all hunks match\n"
        "\n"
        "## Findings\n"
        "(none)\n"
        "\n"
        "## Cited evidence\n"
        "- upstream-fix.patch:hunk=1\n"
        "- patch.diff:hunk=1\n"
        "- upstream-ref.json:eligibility.patch_strategy=source-backport\n"
        "\n"
        "## Cross-family attestation\n"
        "reviewer_family: anthropic-sonnet\n"
        "patcher_family_observed: anthropic-opus\n"
        "rule_honored: true\n"
    )


def test_patch_comparison_not_applicable_for_version_bump(tmp_path: Path) -> None:
    """Non-source-backport bundles are not subject to this scorer."""
    bd = _build_bundle(tmp_path)
    (bd / "review.md").write_text(_accept_review_md())
    r = ReviewPatchComparisonPresentScorer().score(
        bundle_dir=bd, invocation=_review_invocation(["review.md"]),
    )
    assert r.applies is False
    assert r.score is None
    assert "source-backport" in r.notes


def test_patch_comparison_present_scores_1(tmp_path: Path) -> None:
    """Source-backport review with ## Patch comparison section → score=1.0."""
    bd = _source_backport_bundle(tmp_path)
    (bd / "review.md").write_text(_accept_review_with_patch_comparison())
    r = ReviewPatchComparisonPresentScorer().score(
        bundle_dir=bd, invocation=_review_invocation(["review.md"]),
    )
    assert r.applies is True
    assert r.advisory is False
    assert r.score == 1.0
    assert "Patch comparison" in r.notes


def test_patch_comparison_abstains_in_adaptation_lane(tmp_path: Path) -> None:
    """A v10 adaptation-lane source-backport replaces '## Patch comparison' with
    '## Equivalence assessment'; the patch-comparison scorer must abstain, not
    score a false 0.0 that depresses the cohort rate."""
    bd = _source_backport_bundle(tmp_path)
    # Push it into the adaptation lane: non-empty source-context + applies_verbatim=false.
    sc = bd / "source-context" / "src"
    sc.mkdir(parents=True)
    (sc / "x.c").write_text("int main(void){}\n")
    (bd / "preflight.json").write_text(json.dumps({"applies_verbatim": False}))
    # A contract-compliant v10 review omits '## Patch comparison'.
    (bd / "review.md").write_text(_accept_review_md())
    r = ReviewPatchComparisonPresentScorer().score(
        bundle_dir=bd, invocation=_review_invocation(["review.md"]),
    )
    assert r.applies is False
    assert r.score is None
    assert "adaptation lane" in r.notes


def test_patch_comparison_absent_scores_0(tmp_path: Path) -> None:
    """Source-backport review without ## Patch comparison section → score=0.0."""
    bd = _source_backport_bundle(tmp_path)
    (bd / "review.md").write_text(_accept_review_md())
    r = ReviewPatchComparisonPresentScorer().score(
        bundle_dir=bd, invocation=_review_invocation(["review.md"]),
    )
    assert r.applies is True
    assert r.advisory is False
    assert r.score == 0.0
    assert "missing" in r.notes


def test_patch_comparison_skipped_on_refusal(tmp_path: Path) -> None:
    bd = _source_backport_bundle(tmp_path)
    (bd / "review-refusal.json").write_text(json.dumps({"rule": 1, "reason": "x"}))
    r = ReviewPatchComparisonPresentScorer().score(
        bundle_dir=bd, invocation=_review_invocation(["review-refusal.json"]),
    )
    assert r.applies is False
    assert r.score is None
