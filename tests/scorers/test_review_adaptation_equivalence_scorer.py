"""Tests for ReviewAdaptationEquivalenceScorer.

Compares a Reviewer's declared adaptation-lane `equivalence:` verdict
(reviewer.v10+, `## Equivalence assessment` section) against the
ground-truth oracle registry (`agents/scorers/adaptation_oracle.py`).
Only registered CVE-2024-34490 has an oracle at time of writing
(ground_truth_equivalence="equivalent"), so these tests anchor on it.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from agents.scorers.adaptation_oracle import AdaptationOracle, OracleProvenance
from agents.scorers.reviewer_scorers import ReviewAdaptationEquivalenceScorer


REGISTERED_CVE = "CVE-2024-34490"
_DEFAULT_PATCH_DIFF = (
    "--- a/src/gnuplot_def.lisp\n"
    "+++ b/src/gnuplot_def.lisp\n"
    "@@ -1 +1 @@\n"
    "-old\n"
    "+new\n"
)


# ─── shared fixtures ───────────────────────────────────────────────────────


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


def _adaptation_bundle(tmp_path: Path, *,
                       cve_id: str = REGISTERED_CVE,
                       applies_verbatim: bool | None = False,
                       with_patch: bool = True,
                       patch_diff: str = _DEFAULT_PATCH_DIFF) -> Path:
    """Bundle in the adaptation lane: non-empty source-context/ +
    preflight.json with applies_verbatim != true. Also writes patch.diff
    by default (the scorer hash-binds the oracle label to this file)."""
    bd = tmp_path / "bundle"
    bd.mkdir()
    (bd / "finding.json").write_text(json.dumps({"cve_id": cve_id}))
    (bd / "upstream-ref.json").write_text(json.dumps({
        "eligibility": {"patch_strategy": "source-backport"}
    }))
    preflight: dict = {}
    if applies_verbatim is not None:
        preflight["applies_verbatim"] = applies_verbatim
    (bd / "preflight.json").write_text(json.dumps(preflight))
    src_dir = bd / "source-context" / "src"
    src_dir.mkdir(parents=True)
    (src_dir / "x").write_text("l = l * base;\n")
    if with_patch:
        (bd / "patch.diff").write_text(patch_diff)
    return bd


def _install_matching_oracle(monkeypatch: pytest.MonkeyPatch, bd: Path, *,
                             cve_id: str = REGISTERED_CVE,
                             ground_truth_equivalence: str = "equivalent") -> AdaptationOracle:
    """Monkeypatch get_oracle so the registered oracle's
    adjudicated_patch_sha256 matches this bundle's own patch.diff bytes —
    the scorer hash-binds the label to a specific adjudicated patch, and a
    fresh test bundle's patch.diff can never equal the real maxima
    registry's fixed hash."""
    patch_bytes = (bd / "patch.diff").read_bytes()
    oracle = AdaptationOracle(
        cve_id=cve_id,
        ground_truth_equivalence=ground_truth_equivalence,
        adjudicated_patch_sha256=hashlib.sha256(patch_bytes).hexdigest(),
        provenance=OracleProvenance(
            source="test-fixture",
            ref="0" * 8,
            path="test.patch",
            sha256="0" * 64,
            base_relation="same-base",
        ),
        adjudicated_by="test-harness",
    )
    monkeypatch.setattr(
        "agents.scorers.reviewer_scorers.get_oracle",
        lambda cve: oracle if cve == cve_id else None,
    )
    return oracle


def _v10_review_md(equivalence_line: str | None, *, verdict: str = "accept") -> str:
    """Minimal reviewer.v10 review body (no BEGIN/END markers — matches what
    `execute()` writes to review.md on disk; `_load_review_md` re-wraps
    with markers before parsing)."""
    equivalence_section = (
        f"## Equivalence assessment\n- {equivalence_line}\n\n"
        if equivalence_line is not None else ""
    )
    findings = "(none)\n" if verdict == "accept" else (
        "- severity: high — adaptation not equivalent — source-context/src/x\n"
    )
    return (
        "## Verdict\n"
        f"{verdict}\n"
        "\n"
        "## Reasoning\n"
        "Adaptation preserves the bounds check present in the pinned source.\n"
        "\n"
        f"{equivalence_section}"
        "## Findings\n"
        f"{findings}"
        "\n"
        "## Cited evidence\n"
        "- source-context/src/x\n"
        "- patch.diff\n"
        "\n"
        "## Cross-family attestation\n"
        "reviewer_family: anthropic-sonnet\n"
        "patcher_family_observed: anthropic-opus\n"
        "rule_honored: true\n"
    )


# ─── applies=False gates ────────────────────────────────────────────────────


def test_refusal_invocation_does_not_apply(tmp_path: Path) -> None:
    bd = _adaptation_bundle(tmp_path)
    (bd / "review-refusal.json").write_text(json.dumps({"rule": 1, "reason": "x"}))
    r = ReviewAdaptationEquivalenceScorer().score(
        bundle_dir=bd, invocation=_review_invocation(["review-refusal.json"]),
    )
    assert r.applies is False
    assert r.score is None


def test_verbatim_lane_does_not_apply(tmp_path: Path) -> None:
    """preflight.json.applies_verbatim=true → verbatim lane, not adaptation."""
    bd = _adaptation_bundle(tmp_path, applies_verbatim=True)
    (bd / "review.md").write_text(_v10_review_md("equivalence: equivalent — match"))
    r = ReviewAdaptationEquivalenceScorer().score(
        bundle_dir=bd, invocation=_review_invocation(["review.md"]),
    )
    assert r.applies is False
    assert r.score is None
    assert "adaptation lane" in r.notes


def test_no_source_context_does_not_apply(tmp_path: Path) -> None:
    bd = tmp_path / "bundle"
    bd.mkdir()
    (bd / "finding.json").write_text(json.dumps({"cve_id": REGISTERED_CVE}))
    (bd / "preflight.json").write_text(json.dumps({"applies_verbatim": False}))
    (bd / "review.md").write_text(_v10_review_md("equivalence: equivalent — match"))
    r = ReviewAdaptationEquivalenceScorer().score(
        bundle_dir=bd, invocation=_review_invocation(["review.md"]),
    )
    assert r.applies is False


def test_missing_cve_id_does_not_apply(tmp_path: Path) -> None:
    bd = _adaptation_bundle(tmp_path)
    (bd / "finding.json").write_text(json.dumps({"summary": "no cve id here"}))
    (bd / "review.md").write_text(_v10_review_md("equivalence: equivalent — match"))
    r = ReviewAdaptationEquivalenceScorer().score(
        bundle_dir=bd, invocation=_review_invocation(["review.md"]),
    )
    assert r.applies is False
    assert "cve_id" in r.notes


def test_unregistered_cve_does_not_apply(tmp_path: Path) -> None:
    bd = _adaptation_bundle(tmp_path, cve_id="CVE-9999-99999")
    (bd / "review.md").write_text(_v10_review_md("equivalence: equivalent — match"))
    r = ReviewAdaptationEquivalenceScorer().score(
        bundle_dir=bd, invocation=_review_invocation(["review.md"]),
    )
    assert r.applies is False
    assert "no adaptation-equivalence oracle registered" in r.notes


# ─── applies=True scoring ───────────────────────────────────────────────────


def test_matching_equivalence_scores_one(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    bd = _adaptation_bundle(tmp_path)
    _install_matching_oracle(monkeypatch, bd)
    (bd / "review.md").write_text(
        _v10_review_md("equivalence: equivalent — same bounds check")
    )
    r = ReviewAdaptationEquivalenceScorer().score(
        bundle_dir=bd, invocation=_review_invocation(["review.md"]),
    )
    assert r.applies is True
    assert r.advisory is False
    assert r.score == 1.0
    assert r.details["cve_id"] == REGISTERED_CVE
    assert r.details["reviewer_equivalence"] == "equivalent"
    assert r.details["ground_truth_equivalence"] == "equivalent"
    assert r.details["oracle_base_relation"] == "same-base"
    assert r.details["match"] is True


def test_wrong_direction_scores_zero(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Oracle says 'equivalent'; reviewer says 'not-equivalent' → wrong-direction miss."""
    bd = _adaptation_bundle(tmp_path)
    _install_matching_oracle(monkeypatch, bd)
    (bd / "review.md").write_text(
        _v10_review_md("equivalence: not-equivalent — diverges (test)")
    )
    r = ReviewAdaptationEquivalenceScorer().score(
        bundle_dir=bd, invocation=_review_invocation(["review.md"]),
    )
    assert r.applies is True
    assert r.score == 0.0
    assert "wrong-direction" in r.notes
    assert r.details["reviewer_equivalence"] == "not-equivalent"
    assert r.details["match"] is False


def test_indeterminate_scores_zero_with_undercommitment_note(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    bd = _adaptation_bundle(tmp_path)
    _install_matching_oracle(monkeypatch, bd)
    (bd / "review.md").write_text(
        _v10_review_md("equivalence: indeterminate — insufficient evidence")
    )
    r = ReviewAdaptationEquivalenceScorer().score(
        bundle_dir=bd, invocation=_review_invocation(["review.md"]),
    )
    assert r.applies is True
    assert r.score == 0.0
    assert "under-commitment" in r.notes
    assert r.details["reviewer_equivalence"] == "indeterminate"
    assert r.details["match"] is False


def test_unrecognized_equivalence_value_scores_zero(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    bd = _adaptation_bundle(tmp_path)
    _install_matching_oracle(monkeypatch, bd)
    (bd / "review.md").write_text(
        _v10_review_md("equivalence: maybe — unrecognized token")
    )
    r = ReviewAdaptationEquivalenceScorer().score(
        bundle_dir=bd, invocation=_review_invocation(["review.md"]),
    )
    assert r.applies is True
    assert r.score == 0.0
    assert "unrecognized" in r.notes
    assert r.details["reviewer_equivalence"] == "maybe"


def test_no_equivalence_line_scores_zero(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    bd = _adaptation_bundle(tmp_path)
    _install_matching_oracle(monkeypatch, bd)
    (bd / "review.md").write_text(_v10_review_md(None))
    r = ReviewAdaptationEquivalenceScorer().score(
        bundle_dir=bd, invocation=_review_invocation(["review.md"]),
    )
    assert r.applies is True
    assert r.score == 0.0
    assert "Equivalence assessment" in r.notes
    assert r.details["reviewer_equivalence"] is None


def test_missing_review_md_scores_zero(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    bd = _adaptation_bundle(tmp_path)
    _install_matching_oracle(monkeypatch, bd)
    r = ReviewAdaptationEquivalenceScorer().score(
        bundle_dir=bd, invocation=_review_invocation(["review.md"]),
    )
    assert r.applies is True
    assert r.score == 0.0
    assert "missing" in r.notes or "fails strict parser" in r.notes


# ─── patch-hash binding (oracle label applies to ONE adjudicated patch) ────


def test_patch_diff_missing_does_not_apply(tmp_path: Path) -> None:
    """No patch.diff at all: the scorer cannot bind the oracle label to a
    specific adaptation, so it abstains rather than guessing."""
    bd = _adaptation_bundle(tmp_path, with_patch=False)
    (bd / "review.md").write_text(
        _v10_review_md("equivalence: equivalent — same bounds check")
    )
    r = ReviewAdaptationEquivalenceScorer().score(
        bundle_dir=bd, invocation=_review_invocation(["review.md"]),
    )
    assert r.applies is False
    assert r.score is None
    assert "patch.diff missing" in r.notes


def test_patch_hash_mismatch_does_not_apply(tmp_path: Path) -> None:
    """Bundle's patch.diff does not match the registered oracle's
    adjudicated_patch_sha256 (uses the real CVE-2024-34490 registry entry,
    unmodified, so any arbitrary test patch.diff naturally mismatches it):
    the oracle label is settled against a specific adjudicated adaptation
    and does not generalize to a different patch, so the scorer abstains."""
    bd = _adaptation_bundle(tmp_path)
    (bd / "review.md").write_text(
        _v10_review_md("equivalence: equivalent — same bounds check")
    )
    r = ReviewAdaptationEquivalenceScorer().score(
        bundle_dir=bd, invocation=_review_invocation(["review.md"]),
    )
    assert r.applies is False
    assert r.score is None
    assert "does not match the adjudicated adaptation" in r.notes


# ─── _is_adaptation_lane: must mirror the executor's fail-closed routing ────


def _lane(tmp_path: Path, *, source_files: bool, preflight: object,
          patch_strategy: str | None = "source-backport") -> bool:
    from agents.scorers.reviewer_scorers import _is_adaptation_lane

    bd = tmp_path / "b"
    bd.mkdir()
    if patch_strategy is not None:
        (bd / "upstream-ref.json").write_text(json.dumps({
            "eligibility": {"patch_strategy": patch_strategy}
        }))
    if source_files:
        sc = bd / "source-context" / "src"
        sc.mkdir(parents=True)
        (sc / "x").write_text("code\n")
    else:
        (bd / "source-context").mkdir()  # empty
    if preflight is not _NO_PREFLIGHT:
        (bd / "preflight.json").write_text(preflight if isinstance(preflight, str)
                                           else json.dumps(preflight))
    return _is_adaptation_lane(bd)


_NO_PREFLIGHT = object()


def test_lane_requires_source_backport_strategy(tmp_path: Path) -> None:
    # A version-bump bundle that retains source-context is NOT the adaptation
    # lane (the executor only enters it in the source-backport branch).
    assert _lane(tmp_path, source_files=True, preflight={"applies_verbatim": False},
                 patch_strategy="version-bump") is False


def test_lane_requires_upstream_ref(tmp_path: Path) -> None:
    assert _lane(tmp_path, source_files=True, preflight={"applies_verbatim": False},
                 patch_strategy=None) is False


def test_lane_requires_nonempty_source_context(tmp_path: Path) -> None:
    assert _lane(tmp_path, source_files=False, preflight={"applies_verbatim": False}) is False


def test_lane_missing_preflight_is_adaptation(tmp_path: Path) -> None:
    # Executor keeps applies_verbatim=None (not True) -> adaptation lane.
    assert _lane(tmp_path, source_files=True, preflight=_NO_PREFLIGHT) is True


def test_lane_malformed_preflight_is_adaptation(tmp_path: Path) -> None:
    assert _lane(tmp_path, source_files=True, preflight="{not json") is True


def test_lane_non_object_preflight_is_adaptation(tmp_path: Path) -> None:
    assert _lane(tmp_path, source_files=True, preflight="[]") is True


def test_lane_applies_verbatim_true_is_verbatim(tmp_path: Path) -> None:
    assert _lane(tmp_path, source_files=True, preflight={"applies_verbatim": True}) is False


def test_lane_applies_verbatim_false_is_adaptation(tmp_path: Path) -> None:
    assert _lane(tmp_path, source_files=True, preflight={"applies_verbatim": False}) is True


def test_lane_applies_verbatim_missing_key_is_adaptation(tmp_path: Path) -> None:
    assert _lane(tmp_path, source_files=True, preflight={"other": 1}) is True
