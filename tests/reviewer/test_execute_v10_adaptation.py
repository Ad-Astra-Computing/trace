"""End-to-end (FakeAdapter) wiring of the reviewer.v10 semantic-adaptation lane.

Slice 5 of the semantic-backport-adaptation arc. A source-backport bundle that
carries a source-context/ dir + preflight.json (applies_verbatim=false) routes the
Reviewer to reviewer.v10, feeds it the pinned source + the applies_verbatim verdict,
records source-context as replay-critical reviewer inputs, and the parser extracts
the new `## Equivalence assessment` section. The verbatim lane stays on v9. No live
model spend (FakeAdapter).
"""

from __future__ import annotations

import json
from pathlib import Path

from agents.patcher import FakeAdapter
from agents.reviewer.parser import parse_reviewer_output
from agents.reviewer.runner import assemble_user_content
from tools.trace_cli.execute import (
    REVIEWER_PROMPT_PATH_ADAPT,
    REVIEWER_PROMPT_PATH_DEFAULT,
    execute,
)

# Reuse the patcher adaptation-lane bundle builder + adapted patch response.
from tests.patcher.test_execute_v4_adaptation import (
    _adapted_patch_response,
    _build_source_context_bundle,
)


def _factory(text: str):
    def _make(model_id: str) -> FakeAdapter:
        return FakeAdapter(model_id, text)
    return _make


def _fresh() -> dict:
    return {"invocation_id": None, "inputs": [], "outputs": []}


_V10_REVIEW = (
    "=== BEGIN review.md ===\n"
    "## Verdict\n"
    "accept\n"
    "\n"
    "## Reasoning\n"
    "upstream-fix.patch does not apply to the pinned base (applies_verbatim=false); "
    "the authored patch adapts the fix to foo.c using constructs present in "
    "source-context/foo.c. Security-relevant behavior is equivalent.\n"
    "\n"
    "## patch.diff extraction\n"
    "hunk 1 — foo.c:\n"
    "- `- l = l * base;`\n"
    "- `+ if (l > limit) return -1;`\n"
    "- critical token window: `if (l > limit)` (guard)\n"
    "\n"
    "## upstream-fix.patch extraction\n"
    "hunk 1 — foo.c:\n"
    "- `- l = archive_ckd_mul_i64(l, base);`\n"
    "- `+ l = archive_ckd_mul_i64(l, base);  /* upstream */`\n"
    "- critical token window: `archive_ckd_mul_i64` (helper)\n"
    "\n"
    "## Patch comparison\n"
    "hunk 1 — foo.c:\n"
    "- patch.diff critical token: `if (l > limit)`\n"
    "- upstream-fix critical token: `archive_ckd_mul_i64`\n"
    "- comparison: mismatch (adaptation — different base idiom)\n"
    "\n"
    "conclusion: textual-mismatch-expected — defer to equivalence assessment\n"
    "\n"
    "## Equivalence assessment\n"
    "- unsafe operation: unchecked multiply `l * base` in source-context/foo.c\n"
    "- safety invariant (upstream): overflow-checked multiply via archive_ckd_mul_i64\n"
    "- invariant established by authored patch: `if (l > limit) return -1;` bounds l "
    "before the multiply, in the pinned code\n"
    "- behavior preserved: yes — safe-path result unchanged\n"
    "- grounded in pinned source: yes — `l = l * base;` is present in source-context/foo.c\n"
    "- no unresolved constructs: yes — no archive_ckd_* helper is referenced\n"
    "- equivalence: equivalent — same overflow invariant established before the multiply\n"
    "\n"
    "## Findings\n"
    "(none)\n"
    "\n"
    "## Cited evidence\n"
    "- source-context/foo.c\n"
    "- upstream-fix.patch\n"
    "- patch.diff\n"
    "\n"
    "## Cross-family attestation\n"
    "reviewer_family: anthropic-sonnet\n"
    "patcher_family_observed: anthropic-opus\n"
    "rule_honored: true\n"
    "=== END review.md ==="
)


def _prep_reviewable_adaptation_bundle(tmp_path: Path) -> Path:
    """Build the source-context bundle and run the Patcher (v4) so patch.diff +
    patch-rationale.md + a patcher replay invocation are on disk for the Reviewer."""
    bd = _build_source_context_bundle(tmp_path)
    execute(
        role="patcher", bundle_dir=bd, invocation=_fresh(), verify=False,
        model_id="claude-opus-4-7", adapter_factory=_factory(_adapted_patch_response()),
    )
    return bd


# ── rendered content ────────────────────────────────────────────────────────

def test_assemble_renders_applies_verbatim_and_source_context():
    content = assemble_user_content({
        "finding": {}, "upstream_ref": {}, "impact": {}, "maintainers": {},
        "package_source": "x", "patch_diff": "d", "patch_rationale_md": "r",
        "patch_strategy": "source-backport",
        "upstream_fix_patch": "diff --git a/foo.c b/foo.c\n",
        "source_context": {"foo.c": "    l = l * base;\n"},
        "applies_verbatim": False,
        "model_attestation_context": {
            "reviewer_model_id": "claude-sonnet-4-5-20250929",
            "reviewer_family": "anthropic-sonnet",
            "patcher_model_id": "claude-opus-4-7",
            "patcher_family": "anthropic-opus",
            "cross_family_rule_honored_expected": True,
            "applies_verbatim": False,
        },
    })
    assert "applies_verbatim: false" in content
    assert "# source-context/ (pinned PRE-PATCH source" in content
    assert "## source-context/foo.c" in content
    assert "l = l * base;" in content


# ── execute end-to-end ──────────────────────────────────────────────────────

def test_reviewer_routes_to_v10_and_declares_source_context(tmp_path):
    bd = _prep_reviewable_adaptation_bundle(tmp_path)
    result = execute(
        role="reviewer", bundle_dir=bd, invocation=_fresh(), verify=False,
        model_id="claude-sonnet-4-5-20250929", adapter_factory=_factory(_V10_REVIEW),
    )
    assert result["kind"] == "review"
    inv = result["replay_invocation"]
    assert inv["prompt"]["path"] == f"prompts/{REVIEWER_PROMPT_PATH_ADAPT.name}"
    declared = {ref["path"] for ref in inv["inputs"]}
    assert "source-context/foo.c" in declared
    assert "preflight.json" in declared
    for ref in inv["inputs"]:
        assert len(ref["sha256"]) == 64


def test_reviewer_v10_review_parses_equivalence_assessment(tmp_path):
    # Parser extracts the new section from the model response (with markers).
    parsed = parse_reviewer_output(_V10_REVIEW)
    assert parsed.verdict == "accept"
    assert parsed.equivalence_assessment_raw is not None
    assert "equivalence: equivalent" in parsed.equivalence_assessment_raw
    d = parsed.to_schema_dict()
    assert "equivalence_assessment" in d
    # And execute wrote the section into the on-disk review.md body.
    bd = _prep_reviewable_adaptation_bundle(tmp_path)
    execute(
        role="reviewer", bundle_dir=bd, invocation=_fresh(), verify=False,
        model_id="claude-sonnet-4-5-20250929", adapter_factory=_factory(_V10_REVIEW),
    )
    review_md = (bd / "review.md").read_text()
    assert "## Equivalence assessment" in review_md
    assert "equivalence: equivalent" in review_md


def test_reviewer_verify_mode_hash_checks_source_context(tmp_path):
    bd = _prep_reviewable_adaptation_bundle(tmp_path)
    fresh = execute(
        role="reviewer", bundle_dir=bd, invocation=_fresh(), verify=False,
        model_id="claude-sonnet-4-5-20250929", adapter_factory=_factory(_V10_REVIEW),
    )
    verified = execute(
        role="reviewer", bundle_dir=bd, invocation=fresh["replay_invocation"], verify=True,
        model_id="claude-sonnet-4-5-20250929", adapter_factory=_factory(_V10_REVIEW),
    )
    vpaths = {v["path"] for v in verified["input_verification"] if v.get("verified")}
    assert "source-context/foo.c" in vpaths


def _v10_review_without_equivalence() -> str:
    # Same shape as _V10_REVIEW but with the ## Equivalence assessment section removed.
    return _V10_REVIEW.replace(
        "## Equivalence assessment\n"
        "- unsafe operation: unchecked multiply `l * base` in source-context/foo.c\n"
        "- safety invariant (upstream): overflow-checked multiply via archive_ckd_mul_i64\n"
        "- invariant established by authored patch: `if (l > limit) return -1;` bounds l "
        "before the multiply, in the pinned code\n"
        "- behavior preserved: yes — safe-path result unchanged\n"
        "- grounded in pinned source: yes — `l = l * base;` is present in source-context/foo.c\n"
        "- no unresolved constructs: yes — no archive_ckd_* helper is referenced\n"
        "- equivalence: equivalent — same overflow invariant established before the multiply\n"
        "\n",
        "",
    )


def test_adaptation_accept_without_equivalence_assessment_is_rejected(tmp_path):
    import pytest
    bd = _prep_reviewable_adaptation_bundle(tmp_path)
    with pytest.raises(Exception, match="Equivalence assessment"):
        execute(
            role="reviewer", bundle_dir=bd, invocation=_fresh(), verify=False,
            model_id="claude-sonnet-4-5-20250929",
            adapter_factory=_factory(_v10_review_without_equivalence()),
        )
    # Nothing signed: no review.md written; raw persisted for debugging.
    assert not (bd / "review.md").exists()
    assert list((bd / ".reviewer-failures").rglob("raw-response.txt"))


def test_string_false_preflight_does_not_flip_to_verbatim(tmp_path):
    # A malformed preflight value (JSON string "false") must fail closed to the
    # adaptation lane, NOT coerce to a verbatim-lane instruction. (codex P2)
    bd = _build_source_context_bundle(tmp_path)
    pf = json.loads((bd / "preflight.json").read_text())
    pf["applies_verbatim"] = "false"  # string, not boolean
    (bd / "preflight.json").write_text(json.dumps(pf))
    execute(
        role="patcher", bundle_dir=bd, invocation=_fresh(), verify=False,
        model_id="claude-opus-4-7", adapter_factory=_factory(_adapted_patch_response()),
    )
    content = assemble_user_content({
        "finding": {}, "upstream_ref": {}, "impact": {}, "maintainers": {},
        "package_source": "x", "patch_diff": "d", "patch_rationale_md": "r",
        "patch_strategy": "source-backport", "upstream_fix_patch": "d\n",
        "source_context": {"foo.c": "x\n"}, "applies_verbatim": False,
        "model_attestation_context": {"applies_verbatim": False},
    })
    # Sanity: assemble renders false, and execute routes to v10 (adaptation).
    assert "applies_verbatim: false" in content
    result = execute(
        role="reviewer", bundle_dir=bd, invocation=_fresh(), verify=False,
        model_id="claude-sonnet-4-5-20250929", adapter_factory=_factory(_V10_REVIEW),
    )
    assert result["replay_invocation"]["prompt"]["path"] == f"prompts/{REVIEWER_PROMPT_PATH_ADAPT.name}"


def test_verbatim_lane_stays_on_v9(tmp_path):
    """A source-backport bundle whose preflight says applies_verbatim=true keeps the
    Reviewer on v9 and does NOT feed source-context."""
    bd = _build_source_context_bundle(tmp_path)
    # flip the verdict to verbatim
    pf = json.loads((bd / "preflight.json").read_text())
    pf["applies_verbatim"] = True
    (bd / "preflight.json").write_text(json.dumps(pf))
    execute(
        role="patcher", bundle_dir=bd, invocation=_fresh(), verify=False,
        model_id="claude-opus-4-7", adapter_factory=_factory(_adapted_patch_response()),
    )
    result = execute(
        role="reviewer", bundle_dir=bd, invocation=_fresh(), verify=False,
        model_id="claude-sonnet-4-5-20250929", adapter_factory=_factory(_V10_REVIEW),
    )
    inv = result["replay_invocation"]
    assert inv["prompt"]["path"] == f"prompts/{REVIEWER_PROMPT_PATH_DEFAULT.name}"
    declared = {ref["path"] for ref in inv["inputs"]}
    assert not any(p.startswith("source-context/") for p in declared)
