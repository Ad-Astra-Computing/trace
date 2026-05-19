"""End-to-end wiring tests for `_execute_reviewer`.

Mirrors tests/patcher/test_execute_wiring.py shape: build a
dispatchable bundle (with a patch.diff + patch-rationale.md committed
by a prior Patcher run), inject a FakeAdapter via adapter_factory, and
verify the executor writes review.md / records the replay invocation /
honours the cross-family rule.
"""

from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest

from agents.patcher import FakeAdapter
from tests.schema.validate import REPO_ROOT
from tools.trace_cli.execute import (
    ExecutionError,
    PatcherDispatchRefused,
    execute,
)


REVIEW_OK = (
    "=== BEGIN review.md ===\n"
    "## Verdict\n"
    "accept\n"
    "\n"
    "## Reasoning\n"
    "patch.diff updates libexample 1.4.7 to 1.4.8 per upstream-ref.json. "
    "Hashes are grounded; rationale cites the upstream commit sha.\n"
    "\n"
    "## Findings\n"
    "(none)\n"
    "\n"
    "## Cited evidence\n"
    "- upstream-ref.json:target_version=1.4.8\n"
    "- patch.diff\n"
    "- patch-rationale.md\n"
    "\n"
    "## Cross-family attestation\n"
    "reviewer_family: anthropic-sonnet\n"
    "patcher_family_observed: anthropic-opus\n"
    "rule_honored: true\n"
    "=== END review.md ==="
)


REVIEW_REJECT = (
    "=== BEGIN review.md ===\n"
    "## Verdict\n"
    "reject\n"
    "\n"
    "## Reasoning\n"
    "patch.diff emits an ungrounded hash value; no match in prefetch_hashes.\n"
    "\n"
    "## Findings\n"
    "- severity: blocking — vendorHash ungrounded — patch.diff:hunk=1\n"
    "\n"
    "## Cited evidence\n"
    "- patch.diff:hunk=1\n"
    "- upstream-ref.json:prefetch_hashes\n"
    "\n"
    "## Cross-family attestation\n"
    "reviewer_family: anthropic-sonnet\n"
    "patcher_family_observed: anthropic-opus\n"
    "rule_honored: true\n"
    "=== END review.md ==="
)


REFUSAL = (
    "=== BEGIN refusal ===\n"
    "rule: 1\n"
    "reason: patch.diff missing\n"
    "=== END refusal ==="
)


FIXTURE_SRC = REPO_ROOT / "traces" / "example" / "CVE-0000-0010--patcher-fixture-dispatchable"


def _factory(text: str):
    def _make(model_id: str) -> FakeAdapter:
        return FakeAdapter(model_id, text)
    return _make


def _build_reviewable_bundle(tmp_path: Path) -> Path:
    """Copy the dispatchable patcher fixture and run the patcher first
    so we have a patch.diff + patch-rationale.md + replay.json with a
    patcher invocation. The reviewer needs all of that on disk."""
    bundle_dir = tmp_path / "bundle"
    shutil.copytree(FIXTURE_SRC, bundle_dir)
    # Run the patcher with a canned response.
    patch_response = (
        "=== BEGIN patch.diff ===\n"
        "--- a/package.nix\n"
        "+++ b/package.nix\n"
        "@@ -4,3 +4,3 @@\n"
        '   pname = "libexample";\n'
        '-  version = "1.4.7";\n'
        '+  version = "1.4.8";\n'
        ' \n'
        "=== END patch.diff ===\n"
        "=== BEGIN patch-rationale.md ===\n"
        "## Upstream reference\nfix at v1.4.8 per upstream commit abc1234\n\n"
        "## Why this version\nsmallest qualifying release\n\n"
        "## Why minimal\nversion only\n\n"
        "## Alternatives rejected\n- cherry-pick: rejected\n- jump to 2.0: rejected\n\n"
        "## Downstream risk\nnone, alice + bob own this attr.\n"
        "=== END patch-rationale.md ==="
    )
    execute(
        role="patcher",
        bundle_dir=bundle_dir,
        invocation={"invocation_id": None, "inputs": [], "outputs": []},
        verify=False,
        model_id="claude-opus-4-7",
        adapter_factory=_factory(patch_response),
    )
    return bundle_dir


# ─── happy path ────────────────────────────────────────────────────────────


def test_reviewer_writes_review_md_and_appends_replay(tmp_path: Path) -> None:
    bundle_dir = _build_reviewable_bundle(tmp_path)
    result = execute(
        role="reviewer",
        bundle_dir=bundle_dir,
        invocation={"invocation_id": None, "inputs": [], "outputs": []},
        verify=False,
        # Cross-family rule: patcher used opus; reviewer uses sonnet.
        model_id="claude-sonnet-4-6",
        adapter_factory=_factory(REVIEW_OK),
    )
    assert result["role"] == "reviewer"
    assert result["kind"] == "review"
    assert result["verdict"] == "accept"
    assert (bundle_dir / "review.md").is_file()
    review_bytes = (bundle_dir / "review.md").read_bytes()
    assert review_bytes.endswith(b"\n")
    assert b"## Verdict" in review_bytes

    # replay.json grew a reviewer role.
    replay = json.loads((bundle_dir / "replay.json").read_text())
    reviewer_roles = [r for r in replay["roles"] if r["role"] == "reviewer"]
    assert len(reviewer_roles) == 1
    inv = reviewer_roles[0]["invocations"][-1]
    assert inv["model"]["model_id"] == "claude-sonnet-4-6"
    # Reviewer's input set includes patch.diff + patch-rationale.md.
    input_paths = {i["path"] for i in inv["inputs"]}
    assert {"finding.json", "upstream-ref.json", "patch.diff",
            "patch-rationale.md", "package.nix"} <= input_paths


def test_reviewer_reject_verdict_writes_findings(tmp_path: Path) -> None:
    bundle_dir = _build_reviewable_bundle(tmp_path)
    result = execute(
        role="reviewer",
        bundle_dir=bundle_dir,
        invocation={"invocation_id": None, "inputs": [], "outputs": []},
        verify=False,
        model_id="claude-sonnet-4-6",
        adapter_factory=_factory(REVIEW_REJECT),
    )
    assert result["verdict"] == "reject"
    review_md = (bundle_dir / "review.md").read_text()
    assert "blocking" in review_md
    assert "vendorHash ungrounded" in review_md


# ─── refusal path ──────────────────────────────────────────────────────────


def test_reviewer_refusal_writes_review_refusal_json(tmp_path: Path) -> None:
    bundle_dir = _build_reviewable_bundle(tmp_path)
    result = execute(
        role="reviewer",
        bundle_dir=bundle_dir,
        invocation={"invocation_id": None, "inputs": [], "outputs": []},
        verify=False,
        model_id="claude-sonnet-4-6",
        adapter_factory=_factory(REFUSAL),
    )
    assert result["kind"] == "refusal"
    refusal = json.loads((bundle_dir / "review-refusal.json").read_text())
    assert refusal["rule"] == 1
    assert "patch.diff missing" in refusal["reason"]
    # patcher's outputs (patch.diff + patch-rationale.md) untouched.
    assert (bundle_dir / "patch.diff").is_file()
    assert (bundle_dir / "patch-rationale.md").is_file()


# ─── dispatch guards ───────────────────────────────────────────────────────


def test_reviewer_refuses_when_patcher_emitted_refusal(tmp_path: Path) -> None:
    bundle_dir = _build_reviewable_bundle(tmp_path)
    # Synthesise a patcher refusal by writing refusal.json.
    (bundle_dir / "refusal.json").write_text('{"rule": 8, "reason": "test"}')
    with pytest.raises(PatcherDispatchRefused, match="refusal.json"):
        execute(
            role="reviewer",
            bundle_dir=bundle_dir,
            invocation={"invocation_id": None, "inputs": [], "outputs": []},
            verify=False,
            model_id="claude-sonnet-4-6",
            adapter_factory=_factory(REVIEW_OK),
        )


def test_reviewer_refuses_advisory_only_bundle(tmp_path: Path) -> None:
    bundle_dir = _build_reviewable_bundle(tmp_path)
    bundle = json.loads((bundle_dir / "bundle.json").read_text())
    bundle["kind"] = "advisory-only"
    bundle["kind_reason"] = "ineligible-no-fix-available"
    (bundle_dir / "bundle.json").write_text(json.dumps(bundle))
    with pytest.raises(PatcherDispatchRefused, match="advisory-only"):
        execute(
            role="reviewer",
            bundle_dir=bundle_dir,
            invocation={"invocation_id": None, "inputs": [], "outputs": []},
            verify=False,
            model_id="claude-sonnet-4-6",
            adapter_factory=_factory(REVIEW_OK),
        )


def test_reviewer_refuses_same_family_as_patcher(tmp_path: Path) -> None:
    """Cross-family rule (SPEC §4): patcher used opus; reviewer requested
    is also opus → refuse with a structural error before any model call."""
    bundle_dir = _build_reviewable_bundle(tmp_path)
    with pytest.raises(ExecutionError, match="cross-family"):
        execute(
            role="reviewer",
            bundle_dir=bundle_dir,
            invocation={"invocation_id": None, "inputs": [], "outputs": []},
            verify=False,
            model_id="claude-opus-4-7",  # SAME family as patcher
            adapter_factory=_factory(REVIEW_OK),
        )


def test_reviewer_requires_patch_diff_on_disk(tmp_path: Path) -> None:
    bundle_dir = _build_reviewable_bundle(tmp_path)
    (bundle_dir / "patch.diff").unlink()
    with pytest.raises(ExecutionError, match="patch.diff"):
        execute(
            role="reviewer",
            bundle_dir=bundle_dir,
            invocation={"invocation_id": None, "inputs": [], "outputs": []},
            verify=False,
            model_id="claude-sonnet-4-6",
            adapter_factory=_factory(REVIEW_OK),
        )


# ─── v2 prompt wiring (DECISIONS 2026-05-19) ───────────────────────────────


def test_reviewer_prompt_path_default_is_v2() -> None:
    """The Reviewer runner must default to prompt v2. F11-era hallucination
    fix: v2 grounds Cross-family attestation in an executor-supplied
    Model attestation context block; if execute.py still pointed at v1,
    the prompt-bump would be a no-op."""
    from tools.trace_cli.execute import REVIEWER_PROMPT_PATH_DEFAULT
    assert REVIEWER_PROMPT_PATH_DEFAULT.name == "reviewer.v2.md"
    assert REVIEWER_PROMPT_PATH_DEFAULT.is_file()


def test_reviewer_user_content_surfaces_attestation_block(tmp_path: Path) -> None:
    """The Reviewer's user message must surface the Model attestation
    context block at the very top so the model copies the family
    strings verbatim, not from inference."""
    bundle_dir = _build_reviewable_bundle(tmp_path)

    captured: dict = {}

    class CapturingAdapter:
        def __init__(self, model_id: str) -> None:
            self.model_id = model_id

        def invoke(self, *, system_prompt, user_content, sampling):
            captured["user_content"] = user_content
            captured["system_prompt"] = system_prompt
            from agents.patcher.adapter import ModelResponse
            return ModelResponse(
                text=REVIEW_OK,
                model_id=self.model_id,
                input_tokens=1,
                output_tokens=1,
                cache_creation_input_tokens=0,
                cache_read_input_tokens=0,
                stop_reason="end_turn",
            )

    execute(
        role="reviewer",
        bundle_dir=bundle_dir,
        invocation={"invocation_id": None, "inputs": [], "outputs": []},
        verify=False,
        model_id="claude-sonnet-4-5-20250929",
        adapter_factory=lambda mid: CapturingAdapter(mid),
    )
    uc = captured["user_content"]
    assert "# Model attestation context" in uc
    assert "reviewer_model_id: claude-sonnet-4-5-20250929" in uc
    assert "reviewer_family: anthropic-sonnet" in uc
    assert "patcher_model_id: claude-opus-4-7" in uc
    assert "patcher_family: anthropic-opus" in uc
    assert "cross_family_rule_honored_expected: true" in uc
