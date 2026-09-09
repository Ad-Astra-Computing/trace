"""Bounded auto-retry tests for `_execute_reviewer` (REVIEWER_MAX_ATTEMPTS).

A live eval showed the Reviewer intermittently (~33%) drops the required
'## Equivalence assessment' section in the adaptation lane — transient model
non-determinism, not a substantive judgment. `_execute_reviewer` retries
ONLY parse/contract-malformed output, up to REVIEWER_MAX_ATTEMPTS total
attempts; a valid refusal or a valid review (any verdict) is a SUCCESS on
the first attempt and is never retried.

Mirrors tests/reviewer/test_execute_wiring.py's bundle-building shape but
adds a SequenceAdapter that returns a DIFFERENT canned response per
successive call, so tests can drive attempt-1-fails / attempt-2-succeeds
scenarios without live model spend.
"""

from __future__ import annotations

import json
import re
import shutil
from pathlib import Path

import pytest

from agents.patcher.adapter import ModelResponse
from tests.schema.validate import REPO_ROOT
from tools.trace_cli.execute import (
    REVIEWER_MAX_ATTEMPTS,
    ExecutionError,
    execute,
)


# Default per-attempt token usage when a test doesn't override it. Non-None so
# the summed-spend assertions have real numbers to add up.
_DEFAULT_INPUT_TOKENS = 100
_DEFAULT_OUTPUT_TOKENS = 50


class SequenceAdapter:
    """Returns `texts[i]` on the i-th call (clamped to the last entry once
    exhausted). Records every invocation so tests can assert call counts.

    `usages` optionally supplies a parallel list of (input_tokens,
    output_tokens) per call; when omitted every call reports the fixed
    _DEFAULT_INPUT_TOKENS / _DEFAULT_OUTPUT_TOKENS. Pass `usages=None`
    explicitly-as-none via the `report_usage=False` flag to model the
    FakeAdapter/OpenAI case where usage is unobserved (both fields None)."""

    def __init__(
        self,
        model_id: str,
        texts: list[str],
        *,
        usages: list[tuple[int, int] | None] | None = None,
        report_usage: bool = True,
    ) -> None:
        self.model_id = model_id
        self._texts = texts
        self._usages = usages
        self._report_usage = report_usage
        self.calls: list[dict] = []

    def invoke(
        self, *, system_prompt: str, user_content: str, sampling: dict
    ) -> ModelResponse:
        idx = min(len(self.calls), len(self._texts) - 1)
        self.calls.append(
            {
                "system_prompt_len": len(system_prompt.encode("utf-8")),
                "user_content_len": len(user_content.encode("utf-8")),
                "sampling": dict(sampling),
            }
        )
        if not self._report_usage:
            in_tok, out_tok = None, None
        elif self._usages is not None:
            uidx = min(idx, len(self._usages) - 1)
            entry = self._usages[uidx]
            # A None entry models an attempt whose usage was unobserved even
            # though a sibling attempt reported tokens (partial-observability).
            in_tok, out_tok = (None, None) if entry is None else entry
        else:
            in_tok, out_tok = _DEFAULT_INPUT_TOKENS, _DEFAULT_OUTPUT_TOKENS
        return ModelResponse(
            text=self._texts[idx],
            model_id=self.model_id,
            input_tokens=in_tok,
            output_tokens=out_tok,
            stop_reason="end_turn",
            extras={"adapter": "fake"},
        )


def _factory(texts: list[str]):
    def _make(model_id: str) -> SequenceAdapter:
        return SequenceAdapter(model_id, texts)

    return _make


MALFORMED_TEXT_1 = "this is not a review at all, no BEGIN marker"
MALFORMED_TEXT_2 = "still not a review, second garbage attempt"


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
    "=== BEGIN refusal ===\nrule: 1\nreason: patch.diff missing\n=== END refusal ==="
)


FIXTURE_SRC = (
    REPO_ROOT / "traces" / "example" / "CVE-0000-0010--patcher-fixture-dispatchable"
)
MAXIMA_FIXTURE_SRC = (
    REPO_ROOT / "traces" / "example" / "CVE-2024-34490--maxima-plot-tempfile-backport"
)


def _build_reviewable_bundle(tmp_path: Path) -> Path:
    """Copy the dispatchable patcher fixture and run the patcher first so
    review.md's dispatch guards + inputs are all satisfied. Verbatim
    (non-adaptation) lane."""
    bundle_dir = tmp_path / "bundle"
    shutil.copytree(FIXTURE_SRC, bundle_dir)
    patch_response = (
        "=== BEGIN patch.diff ===\n"
        "--- a/package.nix\n"
        "+++ b/package.nix\n"
        "@@ -4,3 +4,3 @@\n"
        '   pname = "libexample";\n'
        '-  version = "1.4.7";\n'
        '+  version = "1.4.8";\n'
        " \n"
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
        adapter_factory=_factory([patch_response]),
    )
    return bundle_dir


def _reviewer_failure_dirs(bundle_dir: Path) -> list[Path]:
    fail_root = bundle_dir / ".reviewer-failures"
    if not fail_root.is_dir():
        return []
    return sorted(p for p in fail_root.iterdir() if p.is_dir())


def _build_adaptation_bundle(tmp_path: Path) -> tuple[Path, str, str]:
    """Copy the committed maxima source-backport ADAPTATION-lane fixture
    (does NOT mutate the committed bundle) and strip its previously-recorded
    review artifacts so the test starts from a clean slate. Returns
    (bundle_dir, valid_review_text, missing_equivalence_review_text) built
    from the fixture's own ground-truth review.md, so the two attempts are
    byte-identical except for the '## Equivalence assessment' section."""
    bundle_dir = tmp_path / "bundle"
    shutil.copytree(MAXIMA_FIXTURE_SRC, bundle_dir)

    # Drop the fixture's own prior review artifacts — this test re-drives
    # the reviewer from scratch against a fresh SequenceAdapter.
    (bundle_dir / "review.md").unlink(missing_ok=True)
    (bundle_dir / "reviewer-invocation.json").unlink(missing_ok=True)
    (bundle_dir / "review-scoring-report.json").unlink(missing_ok=True)
    prior_failures = bundle_dir / ".reviewer-failures"
    if prior_failures.is_dir():
        shutil.rmtree(prior_failures)

    body = (MAXIMA_FIXTURE_SRC / "review.md").read_text()
    valid_text = "=== BEGIN review.md ===\n" + body + "=== END review.md ==="

    # Strip the '## Equivalence assessment' section (heading through the next
    # '## ' heading) — mirrors the live flake: parses fine (the section is
    # optional at the parser level) but fails the adaptation-lane contract
    # check, which requires it.
    no_equivalence_body = re.sub(
        r"\n## Equivalence assessment\n.*?(?=\n## )",
        "",
        body,
        flags=re.DOTALL,
    )
    assert "## Equivalence assessment" not in no_equivalence_body
    missing_equivalence_text = (
        "=== BEGIN review.md ===\n" + no_equivalence_body + "=== END review.md ==="
    )
    return bundle_dir, valid_text, missing_equivalence_text


# ─── (a) malformed-parse-then-valid-review ─────────────────────────────────


def test_retry_on_parse_malformed_then_valid_review(tmp_path: Path) -> None:
    bundle_dir = _build_reviewable_bundle(tmp_path)
    adapter = SequenceAdapter("claude-sonnet-4-6", [MALFORMED_TEXT_1, REVIEW_OK])
    result = execute(
        role="reviewer",
        bundle_dir=bundle_dir,
        invocation={"invocation_id": None, "inputs": [], "outputs": []},
        verify=False,
        model_id="claude-sonnet-4-6",
        adapter_factory=lambda mid: adapter,
    )
    assert result["kind"] == "review"
    assert (bundle_dir / "review.md").is_file()
    assert result["reviewer_run"]["first_attempt_conformant"] is False
    assert result["reviewer_run"]["retry_count"] == 1
    assert result["reviewer_run"]["reviewer_attempts"] == 2
    assert len(adapter.calls) == 2
    assert len(_reviewer_failure_dirs(bundle_dir)) == 1

    sidecar = json.loads((bundle_dir / "reviewer-invocation.json").read_text())
    assert sidecar["first_attempt_conformant"] is False
    assert sidecar["retry_count"] == 1
    assert sidecar["reviewer_attempts"] == 2
    # Total realized spend is the SUM across BOTH attempts (100/50 each).
    assert sidecar["usage"]["attempts"] == 2
    assert sidecar["usage"]["input_tokens"] == 200
    assert sidecar["usage"]["output_tokens"] == 100
    cost = sidecar["budget"]["actual_cost_usd"]
    assert cost is not None
    # Cost of two attempts strictly exceeds a single attempt's cost.
    from agents.cost import actual_cost_usd

    single = actual_cost_usd(
        model_id="claude-sonnet-4-6",
        input_tokens=100,
        output_tokens=50,
    )
    assert single is not None and cost > single
    assert cost == pytest.approx(
        actual_cost_usd(
            model_id="claude-sonnet-4-6",
            input_tokens=200,
            output_tokens=100,
        )
    )


# ─── (b) adaptation-lane missing-equivalence-then-valid (the live flake) ──


def test_retry_on_adaptation_lane_missing_equivalence_then_valid(
    tmp_path: Path,
) -> None:
    bundle_dir, valid_text, missing_equivalence_text = _build_adaptation_bundle(
        tmp_path
    )
    adapter = SequenceAdapter(
        "claude-sonnet-4-5-20250929",
        [missing_equivalence_text, valid_text],
    )
    result = execute(
        role="reviewer",
        bundle_dir=bundle_dir,
        invocation={"invocation_id": None, "inputs": [], "outputs": []},
        verify=False,
        model_id="claude-sonnet-4-5-20250929",
        adapter_factory=lambda mid: adapter,
    )
    assert result["kind"] == "review"
    assert (bundle_dir / "review.md").is_file()
    assert "## Equivalence assessment" in (bundle_dir / "review.md").read_text()
    assert result["reviewer_run"]["first_attempt_conformant"] is False
    assert result["reviewer_run"]["retry_count"] == 1
    assert result["reviewer_run"]["reviewer_attempts"] == 2
    assert len(adapter.calls) == 2
    assert len(_reviewer_failure_dirs(bundle_dir)) == 1

    # The adaptation-lane attempt-1 parsed cleanly (only the contract check
    # failed), so its usage is billed too: total is the SUM of both attempts.
    sidecar = json.loads((bundle_dir / "reviewer-invocation.json").read_text())
    assert sidecar["usage"]["attempts"] == 2
    assert sidecar["usage"]["input_tokens"] == 200
    assert sidecar["usage"]["output_tokens"] == 100
    assert sidecar["budget"]["actual_cost_usd"] is not None


# ─── (c) malformed-both ─────────────────────────────────────────────────────


def test_both_attempts_malformed_raises_execution_error(tmp_path: Path) -> None:
    bundle_dir = _build_reviewable_bundle(tmp_path)
    adapter = SequenceAdapter(
        "claude-sonnet-4-6",
        [MALFORMED_TEXT_1, MALFORMED_TEXT_2],
    )
    with pytest.raises(ExecutionError, match="reviewer output malformed"):
        execute(
            role="reviewer",
            bundle_dir=bundle_dir,
            invocation={"invocation_id": None, "inputs": [], "outputs": []},
            verify=False,
            model_id="claude-sonnet-4-6",
            adapter_factory=lambda mid: adapter,
        )
    assert len(adapter.calls) == REVIEWER_MAX_ATTEMPTS == 2
    fail_dirs = _reviewer_failure_dirs(bundle_dir)
    assert len(fail_dirs) == 2
    assert not (bundle_dir / "review.md").is_file()

    # Terminal exhaustion writes no invocation sidecar, so each failed attempt's
    # realized spend must survive in its own failure.json — otherwise a two-call
    # terminal failure would vanish from cost reporting entirely.
    for fd in fail_dirs:
        meta = json.loads((fd / "failure.json").read_text())
        assert meta["usage"]["input_tokens"] == _DEFAULT_INPUT_TOKENS
        assert meta["usage"]["output_tokens"] == _DEFAULT_OUTPUT_TOKENS
        assert meta["actual_cost_usd"] is not None


# ─── (d) valid refusal on first attempt: not retried ───────────────────────


def test_valid_refusal_first_attempt_not_retried(tmp_path: Path) -> None:
    bundle_dir = _build_reviewable_bundle(tmp_path)
    adapter = SequenceAdapter("claude-sonnet-4-6", [REFUSAL])
    result = execute(
        role="reviewer",
        bundle_dir=bundle_dir,
        invocation={"invocation_id": None, "inputs": [], "outputs": []},
        verify=False,
        model_id="claude-sonnet-4-6",
        adapter_factory=lambda mid: adapter,
    )
    assert result["kind"] == "refusal"
    assert (bundle_dir / "review-refusal.json").is_file()
    assert result["reviewer_run"]["reviewer_attempts"] == 1
    assert result["reviewer_run"]["first_attempt_conformant"] is True
    assert result["reviewer_run"]["retry_count"] == 0
    assert len(adapter.calls) == 1
    assert _reviewer_failure_dirs(bundle_dir) == []

    sidecar = json.loads((bundle_dir / "reviewer-invocation.json").read_text())
    assert sidecar["usage"]["attempts"] == 1
    assert sidecar["usage"]["input_tokens"] == _DEFAULT_INPUT_TOKENS
    assert sidecar["usage"]["output_tokens"] == _DEFAULT_OUTPUT_TOKENS


# ─── (e) valid reject-verdict review on first attempt: not retried ────────


def test_valid_reject_review_first_attempt_not_retried(tmp_path: Path) -> None:
    bundle_dir = _build_reviewable_bundle(tmp_path)
    adapter = SequenceAdapter("claude-sonnet-4-6", [REVIEW_REJECT])
    result = execute(
        role="reviewer",
        bundle_dir=bundle_dir,
        invocation={"invocation_id": None, "inputs": [], "outputs": []},
        verify=False,
        model_id="claude-sonnet-4-6",
        adapter_factory=lambda mid: adapter,
    )
    assert result["kind"] == "review"
    assert result["verdict"] == "reject"
    assert result["reviewer_run"]["reviewer_attempts"] == 1
    assert result["reviewer_run"]["first_attempt_conformant"] is True
    assert result["reviewer_run"]["retry_count"] == 0
    assert len(adapter.calls) == 1
    assert _reviewer_failure_dirs(bundle_dir) == []

    sidecar = json.loads((bundle_dir / "reviewer-invocation.json").read_text())
    assert sidecar["usage"]["attempts"] == 1
    assert sidecar["usage"]["input_tokens"] == _DEFAULT_INPUT_TOKENS
    assert sidecar["usage"]["output_tokens"] == _DEFAULT_OUTPUT_TOKENS


# ─── (f) FakeAdapter unobserved usage: null usage/cost, no 0-coercion ──────


def test_unobserved_usage_stays_null_no_zero_coercion(tmp_path: Path) -> None:
    """The FakeAdapter/OpenAI case reports no token usage (both fields None).
    The summed-spend path must keep usage.input_tokens/output_tokens None and
    actual_cost_usd None — a missing cost is 'unobserved', never a spurious 0.
    Exercised on the retry path (attempt 1 malformed, attempt 2 valid) so BOTH
    responses feed the None-safe aggregation."""
    bundle_dir = _build_reviewable_bundle(tmp_path)
    adapter = SequenceAdapter(
        "claude-sonnet-4-6",
        [MALFORMED_TEXT_1, REVIEW_OK],
        report_usage=False,
    )
    result = execute(
        role="reviewer",
        bundle_dir=bundle_dir,
        invocation={"invocation_id": None, "inputs": [], "outputs": []},
        verify=False,
        model_id="claude-sonnet-4-6",
        adapter_factory=lambda mid: adapter,
    )
    assert result["kind"] == "review"
    sidecar = json.loads((bundle_dir / "reviewer-invocation.json").read_text())
    assert sidecar["usage"]["attempts"] == 2
    assert sidecar["usage"]["input_tokens"] is None
    assert sidecar["usage"]["output_tokens"] is None
    assert sidecar["usage"]["cache_creation_input_tokens"] is None
    assert sidecar["usage"]["cache_read_input_tokens"] is None
    assert sidecar["budget"]["actual_cost_usd"] is None


# ─── (g) partial observability across attempts: total stays null ───────────


def test_partial_usage_across_attempts_stays_null(tmp_path: Path) -> None:
    """One attempt reports tokens, the other doesn't. A total can only be
    honest if EVERY included attempt reported the field — so the summed usage
    and cost must be None (unobserved), NOT the partial sum of the one attempt
    that happened to report. Guards against a silent spend undercount."""
    bundle_dir = _build_reviewable_bundle(tmp_path)
    # Attempt 1 (malformed) reports 100/50; attempt 2 (valid) reports nothing.
    adapter = SequenceAdapter(
        "claude-sonnet-4-6",
        [MALFORMED_TEXT_1, REVIEW_OK],
        usages=[(100, 50), None],
    )
    result = execute(
        role="reviewer",
        bundle_dir=bundle_dir,
        invocation={"invocation_id": None, "inputs": [], "outputs": []},
        verify=False,
        model_id="claude-sonnet-4-6",
        adapter_factory=lambda mid: adapter,
    )
    assert result["kind"] == "review"
    sidecar = json.loads((bundle_dir / "reviewer-invocation.json").read_text())
    assert sidecar["usage"]["attempts"] == 2
    # Partial sum (100/50) would be a misleading 'complete' total — must be None.
    assert sidecar["usage"]["input_tokens"] is None
    assert sidecar["usage"]["output_tokens"] is None
    assert sidecar["budget"]["actual_cost_usd"] is None
