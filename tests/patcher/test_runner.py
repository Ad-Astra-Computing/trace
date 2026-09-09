"""Runner tests for Patcher.

Uses FakeAdapter to exercise the full prompt-assembly → adapter →
parse → result pipeline without API calls. Also exercises the
fail-loud path on malformed model output.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from agents.patcher import FakeAdapter, PatcherOutputMalformed, run_patcher


REPO_ROOT = Path(__file__).resolve().parents[2]
PROMPT_PATH = REPO_ROOT / "prompts" / "patcher.v2.md"


RATIONALE = """## Upstream reference
Fix lands in v1.4.8 per upstream commit abc1234.

## Why this version
1.4.8 is the smallest patch release containing the fix.

## Why minimal
Only pkgs/by-name/li/libexample/package.nix is touched.

## Alternatives rejected
- Cherry-pick onto 1.4.7: no benefit over version bump.
- Jump to 2.0.0: unrelated behaviour changes.

## Downstream risk
reverse_closure_count=42; under threshold.
"""


def _fake_patch_response() -> str:
    return (
        "=== BEGIN patch.diff ===\n"
        "--- a/pkgs/by-name/li/libexample/package.nix\n"
        "+++ b/pkgs/by-name/li/libexample/package.nix\n"
        "@@ -1 +1 @@\n"
        '-version = "1.4.7";\n'
        '+version = "1.4.8";\n'
        "=== END patch.diff ===\n"
        "=== BEGIN patch-rationale.md ===\n"
        + RATIONALE
        + "=== END patch-rationale.md ==="
    )


def _fake_refusal_response() -> str:
    return (
        "=== BEGIN refusal ===\n"
        "rule: 3\n"
        "reason: upstream-ref.eligibility.verdict == ineligible-cherry-pick-required\n"
        "=== END refusal ==="
    )


def _minimal_inputs() -> dict:
    return {
        "finding": {
            "cve_id": "CVE-0000-0001",
            "affected": [{"attr_path": "libexample", "version": "1.4.7"}],
        },
        "upstream_ref": {
            "cve_id": "CVE-0000-0001",
            "current_version": "1.4.7",
            "target_version": "1.4.8",
            "fix_tier": "security-patch-release",
            "eligibility": {"verdict": "eligible"},
        },
        "impact": {
            "cve_id": "CVE-0000-0001",
            "reverse_closure_count": 42,
            "exceeds_threshold": False,
        },
        "maintainers": {
            "cve_id": "CVE-0000-0001",
            "attr_paths": {"libexample": {"maintainers": [{"github": "alice"}]}},
        },
        "package_source": 'version = "1.4.7";\n',
        "package_source_path": "pkgs/by-name/li/libexample/package.nix",
    }


def test_runner_happy_path_produces_patch():
    adapter = FakeAdapter("fake-opus-4-7", _fake_patch_response())
    result = run_patcher(
        inputs=_minimal_inputs(), adapter=adapter, prompt_path=PROMPT_PATH
    )
    assert result.kind == "patch"
    assert result.parsed.patch_diff.startswith("--- a/pkgs/by-name/li/libexample")
    assert result.parsed.patch_rationale_md.startswith("## Upstream reference")
    assert len(result.prompt_sha256) == 64
    assert len(result.user_content_sha256) == 64
    assert len(result.raw_response_sha256) == 64
    assert result.prompt_bytes > 0
    assert result.user_content_bytes > 0
    # Adapter was called exactly once with the correct shape
    assert len(adapter.calls) == 1
    call = adapter.calls[0]
    assert call["system_prompt_len"] == result.prompt_bytes
    assert call["sampling"]["temperature"] == 0.0


def test_runner_happy_path_produces_refusal():
    adapter = FakeAdapter("fake-opus-4-7", _fake_refusal_response())
    result = run_patcher(
        inputs=_minimal_inputs(), adapter=adapter, prompt_path=PROMPT_PATH
    )
    assert result.kind == "refusal"
    assert result.parsed.refusal_rule == 3
    assert "ineligible-cherry-pick-required" in result.parsed.refusal_reason


def test_runner_fails_loud_on_malformed_output():
    adapter = FakeAdapter(
        "fake-opus-4-7",
        "Sure! I'll help you patch this. Here's what I think...",
    )
    with pytest.raises(PatcherOutputMalformed):
        run_patcher(inputs=_minimal_inputs(), adapter=adapter, prompt_path=PROMPT_PATH)


def test_runner_rejects_missing_inputs():
    adapter = FakeAdapter("fake-opus-4-7", _fake_patch_response())
    bad_inputs = {"finding": {}}  # missing most keys
    with pytest.raises(ValueError, match="missing input keys"):
        run_patcher(inputs=bad_inputs, adapter=adapter, prompt_path=PROMPT_PATH)


def test_runner_requires_prompt_file(tmp_path):
    adapter = FakeAdapter("fake-opus-4-7", _fake_patch_response())
    missing_prompt = tmp_path / "nope.md"
    with pytest.raises(FileNotFoundError):
        run_patcher(
            inputs=_minimal_inputs(), adapter=adapter, prompt_path=missing_prompt
        )


def test_runner_sampling_override_applies():
    adapter = FakeAdapter("fake-opus-4-7", _fake_patch_response())
    result = run_patcher(
        inputs=_minimal_inputs(),
        adapter=adapter,
        sampling={"temperature": 0.7, "max_tokens": 16384},
        prompt_path=PROMPT_PATH,
    )
    assert result.sampling["temperature"] == 0.7
    assert result.sampling["max_tokens"] == 16384
    assert result.sampling["top_p"] == 1.0  # default preserved
    assert adapter.calls[0]["sampling"]["temperature"] == 0.7


def test_fake_adapter_records_every_call():
    """Structural: FakeAdapter is a research tool, it must record every invocation."""
    adapter = FakeAdapter("fake", _fake_patch_response())
    run_patcher(inputs=_minimal_inputs(), adapter=adapter, prompt_path=PROMPT_PATH)
    run_patcher(inputs=_minimal_inputs(), adapter=adapter, prompt_path=PROMPT_PATH)
    assert len(adapter.calls) == 2
