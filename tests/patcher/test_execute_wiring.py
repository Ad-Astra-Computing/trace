"""End-to-end wiring of `trace replay --execute --role patcher --model <id>`.

Tests operate at the `execute()` API level (not subprocess CLI level) so
we can inject `FakeAdapter` via `adapter_factory` without a real model call.
A thin CLI-level smoke test verifies arg plumbing.

Covers the four constraints from the session plan:
  1. Hard-fail if the corpus entry is advisory-only / non-dispatchable.
  2. Malformed model output stops BEFORE any replay mutation is committed.
  3. Outputs are written atomically (no partial files after parse failure).
  4. Adapter selection explicit; no default live model if --model is absent.
"""

from __future__ import annotations

import json
import os
import shutil
from pathlib import Path

import pytest

from agents.patcher import FakeAdapter
from tools.trace_cli.execute import (
    ExecutionError,
    MODEL_BACKED_ROLES,
    PatcherDispatchRefused,
    execute,
)


RATIONALE = """## Upstream reference
Fix lands in v1.4.8 per upstream commit abc1234.

## Why this version
1.4.8 is the smallest patch release containing the fix.

## Why minimal
Only package.nix is touched.

## Alternatives rejected
- Cherry-pick onto 1.4.7: no benefit over version bump.
- Jump to 2.0.0: unrelated behaviour changes.

## Downstream risk
reverse_closure_count=42; under threshold.
"""


def _valid_patch_response() -> str:
    return (
        "=== BEGIN patch.diff ===\n"
        "--- a/package.nix\n"
        "+++ b/package.nix\n"
        "@@ -1 +1 @@\n"
        "-version = \"1.4.7\";\n"
        "+version = \"1.4.8\";\n"
        "=== END patch.diff ===\n"
        "=== BEGIN patch-rationale.md ===\n"
        + RATIONALE
        + "=== END patch-rationale.md ==="
    )


def _valid_refusal_response() -> str:
    return (
        "=== BEGIN refusal ===\n"
        "rule: 3\n"
        "reason: upstream-ref.eligibility.verdict is ineligible-cherry-pick-required\n"
        "=== END refusal ==="
    )


def _build_dispatchable_bundle(
    tmp_path: Path,
    *,
    kind: str = "auto-merge",
    verdict: str = "eligible",
) -> Path:
    """Write a bundle_dir with the five files Patcher needs and a bundle.json."""
    bundle_dir = tmp_path / "bundle"
    bundle_dir.mkdir()

    (bundle_dir / "bundle.json").write_text(json.dumps({
        "schema_version": "1.0.0",
        "bundle_id": "0000000000000001",
        "cve_id": "CVE-0000-0001",
        "nixpkgs_rev": "0" * 40,
        "kind": kind,
    }))
    (bundle_dir / "finding.json").write_text(json.dumps({
        "cve_id": "CVE-0000-0001",
        "affected": [{"attr_path": "libexample", "version": "1.4.7"}],
    }))
    upstream_ref = {
        "cve_id": "CVE-0000-0001",
        "current_version": "1.4.7",
        "target_version": "1.4.8",
        "fix_tier": "security-patch-release",
        "eligibility": {"verdict": verdict},
    }
    if verdict.startswith("ineligible-"):
        upstream_ref["eligibility"]["verdict_reason"] = "test fixture"
    (bundle_dir / "upstream-ref.json").write_text(json.dumps(upstream_ref))
    (bundle_dir / "impact.json").write_text(json.dumps({
        "cve_id": "CVE-0000-0001",
        "reverse_closure_count": 42,
        "exceeds_threshold": False,
    }))
    (bundle_dir / "maintainers.json").write_text(json.dumps({
        "cve_id": "CVE-0000-0001",
        "attr_paths": {"libexample": {"maintainers": [{"github": "alice"}]}},
    }))
    (bundle_dir / "package.nix").write_text('version = "1.4.7";\n')

    # Minimal replay.json so the patcher replay-metadata writer has a file
    # to append to. Schema requires non-empty roles[] — seed with a single
    # deterministic stub invocation so the file is schema-valid pre-Patcher.
    replay = {
        "schema_version": "1.0.0",
        "bundle_id": "0000000000000001",
        "cve_id": "CVE-0000-0001",
        "nixpkgs_rev": "0" * 40,
        "policy_version": "0" * 64,
        "bundle_schema_sha256": "1" * 64,
        "routing_config_sha256": "2" * 64,
        "tool_manifest": {
            "flake_lock_sha256": "3" * 64,
            "tools": [{"name": "python", "version": "3.13"}],
        },
        "cross_family_rule_honored": True,
        "roles": [
            {
                "role": "upstream-ref-resolver",
                "invocations": [
                    {
                        "invocation_id": "00000000-0000-4000-8000-000000000001",
                        "role": "upstream-ref-resolver",
                        "started_at": "2026-04-23T00:00:00Z",
                        "ended_at": "2026-04-23T00:00:01Z",
                        "model": {
                            "family": "deterministic-no-model",
                            "vendor": "internal",
                            "model_id": "upstream-ref-resolver-deterministic",
                            "version": "1.0.0",
                            "sampling": {"temperature": 0, "top_p": 1, "max_tokens": 1},
                        },
                        "prompt": {"path": "prompts/upstream-ref-resolver.v1.md", "sha256": "7" * 64},
                        "inputs": [{"path": "finding.json", "sha256": "6" * 64}],
                        "outputs": [{"path": "upstream-ref.json", "sha256": "8" * 64}],
                        "rng_seed": None,
                        "validators_passed": ["eligibility-verdict-present"],
                        "network_policy_applied": "feeds-only",
                    }
                ],
            }
        ],
    }
    (bundle_dir / "replay.json").write_text(json.dumps(replay))
    return bundle_dir


def _fresh_invocation() -> dict:
    return {"invocation_id": None, "inputs": [], "outputs": []}


def _factory(response_text: str):
    """Return an adapter_factory that builds a FakeAdapter with the given text."""
    def _make(model_id: str) -> FakeAdapter:
        return FakeAdapter(model_id, response_text)
    return _make


# ─── happy path: patch writes outputs ──────────────────────────────────────


def test_patcher_happy_path_writes_patch_and_rationale(tmp_path):
    bundle_dir = _build_dispatchable_bundle(tmp_path)
    result = execute(
        role="patcher",
        bundle_dir=bundle_dir,
        invocation=_fresh_invocation(),
        verify=False,
        model_id="fake-opus-4-7",
        adapter_factory=_factory(_valid_patch_response()),
    )
    assert result["kind"] == "patch"
    assert (bundle_dir / "patch.diff").is_file()
    assert (bundle_dir / "patch-rationale.md").is_file()
    assert not (bundle_dir / "refusal.json").exists()

    # Output paths + sha256s reported in result
    paths = {o["path"] for o in result["outputs"]}
    assert paths == {"patch.diff", "patch-rationale.md"}
    for o in result["outputs"]:
        assert len(o["sha256"]) == 64
        assert o["bytes"] > 0

    # patcher_run metadata present (for replay.json writer to consume)
    pr = result["patcher_run"]
    assert pr["model_id"] == "fake-opus-4-7"
    assert len(pr["prompt_sha256"]) == 64
    assert len(pr["user_content_sha256"]) == 64
    assert len(pr["raw_response_sha256"]) == 64
    assert pr["sampling"]["temperature"] == 0.0
    assert pr["adapter"] == "fake"


# ─── happy path: model refusal writes refusal.json (not patch) ─────────────


def test_patcher_refusal_response_writes_refusal_json(tmp_path):
    bundle_dir = _build_dispatchable_bundle(tmp_path)
    result = execute(
        role="patcher",
        bundle_dir=bundle_dir,
        invocation=_fresh_invocation(),
        verify=False,
        model_id="fake-opus-4-7",
        adapter_factory=_factory(_valid_refusal_response()),
    )
    assert result["kind"] == "refusal"
    assert (bundle_dir / "refusal.json").is_file()
    assert not (bundle_dir / "patch.diff").exists()
    assert not (bundle_dir / "patch-rationale.md").exists()

    refusal = json.loads((bundle_dir / "refusal.json").read_text())
    assert refusal["rule"] == 3
    assert "ineligible-cherry-pick-required" in refusal["reason"]


# ─── constraint 1: hard-fail on advisory-only / ineligible ─────────────────


def test_patcher_refuses_advisory_only_bundle(tmp_path):
    bundle_dir = _build_dispatchable_bundle(tmp_path, kind="advisory-only")
    with pytest.raises(PatcherDispatchRefused, match="advisory-only"):
        execute(
            role="patcher",
            bundle_dir=bundle_dir,
            invocation=_fresh_invocation(),
            verify=False,
            model_id="fake-opus-4-7",
            adapter_factory=_factory(_valid_patch_response()),
        )
    # No outputs written.
    assert not (bundle_dir / "patch.diff").exists()
    assert not (bundle_dir / "patch-rationale.md").exists()
    assert not (bundle_dir / "refusal.json").exists()


def test_patcher_refuses_ineligible_verdict(tmp_path):
    bundle_dir = _build_dispatchable_bundle(
        tmp_path, verdict="ineligible-cherry-pick-required"
    )
    with pytest.raises(PatcherDispatchRefused, match="ineligible-cherry-pick-required"):
        execute(
            role="patcher",
            bundle_dir=bundle_dir,
            invocation=_fresh_invocation(),
            verify=False,
            model_id="fake-opus-4-7",
            adapter_factory=_factory(_valid_patch_response()),
        )
    assert not (bundle_dir / "patch.diff").exists()


def test_patcher_refuses_missing_eligibility(tmp_path):
    bundle_dir = _build_dispatchable_bundle(tmp_path)
    # remove eligibility from upstream-ref
    ur = json.loads((bundle_dir / "upstream-ref.json").read_text())
    ur.pop("eligibility", None)
    (bundle_dir / "upstream-ref.json").write_text(json.dumps(ur))
    with pytest.raises(ExecutionError, match="eligibility.verdict"):
        execute(
            role="patcher",
            bundle_dir=bundle_dir,
            invocation=_fresh_invocation(),
            verify=False,
            model_id="fake-opus-4-7",
            adapter_factory=_factory(_valid_patch_response()),
        )


# ─── constraint 2: malformed output commits no replay mutation ─────────────


def test_patcher_malformed_model_output_writes_no_files(tmp_path):
    bundle_dir = _build_dispatchable_bundle(tmp_path)
    malformed = "Sure! Here's your patch:\n\nsome random text without the block markers"
    with pytest.raises(ExecutionError, match="patcher output malformed"):
        execute(
            role="patcher",
            bundle_dir=bundle_dir,
            invocation=_fresh_invocation(),
            verify=False,
            model_id="fake-opus-4-7",
            adapter_factory=_factory(malformed),
        )
    # Neither outputs nor any partial files linger.
    assert not (bundle_dir / "patch.diff").exists()
    assert not (bundle_dir / "patch-rationale.md").exists()
    assert not (bundle_dir / "refusal.json").exists()
    # No temp files either.
    stray_tmps = list(bundle_dir.glob(".*.tmp"))
    assert not stray_tmps, f"stray temp files: {stray_tmps}"


# ─── constraint 3: atomic write leaves no temp files on disk ───────────────


def test_patcher_happy_path_leaves_no_temp_files(tmp_path):
    bundle_dir = _build_dispatchable_bundle(tmp_path)
    execute(
        role="patcher",
        bundle_dir=bundle_dir,
        invocation=_fresh_invocation(),
        verify=False,
        model_id="fake-opus-4-7",
        adapter_factory=_factory(_valid_patch_response()),
    )
    # Temp files used by _atomic_write_bytes (prefix `.<name>.`, suffix `.tmp`).
    stray_tmps = list(bundle_dir.glob(".*.tmp"))
    assert not stray_tmps, f"stray temp files after successful run: {stray_tmps}"


# ─── constraint 4: adapter selection explicit ──────────────────────────────


def test_patcher_requires_explicit_model_id(tmp_path):
    bundle_dir = _build_dispatchable_bundle(tmp_path)
    with pytest.raises(ExecutionError, match="requires explicit --model"):
        execute(
            role="patcher",
            bundle_dir=bundle_dir,
            invocation=_fresh_invocation(),
            verify=False,
            model_id=None,  # the whole point
        )


def test_patcher_refuses_non_claude_without_adapter_factory(tmp_path):
    bundle_dir = _build_dispatchable_bundle(tmp_path)
    with pytest.raises(ExecutionError, match="no adapter wired"):
        execute(
            role="patcher",
            bundle_dir=bundle_dir,
            invocation=_fresh_invocation(),
            verify=False,
            model_id="some-open-weight-model",  # not claude-* and no factory
        )


# ─── CLI-level smoke: arg plumbing ─────────────────────────────────────────


def test_cli_rejects_patcher_without_model(tmp_path, capsys):
    from tools.trace_cli.cli import main

    bundle_dir = _build_dispatchable_bundle(tmp_path)
    # Need a minimal replay.json so the CLI's bundle-loader is happy.
    (bundle_dir / "replay.json").write_text(json.dumps({"roles": []}))

    rc = main([
        "replay", str(bundle_dir),
        "--execute", "--role", "patcher",
        "--traces-root", str(tmp_path),
    ])
    assert rc != 0
    err = capsys.readouterr().err
    assert "requires --model" in err


# ─── Reviewer / Reproducer still rejected ──────────────────────────────────


def test_reviewer_still_rejected(tmp_path):
    bundle_dir = _build_dispatchable_bundle(tmp_path)
    with pytest.raises(ExecutionError, match="not yet wired"):
        execute(
            role="reviewer",
            bundle_dir=bundle_dir,
            invocation=_fresh_invocation(),
            verify=False,
            model_id="fake",
        )


def test_model_backed_roles_set_is_stable():
    """Structural: only patcher in MODEL_BACKED_ROLES for now."""
    assert MODEL_BACKED_ROLES == frozenset({"patcher"})
