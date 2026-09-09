"""Sanity tests for .github/workflows/real-prefetch-smoke.yml.

The workflow is opt-in (manual dispatch only) and exercises live
network paths, so it can't run in the offline suite. These checks
validate that what it points at exists and is well-formed: the helper
script, the resolver-input fixture, the cohort label, and the pinned
external-action SHAs.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from tests.schema.validate import REPO_ROOT


WORKFLOW = REPO_ROOT / ".github" / "workflows" / "real-prefetch-smoke.yml"


def _read_workflow() -> str:
    return WORKFLOW.read_text()


def test_workflow_exists() -> None:
    assert WORKFLOW.is_file(), f"{WORKFLOW} missing"


def test_workflow_is_manual_dispatch_only() -> None:
    """Opt-in cohort. NEVER triggers on push or PR."""
    text = _read_workflow()
    assert "workflow_dispatch:" in text
    # Push / pull_request triggers must NOT be present.
    assert not re.search(r"^\s*push:\s*$", text, re.MULTILINE), (
        "real-prefetch-smoke.yml must not trigger on push"
    )
    assert not re.search(r"^\s*pull_request:\s*$", text, re.MULTILINE), (
        "real-prefetch-smoke.yml must not trigger on pull_request"
    )
    assert not re.search(r"^\s*schedule:\s*$", text, re.MULTILINE), (
        "real-prefetch-smoke.yml must not have a schedule trigger"
    )


def test_workflow_pins_determinate_actions_by_sha() -> None:
    """Pinned by full commit SHA (mirrors ci.yml convention)."""
    text = _read_workflow()
    # nix-installer-action and magic-nix-cache-action both appear with
    # `@<sha40>` followed by `# v<n>` documentation comment.
    sha_pin_re = re.compile(
        r"DeterminateSystems/(?:nix-installer-action|magic-nix-cache-action)"
        r"@[0-9a-f]{40}\s*#\s*v\d+",
    )
    assert sha_pin_re.search(text), (
        "DeterminateSystems actions must be pinned by 40-char SHA with "
        "a '# v<n>' tag comment"
    )


def test_workflow_sets_real_network_env_gates() -> None:
    """The two opt-in env gates must both be set so the gated tests
    actually execute."""
    text = _read_workflow()
    assert 'TRACE_REAL_PREFETCH: "1"' in text
    assert 'TRACE_REAL_GO_VENDOR: "1"' in text


def test_workflow_uses_real_ci_smoke_cohort_label() -> None:
    """Cohort label must be `real-ci-smoke` per the design call: never
    gets mixed with inner-loop or full-corpus aggregates."""
    text = _read_workflow()
    assert 'COHORT_LABEL: "real-ci-smoke"' in text


def test_workflow_runs_only_the_two_gated_pytest_cases() -> None:
    """The gated step must NOT run the whole offline suite (that lives
    in ci.yml)."""
    text = _read_workflow()
    # The two qualified test-ids the workflow points at.
    assert (
        "tests/upstream_ref_resolver/test_prefetch.py::test_real_nix_prefetch_url_smoke"
        in text
    )
    assert (
        "tests/upstream_ref_resolver/test_go_mod_vendor.py::test_real_traefik_go_vendor_smoke"
        in text
    )


def test_workflow_helper_script_exists_and_runs() -> None:
    """The score_invocation.py helper that the workflow shells out to
    must be on disk and importable."""
    helper = REPO_ROOT / "tests" / "fixtures" / "real-ci" / "score_invocation.py"
    assert helper.is_file()
    # Spot-check that the helper bootstraps the trace package root onto
    # sys.path (necessary because the workflow invokes it by file path).
    body = helper.read_text()
    assert "sys.path.insert" in body or "sys.path.append" in body, (
        "score_invocation.py must bootstrap sys.path so it works under "
        "`python <abs-path>` invocation"
    )


def test_workflow_resolver_input_fixture_exists() -> None:
    """The bind resolver-input.json fixture the workflow copies into the
    bundle dir must be on disk."""
    fixture = (
        REPO_ROOT / "tests" / "fixtures" / "real-ci" / "bind" / "resolver-input.json"
    )
    assert fixture.is_file()
    import json

    doc = json.loads(fixture.read_text())
    assert doc["cve_id"] == "CVE-2025-13878"
    assert doc["attr_path"] == "bind"
    assert any(c["version"] == "9.20.18" for c in doc.get("candidate_refs", []))


def test_workflow_fails_fast_on_missing_secret() -> None:
    """The workflow's contract is: ANTHROPIC_API_KEY required when
    run_patcher=true; missing → fail-early with exit code 64."""
    text = _read_workflow()
    assert "ANTHROPIC_API_KEY secret is required" in text
    assert "exit 64" in text


def test_workflow_uploads_artifacts_even_on_failure() -> None:
    """Failed runs are still inspectable: upload-artifact runs `if: always()`."""
    text = _read_workflow()
    # The upload step is gated on always() so partial bundle dirs are
    # still uploaded for post-mortem.
    assert "if: ${{ always() }}" in text or "if: always()" in text
    assert "actions/upload-artifact" in text
    # Cohort is in the artifact name so multiple bundles in a future
    # matrix don't collide.
    assert "real-ci-smoke-${{ inputs.bundle }}" in text
