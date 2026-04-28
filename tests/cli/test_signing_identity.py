"""Tests for `policy/signing-identity.json` and the v1 signing contract.

Per `docs/SIGNING_V1.md`:

  * (A) Sigstore keyless OIDC via GitHub Actions is the v0-locked path.
  * `policy/signing-identity.json` is the single source of truth for the
    identity policy verifiers pin against.
  * `policy/bundle-schema.json:signed_manifest` accepts the optional
    sigstore Rekor coordinates (rekor_log_index, rekor_uuid) and the
    OIDC claims (identity_subject, identity_issuer).

These tests assert: (1) the policy document parses + has the locked
structure, (2) the subject_regex matches the expected Steward workflow
paths and rejects others, (3) the bundle-schema accepts a fully-
populated signed_manifest with the new fields.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator

from tests.schema.validate import REPO_ROOT


SIGNING_IDENTITY_PATH = REPO_ROOT / "policy" / "signing-identity.json"
BUNDLE_SCHEMA_PATH = REPO_ROOT / "policy" / "bundle-schema.json"


# ─── policy/signing-identity.json ─────────────────────────────────────────


def test_signing_identity_parses() -> None:
    raw = json.loads(SIGNING_IDENTITY_PATH.read_text())
    assert raw["schema_version"] == "1.0.0"
    assert raw["active_path"] == "sigstore-keyless-oidc-github-actions"
    assert "sigstore-keyless-oidc-github-actions" in raw["paths"]


def test_signing_identity_locks_v0_choice() -> None:
    """v0 lock per the 2026-04-28 hand-off: option (A) Sigstore keyless OIDC.
    The active_path key MUST point at the sigstore entry, with the OIDC
    issuer pinned to GitHub's actions issuer."""
    raw = json.loads(SIGNING_IDENTITY_PATH.read_text())
    sigstore = raw["paths"]["sigstore-keyless-oidc-github-actions"]
    assert sigstore["algorithm"] == "sigstore-cosign-v1"
    assert sigstore["oidc_issuer"] == "https://token.actions.githubusercontent.com"
    assert sigstore["subject_regex"]
    assert "Ad-Astra-Computing/trace" in sigstore["subject_regex"]
    # Regex is dot-escaped for cosign, so look for the escaped form.
    assert "steward\\.yml" in sigstore["subject_regex"]


def test_subject_regex_matches_expected_paths() -> None:
    """The locked subject_regex MUST accept main-branch and release-tag
    runs of the Steward workflow, and MUST reject everything else."""
    raw = json.loads(SIGNING_IDENTITY_PATH.read_text())
    pattern = raw["paths"]["sigstore-keyless-oidc-github-actions"]["subject_regex"]
    rx = re.compile(pattern)

    # Should match
    accepted = [
        "https://github.com/Ad-Astra-Computing/trace/.github/workflows/steward.yml@refs/heads/main",
        "https://github.com/Ad-Astra-Computing/trace/.github/workflows/steward.yml@refs/tags/v0.1.0",
        "https://github.com/Ad-Astra-Computing/trace/.github/workflows/steward.yml@refs/tags/v1.5.3-rc1",
    ]
    for s in accepted:
        assert rx.match(s), f"identity policy should accept: {s!r}"

    # Should reject
    rejected = [
        # Wrong repo
        "https://github.com/Some-Fork/trace/.github/workflows/steward.yml@refs/heads/main",
        # Wrong workflow
        "https://github.com/Ad-Astra-Computing/trace/.github/workflows/other.yml@refs/heads/main",
        # Wrong owner
        "https://github.com/some-other-org/trace/.github/workflows/steward.yml@refs/heads/main",
        # Feature branch
        "https://github.com/Ad-Astra-Computing/trace/.github/workflows/steward.yml@refs/heads/feature/x",
        # PR ref
        "https://github.com/Ad-Astra-Computing/trace/.github/workflows/steward.yml@refs/pull/42/merge",
        # Empty
        "",
    ]
    for s in rejected:
        assert not rx.match(s), f"identity policy should reject: {s!r}"


def test_signing_identity_documents_graduation_path() -> None:
    """The (B) Ad Astra-held key path is documented as deferred per the
    2026-04-28 hand-off; trigger conditions are recorded so a future
    project state knows when to graduate."""
    raw = json.loads(SIGNING_IDENTITY_PATH.read_text())
    grad = raw["graduation_path"]
    assert grad["status"] == "deferred"
    assert grad["label"] == "ad-astra-held-key"
    triggers = set(grad["trigger_conditions"])
    assert "offline-or-non-github-signing-requirement" in triggers
    assert "maintainer-requests-organization-held-identity" in triggers


# ─── bundle-schema signed_manifest extensions ─────────────────────────────


def _bundle_validator() -> Draft202012Validator:
    schema = json.loads(BUNDLE_SCHEMA_PATH.read_text())
    return Draft202012Validator(schema)


def _minimal_auto_merge_bundle() -> dict:
    """Smallest auto-merge bundle that validates against the schema, used
    as a fixture for signed_manifest extension tests."""
    return {
        "schema_version": "1.0.0",
        "bundle_id": "0" * 16,
        "cve_id": "CVE-0000-0001",
        "nixpkgs_rev": "0" * 40,
        "kind": "auto-merge",
        "created_at": "2026-04-28T00:00:00Z",
        "policy_version": "0" * 64,
        "bundle_schema_version": "1" * 64,
        "files": {
            "bundle.json":             {"sha256": "a" * 64, "bytes": 1, "producer_role": "steward",      "replay_critical": True},
            "finding.json":            {"sha256": "b" * 64, "bytes": 1, "producer_role": "scout",        "replay_critical": True},
            "impact.json":             {"sha256": "c" * 64, "bytes": 1, "producer_role": "cartographer", "replay_critical": True},
            "maintainers.json":        {"sha256": "d" * 64, "bytes": 1, "producer_role": "cartographer", "replay_critical": True},
            "upstream-ref.json":       {"sha256": "e" * 64, "bytes": 1, "producer_role": "upstream-ref-resolver", "replay_critical": True},
            "patch.diff":              {"sha256": "f" * 64, "bytes": 1, "producer_role": "patcher",      "replay_critical": True},
            "patch-rationale.md":      {"sha256": "1" * 64, "bytes": 1, "producer_role": "patcher",      "replay_critical": True},
            "passthru-tests.json":     {"sha256": "2" * 64, "bytes": 1, "producer_role": "reproducer",   "replay_critical": True},
            "reproducer.nix":          {"sha256": "3" * 64, "bytes": 1, "producer_role": "reproducer",   "replay_critical": True},
            "reproducer-log.txt":      {"sha256": "4" * 64, "bytes": 1, "producer_role": "reproducer",   "replay_critical": False},
            "build.json":              {"sha256": "5" * 64, "bytes": 1, "producer_role": "builder",      "replay_critical": False},
            "review.md":               {"sha256": "6" * 64, "bytes": 1, "producer_role": "reviewer",     "replay_critical": True},
            "sbom-delta.json":         {"sha256": "7" * 64, "bytes": 1, "producer_role": "upstream-ref-resolver", "replay_critical": True},
            "replay.json":             {"sha256": "8" * 64, "bytes": 1, "producer_role": "steward",      "replay_critical": True},
            "provenance.jsonl":        {"sha256": "9" * 64, "bytes": 1, "producer_role": "steward",      "replay_critical": False},
            "bundle.sig":              {"sha256": "0" * 63 + "a", "bytes": 1, "producer_role": "steward", "replay_critical": False},
        },
        "signed_manifest": {
            "algorithm": "sigstore-cosign-v1",
            "signer": "https://github.com/Ad-Astra-Computing/trace/.github/workflows/steward.yml@refs/heads/main",
            "signed_files": [
                {"path": "bundle.json",        "sha256": "a" * 64},
                {"path": "finding.json",       "sha256": "b" * 64},
                {"path": "impact.json",        "sha256": "c" * 64},
                {"path": "maintainers.json",   "sha256": "d" * 64},
                {"path": "upstream-ref.json",  "sha256": "e" * 64},
                {"path": "patch.diff",         "sha256": "f" * 64},
                {"path": "patch-rationale.md", "sha256": "1" * 64},
                {"path": "passthru-tests.json","sha256": "2" * 64},
                {"path": "reproducer.nix",     "sha256": "3" * 64},
                {"path": "review.md",          "sha256": "6" * 64},
                {"path": "sbom-delta.json",    "sha256": "7" * 64},
                {"path": "replay.json",        "sha256": "8" * 64},
            ],
        },
    }


def test_signed_manifest_accepts_v1_optional_sigstore_fields() -> None:
    bundle = _minimal_auto_merge_bundle()
    bundle["signed_manifest"]["identity_subject"] = (
        "https://github.com/Ad-Astra-Computing/trace/.github/workflows/steward.yml@refs/heads/main"
    )
    bundle["signed_manifest"]["identity_issuer"] = (
        "https://token.actions.githubusercontent.com"
    )
    bundle["signed_manifest"]["rekor_log_index"] = 142857309
    bundle["signed_manifest"]["rekor_uuid"] = "24296fb24b8ad77a" + "0" * 16
    errors = sorted(
        _bundle_validator().iter_errors(bundle), key=lambda e: e.path,
    )
    assert not errors, [e.message for e in errors]


def test_signed_manifest_rekor_uuid_format_enforced() -> None:
    bundle = _minimal_auto_merge_bundle()
    bundle["signed_manifest"]["rekor_uuid"] = "not-hex-content"
    errs = list(_bundle_validator().iter_errors(bundle))
    assert any("rekor_uuid" in str(e.absolute_path) or "pattern" in e.message for e in errs)


def test_signed_manifest_rekor_log_index_must_be_non_negative_integer() -> None:
    bundle = _minimal_auto_merge_bundle()
    bundle["signed_manifest"]["rekor_log_index"] = -1
    errs = list(_bundle_validator().iter_errors(bundle))
    assert errs


def test_signed_manifest_rejects_unknown_keys() -> None:
    """additionalProperties must remain false; any unknown sigstore-side
    field accidentally added must error rather than silently passing."""
    bundle = _minimal_auto_merge_bundle()
    bundle["signed_manifest"]["fictional_field"] = "should-not-be-allowed"
    errs = list(_bundle_validator().iter_errors(bundle))
    assert errs


# ─── trust-statement consistency ──────────────────────────────────────────


def test_signing_identity_oidc_issuer_matches_schema_subject_format() -> None:
    """The OIDC issuer documented in policy/signing-identity.json is the
    GitHub Actions token issuer — verifiable independent of any
    schema field; this test just guards against typos."""
    raw = json.loads(SIGNING_IDENTITY_PATH.read_text())
    issuer = raw["paths"]["sigstore-keyless-oidc-github-actions"]["oidc_issuer"]
    assert issuer == "https://token.actions.githubusercontent.com"


# ─── steward.yml extraction-shape regressions ─────────────────────────────


def test_steward_yml_resolves_rekor_uuid_via_api_not_logid() -> None:
    """Regression guard for the bug fixed in `dd6fbdc`.

    `cosign sign-blob --bundle` writes a JSON document whose
    `rekorBundle.Payload.logID` is the Rekor public-instance shard
    identifier — constant across every entry on that shard. Earlier
    workflow logic stored that constant in `signed_manifest.rekor_uuid`,
    which meant every signed bundle reported the same UUID. The per-
    entry UUID must come from the Rekor public API, queried by
    `logIndex`. This test reads the workflow and asserts it does so.

    If the workflow regresses to reading `logID` directly into
    `rekor_uuid`, this test breaks loudly rather than waiting for a
    human to notice that two unrelated signed bundles share a UUID."""
    workflow = (REPO_ROOT / ".github" / "workflows" / "steward.yml").read_text()

    # The signed_manifest must populate rekor_uuid via the Rekor API.
    assert "rekor.sigstore.dev/api/v1/log/entries" in workflow, (
        "rekor_uuid must come from Rekor's per-entry API lookup, not "
        "from cosign's bundle.sig logID field."
    )

    # And the deprecated rekor_log['logID'] → rekor_uuid path must not
    # be present anywhere in the workflow.
    bad = re.compile(
        r"rekor_uuid\s*[:=]\s*[^=\n]*logID",
    )
    assert not bad.search(workflow), (
        "Found a regression assigning rekor_log['logID'] into rekor_uuid. "
        "The logID is the constant Rekor shard ID, not a per-entry UUID."
    )
