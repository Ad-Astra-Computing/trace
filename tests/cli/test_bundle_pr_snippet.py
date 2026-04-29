"""Tests for `trace bundle pr-snippet`.

The PR snippet is a paste-ready Markdown block that an upstream maintainer
adds to a nixpkgs PR description so reviewers can audit the trace bundle
that proposed the patch. The bundle itself stays a CI artifact (not
checked into nixpkgs); the snippet links to the public Rekor entry, the
Actions run, and the bundle SHA so the chain of evidence stays
verifiable from the PR alone.

Goal: turn the question "did this patch come from a trustworthy
pipeline?" into "click the Rekor link and verify."

Inputs: a bundle directory containing `bundle.json` (post-sign-mutation
copy with populated `signed_manifest.identity_subject`,
`rekor_log_index`, `rekor_uuid`).

Output: stdout markdown block. Stable shape so downstream tooling can
parse it back if needed.
"""

from __future__ import annotations

import argparse
import io
import json
import sys
from pathlib import Path
from unittest import mock

import pytest

from tools.trace_cli import pr_snippet


def _signed_bundle(tmp_path: Path, **overrides) -> Path:
    """Build a minimal post-sign bundle.json under a fresh dir."""
    bundle_dir = tmp_path / "artifact"
    bundle_dir.mkdir()
    bundle = {
        "schema_version": "1.0.0",
        "bundle_id": "abcd1234ef567890",
        "cve_id": "CVE-2025-67899",
        "nixpkgs_rev": "20bb5d462943a0f38eba2372db9f7a6d9fd22be2",
        "kind": "human-review-required",
        "signed_manifest": {
            "algorithm": "sigstore-cosign-v1",
            "signer": "https://github.com/Ad-Astra-Computing/trace/.github/workflows/steward.yml@refs/heads/main",
            "identity_subject": "https://github.com/Ad-Astra-Computing/trace/.github/workflows/steward.yml@refs/heads/main",
            "identity_issuer": "https://token.actions.githubusercontent.com",
            "rekor_log_index": 1397922891,
            "rekor_uuid": "108e9186e8c5cdd5c2a0d3a8b6f2e9a1b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8",
        },
    }
    bundle.update(overrides)
    (bundle_dir / "bundle.json").write_text(json.dumps(bundle, indent=2))
    return bundle_dir


def _args(bundle_dir: Path, fmt: str = "markdown") -> argparse.Namespace:
    return argparse.Namespace(
        cmd="bundle",
        bundle_cmd="pr-snippet",
        bundle_dir=bundle_dir,
        format=fmt,
    )


def test_emits_cve_id_and_kind(tmp_path: Path, capsys) -> None:
    bundle = _signed_bundle(tmp_path)
    rc = pr_snippet.run(_args(bundle))
    assert rc == 0
    out = capsys.readouterr().out
    assert "CVE-2025-67899" in out
    assert "human-review-required" in out


def test_emits_rekor_link(tmp_path: Path, capsys) -> None:
    bundle = _signed_bundle(tmp_path)
    pr_snippet.run(_args(bundle))
    out = capsys.readouterr().out
    # Rekor public-instance URL pattern, anchored on the log_index from
    # signed_manifest. Verifiers click this to see the transparency-log
    # entry inline.
    assert "rekor.sigstore.dev" in out
    assert "1397922891" in out


def test_emits_identity_for_verifier_pinning(tmp_path: Path, capsys) -> None:
    bundle = _signed_bundle(tmp_path)
    pr_snippet.run(_args(bundle))
    out = capsys.readouterr().out
    # The identity_subject + issuer are the two values a verifier passes
    # to `cosign verify-blob`; surface them so the reviewer can run the
    # check without digging into policy/signing-identity.json.
    assert "Ad-Astra-Computing/trace" in out
    assert "token.actions.githubusercontent.com" in out


def test_emits_verify_command(tmp_path: Path, capsys) -> None:
    bundle = _signed_bundle(tmp_path)
    pr_snippet.run(_args(bundle))
    out = capsys.readouterr().out
    # The snippet must include a copy-pasteable verify command so the
    # reviewer can run it without consulting external docs.
    assert "trace bundle verify" in out


def test_rejects_missing_bundle_json(tmp_path: Path, capsys) -> None:
    empty = tmp_path / "empty"
    empty.mkdir()
    rc = pr_snippet.run(_args(empty))
    assert rc != 0
    err = capsys.readouterr().err
    assert "bundle.json" in err


def test_rejects_unsigned_bundle(tmp_path: Path, capsys) -> None:
    """Bundles whose signed_manifest still says signer=ci-pending are
    pre-sign drafts. The PR-snippet command refuses on those because
    the snippet's value is the cryptographic anchor; without a Rekor
    entry, there's nothing to anchor."""
    bundle = _signed_bundle(tmp_path)
    bj = json.loads((bundle / "bundle.json").read_text())
    bj["signed_manifest"]["signer"] = "ci-pending"
    bj["signed_manifest"].pop("rekor_log_index", None)
    bj["signed_manifest"].pop("rekor_uuid", None)
    (bundle / "bundle.json").write_text(json.dumps(bj, indent=2))

    rc = pr_snippet.run(_args(bundle))
    assert rc != 0
    err = capsys.readouterr().err
    assert "signed" in err.lower() or "rekor" in err.lower()


def test_json_format_is_machine_parseable(tmp_path: Path, capsys) -> None:
    bundle = _signed_bundle(tmp_path)
    rc = pr_snippet.run(_args(bundle, fmt="json"))
    assert rc == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["cve_id"] == "CVE-2025-67899"
    assert payload["rekor_log_index"] == 1397922891
    assert "rekor_url" in payload
    assert "verify_command" in payload
    assert payload["bundle_kind"] == "human-review-required"
