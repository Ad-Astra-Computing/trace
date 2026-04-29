"""Tests for `trace bundle verify`.

These tests exercise the verifier's input-validation paths and the policy
read. They do NOT shell out to a real cosign — that would require fixture
artifacts with valid Sigstore signatures, which can only be produced by an
end-to-end CI run. Instead, we mock subprocess.run to assert the verifier
constructs the expected cosign invocation given the locked identity policy.

End-to-end signature verification is exercised by `.github/workflows/steward.yml`
itself (the verify step that runs after sign).
"""

from __future__ import annotations

import argparse
import io
import json
import sys
from pathlib import Path
from unittest import mock

import pytest

from tools.trace_cli import verify as v
from tests.schema.validate import REPO_ROOT


@pytest.fixture
def policy_path() -> Path:
    return REPO_ROOT / "policy" / "signing-identity.json"


def _args(artifact_dir: Path, fmt: str = "json", policy: Path | None = None) -> argparse.Namespace:
    return argparse.Namespace(
        cmd="bundle",
        bundle_cmd="verify",
        artifact_dir=artifact_dir,
        policy=policy,
        format=fmt,
    )


def test_artifact_dir_missing_returns_not_found(tmp_path: Path, capsys) -> None:
    nonexistent = tmp_path / "does-not-exist"
    rc = v.run(_args(nonexistent), repo_root=REPO_ROOT)
    assert rc == v.EXIT_NOT_FOUND
    out = capsys.readouterr()
    assert "artifact dir not found" in (out.err + out.out)


def test_canonical_missing_returns_not_found(tmp_path: Path, capsys) -> None:
    artifact = tmp_path / "artifact"
    artifact.mkdir()
    # No bundle.canonical.json
    (artifact / "bundle.sig").write_text("{}")
    rc = v.run(_args(artifact), repo_root=REPO_ROOT)
    assert rc == v.EXIT_NOT_FOUND
    payload = json.loads(capsys.readouterr().out)
    assert payload["verified"] is False
    assert "bundle.canonical.json missing" in payload["error"]


def test_sig_missing_returns_not_found(tmp_path: Path, capsys) -> None:
    artifact = tmp_path / "artifact"
    artifact.mkdir()
    (artifact / "bundle.canonical.json").write_text("{}")
    rc = v.run(_args(artifact), repo_root=REPO_ROOT)
    assert rc == v.EXIT_NOT_FOUND
    payload = json.loads(capsys.readouterr().out)
    assert "bundle.sig missing" in payload["error"]


def test_policy_missing_returns_not_found(tmp_path: Path, capsys) -> None:
    artifact = tmp_path / "artifact"
    artifact.mkdir()
    (artifact / "bundle.canonical.json").write_text("{}")
    (artifact / "bundle.sig").write_text("{}")
    fake_policy = tmp_path / "no-policy.json"
    rc = v.run(_args(artifact, policy=fake_policy), repo_root=REPO_ROOT)
    assert rc == v.EXIT_NOT_FOUND


def test_verify_constructs_expected_cosign_invocation(tmp_path: Path, policy_path: Path) -> None:
    artifact = tmp_path / "artifact"
    artifact.mkdir()
    (artifact / "bundle.canonical.json").write_text('{"k":"v"}')
    (artifact / "bundle.sig").write_text("{}")

    captured: dict[str, list[str]] = {}

    def fake_run(cmd, capture_output, text):  # type: ignore[no-untyped-def]
        captured["cmd"] = cmd

        class _R:
            returncode = 0
            stdout = "Verified OK\n"
            stderr = ""

        return _R()

    with mock.patch.object(v.subprocess, "run", fake_run), \
         mock.patch.object(v.shutil, "which", return_value="/fake/cosign"):
        rc = v.run(_args(artifact, fmt="json"), repo_root=REPO_ROOT)

    assert rc == v.EXIT_OK
    cmd = captured["cmd"]
    # Locked policy values must appear in the cosign invocation
    policy = json.loads(policy_path.read_text())
    active = policy["paths"][policy["active_path"]]

    assert cmd[0] == "/fake/cosign"
    assert cmd[1] == "verify-blob"
    assert "--certificate-identity-regexp" in cmd
    idx = cmd.index("--certificate-identity-regexp")
    assert cmd[idx + 1] == active["subject_regex"]
    assert "--certificate-oidc-issuer" in cmd
    idx = cmd.index("--certificate-oidc-issuer")
    assert cmd[idx + 1] == active["oidc_issuer"]
    assert "--bundle" in cmd
    idx = cmd.index("--bundle")
    assert cmd[idx + 1] == str(artifact / "bundle.sig")
    # Last positional must be the canonical input
    assert cmd[-1] == str(artifact / "bundle.canonical.json")


def test_cosign_failure_emits_failure_payload(tmp_path: Path, capsys) -> None:
    artifact = tmp_path / "artifact"
    artifact.mkdir()
    (artifact / "bundle.canonical.json").write_text("{}")
    (artifact / "bundle.sig").write_text("{}")

    def fake_run(cmd, capture_output, text):  # type: ignore[no-untyped-def]
        class _R:
            returncode = 1
            stdout = ""
            stderr = "Error: certificate identity mismatch\n"

        return _R()

    with mock.patch.object(v.subprocess, "run", fake_run), \
         mock.patch.object(v.shutil, "which", return_value="/fake/cosign"):
        rc = v.run(_args(artifact, fmt="json"), repo_root=REPO_ROOT)

    assert rc == v.EXIT_VERIFY_FAILED
    payload = json.loads(capsys.readouterr().out)
    assert payload["verified"] is False
    assert "certificate identity mismatch" in payload["cosign_stderr"]


def test_cosign_missing_returns_not_found(tmp_path: Path, capsys) -> None:
    artifact = tmp_path / "artifact"
    artifact.mkdir()
    (artifact / "bundle.canonical.json").write_text("{}")
    (artifact / "bundle.sig").write_text("{}")

    with mock.patch.object(v.shutil, "which", return_value=None):
        rc = v.run(_args(artifact, fmt="json"), repo_root=REPO_ROOT)

    assert rc == v.EXIT_NOT_FOUND
    payload = json.loads(capsys.readouterr().out)
    assert "cosign not found on PATH" in payload["error"]
