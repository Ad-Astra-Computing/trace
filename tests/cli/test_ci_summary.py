"""Tests for tools.trace_cli.ci_summary — the GitHub Actions step-summary
renderer for the cert + steward workflows.

The renderer reads the JSON evidence a workflow has already produced and emits
a Markdown summary for $GITHUB_STEP_SUMMARY. It must:
  * surface the verdict + key evidence (build outcome, SIGNAL match, Steward
    allow/deny, signing/Rekor coordinates) so a completed run says what
    happened without digging into artifacts;
  * be robust to missing files (it runs under `if: always()`, so evidence may
    be absent on a failed run) — never raise;
  * never emit secret material (cosign cert, signature bytes, tokens).
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from tools.trace_cli import ci_summary


def _write(p: Path, obj) -> None:
    p.write_text(json.dumps(obj))


# ─── cert mode ────────────────────────────────────────────────────────────────


def test_cert_summary_green(tmp_path: Path) -> None:
    bd = tmp_path / "bundle"
    bd.mkdir()
    _write(
        bd / "build.json",
        {
            "dispatch_outcome": "ok",
            "patch_apply": {"applied": True},
            "patched_build": {"outcome": "succeeded"},
            "host": {"system": "x86_64-linux"},
            "unpatched": {"stdout_stderr": "vuln-triggered: ASAN aborted (rc=42)"},
            "patched": {"stdout_stderr": "fix-confirmed: clean (rc=0)"},
        },
    )
    _write(bd / "reproducer-log.txt", "")  # not used by renderer; presence only
    (bd / "reproducer-log.txt").write_text(
        "SIGNAL_UNPATCHED: vuln-triggered: ASAN aborted (rc=42)\n"
        "SIGNAL_PATCHED: fix-confirmed: clean (rc=0)\n"
    )
    _write(
        tmp_path / "opa-decision.json",
        {"result": [{"expressions": [{"value": {"allow": True, "deny": []}}]}]},
    )

    out = ci_summary.render_cert_summary(
        bundle_dir=bd,
        bundle_name="CVE-2025-2337--matio",
        kind="auto-merge",
        decision_path=tmp_path / "opa-decision.json",
        artifact_name="bundle-linux-cert-matio-123",
    )

    assert "CVE-2025-2337--matio" in out
    assert "CERT GREEN" in out
    assert "x86_64-linux" in out
    assert "allow" in out.lower()
    # SIGNAL rows reflect a verbatim match
    assert out.lower().count("present") >= 2
    assert "bundle-linux-cert-matio-123" in out


def test_cert_summary_failure_lists_deny(tmp_path: Path) -> None:
    bd = tmp_path / "bundle"
    bd.mkdir()
    _write(
        bd / "build.json",
        {
            "patch_apply": {"applied": False},
            "patched_build": {"outcome": "failed"},
            "host": {"system": "x86_64-linux"},
        },
    )
    _write(
        tmp_path / "opa-decision.json",
        {
            "result": [
                {
                    "expressions": [
                        {
                            "value": {
                                "allow": False,
                                "deny": [
                                    {
                                        "rule_id": "rule-3",
                                        "message": "patch did not apply",
                                    }
                                ],
                            }
                        }
                    ]
                }
            ]
        },
    )

    out = ci_summary.render_cert_summary(
        bundle_dir=bd,
        bundle_name="CVE-X",
        kind="auto-merge",
        decision_path=tmp_path / "opa-decision.json",
        artifact_name=None,
    )

    assert "rule-3" in out
    assert "patch did not apply" in out
    assert "CERT GREEN" not in out
    assert "FAIL" in out.upper()


def test_cert_summary_signal_mismatch_blocks_green(tmp_path: Path) -> None:
    """Patch/build/host/verdict all pass, but a SIGNAL substring is absent from
    build.json — the workflow's verify-signals gate fails, so the summary must
    NOT say CERT GREEN."""
    bd = tmp_path / "bundle"
    bd.mkdir()
    _write(
        bd / "build.json",
        {
            "patch_apply": {"applied": True},
            "patched_build": {"outcome": "succeeded"},
            "host": {"system": "x86_64-linux"},
            "unpatched": {"stdout_stderr": "nothing matching here"},
            "patched": {"stdout_stderr": "fix-confirmed: clean (rc=0)"},
        },
    )
    (bd / "reproducer-log.txt").write_text(
        "SIGNAL_UNPATCHED: vuln-triggered: ASAN aborted (rc=42)\n"
        "SIGNAL_PATCHED: fix-confirmed: clean (rc=0)\n"
    )
    _write(tmp_path / "opa.json", {"allow": True, "deny": []})

    out = ci_summary.render_cert_summary(
        bundle_dir=bd,
        bundle_name="CVE-SIG",
        kind="auto-merge",
        decision_path=tmp_path / "opa.json",
        artifact_name=None,
    )
    assert "CERT GREEN" not in out
    assert "FAIL" in out.upper()
    assert f"{ci_summary.FAIL} absent" in out  # the unpatched signal row


def test_cert_summary_non_auto_merge_deny_is_not_failure(tmp_path: Path) -> None:
    """For human-review-required / advisory-only kinds the cert job succeeds
    even with a deny set (the verdict is informational). A deny must not paint
    the run red."""
    bd = tmp_path / "bundle"
    bd.mkdir()
    _write(
        bd / "build.json",
        {
            "patch_apply": {"applied": True},
            "patched_build": {"outcome": "succeeded"},
            "host": {"system": "x86_64-linux"},
        },
    )
    _write(
        tmp_path / "opa.json",
        {
            "allow": False,
            "deny": [{"rule_id": "rule-4", "message": "blast radius too large"}],
        },
    )
    out = ci_summary.render_cert_summary(
        bundle_dir=bd,
        bundle_name="CVE-HR",
        kind="human-review-required",
        decision_path=tmp_path / "opa.json",
        artifact_name=None,
    )
    assert "CERT FAILED" not in out
    assert "CERT COMPLETE" in out
    assert "human-review-required" in out
    # the deny is still surfaced, just not as a failure marker on the verdict
    assert "rule-4" in out
    assert "informational" in out.lower()


def test_cert_summary_non_auto_merge_missing_decision_not_complete(
    tmp_path: Path,
) -> None:
    """A missing Steward decision is an infra failure for EVERY kind — even
    human-review/advisory must not render CERT COMPLETE without one."""
    bd = tmp_path / "bundle"
    bd.mkdir()
    _write(
        bd / "build.json",
        {
            "patch_apply": {"applied": True},
            "patched_build": {"outcome": "succeeded"},
            "host": {"system": "x86_64-linux"},
        },
    )
    # decision file absent
    out = ci_summary.render_cert_summary(
        bundle_dir=bd,
        bundle_name="CVE-HR2",
        kind="advisory-only",
        decision_path=tmp_path / "absent.json",
        artifact_name=None,
    )
    assert "CERT COMPLETE" not in out
    assert "CERT GREEN" not in out
    assert "FAIL" in out.upper()


def test_cert_summary_tolerates_non_utf8_log(tmp_path: Path) -> None:
    """reproducer-log.txt can carry raw program bytes (ASAN output); a non-UTF-8
    log must not crash the always()-run renderer."""
    bd = tmp_path / "bundle"
    bd.mkdir()
    _write(
        bd / "build.json",
        {
            "patch_apply": {"applied": True},
            "patched_build": {"outcome": "succeeded"},
            "host": {"system": "x86_64-linux"},
        },
    )
    (bd / "reproducer-log.txt").write_bytes(b"SIGNAL_UNPATCHED: \xff\xfe bad bytes\n")
    out = ci_summary.render_cert_summary(
        bundle_dir=bd,
        bundle_name="CVE-BIN",
        kind="auto-merge",
        decision_path=None,
        artifact_name=None,
    )
    assert isinstance(out, str) and "CVE-BIN" in out


def test_cert_summary_tolerates_missing_files(tmp_path: Path) -> None:
    bd = tmp_path / "bundle"
    bd.mkdir()
    # no build.json, no decision — must not raise
    out = ci_summary.render_cert_summary(
        bundle_dir=bd,
        bundle_name="CVE-Y",
        kind="auto-merge",
        decision_path=tmp_path / "absent.json",
        artifact_name=None,
    )
    assert "CVE-Y" in out
    assert isinstance(out, str) and out


# ─── steward mode ─────────────────────────────────────────────────────────────


def test_steward_summary_signed(tmp_path: Path) -> None:
    bd = tmp_path / "bundle"
    bd.mkdir()
    _write(
        bd / "bundle.json",
        {
            "cve_id": "CVE-2025-2337",
            "kind": "auto-merge",
            "signed_manifest": {
                "signer": "https://github.com/Ad-Astra-Computing/trace/.github/workflows/steward.yml@refs/heads/main",
                "identity_subject": "https://github.com/Ad-Astra-Computing/trace/.github/workflows/steward.yml@refs/heads/main",
                "identity_issuer": "https://token.actions.githubusercontent.com",
                "rekor_log_index": 1761002365,
                "rekor_uuid": "a" * 64,
            },
        },
    )
    _write(bd / "steward-decision.json", {"allow": True, "deny": []})

    out = ci_summary.render_steward_summary(
        bundle_dir=bd,
        bundle_name="CVE-2025-2337--matio",
        decision_path=bd / "steward-decision.json",
        artifact_name="steward-matio-123",
    )

    assert "CVE-2025-2337--matio" in out
    assert "1761002365" in out
    assert "SIGNED" in out.upper()
    assert "steward.yml@refs/heads/main" in out
    # Rekor entry should be a dereferenceable URL pointing at the log index
    assert "rekor.sigstore.dev" in out
    assert "1761002365" in out


def test_steward_summary_denied_skips_signing(tmp_path: Path) -> None:
    bd = tmp_path / "bundle"
    bd.mkdir()
    _write(
        bd / "bundle.json",
        {
            "cve_id": "CVE-Z",
            "kind": "auto-merge",
            "signed_manifest": {"signer": "trace-dev"},
        },
    )
    _write(
        bd / "steward-decision.json",
        {
            "allow": False,
            "deny": [{"rule_id": "rule-7", "message": "missing reproducer"}],
        },
    )

    out = ci_summary.render_steward_summary(
        bundle_dir=bd,
        bundle_name="CVE-Z",
        decision_path=bd / "steward-decision.json",
        artifact_name=None,
    )
    assert "rule-7" in out
    assert "missing reproducer" in out
    assert "DENIED" in out.upper()
    # denied → must not claim a successful sign
    assert "ALLOWED + SIGNED" not in out
    assert "cosign keyless OIDC" not in out


def test_steward_summary_missing_decision_is_na_not_deny(tmp_path: Path) -> None:
    """If the gate step failed before writing steward-decision.json, the
    always()-run summary must show n/a, NOT dress the infra failure up as a
    policy denial."""
    bd = tmp_path / "bundle"
    bd.mkdir()
    _write(
        bd / "bundle.json",
        {"cve_id": "CVE-N", "kind": "auto-merge", "signed_manifest": {}},
    )
    # decision file absent
    out = ci_summary.render_steward_summary(
        bundle_dir=bd,
        bundle_name="CVE-N",
        decision_path=bd / "steward-decision.json",
        artifact_name=None,
    )
    assert "NO STEWARD DECISION" in out
    assert "DENIED" not in out
    assert "n/a" in out.lower()


def test_steward_summary_allowed_but_unsigned_is_failure(tmp_path: Path) -> None:
    """Steward allowed but cosign/Rekor population failed → no rekor index.
    The gate+sign workflow's job is a signed artifact, so this is a FAILURE
    banner, never a green pass."""
    bd = tmp_path / "bundle"
    bd.mkdir()
    _write(
        bd / "bundle.json",
        {"cve_id": "CVE-U", "kind": "auto-merge", "signed_manifest": {}},
    )  # no rekor_log_index
    _write(bd / "steward-decision.json", {"allow": True, "deny": []})

    out = ci_summary.render_steward_summary(
        bundle_dir=bd,
        bundle_name="CVE-U",
        decision_path=bd / "steward-decision.json",
        artifact_name=None,
    )
    assert "SIGNING FAILED" in out.upper()
    assert "ALLOWED + SIGNED" not in out
    assert "signing failed" in out.lower()
    # the failure banner must use the fail marker, not the pass check
    assert out.split("\n")[2].startswith("### " + ci_summary.FAIL)


@pytest.mark.parametrize("outcome", ["failure", "cancelled", "skipped"])
def test_steward_summary_verification_not_success_not_green(
    tmp_path: Path, outcome: str
) -> None:
    """Rekor index present, but the verify-signature step did not SUCCEED
    (failed / cancelled / skipped) → the artifact is not policy-verified, so
    NOT green. A skipped verify is not evidence of verification."""
    bd = tmp_path / "bundle"
    bd.mkdir()
    _write(
        bd / "bundle.json",
        {
            "cve_id": "CVE-V",
            "kind": "auto-merge",
            "signed_manifest": {"rekor_log_index": 999},
        },
    )
    _write(bd / "steward-decision.json", {"allow": True, "deny": []})

    out = ci_summary.render_steward_summary(
        bundle_dir=bd,
        bundle_name="CVE-V",
        decision_path=bd / "steward-decision.json",
        artifact_name=None,
        verified=outcome,
    )
    assert "ALLOWED + SIGNED" not in out
    assert "NOT VERIFIED" in out.upper()
    assert out.split("\n")[2].startswith("### " + ci_summary.FAIL)


def test_steward_summary_signed_requires_verified_success(tmp_path: Path) -> None:
    """Passing verified='success' keeps the green SIGNED banner."""
    bd = tmp_path / "bundle"
    bd.mkdir()
    _write(
        bd / "bundle.json",
        {
            "cve_id": "CVE-OK",
            "kind": "auto-merge",
            "signed_manifest": {"rekor_log_index": 5},
        },
    )
    _write(bd / "steward-decision.json", {"allow": True, "deny": []})
    out = ci_summary.render_steward_summary(
        bundle_dir=bd,
        bundle_name="CVE-OK",
        decision_path=bd / "steward-decision.json",
        artifact_name=None,
        verified="success",
    )
    assert "ALLOWED + SIGNED" in out


def test_steward_summary_never_leaks_secret_material(tmp_path: Path) -> None:
    """Defense in depth: even if a cert/sig file sits in the bundle dir, the
    renderer reads only known-safe fields and must not echo their bytes."""
    bd = tmp_path / "bundle"
    bd.mkdir()
    _write(
        bd / "bundle.json",
        {
            "cve_id": "CVE-S",
            "kind": "auto-merge",
            "signed_manifest": {"rekor_log_index": 7},
        },
    )
    _write(bd / "steward-decision.json", {"allow": True, "deny": []})
    (bd / "cosign-cert.pem").write_text("-----BEGIN CERTIFICATE-----\nSECRETBYTES\n")
    (bd / "bundle.sig").write_text("SIGNATUREBYTES")

    out = ci_summary.render_steward_summary(
        bundle_dir=bd,
        bundle_name="CVE-S",
        decision_path=bd / "steward-decision.json",
        artifact_name=None,
    )
    assert "SECRETBYTES" not in out
    assert "SIGNATUREBYTES" not in out
    assert "BEGIN CERTIFICATE" not in out


# ─── decision-shape helper ────────────────────────────────────────────────────


def test_extract_decision_handles_both_shapes() -> None:
    raw_opa = {"result": [{"expressions": [{"value": {"allow": True, "deny": []}}]}]}
    bare = {"allow": False, "deny": [{"rule_id": "r"}]}
    assert ci_summary._extract_decision(raw_opa) == {"allow": True, "deny": []}
    assert ci_summary._extract_decision(bare)["allow"] is False
    assert ci_summary._extract_decision(None) is None
    assert ci_summary._extract_decision({"junk": 1}) is None


# ─── main() smoke ─────────────────────────────────────────────────────────────


def test_main_writes_to_stdout(tmp_path: Path, capsys) -> None:
    bd = tmp_path / "bundle"
    bd.mkdir()
    _write(
        bd / "build.json",
        {
            "patch_apply": {"applied": True},
            "patched_build": {"outcome": "succeeded"},
            "host": {"system": "x86_64-linux"},
        },
    )
    rc = ci_summary.main(
        [
            "--mode",
            "cert",
            "--bundle-dir",
            str(bd),
            "--bundle-name",
            "CVE-M",
        ]
    )
    assert rc == 0
    assert "CVE-M" in capsys.readouterr().out
