"""`trace bundle verify`: local verification of a signed CI artifact.

Verifies that a downloaded artifact bundle from a Steward workflow run
carries a valid sigstore-keyless-OIDC signature anchored to the workflow
identity locked in `policy/signing-identity.json`.

# Inputs

The artifact directory MUST contain:
  * `bundle.canonical.json`: the frozen pre-sign snapshot. The signed bytes.
  * `bundle.sig`: cosign sign-blob output (DSSE envelope + Rekor proof).

`bundle.json` (post-sign mutation) is NOT what got signed; verifying against
it fails because Steward populates identity_subject + rekor coordinates
into `bundle.json` AFTER signing. The whole reason `bundle.canonical.json`
exists is to give downstream verifiers an immutable target.

# Identity policy

`subject_regex` and `oidc_issuer` are read from
`policy/signing-identity.json` in the trace checkout the verifier runs
from. Verifiers pinning to a specific trace tag should check out that tag
and run `trace bundle verify` from there. The regex is the load-bearing
field.

# What this command does NOT do

  * Does not download the artifact; bring your own (e.g. via
    `gh run download <run-id>`).
  * Does not verify replay/provenance internal consistency. That's
    Steward rules 4 + 5, asserted at sign time. The signature is a
    promise the bundle passed those rules; this command verifies the
    promise, not the rules themselves.
  * Does not query Rekor directly. cosign verify-blob includes Rekor
    inclusion proof verification inline; an explicit Rekor lookup
    would be redundant for correctness.
"""

from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any


EXIT_OK = 0
EXIT_USAGE = 64
EXIT_NOT_FOUND = 65
EXIT_VERIFY_FAILED = 66


def add_parser(subs: argparse._SubParsersAction) -> argparse.ArgumentParser:
    """Register the `bundle verify` subcommand under the bundle group."""
    p = subs.add_parser(
        "verify",
        help=(
            "verify a signed CI artifact's cosign signature against the "
            "locked identity in policy/signing-identity.json"
        ),
        description=(
            "Verify a downloaded Steward artifact bundle. Requires "
            "bundle.canonical.json + bundle.sig in the supplied dir, "
            "cosign on PATH, and a trace checkout (this one) for the "
            "signing-identity policy."
        ),
    )
    p.add_argument(
        "artifact_dir",
        type=Path,
        help="path to the unzipped artifact directory from the Steward "
        "workflow run (must contain bundle.canonical.json + bundle.sig)",
    )
    p.add_argument(
        "--policy",
        type=Path,
        default=None,
        help="override path to signing-identity.json (default: "
        "policy/signing-identity.json relative to repo root)",
    )
    p.add_argument(
        "--format",
        choices=("human", "json"),
        default="human",
    )
    return p


def run(args: argparse.Namespace, repo_root: Path) -> int:
    artifact_dir: Path = args.artifact_dir.resolve()
    canonical = artifact_dir / "bundle.canonical.json"
    sig = artifact_dir / "bundle.sig"

    if not artifact_dir.is_dir():
        return _emit_error(
            args.format, EXIT_NOT_FOUND, f"artifact dir not found: {artifact_dir}"
        )
    if not canonical.is_file():
        return _emit_error(
            args.format,
            EXIT_NOT_FOUND,
            f"bundle.canonical.json missing under {artifact_dir}. "
            f"This is the frozen pre-sign snapshot; without it "
            f"the signature cannot be verified. Did the artifact "
            f"come from a Steward run that allowed (signed) the "
            f"bundle? Denied runs do not produce a canonical.",
        )
    if not sig.is_file():
        return _emit_error(
            args.format, EXIT_NOT_FOUND, f"bundle.sig missing under {artifact_dir}"
        )

    policy_path = args.policy or (repo_root / "policy" / "signing-identity.json")
    if not policy_path.is_file():
        return _emit_error(
            args.format,
            EXIT_NOT_FOUND,
            f"signing-identity policy not found at {policy_path}",
        )

    try:
        policy = json.loads(policy_path.read_text())
        active = policy["paths"][policy["active_path"]]
        subject_regex = active["subject_regex"]
        oidc_issuer = active["oidc_issuer"]
    except (KeyError, json.JSONDecodeError) as exc:
        return _emit_error(
            args.format, EXIT_USAGE, f"signing-identity policy malformed: {exc}"
        )

    cosign = shutil.which("cosign")
    if not cosign:
        return _emit_error(
            args.format,
            EXIT_NOT_FOUND,
            "cosign not found on PATH. Install from "
            "https://github.com/sigstore/cosign/releases or "
            "via your platform package manager. v0 trace's "
            "dev shell does not bundle cosign because verifiers "
            "are typically external to the project.",
        )

    cmd = [
        cosign,
        "verify-blob",
        "--certificate-identity-regexp",
        subject_regex,
        "--certificate-oidc-issuer",
        oidc_issuer,
        "--bundle",
        str(sig),
        str(canonical),
    ]
    proc = subprocess.run(cmd, capture_output=True, text=True)

    if proc.returncode != 0:
        return _emit_failure(
            args.format,
            artifact_dir=artifact_dir,
            subject_regex=subject_regex,
            oidc_issuer=oidc_issuer,
            cosign_stderr=proc.stderr,
            cosign_stdout=proc.stdout,
        )

    return _emit_success(
        args.format,
        artifact_dir=artifact_dir,
        subject_regex=subject_regex,
        oidc_issuer=oidc_issuer,
        canonical_path=canonical,
        sig_path=sig,
    )


def _emit_error(fmt: str, exit_code: int, message: str) -> int:
    if fmt == "json":
        json.dump(
            {"verified": False, "error": message},
            sys.stdout,
            indent=2,
        )
        sys.stdout.write("\n")
    else:
        print(f"error: {message}", file=sys.stderr)
    return exit_code


def _emit_failure(fmt: str, **kwargs: Any) -> int:
    payload = {
        "verified": False,
        "artifact_dir": str(kwargs["artifact_dir"]),
        "subject_regex": kwargs["subject_regex"],
        "oidc_issuer": kwargs["oidc_issuer"],
        "cosign_stderr": kwargs["cosign_stderr"].strip(),
        "cosign_stdout": kwargs["cosign_stdout"].strip(),
    }
    if fmt == "json":
        json.dump(payload, sys.stdout, indent=2)
        sys.stdout.write("\n")
    else:
        print("VERIFY FAILED", file=sys.stderr)
        print(f"  artifact:        {payload['artifact_dir']}", file=sys.stderr)
        print(f"  subject regex:   {payload['subject_regex']}", file=sys.stderr)
        print(f"  oidc issuer:     {payload['oidc_issuer']}", file=sys.stderr)
        if payload["cosign_stderr"]:
            print("  cosign stderr:", file=sys.stderr)
            for line in payload["cosign_stderr"].splitlines():
                print(f"    {line}", file=sys.stderr)
    return EXIT_VERIFY_FAILED


def _emit_success(fmt: str, **kwargs: Any) -> int:
    payload = {
        "verified": True,
        "artifact_dir": str(kwargs["artifact_dir"]),
        "subject_regex": kwargs["subject_regex"],
        "oidc_issuer": kwargs["oidc_issuer"],
        "canonical_path": str(kwargs["canonical_path"]),
        "sig_path": str(kwargs["sig_path"]),
    }
    if fmt == "json":
        json.dump(payload, sys.stdout, indent=2)
        sys.stdout.write("\n")
    else:
        print("VERIFIED")
        print(f"  artifact:        {payload['artifact_dir']}")
        print(f"  signed input:    {payload['canonical_path']}")
        print(f"  signature:       {payload['sig_path']}")
        print(f"  subject regex:   {payload['subject_regex']}")
        print(f"  oidc issuer:     {payload['oidc_issuer']}")
    return EXIT_OK
