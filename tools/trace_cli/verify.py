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

# Payload reconciliation (--payload-dir)

cosign only proves `bundle.canonical.json` itself was signed; the Steward
artifact doesn't carry the payload files (`patch.diff`, `reproducer.nix`,
etc.) it describes, so a VERIFIED signature says nothing about whether a
given directory's bytes (e.g. the bundle committed under
`traces/example/<CVE>/`) are the ones that were actually signed. Passing
`--payload-dir` re-hashes every entry in `signed_manifest.signed_files`
against that directory and fails closed on any mismatch or missing file.
"""

from __future__ import annotations

import argparse
import hashlib
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
        "--payload-dir",
        type=Path,
        default=None,
        help="directory holding the bundle's payload files (patch.diff, "
        "reproducer.nix, etc. — e.g. traces/example/<CVE>/); when given, "
        "every entry in signed_manifest.signed_files is re-hashed against "
        "it and a mismatch or missing file fails verification even if "
        "the cosign signature itself is valid",
    )
    p.add_argument(
        "--format",
        choices=("human", "json"),
        default="human",
    )
    return p


_SENTINEL_HASH = "d" * 64


def _check_payload(canonical: Path, payload_dir: Path) -> list[dict[str, str]]:
    """Re-hash signed_manifest.signed_files against payload_dir.

    Returns a list of mismatch records ({path, reason}); empty means every
    signed file's on-disk bytes match the hash that was actually signed.

    Two grandfathered cases (S4 fable audit 2026-10-06, pre-fix `finalize`
    signed both of these): a `bundle.json` self-entry is skipped outright,
    since Steward mutates that file (signer, rekor coordinates) after
    signing it, so it can never match by construction; and an entry whose
    expected hash is the sentinel placeholder (`"d" * 64`, written for a
    replay-critical file that did not exist yet) is skipped when the file
    is still absent, since the signature was never a claim about real
    bytes there. Either case present on disk is checked normally.
    """
    doc = json.loads(canonical.read_text())
    signed_files = doc.get("signed_manifest", {}).get("signed_files", [])
    mismatches: list[dict[str, str]] = []
    for entry in signed_files:
        rel_path = entry.get("path", "")
        expected = entry.get("sha256", "")
        if rel_path == "bundle.json":
            continue
        target = (payload_dir / rel_path).resolve()
        if (
            payload_dir.resolve() not in target.parents
            and target != payload_dir.resolve()
        ):
            mismatches.append({"path": rel_path, "reason": "escapes payload_dir"})
            continue
        if not target.is_file():
            if expected == _SENTINEL_HASH:
                continue
            mismatches.append({"path": rel_path, "reason": "missing"})
            continue
        actual = hashlib.sha256(target.read_bytes()).hexdigest()
        if actual != expected:
            mismatches.append(
                {
                    "path": rel_path,
                    "reason": f"sha256 mismatch (expected {expected}, got {actual})",
                }
            )
    return mismatches


def verify_signature(
    canonical: Path, sig: Path, policy_path: Path
) -> tuple[bool, str | None]:
    """Run `cosign verify-blob` for `canonical` against `sig` under the
    identity locked in `policy_path`. Returns (True, None) on success or
    (False, error-message). Shared with `trace pr`, which must verify the
    SIGNED canonical rather than trusting bundle.json's own hash fields
    (S4 fable audit 2026-10-06)."""
    try:
        policy = json.loads(policy_path.read_text())
        active = policy["paths"][policy["active_path"]]
        subject_regex = active["subject_regex"]
        oidc_issuer = active["oidc_issuer"]
    except (KeyError, json.JSONDecodeError, FileNotFoundError) as exc:
        return False, f"signing-identity policy malformed: {exc}"
    cosign = shutil.which("cosign")
    if not cosign:
        return False, "cosign not found on PATH"
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
        return False, f"cosign verify-blob failed: {proc.stderr.strip()}"
    return True, None


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

    payload_mismatches: list[dict[str, str]] | None = None
    if args.payload_dir is not None:
        payload_dir: Path = args.payload_dir.resolve()
        if not payload_dir.is_dir():
            return _emit_error(
                args.format, EXIT_NOT_FOUND, f"payload dir not found: {payload_dir}"
            )
        payload_mismatches = _check_payload(canonical, payload_dir)
        if payload_mismatches:
            return _emit_payload_mismatch(
                args.format,
                artifact_dir=artifact_dir,
                payload_dir=payload_dir,
                mismatches=payload_mismatches,
            )

    return _emit_success(
        args.format,
        artifact_dir=artifact_dir,
        subject_regex=subject_regex,
        oidc_issuer=oidc_issuer,
        canonical_path=canonical,
        sig_path=sig,
        payload_dir=args.payload_dir,
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


def _emit_payload_mismatch(fmt: str, **kwargs: Any) -> int:
    payload = {
        "verified": False,
        "artifact_dir": str(kwargs["artifact_dir"]),
        "payload_dir": str(kwargs["payload_dir"]),
        "reason": "signature valid but payload bytes do not match signed_manifest",
        "mismatches": kwargs["mismatches"],
    }
    if fmt == "json":
        json.dump(payload, sys.stdout, indent=2)
        sys.stdout.write("\n")
    else:
        print("VERIFY FAILED (payload mismatch)", file=sys.stderr)
        print(f"  artifact:        {payload['artifact_dir']}", file=sys.stderr)
        print(f"  payload dir:     {payload['payload_dir']}", file=sys.stderr)
        print(
            "  the cosign signature is valid, but these files do not match",
            file=sys.stderr,
        )
        print("  the bytes it actually signed:", file=sys.stderr)
        for m in payload["mismatches"]:
            print(f"    {m['path']}: {m['reason']}", file=sys.stderr)
    return EXIT_VERIFY_FAILED


def _emit_success(fmt: str, **kwargs: Any) -> int:
    payload = {
        "verified": True,
        "artifact_dir": str(kwargs["artifact_dir"]),
        "subject_regex": kwargs["subject_regex"],
        "oidc_issuer": kwargs["oidc_issuer"],
        "canonical_path": str(kwargs["canonical_path"]),
        "sig_path": str(kwargs["sig_path"]),
        "payload_dir": str(kwargs["payload_dir"])
        if kwargs.get("payload_dir")
        else None,
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
        if payload["payload_dir"]:
            print(
                f"  payload dir:     {payload['payload_dir']} (all signed files match)"
            )
    return EXIT_OK
