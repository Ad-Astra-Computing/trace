"""`trace bundle pr-snippet`: paste-ready evidence block for upstream PRs.

The bundle itself is a CI artifact (not checked into nixpkgs); the
snippet is the chain-of-evidence pointer that makes a nixpkgs PR
auditable from its description alone. A reviewer reading the upstream
PR sees:

  * what CVE this fixes
  * what shape the bundle had (auto-merge, human-review-required,
    advisory-only)
  * a Rekor public-log entry URL (transparency-log proof the bundle
    came from the locked trace workflow)
  * the workflow identity the signature is anchored to
  * a `trace bundle verify` command they can run locally

The snippet is intentionally small and pasteable. Bundle.json itself
is overkill in a PR description; this is the shortest pointer that
keeps every claim verifiable.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any


REKOR_PUBLIC_LOG_URL = "https://rekor.sigstore.dev"


def add_parser(subs: argparse._SubParsersAction) -> argparse.ArgumentParser:
    p = subs.add_parser(
        "pr-snippet",
        help=(
            "emit a paste-ready Markdown evidence block for an upstream "
            "PR description (Rekor link + identity + verify command)"
        ),
        description=(
            "Reads a signed bundle's bundle.json and emits a small "
            "Markdown block (or JSON) suitable for an upstream PR "
            "description so reviewers can audit the chain of evidence "
            "without inspecting CI internals."
        ),
    )
    p.add_argument(
        "bundle_dir",
        type=Path,
        help="path to the bundle directory (must contain bundle.json with "
             "signed_manifest.rekor_log_index populated)",
    )
    p.add_argument(
        "--format",
        choices=("markdown", "json"),
        default="markdown",
    )
    return p


def run(args: argparse.Namespace) -> int:
    bundle_path = args.bundle_dir / "bundle.json"
    if not bundle_path.is_file():
        print(f"error: bundle.json not found under {args.bundle_dir}",
              file=sys.stderr)
        return 65

    bundle = json.loads(bundle_path.read_text())
    sm = bundle.get("signed_manifest", {})

    log_index = sm.get("rekor_log_index")
    signer = sm.get("signer", "")
    if signer == "ci-pending" or log_index is None:
        print(
            "error: bundle is not signed (signer=ci-pending or "
            "rekor_log_index missing). Run the bundle through "
            "steward.yml first; pr-snippet anchors on the Rekor entry.",
            file=sys.stderr,
        )
        return 65

    cve_id = bundle.get("cve_id", "?")
    kind = bundle.get("kind", "?")
    bundle_id = bundle.get("bundle_id", "?")
    nixpkgs_rev = bundle.get("nixpkgs_rev", "?")
    identity_subject = sm.get("identity_subject", "")
    identity_issuer = sm.get("identity_issuer", "")
    rekor_url = f"{REKOR_PUBLIC_LOG_URL}/api/v1/log/entries?logIndex={log_index}"
    verify_command = f"trace bundle verify ./artifact  # bundle_id={bundle_id}"

    if args.format == "json":
        json.dump(
            {
                "cve_id": cve_id,
                "bundle_kind": kind,
                "bundle_id": bundle_id,
                "nixpkgs_rev": nixpkgs_rev,
                "rekor_log_index": log_index,
                "rekor_uuid": sm.get("rekor_uuid"),
                "rekor_url": rekor_url,
                "identity_subject": identity_subject,
                "identity_issuer": identity_issuer,
                "verify_command": verify_command,
            },
            sys.stdout,
            indent=2,
        )
        sys.stdout.write("\n")
        return 0

    # Markdown form. Designed for a "paste into PR description" workflow.
    lines = [
        f"**Evidence:** {cve_id} ({kind}) trace bundle `{bundle_id}`",
        "",
        f"* **Rekor entry:** {rekor_url}",
        f"* **Workflow identity:** `{identity_subject}`",
        f"* **OIDC issuer:** `{identity_issuer}`",
        f"* **nixpkgs rev:** `{nixpkgs_rev}`",
        "",
        "<details><summary>Verify locally</summary>",
        "",
        "```sh",
        f"gh run download <run-id> --name steward-smoke-<bundle> --dir ./artifact",
        f"{verify_command}",
        "```",
        "",
        "</details>",
    ]
    sys.stdout.write("\n".join(lines) + "\n")
    return 0
