"""Live `vendorHash` prefetch for Go-module packages.

After commit 1aa7bae (traefik run 3 partial-grounding refusal) the
remaining contract gap is `vendorHash`: traefik refuses cleanly under
rule 8 because the resolver has no way to ground that hash. This module
adds the mechanism per the user's design call:

  * Separate from URL derivation. vendorHash has different inputs,
    network behaviour, and reproducibility risks; it deserves its own
    module rather than being folded into url_derivation.
  * Narrow v0 scope: handles a single Go package at a time. cargo-
    vendor, npm-deps, etc. land later as their own modules.
  * Inputs: package source, attr_path, target_version, optional
    src_hash override, optional nixpkgs_rev. The src_hash override is
    needed because the build derivation has to first fetch the new
    source before it can compute the vendor hash; the resolver's URL-
    derivation+prefetch step provides it.
  * Output: the schema-shape `prefetch_hashes[]` entry with
    `prefetch_kind: "go-mod-vendor"`, plus tool/tool_version/
    fetched_at/derivation_command attribution.
  * On failure: returns a structured failure that translates into a
    `prefetch_skips[]` entry with reason `go-mod-vendor-prefetch-
    failed`, preserving rule-8 refusal behaviour.

Acquisition mechanism (the FOD-hash-extraction trick):
  1. Build a small Nix expression that overrides the package's
     vendorHash to `lib.fakeHash` (and src to use the supplied src_hash
     if provided).
  2. Run `nix-build`. The build is expected to FAIL on the fixed-
     output-derivation hash check.
  3. Parse the error output for the `got: sha256-...=` line.
  4. Return that hash as the vendorHash.

The expression construction + parsing live behind a `command_runner`
parameter so tests can inject a fake. The default runner shells out to
`nix-build` directly.
"""

from __future__ import annotations

import re
import shutil
import subprocess
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Callable


@dataclass(frozen=True)
class GoModVendorRequest:
    attr_path: str           # e.g. "traefik"
    target_version: str      # e.g. "3.6.8"
    src_hash: str | None = None  # SRI-form; if absent, uses upstream pin as-is
    nixpkgs_rev: str | None = None
    timeout_seconds: int = 1800  # Go vendoring of a real package can be slow


@dataclass(frozen=True)
class GoModVendorSuccess:
    """Schema-shape entry ready to drop into prefetch_hashes[]."""

    name: str
    algorithm: str
    value: str          # SRI-form, e.g. "sha256-..."
    source: str         # always "go-mod-vendor" for this module
    prefetch_kind: str  # always "go-mod-vendor"
    tool: str
    tool_version: str
    fetched_at: str
    derivation_command: str
    replay_critical: bool = True

    def to_schema_dict(self) -> dict:
        return {
            "name": self.name,
            "algorithm": self.algorithm,
            "value": self.value,
            "source": self.source,
            "prefetch_kind": self.prefetch_kind,
            "tool": self.tool,
            "tool_version": self.tool_version,
            "fetched_at": self.fetched_at,
            "derivation_command": self.derivation_command,
            "replay_critical": self.replay_critical,
        }


@dataclass(frozen=True)
class GoModVendorFailure:
    """Schema-shape entry ready to drop into prefetch_skips[]."""

    name: str
    reason: str  # always "go-mod-vendor-prefetch-failed" for this module
    required_for_patch: bool
    detail: str
    attempted_command: str
    attempted_at: str

    def to_schema_dict(self) -> dict:
        return {
            "name": self.name,
            "reason": self.reason,
            "required_for_patch": self.required_for_patch,
            "detail": self.detail[:2048],
        }


# Type for the swappable runner.
# Returns: ("ok", sri_hash, tool_version, derivation_command)
# or       ("err", failure_detail, derivation_command, "")
CommandRunResult = tuple[str, str, str, str]
CommandRunner = Callable[[str, GoModVendorRequest], CommandRunResult]


def prefetch_go_mod_vendor(
    request: GoModVendorRequest,
    *,
    command_runner: CommandRunner | None = None,
) -> GoModVendorSuccess | GoModVendorFailure:
    """Run the FOD-hash-extraction prefetch and return a structured result.

    Args:
        request: GoModVendorRequest with attr_path, target_version, etc.
        command_runner: swappable shell-out. Default: _run_nix_build_fod_extract.

    Returns:
        GoModVendorSuccess on a clean acquisition, or GoModVendorFailure
        with structured reason on any failure.
    """
    runner = command_runner or _run_nix_build_fod_extract
    expression = _build_expression(request)
    ts = _utc_now_iso()
    outcome, value, tool_version, derivation_command = runner(expression, request)
    if outcome == "ok":
        return GoModVendorSuccess(
            name="vendorHash",
            algorithm="sha256",
            value=value,
            source="go-mod-vendor",
            prefetch_kind="go-mod-vendor",
            tool="nix-build",
            tool_version=tool_version,
            fetched_at=ts,
            derivation_command=derivation_command,
        )
    return GoModVendorFailure(
        name="vendorHash",
        reason="go-mod-vendor-prefetch-failed",
        required_for_patch=True,
        detail=value,
        attempted_command=derivation_command,
        attempted_at=ts,
    )


def _build_expression(request: GoModVendorRequest) -> str:
    """Construct the Nix expression that triggers Go vendoring with a fake hash.

    The override sets vendorHash to lib.fakeHash and (optionally) version
    + src. We deliberately keep the expression simple: just override
    against the supplied nixpkgs_rev (or the ambient one). Building
    `pkg.goModules` directly is the cheapest way to trigger ONLY the
    vendor step without compiling the package itself.
    """
    parts: list[str] = []
    if request.nixpkgs_rev:
        parts.append(
            f"let pkgs = import (fetchTarball "
            f"\"https://github.com/NixOS/nixpkgs/archive/{request.nixpkgs_rev}.tar.gz\") "
            f"{{}}; in"
        )
    else:
        parts.append("let pkgs = import <nixpkgs> {}; in")

    overrides_lines: list[str] = [
        f'  version = "{request.target_version}";',
        '  vendorHash = pkgs.lib.fakeHash;',
    ]
    if request.src_hash is not None:
        # If an external src_hash is supplied, override src to use it.
        # The fetchzip / fetchurl expression below mirrors the patterns
        # commonly used in nixpkgs Go packages; tightening this per
        # actual fetcher is future work.
        overrides_lines.append(
            f'  # External src_hash supplied by caller; override is opaque\n'
            f'  # but lets the build proceed past the source-fetch FOD.'
        )
        overrides_lines.append(
            f'  src = (pkgs.{request.attr_path}.src.overrideAttrs '
            f'(_: {{ outputHash = "{request.src_hash}"; }}));'
        )

    overrides = "\n".join(overrides_lines)
    parts.append(
        f"(pkgs.{request.attr_path}.override {{}}).overrideAttrs (old: {{\n"
        f"{overrides}\n"
        f"}})"
    )
    return "\n".join(parts)


def _run_nix_build_fod_extract(
    expression: str, request: GoModVendorRequest,
) -> CommandRunResult:
    """Default runner. Shell out to nix-build, expect FOD-hash failure,
    parse the error for the real hash."""
    if not shutil.which("nix-build"):
        return ("err",
                "nix-build not on PATH; go-mod-vendor prefetch requires Nix",
                "", "")

    # Capture tool version best-effort.
    tool_version = ""
    try:
        ver = subprocess.run(
            ["nix-build", "--version"],
            check=False, capture_output=True, text=True, timeout=10,
        )
        if ver.returncode == 0:
            tool_version = (ver.stdout or "").strip().splitlines()[0] if ver.stdout else ""
    except subprocess.SubprocessError:
        pass

    # The exact derivation command used. -A goModules targets ONLY the
    # vendor step (avoiding the full Go build). --no-out-link keeps the
    # transient store path GC-eligible.
    cmd = [
        "nix-build", "--no-out-link", "-A", "goModules",
        "-E", expression,
    ]
    derivation_command = " ".join(cmd)

    try:
        result = subprocess.run(
            cmd, check=False, capture_output=True, text=True,
            timeout=request.timeout_seconds,
        )
    except subprocess.TimeoutExpired:
        return ("err",
                f"nix-build timed out after {request.timeout_seconds}s",
                tool_version, derivation_command)
    except OSError as exc:
        return ("err", f"OSError: {exc}", tool_version, derivation_command)

    # Successful build means vendorHash already matched lib.fakeHash —
    # which would mean someone forgot to bump it. Treat as failure.
    if result.returncode == 0:
        return ("err",
                "nix-build succeeded with vendorHash=lib.fakeHash; the override "
                "was bypassed or the package does not require vendoring",
                tool_version, derivation_command)

    combined = (result.stderr or "") + "\n" + (result.stdout or "")
    sri = _parse_fod_hash_mismatch(combined)
    if sri is None:
        # Truncate combined output for the failure detail.
        return ("err",
                f"could not parse FOD hash mismatch from nix-build output; "
                f"exit={result.returncode}, last-2KiB-stderr: "
                f"{(result.stderr or '')[-1900:]!r}",
                tool_version, derivation_command)
    return ("ok", sri, tool_version, derivation_command)


# The FOD-hash mismatch error format from modern Nix:
#   error: hash mismatch in fixed-output derivation '...':
#            specified: sha256-AAAA...
#                 got:    sha256-RealHash...
# Older Nix used "got:" without indent. Be permissive on whitespace.
_FOD_GOT_RE = re.compile(
    r"^\s*got:\s+(?P<sri>sha(?:256|512)-[A-Za-z0-9+/=]+)\s*$",
    re.MULTILINE,
)


def _parse_fod_hash_mismatch(text: str) -> str | None:
    m = _FOD_GOT_RE.search(text)
    if m:
        return m.group("sri")
    return None


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


__all__ = [
    "GoModVendorRequest",
    "GoModVendorSuccess",
    "GoModVendorFailure",
    "prefetch_go_mod_vendor",
]
