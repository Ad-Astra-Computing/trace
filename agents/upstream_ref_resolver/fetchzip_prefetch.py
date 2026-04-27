"""Live `src.hash` prefetch for fetchzip-shaped fetchers.

After commit `c7b6741` (uriparser run) the URL-derivation layer's
`github-release-archive` rule was downgraded to medium confidence
because `nix-prefetch-url` is the wrong tool for `fetchFromGitHub` /
`fetchzip` / `fetchgit` hashes: those fetchers use fetchzip semantics
under the hood (download → unpack → re-archive → hash), so the raw
github archive hash diverges from what the package's actual fetcher
will demand at build time.

This module is the right tool. Mirrors `agents/upstream_ref_resolver/
go_mod_vendor.py`'s FOD-extraction approach, but targets `src` instead
of `goModules`:

  1. Build a small Nix expression that overrides the package's
     `src` to use the same fetcher attrs but with `hash = lib.fakeHash`.
  2. Run `nix-build`. The build is expected to FAIL on the fixed-
     output-derivation hash check.
  3. Parse the error output for the `got: sha256-...=` line.
  4. Return that hash as the real `src.hash`.

Output applies to `src.hash`. Schema attribution: `prefetch_kind:
"fetchzip"`, `source: "fetchzip-src-extract"`. The `command_runner`
parameter is swappable so tests inject a fake.
"""

from __future__ import annotations

import re
import shutil
import subprocess
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Callable


@dataclass(frozen=True)
class FetchzipRequest:
    attr_path: str           # e.g. "uriparser"
    target_version: str      # e.g. "1.0.0"
    nixpkgs_rev: str | None = None
    timeout_seconds: int = 600  # tarball download + extract + hash


@dataclass(frozen=True)
class FetchzipSuccess:
    """Schema-shape entry ready to drop into prefetch_hashes[]."""

    name: str
    algorithm: str
    value: str          # SRI-form, e.g. "sha256-..."
    source: str         # always "fetchzip-src-extract" for this module
    prefetch_kind: str  # always "fetchzip"
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
class FetchzipFailure:
    """Schema-shape entry ready to drop into prefetch_failures[]."""

    name: str
    reason: str  # always "fetchzip-prefetch-failed" for this module
    required_for_patch: bool
    detail: str
    attempted_command: str
    attempted_at: str

    def to_schema_dict(self) -> dict:
        return {
            "name": self.name,
            "reason": self.reason,
            "required_for_patch": self.required_for_patch,
            "tool": "nix-build",
            "attempted_command": self.attempted_command,
            "detail": self.detail[:2048],
            "attempted_at": self.attempted_at,
        }


# Type alias mirrors the go-mod-vendor module's CommandRunner shape.
# Returns: ("ok", sri_hash, tool_version, derivation_command)
# or       ("err", failure_detail, tool_version_or_empty, derivation_command)
CommandRunResult = tuple[str, str, str, str]
CommandRunner = Callable[[str, FetchzipRequest], CommandRunResult]


def prefetch_fetchzip(
    request: FetchzipRequest,
    *,
    command_runner: CommandRunner | None = None,
) -> FetchzipSuccess | FetchzipFailure:
    """Run the FOD-hash-extraction prefetch for `src.hash`.

    Args:
        request: FetchzipRequest with attr_path, target_version, etc.
        command_runner: swappable shell-out. Default: _run_nix_build_src_fod.

    Returns:
        FetchzipSuccess on a clean acquisition, or FetchzipFailure with
        a structured reason on any failure.
    """
    runner = command_runner or _run_nix_build_src_fod
    expression = _build_expression(request)
    ts = _utc_now_iso()
    outcome, value, tool_version, derivation_command = runner(expression, request)
    if outcome == "ok":
        return FetchzipSuccess(
            name="src.hash",
            algorithm="sha256",
            value=value,
            source="fetchzip-src-extract",
            prefetch_kind="fetchzip",
            tool="nix-build",
            tool_version=tool_version,
            fetched_at=ts,
            derivation_command=derivation_command,
        )
    return FetchzipFailure(
        name="src.hash",
        reason="fetchzip-prefetch-failed",
        required_for_patch=True,
        detail=value,
        attempted_command=derivation_command,
        attempted_at=ts,
    )


def _build_expression(request: FetchzipRequest) -> str:
    """Construct the Nix expression that triggers a src download with
    a fake hash. Overriding `src` directly to a fresh derivation that
    inherits the original fetcher attrs but pins `outputHash` to
    `lib.fakeHash` produces the expected FOD-mismatch error.

    Building the package itself (vs `-A goModules`) means the full
    src-fetch step runs without unnecessary subsequent build phases —
    the FOD check fires immediately on src materialisation.
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

    # Override the version (so the fetcher templates it into the URL/
    # tag) and replace `src` with the SAME derivation but with
    # `outputHash` pinned to `lib.fakeHash`. The expression assumes the
    # original `src` was produced by a fetchzip-style fetcher — that's
    # the contract this module exists for. Other fetcher classes get a
    # different prefetch_kind module.
    parts.append(
        f"(pkgs.{request.attr_path}.override {{}}).overrideAttrs (old: {{\n"
        f'  version = "{request.target_version}";\n'
        f"  src = old.src.overrideAttrs (_: {{ outputHash = pkgs.lib.fakeHash; }});\n"
        f"}})"
    )
    return "\n".join(parts)


def _run_nix_build_src_fod(
    expression: str, request: FetchzipRequest,
) -> CommandRunResult:
    """Default runner. Shell out to `nix-build`, expect FOD-hash failure
    on src, parse the error for the real hash."""
    if not shutil.which("nix-build"):
        return ("err",
                "nix-build not on PATH; fetchzip prefetch requires Nix",
                "", "")

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

    # `--no-out-link` keeps the transient store path GC-eligible.
    # No `-A` argument: we want the package's default output, which
    # depends on src materialising first.
    cmd = [
        "nix-build", "--no-out-link",
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

    if result.returncode == 0:
        return ("err",
                "nix-build succeeded with src outputHash=lib.fakeHash; the "
                "override was bypassed or src did not require fetching",
                tool_version, derivation_command)

    combined = (result.stderr or "") + "\n" + (result.stdout or "")
    sri = _parse_fod_hash_mismatch(combined)
    if sri is None:
        return ("err",
                f"could not parse FOD hash mismatch from nix-build output; "
                f"exit={result.returncode}, last-2KiB-stderr: "
                f"{(result.stderr or '')[-1900:]!r}",
                tool_version, derivation_command)
    return ("ok", sri, tool_version, derivation_command)


# Identical to go_mod_vendor.py's regex by design — the FOD-mismatch
# error format is the same regardless of which fixed-output derivation
# missed.
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
    "FetchzipRequest",
    "FetchzipSuccess",
    "FetchzipFailure",
    "prefetch_fetchzip",
]
