"""BuildRunner Protocol + concrete implementations.

Builder is a deterministic role (no model call); it shells out to
`nix-build` (or a substituter-backed equivalent) to materialise the
patched derivation, run the reproducer's `test` derivation against
both unpatched and patched contexts, and enumerate `passthru.tests` /
`nixosTests` for the affected attr.

The orchestration logic in `agents.builder.runner` does NOT call
`nix-build` directly. It calls a `BuildRunner` whose concrete
implementation depends on the host environment:

  * `FakeBuildRunner` — for tests. Returns caller-supplied
    `BuildOutcome` instances, recording every invocation. No Nix
    dependency.
  * `LocalNixBuildRunner` — production path on a Linux host with
    `nix-build` on `$PATH`. Captures stdout+stderr, truncates per
    the `docs/BUILDER_V1.md` §3 64 KiB rule, returns a `BuildOutcome`.

Future implementations: `RemoteSSHBuildRunner` (delegates to a remote
Linux host over SSH), `GitHubActionsBuildRunner` (CI-shaped). All
conform to the same Protocol surface.

The Protocol shape is deliberately minimal. The runner orchestrates;
the BuildRunner just executes one nix-build invocation at a time and
reports what happened.
"""

from __future__ import annotations

import shutil
import subprocess
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Protocol


# Per `docs/BUILDER_V1.md` §3: stdout_stderr is truncated to the trailing
# 64 KiB. Above that, the full log is persisted to `build.log`.
INLINE_STDOUT_STDERR_CAP_BYTES = 65536


@dataclass(frozen=True)
class BuildOutcome:
    """One nix-build invocation's outcome.

    Field semantics mirror `docs/BUILDER_V1.md` §3's per-phase shape:
      * exit_code:        process return code; None if the runner
                          could not even invoke nix-build (infra-failure)
      * drv_path:         derivation path for the requested expression,
                          if the runner could resolve it (None on infra
                          failure or pre-eval failure)
      * out_path:         output store path on success; None otherwise
      * stdout_stderr:    raw combined stdout+stderr (untruncated as
                          collected; the runner truncates downstream)
      * elapsed_seconds:  wall-clock time the invocation took
      * timed_out:        True iff the runner enforced a timeout and
                          the invocation exceeded it
    """

    exit_code: int | None
    drv_path: str | None
    out_path: str | None
    stdout_stderr: str
    elapsed_seconds: float
    timed_out: bool = False
    extras: dict[str, Any] = field(default_factory=dict)

    @property
    def succeeded(self) -> bool:
        return self.exit_code == 0 and not self.timed_out


class BuildRunner(Protocol):
    """Encapsulates a single nix-build invocation."""

    def run(
        self,
        *,
        nix_expression: str | None = None,
        attr: str | None = None,
        cwd: Path,
        timeout_seconds: int = 1800,
    ) -> BuildOutcome:
        """Invoke nix-build with `-E <nix_expression>` OR `-A <attr>`.

        Exactly one of `nix_expression` / `attr` must be supplied.
        `cwd` is the working directory (a nixpkgs checkout); for
        expression-mode the caller passes the expression literal, for
        attr-mode the caller passes the attr to evaluate against the
        current default.nix in cwd.
        """
        ...


# ─── Fake adapter for tests / dry-runs ────────────────────────────────────


class FakeBuildRunner:
    """Returns pre-canned BuildOutcomes. Records every invocation.

    Two modes:

      (a) Single response. Construct with `response=BuildOutcome(...)`;
          every `.run()` returns the same outcome. Useful for "everything
          succeeds" or "everything fails" sweeps.

      (b) Per-call queue. Construct with `responses=[BuildOutcome,
          BuildOutcome, ...]`; each `.run()` consumes the next entry in
          order. When the queue is exhausted, an IndexError is raised
          (signalling the test fixture is incomplete).

    `calls` records each invocation as a dict so tests can assert on
    the arguments the runner saw.
    """

    def __init__(
        self,
        *,
        response: BuildOutcome | None = None,
        responses: list[BuildOutcome] | None = None,
    ):
        if (response is None) == (responses is None):
            raise ValueError(
                "FakeBuildRunner: supply exactly one of response= or "
                "responses= (single response vs per-call queue)"
            )
        self._single = response
        self._queue: list[BuildOutcome] = list(responses) if responses else []
        self.calls: list[dict[str, Any]] = []

    def run(
        self,
        *,
        nix_expression: str | None = None,
        attr: str | None = None,
        cwd: Path,
        timeout_seconds: int = 1800,
    ) -> BuildOutcome:
        if (nix_expression is None) == (attr is None):
            raise ValueError(
                "BuildRunner.run requires exactly one of nix_expression / attr"
            )
        self.calls.append({
            "nix_expression": nix_expression,
            "attr": attr,
            "cwd": str(cwd),
            "timeout_seconds": timeout_seconds,
        })
        if self._single is not None:
            return self._single
        if not self._queue:
            raise IndexError(
                "FakeBuildRunner queue exhausted; the test fixture supplied "
                f"fewer responses than the runner made calls (call #{len(self.calls)})"
            )
        return self._queue.pop(0)


# ─── Production runner (deferred on darwin without Linux infra) ──────────


class LocalNixBuildRunner:
    """Shells out to `nix-build` on `$PATH`.

    Activates only when nix-build is reachable AND the host system is
    Linux (or a configured remote builder is available — the Protocol
    is system-agnostic but production v0 use is Linux-only). On a
    darwin host without a remote-builder configuration, the orchestration
    layer should detect this and refuse to invoke this runner.
    """

    def __init__(self, *, nix_build_binary: str = "nix-build"):
        self._binary = nix_build_binary

    @property
    def is_available(self) -> bool:
        return shutil.which(self._binary) is not None

    def run(
        self,
        *,
        nix_expression: str | None = None,
        attr: str | None = None,
        cwd: Path,
        timeout_seconds: int = 1800,
    ) -> BuildOutcome:
        if not self.is_available:
            return BuildOutcome(
                exit_code=None, drv_path=None, out_path=None,
                stdout_stderr=f"nix-build not on PATH (looked for {self._binary!r})",
                elapsed_seconds=0.0,
                extras={"reason": "nix-build-not-available"},
            )
        if (nix_expression is None) == (attr is None):
            raise ValueError(
                "LocalNixBuildRunner.run requires exactly one of "
                "nix_expression / attr"
            )
        cmd: list[str] = [self._binary, "--no-out-link"]
        if nix_expression is not None:
            cmd += ["-E", nix_expression]
        else:
            cmd += ["-A", str(attr)]
        started = time.monotonic()
        try:
            proc = subprocess.run(
                cmd, cwd=str(cwd), check=False,
                capture_output=True, text=True,
                timeout=timeout_seconds,
            )
        except subprocess.TimeoutExpired as exc:
            elapsed = time.monotonic() - started
            stdout = exc.stdout or ""
            stderr = exc.stderr or ""
            return BuildOutcome(
                exit_code=None, drv_path=None, out_path=None,
                stdout_stderr=(stdout if isinstance(stdout, str) else "")
                              + "\n"
                              + (stderr if isinstance(stderr, str) else ""),
                elapsed_seconds=elapsed,
                timed_out=True,
                extras={"reason": "timeout", "timeout_seconds": timeout_seconds},
            )
        except OSError as exc:
            elapsed = time.monotonic() - started
            return BuildOutcome(
                exit_code=None, drv_path=None, out_path=None,
                stdout_stderr=f"OSError: {exc}",
                elapsed_seconds=elapsed,
                extras={"reason": "os-error"},
            )
        elapsed = time.monotonic() - started
        # On success, the realised store path is the last line of stdout
        # (nix-build convention). drv_path is harder to recover without
        # `--keep-going --json`; v0 returns None and lets future Builder
        # work fold it in.
        out_path: str | None = None
        if proc.returncode == 0:
            stdout_lines = (proc.stdout or "").rstrip().splitlines()
            if stdout_lines:
                last = stdout_lines[-1].strip()
                if last.startswith("/nix/store/"):
                    out_path = last
        combined = (proc.stdout or "") + "\n" + (proc.stderr or "")
        return BuildOutcome(
            exit_code=proc.returncode,
            drv_path=None,
            out_path=out_path,
            stdout_stderr=combined,
            elapsed_seconds=elapsed,
        )


# ─── helpers ──────────────────────────────────────────────────────────────


def truncate_to_inline_cap(text: str) -> tuple[str, bool]:
    """Truncate `text` to the inline 64 KiB cap.

    Returns (truncated_text, was_truncated). When the input is already
    under the cap, returns (text, False) verbatim. When over the cap,
    returns (last 64 KiB by byte count, True). UTF-8 boundary safety:
    we strip a leading partial code-point if the slice falls inside one.
    """
    encoded = text.encode("utf-8", errors="replace")
    if len(encoded) <= INLINE_STDOUT_STDERR_CAP_BYTES:
        return text, False
    tail = encoded[-INLINE_STDOUT_STDERR_CAP_BYTES:]
    # Strip leading bytes until we land on a UTF-8 boundary.
    while tail and (tail[0] & 0xC0) == 0x80:
        tail = tail[1:]
    return tail.decode("utf-8", errors="replace"), True


__all__ = [
    "BuildOutcome",
    "BuildRunner",
    "FakeBuildRunner",
    "INLINE_STDOUT_STDERR_CAP_BYTES",
    "LocalNixBuildRunner",
    "truncate_to_inline_cap",
]
