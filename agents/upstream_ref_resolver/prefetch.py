"""Live `nix-prefetch-url` integration for UpstreamRefResolver.

The mbedtls A/B (commit 2d5c12d) proved that the `prefetch_hashes[]`
contract upgrade is sufficient to flip the Patcher from refuse-only to
producing merge-ready patches. That run used a hash extracted from the
historical fix commit. This module closes the manual gap: it produces
`prefetch_hashes[]` and `prefetch_failures[]` entries by actually
running `nix-prefetch-url` against a derived target-release URL, with
full replay attribution (tool, tool_version, fetched_at).

Design constraints (from the user's call):
  * Resolver only records hashes for URLs it can derive from the chosen
    target release. URL derivation lives elsewhere (the resolver's
    URL-template logic — for now the caller passes derived URLs in).
  * Each successful prefetch_hashes[] entry records name, value,
    algorithm, source, url, tool, tool_version, fetched_at.
  * Prefetch failures must NOT make the bundle invalid. A failure
    produces a structured prefetch_failures[] entry; the bundle's
    prefetch_hashes[] simply omits that name. Patcher then rule-8
    refuses for that hash slot, which is the contract-correct outcome
    for unprefetchable cases.
  * Network is isolated to this module + UpstreamRefResolver. Patcher
    stays no-network.

The runner takes a list of `PrefetchTarget(name, url)` and returns
`PrefetchOutcome(hashes, failures)`. The shell-out is behind a
parameter (`prefetch_url_fn`) so tests can inject a fake. The default
is `_run_nix_prefetch_url`, which invokes the binary and parses the
output.
"""

from __future__ import annotations

import shutil
import subprocess
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Callable


@dataclass(frozen=True)
class PrefetchTarget:
    """A request to prefetch the hash for one Nix attribute."""

    name: str  # e.g. "src.hash"
    url: str  # the derived target-release URL the resolver wants to pin
    algorithm: str = "sha256"


@dataclass(frozen=True)
class PrefetchSuccess:
    name: str
    algorithm: str
    value: str  # SRI-form, ready to drop into upstream-ref.json
    source: str  # always "nix-prefetch-url" for this module
    url: str
    tool: str
    tool_version: str
    fetched_at: str  # ISO-8601 UTC
    replay_critical: bool = True

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "algorithm": self.algorithm,
            "value": self.value,
            "source": self.source,
            "prefetch_kind": "url",
            "url": self.url,
            "tool": self.tool,
            "tool_version": self.tool_version,
            "fetched_at": self.fetched_at,
            "replay_critical": self.replay_critical,
        }


@dataclass(frozen=True)
class PrefetchFailure:
    name: str
    reason: str  # one of upstream-ref-schema.prefetch_failures.items.reason enum
    # required_for_patch defaults True because every prefetch_targets()
    # caller asked the resolver to acquire this slot in the first place;
    # if the request was just a probe, the caller should pass False
    # explicitly. Mirrors the prefetch_skips[] required_for_patch semantic
    # so Patcher can fire rule 8 against either channel.
    required_for_patch: bool = True
    url_attempted: str | None = None
    tool: str | None = None
    tool_version: str | None = None
    attempted_command: str | None = None
    detail: str | None = None
    attempted_at: str | None = None

    def to_dict(self) -> dict:
        d: dict = {
            "name": self.name,
            "reason": self.reason,
            "required_for_patch": self.required_for_patch,
        }
        if self.url_attempted is not None:
            d["url_attempted"] = self.url_attempted
        if self.tool is not None:
            d["tool"] = self.tool
        if self.tool_version is not None:
            d["tool_version"] = self.tool_version
        if self.attempted_command is not None:
            d["attempted_command"] = self.attempted_command
        if self.detail is not None:
            # Schema caps at 2048 chars; clamp here for safety.
            d["detail"] = self.detail[:2048]
        if self.attempted_at is not None:
            d["attempted_at"] = self.attempted_at
        return d


@dataclass(frozen=True)
class PrefetchOutcome:
    hashes: list[PrefetchSuccess]
    failures: list[PrefetchFailure]

    def hashes_as_list(self) -> list[dict]:
        return [h.to_dict() for h in self.hashes]

    def failures_as_list(self) -> list[dict]:
        return [f.to_dict() for f in self.failures]


# Type for the swappable prefetcher: takes a URL + algorithm, returns
# either ("ok", sri_value, tool_version) or ("err", reason, detail).
PrefetchResult = tuple[str, str, str | None]
PrefetchUrlFn = Callable[[str, str], PrefetchResult]


def prefetch_targets(
    targets: list[PrefetchTarget],
    *,
    prefetch_url_fn: PrefetchUrlFn | None = None,
) -> PrefetchOutcome:
    """Run prefetches for every target. Returns successes + failures.

    Args:
        targets: list of PrefetchTarget(name, url, algorithm).
        prefetch_url_fn: swappable shell-out. Default: _run_nix_prefetch_url,
            which invokes the binary on PATH. Tests inject a fake.

    Returns:
        PrefetchOutcome with hashes[] and failures[] populated.
    """
    fn = prefetch_url_fn or _run_nix_prefetch_url
    hashes: list[PrefetchSuccess] = []
    failures: list[PrefetchFailure] = []
    for t in targets:
        ts = _utc_now_iso()
        outcome, value, detail = fn(t.url, t.algorithm)
        if outcome == "ok":
            tool_version = detail or ""
            hashes.append(
                PrefetchSuccess(
                    name=t.name,
                    algorithm=t.algorithm,
                    value=value,
                    source="nix-prefetch-url",
                    url=t.url,
                    tool="nix-prefetch-url",
                    tool_version=tool_version,
                    fetched_at=ts,
                )
            )
        else:
            # outcome is the failure-reason enum value; value is the
            # detail string (stderr excerpt, exit code etc.); detail is
            # tool_version when known.
            tool_version = detail
            failures.append(
                PrefetchFailure(
                    name=t.name,
                    reason=outcome,
                    url_attempted=t.url,
                    tool="nix-prefetch-url",
                    tool_version=tool_version,
                    detail=value,
                    attempted_at=ts,
                )
            )
    return PrefetchOutcome(hashes=hashes, failures=failures)


def _run_nix_prefetch_url(url: str, algorithm: str) -> PrefetchResult:
    """Default prefetcher: shells out to `nix-prefetch-url`.

    Returns:
      ("ok", sri_value, tool_version_string)
      ("tool-not-on-path", "<error>", None)
      ("tool-exit-nonzero", "<stderr-excerpt>", tool_version_or_none)
      ("tool-output-unparseable", "<stdout-excerpt>", tool_version)
    """
    if not shutil.which("nix-prefetch-url"):
        return ("tool-not-on-path", "nix-prefetch-url not on PATH", None)

    # Tool version first, for replay attribution. Best-effort.
    tool_version = ""
    try:
        ver = subprocess.run(
            ["nix-prefetch-url", "--version"],
            check=False,
            capture_output=True,
            text=True,
            timeout=10,
        )
        if ver.returncode == 0:
            tool_version = (
                (ver.stdout or "").strip().splitlines()[0] if ver.stdout else ""
            )
    except subprocess.SubprocessError:
        pass

    if algorithm not in ("sha256", "sha512"):
        return (
            "ecosystem-not-supported",
            f"nix-prefetch-url does not support algorithm {algorithm!r}",
            tool_version,
        )

    try:
        # `--print-path` is intentionally OMITTED so stdout is just the hash.
        # `--type sha256` ensures the hash type matches what nixpkgs uses.
        result = subprocess.run(
            ["nix-prefetch-url", "--type", algorithm, url],
            check=False,
            capture_output=True,
            text=True,
            timeout=120,
        )
    except subprocess.TimeoutExpired:
        return (
            "fetch-error-other",
            "nix-prefetch-url timed out after 120s",
            tool_version,
        )
    except FileNotFoundError:
        return (
            "tool-not-on-path",
            "nix-prefetch-url disappeared mid-run",
            tool_version,
        )
    except OSError as exc:
        return ("fetch-error-other", f"OSError: {exc}", tool_version)

    if result.returncode != 0:
        stderr = (result.stderr or "").strip()
        # Be charitable: 404 / not-found get their own reason.
        lo = stderr.lower()
        if "404" in lo or "not found" in lo:
            return ("fetch-error-404", stderr[:2048], tool_version)
        return (
            "tool-exit-nonzero",
            f"exit={result.returncode}; stderr: {stderr[:1900]}",
            tool_version,
        )

    # Parse stdout into the SRI form.
    raw = (result.stdout or "").strip()
    # nix-prefetch-url output is the base32 hash on stdout. Convert to SRI.
    sri = _to_sri(raw, algorithm)
    if sri is None:
        return (
            "tool-output-unparseable",
            f"could not parse stdout as a {algorithm} hash: {raw[:200]!r}",
            tool_version,
        )
    return ("ok", sri, tool_version)


def _to_sri(hash_str: str, algorithm: str) -> str | None:
    """Convert nix-prefetch-url's output (base32 by default) to SRI form.

    Strategy: shell out to `nix hash to-sri` if available; otherwise
    accept that the caller can pass us output in any form `nix hash to-sri`
    would convert. If neither path works, return None. Note: starting with
    Nix 2.4, `nix-prefetch-url` returns base32 by default.
    """
    if not hash_str:
        return None
    # If the value is already SRI, pass it through.
    if hash_str.startswith(f"{algorithm}-"):
        return hash_str
    # Try `nix hash to-sri`.
    if shutil.which("nix"):
        try:
            result = subprocess.run(
                ["nix", "hash", "to-sri", "--type", algorithm, hash_str],
                check=False,
                capture_output=True,
                text=True,
                timeout=10,
            )
            if result.returncode == 0:
                out = (result.stdout or "").strip()
                if out.startswith(f"{algorithm}-"):
                    return out
        except (subprocess.SubprocessError, OSError):
            pass
    return None


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


__all__ = [
    "PrefetchTarget",
    "PrefetchSuccess",
    "PrefetchFailure",
    "PrefetchOutcome",
    "prefetch_targets",
]
