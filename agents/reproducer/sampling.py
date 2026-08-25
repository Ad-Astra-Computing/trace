"""Verifier-guided pass@K sampling for the Reproducer stage.

The conversion study (DECISIONS 2026-08-02) established that single-shot
Reproducer generation at temperature 0 fails the discrimination oracle
roughly two thirds of the time: the model authors a fixture that is
malformed, tests the wrong scenario, or omits a dependency. Format
handling is solved (prompt v14); what remains is DESIGN quality, which a
single greedy draw cannot recover from.

This module samples K candidate reproducers at temperature > 0 and runs
each through the SAME behavioral verifier the cert uses (an actual
two-arm `nix-build`, not the model's self-reported log — the model log
can be fabricated, per the reproducer-log-fabrication finding). The first
candidate whose unpatched arm emits SIGNAL_UNPATCHED and whose patched
arm emits SIGNAL_PATCHED wins; the rest are discarded. Every draw's
verdict is recorded so the selection is auditable.

The core `sample_reproducer` is pure orchestration: it drives an injected
`ModelAdapter` and an injected `probe_fn`. Under test, a fake adapter
feeds diverse candidates and a fake probe returns canned verdicts, so the
first-green-wins logic is exercised without a nix-build. In production the
probe is `build_probe_fn(...)`, which runs the real Builder over an
isolated workspace copied from the bundle. The sampler never mutates the
caller's bundle directory; it returns the winning bytes for the caller to
commit.
"""

from __future__ import annotations

import hashlib
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable

from agents.builder.protocol import BuildRunner
from agents.patcher.adapter import ModelAdapter
from agents.reproducer.parser import ReproducerOutputMalformed
from agents.reproducer.runner import run_reproducer

# NOTE: agents.builder.run_builder and the reproducer scorers are imported
# lazily inside build_probe_fn. The scorers import agents.reproducer, so
# importing them at module top would cycle through this package's __init__
# (which re-exports this module). They are only needed to construct a probe.

# Draw 0 stays near the deterministic mode (the best single greedy attempt);
# later draws climb toward exploratory so the sample actually diversifies
# instead of re-drawing the same fixture. The ceiling stops at 0.9, not 1.0:
# the top of the range buys gratuitous malformed novelty more than genuine
# design diversity, so the schedule spends its draws where they pay off.
_DEFAULT_MAX_TEMPERATURE = 0.9
_FLOOR_TEMPERATURE = 0.2


def default_temperature_schedule(k: int) -> list[float]:
    """A ramp from a near-deterministic first draw to exploratory later draws.

    K == 1 degenerates to a single near-greedy draw (floor temperature). For
    K > 1 the schedule spans [_FLOOR_TEMPERATURE, _DEFAULT_MAX_TEMPERATURE]
    linearly, so no two draws share a temperature and the earliest draw is
    closest to the greedy mode single-shot generation would have used.
    """
    if k < 1:
        raise ValueError(f"k must be >= 1, got {k}")
    if k == 1:
        return [_FLOOR_TEMPERATURE]
    span = _DEFAULT_MAX_TEMPERATURE - _FLOOR_TEMPERATURE
    return [round(_FLOOR_TEMPERATURE + span * i / (k - 1), 4) for i in range(k)]


@dataclass(frozen=True)
class ProbeVerdict:
    """The two-arm verifier's judgment on one candidate reproducer."""

    signal_unpatched_present: bool
    signal_patched_present: bool
    signal_specificity_ok: bool  # advisory: named signal is CVE-specific
    detail: str

    @property
    def discriminates(self) -> bool:
        return self.signal_unpatched_present and self.signal_patched_present


# A probe takes the isolated workspace and the candidate's three output blobs
# and returns the oracle verdict. The default (build_probe_fn) runs the real
# Builder; tests inject a canned one.
ProbeFn = Callable[[Path, bytes, bytes, bytes], ProbeVerdict]


@dataclass(frozen=True)
class DrawResult:
    """One sampled candidate and the verifier's verdict on it."""

    index: int
    temperature: float
    kind: str  # "reproducer" | "refusal" | "malformed" | "probe-error"
    signal_unpatched_present: bool | None
    signal_patched_present: bool | None
    discriminates: bool
    signal_specificity_ok: bool | None
    reproducer_nix_sha256: str | None
    detail: str


@dataclass(frozen=True)
class SamplingResult:
    """The outcome of a pass@K sweep.

    `winner_index` is None when no draw discriminated (the caller routes the
    bundle to human-review / refusal, not a fabricated pass). `winning_files`
    carries the winner's bytes for the caller to commit; None when no winner.
    """

    k: int
    winner_index: int | None
    draws: tuple[DrawResult, ...]
    winning_files: dict[str, bytes] | None
    temperatures: tuple[float, ...]

    @property
    def discriminating_draws(self) -> int:
        return sum(1 for d in self.draws if d.discriminates)


def _sha256(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


# The Builder and signal scorers read the top-level bundle files; the model's
# reproducer.nix may also reference a bundle-local PoC under repro/ by path
# (prompt v14), so that subdirectory travels into the workspace too. Nothing
# else (.git, model failure captures) is builder-relevant, and copying it would
# be wasteful and racy.
def _seed_probe_workspace(bundle_dir: Path, probe_dir: Path) -> None:
    """Copy the bundle's builder-relevant files into probe_dir.

    Top-level files plus the repro/ PoC directory. Leaves out any stale
    reproducer/build outputs — the caller drops the candidate's own
    reproducer files in afterward, and a leftover reproducer-refusal.json or
    build.json would poison the verdict.
    """
    probe_dir.mkdir(parents=True, exist_ok=True)
    skip = {
        "reproducer.nix",
        "reproducer-log.txt",
        "passthru-tests.json",
        "reproducer-refusal.json",
        "build.json",
        "build.log",
    }
    for entry in bundle_dir.iterdir():
        if entry.is_file() and entry.name not in skip:
            shutil.copyfile(entry, probe_dir / entry.name)
    repro_src = bundle_dir / "repro"
    if repro_src.is_dir():
        shutil.copytree(repro_src, probe_dir / "repro", dirs_exist_ok=True)


def _restore_checkout(nixpkgs_checkout: Path) -> None:
    """Restore a checkout to its pristine HEAD state.

    The Builder's patch-apply mutates the checkout in place: it modifies
    tracked files AND, for source-backports that add a `.patch` file, leaves
    untracked additions behind. Between pass@K draws (and after the last one)
    the checkout must return to HEAD, or a later draw's unpatched arm builds
    against an already-patched tree and patch re-apply fails on the pre-existing
    file. `reset --hard` reverts tracked changes; `clean -fdq` removes the
    untracked additions. The caller's checkout is therefore treated as
    disposable (restorable to HEAD), which run_builder already assumes. A no-op
    when the path is not a git checkout. `.exists()` is true for both a `.git`
    directory and a worktree's `.git` file, so worktree checkouts are covered.
    """
    if not (nixpkgs_checkout / ".git").exists():
        return
    for args in (
        ["git", "-C", str(nixpkgs_checkout), "reset", "--hard", "-q", "HEAD"],
        ["git", "-C", str(nixpkgs_checkout), "clean", "-fdq"],
    ):
        subprocess.run(args, capture_output=True, text=True, check=False)


def build_probe_fn(
    *,
    bundle_dir: Path,
    build_runner: BuildRunner,
    nixpkgs_checkout: Path | None = None,
    timeout_seconds_per_build: int = 1800,
) -> ProbeFn:
    """The production probe: run the real two-arm Builder over an isolated copy.

    Each candidate is written into its own workspace (seeded from bundle_dir),
    built by the injected BuildRunner, and judged by the exact signal scorers
    the cert uses — so a local green here means the cert greens too (modulo
    store health). Returns a ProbeFn closed over the build configuration.
    """
    from agents.builder import run_builder
    from agents.scorers.reproducer_scorers import (
        ReproPatchedPassesScorer,
        ReproSignalSpecificityScorer,
        ReproUnpatchedFailsScorer,
    )

    invocation = {
        "outputs": [
            {"path": "reproducer.nix"},
            {"path": "reproducer-log.txt"},
            {"path": "passthru-tests.json"},
        ]
    }

    def _probe(probe_dir: Path, nix_bytes: bytes, log_bytes: bytes, json_bytes: bytes) -> ProbeVerdict:
        _seed_probe_workspace(bundle_dir, probe_dir)
        for name, buf in (
            ("reproducer.nix", nix_bytes),
            ("reproducer-log.txt", log_bytes),
            ("passthru-tests.json", json_bytes),
        ):
            if buf and not buf.endswith(b"\n"):
                buf = buf + b"\n"
            (probe_dir / name).write_bytes(buf)

        # Each draw builds against a pristine tree, and the checkout is left
        # pristine afterward so an early winner or the final draw does not hand
        # the caller a patched checkout. Restore both before and after (finally)
        # — before defends against an externally-dirty input, after guarantees a
        # clean exit. No-op when nixpkgs_checkout is None (FakeBuildRunner).
        if nixpkgs_checkout is not None:
            _restore_checkout(nixpkgs_checkout)
        try:
            result = run_builder(
                bundle_dir=probe_dir,
                build_runner=build_runner,
                nixpkgs_checkout=nixpkgs_checkout,
                timeout_seconds_per_build=timeout_seconds_per_build,
            )
        finally:
            if nixpkgs_checkout is not None:
                _restore_checkout(nixpkgs_checkout)
        import json as _json

        (probe_dir / "build.json").write_text(
            _json.dumps(result.build_json, indent=2, ensure_ascii=False) + "\n"
        )

        unpatched = ReproUnpatchedFailsScorer().score(bundle_dir=probe_dir, invocation=invocation)
        patched = ReproPatchedPassesScorer().score(bundle_dir=probe_dir, invocation=invocation)
        specificity = ReproSignalSpecificityScorer().score(bundle_dir=probe_dir, invocation=invocation)
        return ProbeVerdict(
            signal_unpatched_present=bool(unpatched.applies and unpatched.score == 1.0),
            signal_patched_present=bool(patched.applies and patched.score == 1.0),
            signal_specificity_ok=bool(specificity.applies and specificity.score == 1.0),
            detail=f"unpatched={unpatched.notes}; patched={patched.notes}",
        )

    return _probe


def sample_reproducer(
    *,
    inputs: dict[str, Any],
    adapter: ModelAdapter,
    probe_fn: ProbeFn,
    prompt_path: Path,
    probe_root: Path,
    k: int,
    temperatures: list[float] | None = None,
    exhaustive: bool = False,
) -> SamplingResult:
    """Sample up to K reproducers; keep the first that discriminates.

    Args:
        inputs:      the reproducer input dict (see runner.assemble_user_content).
        adapter:     a ModelAdapter (Fake under test, Anthropic in prod).
        probe_fn:    the two-arm verifier seam. Use build_probe_fn(...) in prod;
                     inject a canned verdict under test.
        prompt_path: the Reproducer system prompt.
        probe_root:  a scratch directory; each draw gets probe_root/draw-N.
        k:           number of candidates to try.
        temperatures: per-draw temperature; defaults to a ramp of length k.
        exhaustive:  when True, keep probing past the first winner so the full
                     pass-rate is measured (a corpus signal). Default False:
                     early-exit on first green (first-green-wins).

    Returns:
        SamplingResult with per-draw verdicts and the winner's bytes.
    """
    if k < 1:
        raise ValueError(f"k must be >= 1, got {k}")
    temps = temperatures if temperatures is not None else default_temperature_schedule(k)
    if len(temps) != k:
        raise ValueError(f"temperatures length {len(temps)} != k {k}")

    draws: list[DrawResult] = []
    winner_index: int | None = None
    winning_files: dict[str, bytes] | None = None

    for i in range(k):
        temp = temps[i]
        try:
            run = run_reproducer(
                inputs=inputs,
                adapter=adapter,
                sampling={"temperature": temp},
                prompt_path=prompt_path,
            )
        except ReproducerOutputMalformed as exc:
            draws.append(DrawResult(
                index=i, temperature=temp, kind="malformed",
                signal_unpatched_present=None, signal_patched_present=None,
                discriminates=False, signal_specificity_ok=None,
                reproducer_nix_sha256=None, detail=f"output malformed: {exc}",
            ))
            continue

        if run.kind != "reproducer":
            draws.append(DrawResult(
                index=i, temperature=temp, kind="refusal",
                signal_unpatched_present=None, signal_patched_present=None,
                discriminates=False, signal_specificity_ok=None,
                reproducer_nix_sha256=None,
                detail=(
                    f"refusal rule={run.parsed.refusal_rule!r} "
                    f"reason={run.parsed.refusal_reason!r}"
                ),
            ))
            continue

        nix_bytes = (run.parsed.raw_reproducer_nix or "").encode("utf-8")
        log_bytes = (run.parsed.raw_reproducer_log_txt or "").encode("utf-8")
        json_bytes = (run.parsed.raw_passthru_tests_json or "").encode("utf-8")
        nix_sha = _sha256(nix_bytes)

        # A proxy reproducer omits the unpatched arm by contract (the class
        # needs a capability the sandbox forbids), so it cannot behaviorally
        # discriminate and is not a pass@K winner — it routes reviewer-attested
        # elsewhere. Record it as its own class so a proxy-heavy sweep is
        # visible rather than being silently miscounted as a failed draw.
        if run.parsed.is_proxy:
            reason = run.parsed.proxy.proxy_reason if run.parsed.proxy else "unknown"
            draws.append(DrawResult(
                index=i, temperature=temp, kind="proxy",
                signal_unpatched_present=None, signal_patched_present=None,
                discriminates=False, signal_specificity_ok=None,
                reproducer_nix_sha256=nix_sha,
                detail=(
                    f"proxy reproducer (proxy_reason={reason!r}); unpatched-arm "
                    "evidence out of scope by contract, not a behavioral winner"
                ),
            ))
            continue

        probe_dir = probe_root / f"draw-{i}"
        try:
            verdict = probe_fn(probe_dir, nix_bytes, log_bytes, json_bytes)
        except Exception as exc:  # probe infra failure — record, keep sampling
            draws.append(DrawResult(
                index=i, temperature=temp, kind="probe-error",
                signal_unpatched_present=None, signal_patched_present=None,
                discriminates=False, signal_specificity_ok=None,
                reproducer_nix_sha256=nix_sha,
                detail=f"probe raised: {type(exc).__name__}: {exc}",
            ))
            continue

        draws.append(DrawResult(
            index=i, temperature=temp, kind="reproducer",
            signal_unpatched_present=verdict.signal_unpatched_present,
            signal_patched_present=verdict.signal_patched_present,
            discriminates=verdict.discriminates,
            signal_specificity_ok=verdict.signal_specificity_ok,
            reproducer_nix_sha256=nix_sha, detail=verdict.detail,
        ))

        if verdict.discriminates and winner_index is None:
            winner_index = i
            winning_files = {
                "reproducer.nix": nix_bytes,
                "reproducer-log.txt": log_bytes,
                "passthru-tests.json": json_bytes,
            }
            if not exhaustive:
                break

    return SamplingResult(
        k=k,
        winner_index=winner_index,
        draws=tuple(draws),
        winning_files=winning_files,
        temperatures=tuple(temps),
    )


__all__ = [
    "DrawResult",
    "ProbeFn",
    "ProbeVerdict",
    "SamplingResult",
    "build_probe_fn",
    "default_temperature_schedule",
    "sample_reproducer",
]
