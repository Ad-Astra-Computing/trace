"""End-to-end pipeline test for the mruby ASAN reproducer (CVE-2025-7207).

Exercises the full Builder → reproducer-scorers chain on a bundle
scaffolded from the live seed artifacts in
`traces/example/CVE-2025-7207--mruby/`. The BuildRunner is the test
fake — it emits the *predicted* ASAN / LocalJumpError lines that the
Linux-instrumented run will produce. Local Darwin certification of the
real `nix-build` path is a separate axis covered by manual validation
notes in the bundle README; this test is the deterministic CI guard.

Proves the user-locked invariants for the slice:
  * BuildRunner sees `instrumentation="asan"` on the unpatched + patched
    reproducer phases (from reproducer-instrumentation.json)
  * build.json records `instrumentation: "asan"`
  * `repro-unpatched-fails` scorer fires 1.0 against the unpatched run
    (SIGNAL_UNPATCHED substring matches Builder's recorded stdout/stderr)
  * `repro-patched-passes` scorer fires 1.0 against the patched run
    (SIGNAL_PATCHED substring matches)

Linux certification (canonical CI Builder reality) is the remaining
axis. This test guarantees that once Linux runs produce the predicted
output shapes, the scoring chain returns 1.0 / 1.0 without further code
changes.
"""

from __future__ import annotations

import json
import shutil
from pathlib import Path

from agents.builder import BuildOutcome, FakeBuildRunner
from agents.scorers.reproducer_scorers import (
    ReproPatchedPassesScorer,
    ReproUnpatchedFailsScorer,
)
from tools.trace_cli.execute import execute


SEED_DIR = (
    Path(__file__).resolve().parents[2] / "traces" / "example" / "CVE-2025-7207--mruby"
)


# ─── realistic Builder output fixtures ────────────────────────────────────


# What the actual `nix-build ((import reproducer.nix {}).unpatched.test)`
# invocation prints under TRACE_INSTRUMENTATION=asan, distilled from the
# 12 May 2026 manual validation. The exact ASAN stack frame addresses
# are variable; the discriminator is the SUMMARY-line substring the
# scorer greps for.
_UNPATCHED_ASAN_STDERR = """\
=================================================================
==12345==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x619000002280 at pc 0x000102ab8a10 bp 0x00016aa3eb70 sp 0x00016aa3eb68
WRITE of size 8 at 0x619000002280 thread T0
    #0 0x102ab8a0c in stack_clear+0xdc (mruby:arm64+0x1001f4a0c)
    #1 0x102a91234 in mrb_run+0x4f0
SUMMARY: AddressSanitizer: heap-buffer-overflow (mruby:arm64+0x1001f4a0c) in stack_clear+0xdc
==12345==ABORTING
REPRO_EXIT_CODE: 134
TRACE_INSTRUMENTATION: asan
vuln-triggered: AddressSanitizer: heap-buffer-overflow in mruby stack_clear (CVE-2025-7207 unpatched)
"""

_PATCHED_STDERR = """\
trace (most recent call last):
  [1] /nix/store/.../mruby_crash.txt:1
/nix/store/.../mruby_crash.txt:1: unexpected retry (LocalJumpError)
REPRO_EXIT_CODE: 1
TRACE_INSTRUMENTATION: asan
rejected-malformed-input: mruby raised LocalJumpError on unexpected retry token (CVE-2025-7207 patched)
"""


def _scaffold_mruby_bundle(tmp_path: Path) -> Path:
    """Materialise a bundle in tmp_path that mirrors the seed's artifacts.

    Copies the live reproducer.nix, reproducer-log.txt, passthru-tests.json,
    patch.diff, reproducer-instrumentation.json, the PoC at repro/, plus
    the bundle.json / finding.json metadata. Writes a minimal replay.json
    (Builder requires one to exist as the anchor for its invocation).
    """
    bundle = tmp_path / "bundle"
    bundle.mkdir()
    bundle_id = "2c4f9a1d8e6b4a07"
    cve = "CVE-2025-7207"
    nixpkgs_rev = "a08477a48bee5d7617c168aed10febeb1386dac3"

    for name in (
        "reproducer.nix",
        "reproducer-log.txt",
        "passthru-tests.json",
        "reproducer-instrumentation.json",
        "patch.diff",
    ):
        shutil.copy(SEED_DIR / name, bundle / name)
    (bundle / "repro").mkdir()
    shutil.copy(
        SEED_DIR / "repro" / "mruby_crash.txt", bundle / "repro" / "mruby_crash.txt"
    )

    # Minimal package.nix stand-in (Builder's patch-apply phase is
    # exercised separately; we run with nixpkgs_checkout=None +
    # apply_patch=False to focus on the reproducer-phase signal flow).
    (bundle / "package.nix").write_text(
        "# placeholder; nixpkgs supplies the real one\n"
    )

    (bundle / "bundle.json").write_text(
        json.dumps(
            {
                "schema_version": "1.0.0",
                "bundle_id": bundle_id,
                "cve_id": cve,
                "nixpkgs_rev": nixpkgs_rev,
                "kind": "human-review-required",
            }
        )
    )
    (bundle / "finding.json").write_text(
        json.dumps(
            {
                "cve_id": cve,
                "affected": [{"attr_path": "mruby", "version": "3.3.0"}],
            }
        )
    )
    (bundle / "replay.json").write_text(
        json.dumps(
            {
                "schema_version": "1.0.0",
                "bundle_id": bundle_id,
                "cve_id": cve,
                "nixpkgs_rev": nixpkgs_rev,
                "policy_version": "0" * 64,
                "bundle_schema_sha256": "1" * 64,
                "routing_config_sha256": "2" * 64,
                "tool_manifest": {
                    "flake_lock_sha256": "3" * 64,
                    "tools": [{"name": "python", "version": "3.13"}],
                },
                "cross_family_rule_honored": True,
                "roles": [],
            }
        )
    )
    return bundle


# ─── end-to-end pipeline ─────────────────────────────────────────────────


def test_mruby_asan_pipeline_scores_1_0_unpatched_fails_and_patched_passes(
    tmp_path: Path,
) -> None:
    bundle = _scaffold_mruby_bundle(tmp_path)

    # Three FakeBuildRunner responses, in the order Builder dispatches
    # (per F7 / DECISIONS 2026-05-17):
    #   1. unpatched reproducer-run (instrumentation=asan, pre-patch tree)
    #   2. patched-build sanity check (not instrumented, post-patch tree)
    #   3. patched reproducer-run   (instrumentation=asan, post-patch tree)
    captured: dict[str, FakeBuildRunner] = {}

    def factory() -> FakeBuildRunner:
        runner = FakeBuildRunner(
            responses=[
                BuildOutcome(
                    exit_code=1,
                    drv_path=None,
                    out_path=None,
                    stdout_stderr=_UNPATCHED_ASAN_STDERR,
                    elapsed_seconds=12.5,
                ),
                BuildOutcome(
                    exit_code=0,
                    drv_path=None,
                    out_path="/nix/store/x-mruby-patched-build",
                    stdout_stderr="patched-build ok\n",
                    elapsed_seconds=1.0,
                ),
                BuildOutcome(
                    exit_code=0,
                    drv_path=None,
                    out_path="/nix/store/x-mruby-patched-test",
                    stdout_stderr=_PATCHED_STDERR,
                    elapsed_seconds=11.8,
                ),
            ]
        )
        captured["runner"] = runner
        return runner

    result = execute(
        role="builder",
        bundle_dir=bundle,
        invocation={"invocation_id": None, "inputs": [], "outputs": []},
        verify=False,
        build_runner_factory=factory,
        nixpkgs_checkout=None,
    )

    # ── Builder threaded instrumentation correctly. ─────────────────────
    assert result["dispatch_outcome"] == "ok"
    bj = json.loads((bundle / "build.json").read_text())
    assert bj["instrumentation"] == "asan"
    calls = captured["runner"].calls
    assert len(calls) == 3
    # Order under F7: unpatched (asan), patched-build (none), patched (asan).
    # patched-build sanity check is intentionally NOT instrumented
    # (per BUILDER_V1.md §2.6, only the reproducer-run phases get the flag).
    assert calls[0]["instrumentation"] == "asan"  # unpatched reproducer
    assert calls[1]["instrumentation"] is None  # patched-build sanity
    assert calls[2]["instrumentation"] == "asan"  # patched reproducer

    # ── build.json carries the realistic stdout/stderr. ─────────────────
    assert "AddressSanitizer: heap-buffer-overflow" in bj["unpatched"]["stdout_stderr"]
    assert "stack_clear" in bj["unpatched"]["stdout_stderr"]
    assert "LocalJumpError" in bj["patched"]["stdout_stderr"]

    # ── Reproducer scorers fire 1.0 / 1.0. ──────────────────────────────
    # The scorer reads bundle's reproducer.nix + reproducer-log.txt +
    # passthru-tests.json (parses the SIGNAL_* substrings) and greps
    # them against build.json.unpatched.stdout_stderr / .patched.stdout_stderr.
    repro_invocation = {
        "outputs": [
            {"path": "reproducer.nix", "sha256": "x" * 64},
            {"path": "reproducer-log.txt", "sha256": "y" * 64},
            {"path": "passthru-tests.json", "sha256": "z" * 64},
        ],
    }

    unpatched_score = ReproUnpatchedFailsScorer().score(
        bundle_dir=bundle,
        invocation=repro_invocation,
    )
    assert unpatched_score.applies is True
    assert unpatched_score.score == 1.0, (
        f"repro-unpatched-fails should be 1.0 (SIGNAL_UNPATCHED appears "
        f"in unpatched.stdout_stderr); got {unpatched_score.score}, notes="
        f"{unpatched_score.notes!r}"
    )

    patched_score = ReproPatchedPassesScorer().score(
        bundle_dir=bundle,
        invocation=repro_invocation,
    )
    assert patched_score.applies is True
    assert patched_score.score == 1.0, (
        f"repro-patched-passes should be 1.0 (SIGNAL_PATCHED appears in "
        f"patched.stdout_stderr); got {patched_score.score}, notes="
        f"{patched_score.notes!r}"
    )


def test_mruby_asan_pipeline_unpatched_signal_absent_drops_to_zero(
    tmp_path: Path,
) -> None:
    """Sanity check the other direction: if Builder's recorded
    unpatched.stdout_stderr does NOT contain the SIGNAL_UNPATCHED
    substring, the scorer correctly returns 0.0. This is the failure
    case Linux certification must avoid — the build ran, but the signal
    didn't appear (e.g. ASAN wasn't actually applied)."""
    bundle = _scaffold_mruby_bundle(tmp_path)

    def factory() -> FakeBuildRunner:
        # Order under F7: unpatched, patched-build, patched.
        return FakeBuildRunner(
            responses=[
                # Unpatched ran but no ASAN diagnostic; e.g. instrumentation
                # didn't take effect.
                BuildOutcome(
                    exit_code=0,
                    drv_path=None,
                    out_path="/nix/store/x",
                    stdout_stderr="some unrelated mruby output, no ASAN\n",
                    elapsed_seconds=10.0,
                ),
                BuildOutcome(0, None, "/nix/store/x", "ok\n", 1.0),
                BuildOutcome(
                    exit_code=0,
                    drv_path=None,
                    out_path="/nix/store/x",
                    stdout_stderr=_PATCHED_STDERR,
                    elapsed_seconds=10.0,
                ),
            ]
        )

    execute(
        role="builder",
        bundle_dir=bundle,
        invocation={"invocation_id": None, "inputs": [], "outputs": []},
        verify=False,
        build_runner_factory=factory,
        nixpkgs_checkout=None,
    )

    repro_invocation = {
        "outputs": [
            {"path": "reproducer.nix", "sha256": "x" * 64},
            {"path": "reproducer-log.txt", "sha256": "y" * 64},
            {"path": "passthru-tests.json", "sha256": "z" * 64},
        ],
    }
    unpatched_score = ReproUnpatchedFailsScorer().score(
        bundle_dir=bundle,
        invocation=repro_invocation,
    )
    assert unpatched_score.score == 0.0
    assert "NOT present" in unpatched_score.notes
