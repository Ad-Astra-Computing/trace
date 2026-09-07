"""Tests for `agents.reproducer.sampling` — verifier-guided pass@K.

The orchestration (first-green-wins, temperature ramp, draw bookkeeping,
refusal / malformed / probe-error handling) is exercised with a queued
fake adapter and a canned probe. One integration test wires the real
`build_probe_fn` through `run_builder` + `FakeBuildRunner` to prove the
probe seam produces a correct verdict off a Builder-shaped build.json.
"""

from __future__ import annotations

import contextlib
from pathlib import Path
from typing import Any

import pytest

from agents.builder.protocol import BuildOutcome, FakeBuildRunner
from agents.patcher.adapter import ModelResponse
from agents.reproducer.sampling import (
    ProbeVerdict,
    build_probe_fn,
    default_temperature_schedule,
    sample_reproducer,
)

REPRO_PROMPT = Path("prompts/reproducer.v18.md")


# ─── fixtures: adapter + reproducer output shapes ─────────────────────────


class QueueAdapter:
    """Returns a different pre-canned response per call (a diverse sample)."""

    def __init__(self, model_id: str, responses: list[str]):
        self.model_id = model_id
        self._responses = list(responses)
        self.calls: list[dict[str, Any]] = []

    def invoke(self, *, system_prompt: str, user_content: str, sampling: dict[str, Any]) -> ModelResponse:
        self.calls.append({"sampling": dict(sampling)})
        text = self._responses.pop(0)
        return ModelResponse(
            text=text, model_id=self.model_id,
            input_tokens=None, output_tokens=None,
            stop_reason="end_turn", extras={"adapter": "queue"},
        )


class QueueProbe:
    """Consumes canned verdicts in order; only called for reproducer draws.

    An entry may be a ProbeVerdict (a verdict) or an Exception (a probe
    infra failure to raise, exercising the probe-error path).
    """

    def __init__(self, verdicts: list[Any]):
        self._verdicts = list(verdicts)
        self.calls: list[Path] = []

    def __call__(self, probe_dir: Path, nix_b: bytes, log_b: bytes, json_b: bytes) -> ProbeVerdict:
        self.calls.append(probe_dir)
        v = self._verdicts.pop(0)
        if isinstance(v, Exception):
            raise v
        return v


_NIX = """\
{ pkgs ? import <nixpkgs> { } }:

let
  unpatched = pkgs.demo.overrideAttrs (old: { version = "1.0.0"; });
  patched = pkgs.demo;
in
{
  inherit unpatched patched;

  test = pkgs.runCommand "repro-CVE-2026-99999" { } ''
    echo "vuln-triggered: deserialise() out-of-bounds for malformed length-prefix"
    echo "rejected-malformed-length-prefix-as-expected-from-CVE-2026-99999"
  '';
}
"""

_LOG = """\
The unpatched demo binary fails to bound the length prefix in deserialise().

=== unpatched ===
+ ${unpatched}/bin/demo --check
SIGNAL_UNPATCHED: vuln-triggered: deserialise() out-of-bounds for malformed length-prefix
EXIT: 1

=== patched ===
+ ${patched}/bin/demo --check
SIGNAL_PATCHED: rejected-malformed-length-prefix-as-expected-from-CVE-2026-99999
EXIT: 0
"""

_PASSTHRU = """\
[
  { "name": "passthru.tests.basic", "drv_path": null, "kind": "passthru.tests" }
]
"""


def _repro_output(nix: str = _NIX, log: str = _LOG, pj: str = _PASSTHRU) -> str:
    return (
        "=== BEGIN reproducer.nix ===\n" + nix + "=== END reproducer.nix ===\n"
        "=== BEGIN reproducer-log.txt ===\n" + log + "=== END reproducer-log.txt ===\n"
        "=== BEGIN passthru-tests.json ===\n" + pj + "=== END passthru-tests.json ===\n"
    )


_REFUSAL = (
    "=== BEGIN refusal ===\n"
    "rule: 3\n"
    "reason: vuln class is not locally-reproducible (kernel oops)\n"
    "=== END refusal ===\n"
)

_PROXY_NIX = (
    "{ pkgs ? import <nixpkgs> { } }:\n"
    "let\n  unpatched = pkgs.demo;\n  patched = pkgs.demo;\nin {\n"
    "  inherit unpatched patched;\n"
    "  test = pkgs.runCommand \"repro-proxy\" { } ''\n"
    "    echo \"rejected-malformed-length-prefix-as-expected-from-cve-XX\"\n"
    "  '' // {\n    meta = {\n      proxy = true;\n"
    "      proxy_reason = \"sandbox-cannot-trigger\";\n"
    "      why_not_full_repro = \"The full chain requires CAP_SYS_ADMIN which the build sandbox forbids; only the patched-rejection path is locally verifiable.\";\n"
    "      expected_limitations = \"This proxy verifies only the parser's malformed-input rejection, not the downstream privilege escalation.\";\n"
    "    };\n  };\n}\n"
)

_PROXY_LOG = (
    "Proxy reproducer for a CVE whose full chain requires CAP_SYS_ADMIN.\n\n"
    "=== unpatched ===\n"
    "By design out of scope for this proxy; see proxy section below.\n"
    "SIGNAL_UNPATCHED: proxy-test: full-chain unpatched evidence intentionally omitted (CAP_SYS_ADMIN)\n"
    "EXIT: 0\n\n"
    "=== patched ===\n"
    "Proxy verifies the parser's malformed-input rejection on the patched binary.\n"
    "SIGNAL_PATCHED: rejected-malformed-length-prefix-as-expected-from-cve-XX\n"
    "EXIT: 0\n\n"
    "=== proxy ===\n"
    "proxy_reason: sandbox-cannot-trigger\n"
    "why_not_full_repro: The full chain requires CAP_SYS_ADMIN which the build sandbox forbids; only the patched-rejection path is locally verifiable.\n"
    "expected_limitations: This proxy verifies only the parser's malformed-input rejection, not the downstream privilege escalation.\n"
)

_MALFORMED = "here is your reproducer, hope it helps! no markers though.\n"


_DISCRIMINATES = ProbeVerdict(True, True, True, "u=present; p=present")
_NO_DISCRIMINATE = ProbeVerdict(True, False, True, "u=present; p=NOT present")


# ─── temperature schedule ─────────────────────────────────────────────────


def test_temperature_schedule_single_draw_is_floor() -> None:
    assert default_temperature_schedule(1) == [0.2]


def test_temperature_schedule_ramps_floor_to_ceiling() -> None:
    temps = default_temperature_schedule(4)
    assert len(temps) == 4
    assert temps[0] == 0.2
    assert temps[-1] == 0.9
    assert temps == sorted(temps)  # monotonic ramp
    assert len(set(temps)) == 4  # no two draws share a temperature


def test_temperature_schedule_rejects_zero() -> None:
    with pytest.raises(ValueError):
        default_temperature_schedule(0)


# ─── orchestration ────────────────────────────────────────────────────────


def test_first_green_wins_and_early_exits(tmp_path: Path) -> None:
    # Draw 0 does not discriminate, draw 1 does: winner is 1, draw 2 never runs.
    adapter = QueueAdapter("m", [_repro_output(), _repro_output(), _repro_output()])
    probe = QueueProbe([_NO_DISCRIMINATE, _DISCRIMINATES, _DISCRIMINATES])
    res = sample_reproducer(
        inputs=_inputs(), adapter=adapter, probe_fn=probe,
        prompt_path=REPRO_PROMPT, probe_root=tmp_path, k=3,
    )
    assert res.winner_index == 1
    assert res.winning_files is not None
    assert set(res.winning_files) == {"reproducer.nix", "reproducer-log.txt", "passthru-tests.json"}
    # Early exit: only two draws recorded, only two probe + two adapter calls.
    assert len(res.draws) == 2
    assert len(probe.calls) == 2
    assert len(adapter.calls) == 2
    assert res.draws[0].discriminates is False
    assert res.draws[1].discriminates is True
    # Provenance/cost seams: winning_run is the winner's run; both drawn model
    # calls are billed (the losing draw 0 still spent tokens).
    assert res.winning_run is not None
    assert res.winning_run.kind == "reproducer"
    assert len(res.billed_runs) == 2
    assert res.winning_run is res.billed_runs[1]


def test_no_winner_when_none_discriminate(tmp_path: Path) -> None:
    adapter = QueueAdapter("m", [_repro_output(), _repro_output()])
    probe = QueueProbe([_NO_DISCRIMINATE, _NO_DISCRIMINATE])
    res = sample_reproducer(
        inputs=_inputs(), adapter=adapter, probe_fn=probe,
        prompt_path=REPRO_PROMPT, probe_root=tmp_path, k=2,
    )
    assert res.winner_index is None
    assert res.winning_files is None
    assert res.winning_run is None
    assert len(res.billed_runs) == 2  # both non-winning draws still spent tokens
    assert len(res.draws) == 2
    assert res.discriminating_draws == 0


def test_exhaustive_continues_past_first_winner(tmp_path: Path) -> None:
    # First-green is draw 0, but exhaustive keeps probing all K for the
    # audit-slice pass-rate signal. Winner stays the FIRST green.
    adapter = QueueAdapter("m", [_repro_output(), _repro_output(), _repro_output()])
    probe = QueueProbe([_DISCRIMINATES, _NO_DISCRIMINATE, _DISCRIMINATES])
    res = sample_reproducer(
        inputs=_inputs(), adapter=adapter, probe_fn=probe,
        prompt_path=REPRO_PROMPT, probe_root=tmp_path, k=3, exhaustive=True,
    )
    assert res.winner_index == 0
    assert len(res.draws) == 3
    assert res.discriminating_draws == 2


def test_refusal_draw_is_recorded_not_winner(tmp_path: Path) -> None:
    # A principled refusal is a non-winning draw, not a probe input.
    adapter = QueueAdapter("m", [_REFUSAL, _repro_output()])
    probe = QueueProbe([_DISCRIMINATES])
    res = sample_reproducer(
        inputs=_inputs(), adapter=adapter, probe_fn=probe,
        prompt_path=REPRO_PROMPT, probe_root=tmp_path, k=2,
    )
    assert res.draws[0].kind == "refusal"
    assert res.draws[0].discriminates is False
    assert len(probe.calls) == 1  # refusal never reached the probe
    assert res.winner_index == 1


def test_malformed_draw_is_recorded_not_winner(tmp_path: Path) -> None:
    adapter = QueueAdapter("m", [_MALFORMED, _repro_output()])
    probe = QueueProbe([_DISCRIMINATES])
    res = sample_reproducer(
        inputs=_inputs(), adapter=adapter, probe_fn=probe,
        prompt_path=REPRO_PROMPT, probe_root=tmp_path, k=2,
    )
    assert res.draws[0].kind == "malformed"
    assert res.draws[0].discriminates is False
    assert len(probe.calls) == 1
    assert res.winner_index == 1
    # A malformed draw produced no run object, so it is not billed; only the
    # winning draw reached a model result.
    assert len(res.billed_runs) == 1


def test_proxy_draw_is_its_own_class_not_a_winner(tmp_path: Path) -> None:
    # A contract-valid proxy reproducer omits the unpatched arm, so it cannot
    # behaviorally discriminate: it is recorded as kind=proxy, never probed,
    # and never wins. A later real reproducer wins instead.
    adapter = QueueAdapter("m", [_repro_output(_PROXY_NIX, _PROXY_LOG), _repro_output()])
    probe = QueueProbe([_DISCRIMINATES])
    res = sample_reproducer(
        inputs=_inputs(), adapter=adapter, probe_fn=probe,
        prompt_path=REPRO_PROMPT, probe_root=tmp_path, k=2,
    )
    assert res.draws[0].kind == "proxy"
    assert res.draws[0].discriminates is False
    assert "sandbox-cannot-trigger" in res.draws[0].detail
    assert len(probe.calls) == 1  # proxy never reached the probe
    assert res.winner_index == 1


def test_model_error_is_recorded_and_sweep_continues(tmp_path: Path) -> None:
    # A model-call failure on one draw must not crash the sweep or lose later
    # draws: it is recorded as kind="model-error" and sampling continues.
    class FlakyAdapter:
        def __init__(self, model_id: str, script: list[Any]):
            self.model_id = model_id
            self._script = list(script)

        def invoke(self, *, system_prompt, user_content, sampling):
            item = self._script.pop(0)
            if isinstance(item, Exception):
                raise item
            return ModelResponse(text=item, model_id=self.model_id, input_tokens=None,
                                 output_tokens=None, stop_reason="end_turn", extras={})

    adapter = FlakyAdapter("m", [ConnectionError("API down"), _repro_output()])
    probe = QueueProbe([_DISCRIMINATES])
    res = sample_reproducer(
        inputs=_inputs(), adapter=adapter, probe_fn=probe,
        prompt_path=REPRO_PROMPT, probe_root=tmp_path, k=2,
    )
    assert res.draws[0].kind == "model-error"
    assert "ConnectionError" in res.draws[0].detail
    assert res.draws[0].discriminates is False
    assert res.winner_index == 1  # the sweep recovered on the next draw


def test_programming_error_in_model_call_reraises(tmp_path: Path) -> None:
    # A programming error (not a transient adapter error) must NOT be laundered
    # into a model-error draw; it surfaces as a traceback.
    class BuggyAdapter:
        model_id = "m"
        def invoke(self, *, system_prompt, user_content, sampling):
            raise TypeError("regression in runner logic")

    with pytest.raises(TypeError, match="regression"):
        sample_reproducer(
            inputs=_inputs(), adapter=BuggyAdapter(), probe_fn=lambda *a: _DISCRIMINATES,
            prompt_path=REPRO_PROMPT, probe_root=tmp_path, k=1,
        )


def _bj(unpatched=None, patched=None, patched_build=None):
    """Build a build.json-shaped dict; each arm is (exit_code, stdout)."""
    def arm(spec):
        if spec is None:
            return {"exit_code": 0, "stdout_stderr": ""}
        code, out = spec
        return {"exit_code": code, "stdout_stderr": out}
    return {"unpatched": arm(unpatched), "patched": arm(patched),
            "patched_build": arm(patched_build)}


def test_infra_marker_only_trusted_with_nix_context(tmp_path: Path) -> None:
    # A download marker counts only when the line also names a nix resource;
    # fixture output that prints a network phrase is not misread as infra.
    from agents.reproducer.sampling import _build_looks_infra_broken
    assert _build_looks_infra_broken(_bj(patched=(0, "test: server returned 'connection refused' as expected\n"))) is False
    assert _build_looks_infra_broken(_bj(unpatched=(1, "error: unable to download 'http://example.com/x'\n"))) is False
    # Genuine nix diagnostics (cache host / store path) do count.
    assert _build_looks_infra_broken(_bj(unpatched=(1, "error: unable to download 'https://cache.nixos.org/x.narinfo': Could not resolve host\n"))) is True
    assert _build_looks_infra_broken(_bj(unpatched=(1, "error: getting status of '/nix/store/abc-perl-man': Stale file handle\n"))) is True


def test_runner_level_failures_are_infra(tmp_path: Path) -> None:
    # Runner/OS failures the substring+nix-context path would miss.
    from agents.reproducer.sampling import _build_looks_infra_broken
    # exit_code None on a reproducer arm = runner could not invoke nix-build.
    assert _build_looks_infra_broken(_bj(unpatched=(None, "nix-build not on PATH (looked for 'nix-build')"))) is True
    # disk exhaustion (no nix context, but unambiguous OS failure)
    assert _build_looks_infra_broken(_bj(patched=(1, "builder failed: OSError: [Errno 28] No space left on device\n"))) is True
    # a healthy build with the signal absent is NOT infra
    assert _build_looks_infra_broken(_bj(unpatched=(1, "ran fine, no signal\n"), patched=(0, "ok\n"))) is False
    # a SILENT timeout: exit_code None, empty log, outcome timed-out
    silent_timeout = {
        "unpatched": {"exit_code": None, "outcome": "timed-out", "stdout_stderr": ""},
        "patched": {"exit_code": 0, "stdout_stderr": "ok\n"},
    }
    assert _build_looks_infra_broken(silent_timeout) is True


def test_transient_vs_permanent_adapter_errors() -> None:
    # 429 + 5xx SDK errors and stdlib connection/timeout are transient; permanent
    # 4xx (auth, bad request) and programming errors are not absorbed.
    from agents.reproducer.sampling import _is_transient_adapter_error

    class APIStatusError(Exception):
        def __init__(self, status): self.status_code = status

    class RateLimitError(APIStatusError): pass
    class AuthenticationError(APIStatusError): pass

    assert _is_transient_adapter_error(ConnectionError("net")) is True
    assert _is_transient_adapter_error(TimeoutError("slow")) is True
    assert _is_transient_adapter_error(RateLimitError(429)) is True
    assert _is_transient_adapter_error(APIStatusError(503)) is True
    assert _is_transient_adapter_error(AuthenticationError(401)) is False  # permanent
    assert _is_transient_adapter_error(APIStatusError(400)) is False       # bad request
    assert _is_transient_adapter_error(TypeError("bug")) is False          # programming error


def test_probe_error_is_classified_separately(tmp_path: Path) -> None:
    # An infra failure (store corruption) is a false negative, not an oracle
    # fail: it must be its own class, and sampling keeps going.
    adapter = QueueAdapter("m", [_repro_output(), _repro_output()])
    probe = QueueProbe([RuntimeError("stale file handle"), _DISCRIMINATES])
    res = sample_reproducer(
        inputs=_inputs(), adapter=adapter, probe_fn=probe,
        prompt_path=REPRO_PROMPT, probe_root=tmp_path, k=2,
    )
    assert res.draws[0].kind == "probe-error"
    assert "stale file handle" in res.draws[0].detail
    assert res.draws[0].discriminates is False
    assert res.winner_index == 1


def test_signal_specificity_recorded_on_draw(tmp_path: Path) -> None:
    adapter = QueueAdapter("m", [_repro_output()])
    probe = QueueProbe([ProbeVerdict(True, True, False, "spurious")])
    res = sample_reproducer(
        inputs=_inputs(), adapter=adapter, probe_fn=probe,
        prompt_path=REPRO_PROMPT, probe_root=tmp_path, k=1,
    )
    assert res.winner_index == 0
    assert res.draws[0].signal_specificity_ok is False


def test_temperature_passed_through_to_adapter(tmp_path: Path) -> None:
    adapter = QueueAdapter("m", [_repro_output(), _repro_output()])
    probe = QueueProbe([_NO_DISCRIMINATE, _DISCRIMINATES])
    sample_reproducer(
        inputs=_inputs(), adapter=adapter, probe_fn=probe,
        prompt_path=REPRO_PROMPT, probe_root=tmp_path, k=2,
    )
    assert adapter.calls[0]["sampling"]["temperature"] == 0.2
    assert adapter.calls[1]["sampling"]["temperature"] == 0.9


def test_explicit_temperatures_length_must_match_k(tmp_path: Path) -> None:
    adapter = QueueAdapter("m", [_repro_output()])
    probe = QueueProbe([_DISCRIMINATES])
    with pytest.raises(ValueError):
        sample_reproducer(
            inputs=_inputs(), adapter=adapter, probe_fn=probe,
            prompt_path=REPRO_PROMPT, probe_root=tmp_path, k=1,
            temperatures=[0.1, 0.2],
        )


# ─── integration: real build_probe_fn through run_builder ─────────────────


def _seed_bundle(tmp_path: Path) -> Path:
    """A minimal bundle dir the real Builder + scorers can read."""
    import json

    b = tmp_path / "bundle"
    b.mkdir()
    (b / "finding.json").write_text(json.dumps({
        "cve_id": "CVE-2026-99999",
        "summary": "out-of-bounds read in demo's deserialise() on malformed length-prefix",
        "affected": [{"attr_path": "demo"}],
    }))
    (b / "upstream-ref.json").write_text(json.dumps({
        "cve_id": "CVE-2026-99999",
        "current_version": "1.0.0", "target_version": "1.0.1",
        "upstream_fix_commits": [{
            "repo_url": "https://github.com/example/demo",
            "commit_sha": "deadbeef",
            "message": "deserialise: bound length-prefix before reading",
        }],
    }))
    (b / "impact.json").write_text(json.dumps({"rebuild_count": 1}))
    (b / "maintainers.json").write_text(json.dumps({"maintainers": []}))
    (b / "package.nix").write_text("{ }\n")
    (b / "patch.diff").write_text(
        "--- a/pkgs/demo/default.nix\n+++ b/pkgs/demo/default.nix\n"
    )
    (b / "patch-rationale.md").write_text("bounds the length prefix\n")
    (b / "bundle.json").write_text(json.dumps({
        "bundle_id": "CVE-2026-99999--demo", "nixpkgs_rev": "0" * 40,
    }))
    return b


def _outcome_with(stdout: str, exit_code: int) -> BuildOutcome:
    return BuildOutcome(
        exit_code=exit_code, drv_path="/nix/store/x.drv",
        out_path="/nix/store/x", stdout_stderr=stdout, elapsed_seconds=0.1,
    )


def test_build_probe_fn_discriminating_verdict(tmp_path: Path) -> None:
    bundle = _seed_bundle(tmp_path)
    # run_builder invokes the runner three times: unpatched.test,
    # patched-build, patched.test. Feed each arm its named signal.
    sig_u = "vuln-triggered: deserialise() out-of-bounds for malformed length-prefix"
    sig_p = "rejected-malformed-length-prefix-as-expected-from-CVE-2026-99999"
    runner = FakeBuildRunner(responses=[
        _outcome_with(f"+ unpatched\n{sig_u}\n", 1),   # unpatched.test
        _outcome_with("+ patched-build OK\n", 0),       # patched-build
        _outcome_with(f"+ patched\n{sig_p}\n", 0),      # patched.test
    ])
    probe = build_probe_fn(
        bundle_dir=bundle, build_runner=runner, nixpkgs_checkout=None,
    )
    verdict = probe(
        tmp_path / "probe",
        _NIX.encode(), _LOG.encode(), _PASSTHRU.encode(),
    )
    assert verdict.signal_unpatched_present is True
    assert verdict.signal_patched_present is True
    assert verdict.discriminates is True


def test_build_probe_fn_copies_repro_poc_dir(tmp_path: Path) -> None:
    # A bundle-local PoC under repro/ (referenced by the model's fixture by
    # path) must travel into the probe workspace, or the build cannot see it.
    bundle = _seed_bundle(tmp_path)
    (bundle / "repro").mkdir()
    (bundle / "repro" / "crash_poc").write_bytes(b"\x00\x01crash")
    runner = FakeBuildRunner(responses=[
        _outcome_with("+ unpatched\n(no signal)\n", 1),
        _outcome_with("+ patched-build OK\n", 0),
        _outcome_with("+ patched\n(no signal)\n", 0),
    ])
    probe = build_probe_fn(bundle_dir=bundle, build_runner=runner, nixpkgs_checkout=None)
    probe_dir = tmp_path / "probe"
    probe(probe_dir, _NIX.encode(), _LOG.encode(), _PASSTHRU.encode())
    assert (probe_dir / "repro" / "crash_poc").read_bytes() == b"\x00\x01crash"


def test_build_probe_fn_restores_checkout_before_build(tmp_path: Path) -> None:
    # The Builder's patch-apply mutates the checkout in place; the probe must
    # revert tracked changes before building so a later draw is not poisoned by
    # an earlier draw's applied patch.
    import subprocess

    bundle = _seed_bundle(tmp_path)
    checkout = tmp_path / "nixpkgs"
    checkout.mkdir()
    tracked = checkout / "pkg.nix"
    tracked.write_text("pristine\n")
    for args in (
        ["git", "-C", str(checkout), "init", "-q"],
        ["git", "-C", str(checkout), "add", "."],
        ["git", "-C", str(checkout), "-c", "user.email=t@t", "-c", "user.name=t",
         "commit", "-qm", "init"],
    ):
        subprocess.run(args, check=True, capture_output=True)
    # Simulate a prior draw's patch-apply: a modified tracked file AND a new
    # untracked file (as a source-backport .patch addition would leave).
    tracked.write_text("PATCHED by a prior draw\n")
    added = checkout / "CVE-2026-99999.patch"
    added.write_text("+ added by a prior draw\n")

    runner = FakeBuildRunner(response=_outcome_with("ok\n", 0))
    probe = build_probe_fn(bundle_dir=bundle, build_runner=runner, nixpkgs_checkout=checkout)
    # The fake checkout is not a real nixpkgs, so run_builder's patch-apply
    # yields an unbuilt (exit_code None) arm and the probe raises infra AFTER its
    # finally-restore; restoration is what this test asserts, so tolerate it.
    with contextlib.suppress(RuntimeError):
        probe(tmp_path / "probe", _NIX.encode(), _LOG.encode(), _PASSTHRU.encode())
    # Restored to pristine HEAD: tracked reverted, untracked addition removed.
    assert tracked.read_text() == "pristine\n"
    assert not added.exists()


def test_build_probe_fn_restores_checkout_after_probe(tmp_path: Path) -> None:
    # After the probe the caller's checkout must be pristine, so a later cert
    # build does not run against contaminated state.
    import subprocess

    bundle = _seed_bundle(tmp_path)
    checkout = tmp_path / "nixpkgs"
    checkout.mkdir()
    (checkout / "pkg.nix").write_text("pristine\n")
    for args in (
        ["git", "-C", str(checkout), "init", "-q"],
        ["git", "-C", str(checkout), "add", "."],
        ["git", "-C", str(checkout), "-c", "user.email=t@t", "-c", "user.name=t",
         "commit", "-qm", "init"],
    ):
        subprocess.run(args, check=True, capture_output=True)

    # A runner that dirties the checkout mid-build (stands in for patch-apply).
    class DirtyingRunner:
        def run(self, **kw: Any) -> BuildOutcome:
            (checkout / "pkg.nix").write_text("patched mid-build\n")
            (checkout / "new.patch").write_text("added\n")
            return _outcome_with("ok\n", 0)

    probe = build_probe_fn(bundle_dir=bundle, build_runner=DirtyingRunner(), nixpkgs_checkout=checkout)
    # The DirtyingRunner returns exit 0, but run_builder against a non-nixpkgs
    # checkout yields an unbuilt arm, so the probe raises infra after its
    # finally-restore. The post-probe cleanliness is what this test asserts.
    with contextlib.suppress(RuntimeError):
        probe(tmp_path / "probe", _NIX.encode(), _LOG.encode(), _PASSTHRU.encode())
    status = subprocess.run(
        ["git", "-C", str(checkout), "status", "--porcelain"],
        capture_output=True, text=True,
    )
    assert status.stdout == ""  # clean tree after the probe


def test_build_probe_fn_raises_on_infra_broken_build(tmp_path: Path) -> None:
    # A build that failed because the binary cache was unreachable must be an
    # infra probe-error, not a false "signal absent" non-discriminating verdict.
    bundle = _seed_bundle(tmp_path)
    netfail = "error: unable to download 'https://cache.nixos.org/x.narinfo': Could not resolve host"
    runner = FakeBuildRunner(responses=[
        _outcome_with(netfail, 1),   # unpatched.test
        _outcome_with(netfail, 1),   # patched-build
        _outcome_with(netfail, 1),   # patched.test
    ])
    probe = build_probe_fn(bundle_dir=bundle, build_runner=runner, nixpkgs_checkout=None)
    import pytest as _pytest
    with _pytest.raises(RuntimeError, match="infrastructure"):
        probe(tmp_path / "probe", _NIX.encode(), _LOG.encode(), _PASSTHRU.encode())


def test_build_probe_fn_non_discriminating_when_signal_absent(tmp_path: Path) -> None:
    bundle = _seed_bundle(tmp_path)
    sig_p = "rejected-malformed-length-prefix-as-expected-from-CVE-2026-99999"
    runner = FakeBuildRunner(responses=[
        _outcome_with("+ unpatched\n(no specific signal observed)\n", 1),
        _outcome_with("+ patched-build OK\n", 0),
        _outcome_with(f"+ patched\n{sig_p}\n", 0),
    ])
    probe = build_probe_fn(bundle_dir=bundle, build_runner=runner, nixpkgs_checkout=None)
    verdict = probe(tmp_path / "probe", _NIX.encode(), _LOG.encode(), _PASSTHRU.encode())
    assert verdict.signal_unpatched_present is False
    assert verdict.discriminates is False


def _inputs() -> dict[str, Any]:
    """The reproducer input dict; content is irrelevant to orchestration tests
    (the QueueAdapter ignores it), only the required keys must be present."""
    return {
        "finding": {"cve_id": "CVE-2026-99999"},
        "upstream_ref": {},
        "impact": {},
        "maintainers": {},
        "package_source": "{ }\n",
        "patch_diff": "--- a\n+++ b\n",
        "patch_rationale_md": "why\n",
    }
