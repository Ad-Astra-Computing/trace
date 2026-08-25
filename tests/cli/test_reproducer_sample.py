"""Tests for `trace reproducer sample` (verifier-guided pass@K CLI).

Covers the pure provenance builder + winner committer and an end-to-end
`run` with injected fake adapter + probe (no model spend, no nix-build).
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from agents.patcher.adapter import ModelResponse
from agents.reproducer.sampling import DrawResult, ProbeVerdict, SamplingResult
from tools.trace_cli import reproducer_sample as rs

# Reuse the reproducer output fixtures from the sampling test module.
from tests.reproducer.test_sampling import (
    _LOG,
    _NIX,
    _PASSTHRU,
    _repro_output,
)


class QueueAdapter:
    def __init__(self, model_id: str, responses: list[str]):
        self.model_id = model_id
        self._responses = list(responses)

    def invoke(self, *, system_prompt: str, user_content: str, sampling: dict[str, Any]) -> ModelResponse:
        return ModelResponse(
            text=self._responses.pop(0), model_id=self.model_id,
            input_tokens=None, output_tokens=None, stop_reason="end_turn", extras={},
        )


class QueueProbe:
    def __init__(self, verdicts: list[Any]):
        self._verdicts = list(verdicts)

    def __call__(self, probe_dir: Path, nix_b: bytes, log_b: bytes, json_b: bytes) -> ProbeVerdict:
        v = self._verdicts.pop(0)
        if isinstance(v, Exception):
            raise v
        return v


_DISC = ProbeVerdict(True, True, True, "u=present; p=present")
_NODISC = ProbeVerdict(True, False, True, "u=present; p=NOT present")


def _seed_bundle(tmp_path: Path) -> Path:
    b = tmp_path / "bundle"
    b.mkdir()
    (b / "finding.json").write_text(json.dumps({
        "cve_id": "CVE-2026-99999", "summary": "oob read",
        "affected": [{"attr_path": "demo"}],
    }))
    (b / "upstream-ref.json").write_text(json.dumps({"cve_id": "CVE-2026-99999"}))
    (b / "impact.json").write_text(json.dumps({"rebuild_count": 1}))
    (b / "maintainers.json").write_text(json.dumps({"maintainers": []}))
    (b / "package.nix").write_text("{ }\n")
    (b / "patch.diff").write_text("--- a/x\n+++ b/x\n")
    (b / "patch-rationale.md").write_text("why\n")
    (b / "bundle.json").write_text(json.dumps({"bundle_id": "CVE-2026-99999--demo"}))
    return b


def _finalize_replay(bundle: Path) -> None:
    """Write a minimal finalized replay.json (Opus Patcher) so the production
    path clears _validate_finalized_bundle and reaches the checkout check."""
    (bundle / "replay.json").write_text(json.dumps({
        "roles": [{"role": "patcher", "invocations": [
            {"model": {"model_id": "claude-opus-4-7", "family": "anthropic-opus"}}
        ]}]
    }))


def _args(bundle: Path, **over: Any) -> argparse.Namespace:
    base = dict(
        bundle=bundle, model="claude-sonnet-4-5-20250929", k=2,
        nixpkgs_checkout=None, probe_root=None, exhaustive=False,
        builder_timeout_seconds=1800, overwrite=False,
    )
    base.update(over)
    return argparse.Namespace(**base)


# ─── pure: provenance ─────────────────────────────────────────────────────


def _sampling_result(winner: int | None) -> SamplingResult:
    draws = (
        DrawResult(0, 0.2, "reproducer", True, False, False, True, "a" * 64, "d0"),
        DrawResult(1, 0.9, "reproducer", True, True, True, True, "b" * 64, "d1"),
    )
    wf = None
    if winner is not None:
        wf = {"reproducer.nix": b"nix\n", "reproducer-log.txt": b"log\n",
              "passthru-tests.json": b"[]\n"}
    return SamplingResult(k=2, winner_index=winner, draws=draws,
                          winning_files=wf, temperatures=(0.2, 0.9))


def test_provenance_records_winner_and_all_draws() -> None:
    prov = rs.build_sampling_provenance(
        _sampling_result(1), model_id="claude-sonnet-4-5-20250929",
        prompt_path="prompts/reproducer.v14.md", prompt_sha256="deadbeef",
        tool_version="0.7.0", generated_at="2026-08-25T00:00:00Z",
        verifier="local-screen", exhaustive=False,
    )
    assert prov["schema_version"] == rs.SAMPLING_SIDECAR_SCHEMA_VERSION
    assert prov["model_id"] == "claude-sonnet-4-5-20250929"
    assert prov["prompt_sha256"] == "deadbeef"
    assert prov["verifier"] == "local-screen"
    assert prov["winner"]["draw_index"] == 1
    assert prov["winner"]["temperature"] == 0.9
    assert prov["winner"]["reproducer_nix_sha256"] == "b" * 64
    assert len(prov["draws"]) == 2
    assert prov["discriminating_draws"] == 1
    assert prov["draws"][0]["discriminates"] is False


def test_provenance_null_winner_when_none_discriminate() -> None:
    prov = rs.build_sampling_provenance(
        _sampling_result(None), model_id="m", prompt_path="p",
        prompt_sha256="x", tool_version="v", generated_at="t",
        verifier="local-screen", exhaustive=True,
    )
    assert prov["winner"] is None
    assert prov["exhaustive"] is True


# ─── pure: commit_winner ──────────────────────────────────────────────────


def test_commit_winner_writes_three_files(tmp_path: Path) -> None:
    b = _seed_bundle(tmp_path)
    outputs = rs.commit_winner(b, _sampling_result(1))
    assert {o["path"] for o in outputs} == {
        "reproducer.nix", "reproducer-log.txt", "passthru-tests.json"}
    assert (b / "reproducer.nix").read_bytes() == b"nix\n"
    assert (b / "passthru-tests.json").read_bytes() == b"[]\n"


def test_commit_winner_clears_stale_refusal(tmp_path: Path) -> None:
    # Resampling a bundle that previously refused: committing a winner must
    # remove reproducer-refusal.json or the Builder ignores the winner.
    b = _seed_bundle(tmp_path)
    (b / "reproducer-refusal.json").write_text('{"rule": 3, "reason": "x"}\n')
    rs.commit_winner(b, _sampling_result(1))
    assert (b / "reproducer.nix").is_file()
    assert not (b / "reproducer-refusal.json").exists()


def test_commit_winner_raises_without_winner(tmp_path: Path) -> None:
    b = _seed_bundle(tmp_path)
    try:
        rs.commit_winner(b, _sampling_result(None))
        assert False, "expected ValueError"
    except ValueError:
        pass


# ─── end-to-end run with injected fakes ───────────────────────────────────


def test_run_commits_winner_and_writes_sidecar(tmp_path: Path) -> None:
    b = _seed_bundle(tmp_path)
    adapter = QueueAdapter("claude-sonnet-4-5-20250929", [_repro_output(), _repro_output()])
    probe = QueueProbe([_NODISC, _DISC])
    code = rs.run(
        _args(b), _adapter_factory=lambda m: adapter, _probe_fn=probe,
    )
    assert code == rs.EXIT_OK
    assert (b / "reproducer.nix").is_file()
    sidecar = json.loads((b / "reproducer-sampling.json").read_text())
    assert sidecar["winner"]["draw_index"] == 1
    assert len(sidecar["draws"]) == 2
    assert sidecar["prompt_path"] == "prompts/reproducer.v14.md"


def test_run_no_winner_routes_human_review(tmp_path: Path) -> None:
    b = _seed_bundle(tmp_path)
    adapter = QueueAdapter("claude-sonnet-4-5-20250929", [_repro_output(), _repro_output()])
    probe = QueueProbe([_NODISC, _NODISC])
    code = rs.run(_args(b), _adapter_factory=lambda m: adapter, _probe_fn=probe)
    assert code == rs.EXIT_NO_WINNER
    # No reproducer.nix committed, but the sidecar records the failed sweep.
    assert not (b / "reproducer.nix").is_file()
    sidecar = json.loads((b / "reproducer-sampling.json").read_text())
    assert sidecar["winner"] is None
    assert sidecar["discriminating_draws"] == 0


def test_run_rejects_missing_bundle(tmp_path: Path) -> None:
    code = rs.run(_args(tmp_path / "nope"))
    assert code == rs.EXIT_USAGE


def test_run_rejects_advisory_only(tmp_path: Path) -> None:
    b = _seed_bundle(tmp_path)
    (b / "bundle.json").write_text(json.dumps({"kind": "advisory-only"}))
    code = rs.run(_args(b), _adapter_factory=lambda m: None, _probe_fn=lambda *a: _DISC)
    assert code == rs.EXIT_USAGE


def test_run_real_probe_requires_checkout(tmp_path: Path) -> None:
    # With no injected probe (production path) and no --nixpkgs-checkout, the
    # local screen cannot apply the patch, so the command must refuse.
    b = _seed_bundle(tmp_path)
    _finalize_replay(b)
    code = rs.run(_args(b), _adapter_factory=lambda m: None)  # _probe_fn left None
    assert code == rs.EXIT_USAGE


def test_run_refuses_existing_reproducer_without_overwrite(tmp_path: Path) -> None:
    b = _seed_bundle(tmp_path)
    (b / "reproducer.nix").write_text("existing\n")
    code = rs.run(_args(b), _adapter_factory=lambda m: None, _probe_fn=lambda *a: _DISC)
    assert code == rs.EXIT_USAGE
    assert (b / "reproducer.nix").read_text() == "existing\n"  # untouched


def test_run_quarantines_stale_reproducer_on_no_winner(tmp_path: Path) -> None:
    b = _seed_bundle(tmp_path)
    (b / "reproducer.nix").write_text("stale\n")
    (b / "reproducer-log.txt").write_text("stale-log\n")
    (b / "passthru-tests.json").write_text("[]\n")
    adapter = QueueAdapter("claude-sonnet-4-5-20250929", [_repro_output(), _repro_output()])
    probe = QueueProbe([_NODISC, _NODISC])
    code = rs.run(_args(b, overwrite=True), _adapter_factory=lambda m: adapter, _probe_fn=probe)
    assert code == rs.EXIT_NO_WINNER
    # Stale outputs moved out of the canonical path so cert cannot consume them.
    assert not (b / "reproducer.nix").is_file()
    quarantined = list((b / ".reproducer-sampling-quarantine").glob("*/reproducer.nix"))
    assert len(quarantined) == 1
    assert quarantined[0].read_text() == "stale\n"


def test_run_all_probe_error_is_infra_not_no_winner(tmp_path: Path) -> None:
    # Every draw's probe raised (store/daemon down): the verifier never ran, so
    # this is an infra failure (exit 4), the existing reproducer is preserved
    # (not quarantined), and it is not reported as a genuine no-winner sweep.
    b = _seed_bundle(tmp_path)
    (b / "reproducer.nix").write_text("existing\n")
    adapter = QueueAdapter("claude-sonnet-4-5-20250929", [_repro_output(), _repro_output()])

    def boom(*a: Any) -> ProbeVerdict:
        raise RuntimeError("nix daemon unavailable")

    code = rs.run(_args(b, overwrite=True), _adapter_factory=lambda m: adapter, _probe_fn=boom)
    assert code == rs.EXIT_PROBE_INFRA
    assert (b / "reproducer.nix").read_text() == "existing\n"  # preserved
    assert not (b / ".reproducer-sampling-quarantine").exists()
    # The canonical sidecar is NOT clobbered when the reproducer is preserved;
    # the failed sweep is recorded to a separate attempts file.
    assert not (b / "reproducer-sampling.json").is_file()
    attempts = list((b / ".reproducer-sampling-attempts").glob("attempt-*.json"))
    assert len(attempts) == 1
    rec = json.loads(attempts[0].read_text())
    assert all(d["kind"] == "probe-error" for d in rec["draws"])


def test_run_mixed_unevaluated_is_infra_not_quarantine(tmp_path: Path) -> None:
    # One malformed draw + one probe-error: the verifier evaluated no candidate,
    # so this is infra (exit 4) and the existing reproducer is preserved, even
    # though not every draw is a probe-error.
    b = _seed_bundle(tmp_path)
    (b / "reproducer.nix").write_text("existing\n")
    adapter = QueueAdapter("claude-sonnet-4-5-20250929", ["garbage no markers\n", _repro_output()])

    def boom(*a: Any) -> ProbeVerdict:
        raise RuntimeError("store corruption")

    code = rs.run(_args(b, overwrite=True), _adapter_factory=lambda m: adapter, _probe_fn=boom)
    assert code == rs.EXIT_PROBE_INFRA
    assert (b / "reproducer.nix").read_text() == "existing\n"
    assert not (b / ".reproducer-sampling-quarantine").exists()


def test_run_evaluated_plus_probe_error_is_infra_not_quarantine(tmp_path: Path) -> None:
    # One draw evaluated (non-discriminating), one draw probe-errored: the sweep
    # is incomplete (the errored draw might have discriminated), so it must NOT
    # quarantine the existing reproducer — treat as infra and preserve.
    b = _seed_bundle(tmp_path)
    (b / "reproducer.nix").write_text("existing\n")
    adapter = QueueAdapter("claude-sonnet-4-5-20250929", [_repro_output(), _repro_output()])
    probe = QueueProbe([_NODISC, RuntimeError("store hiccup")])
    code = rs.run(_args(b, overwrite=True), _adapter_factory=lambda m: adapter, _probe_fn=probe)
    assert code == rs.EXIT_PROBE_INFRA
    assert (b / "reproducer.nix").read_text() == "existing\n"  # preserved
    assert not (b / ".reproducer-sampling-quarantine").exists()


def test_run_all_malformed_is_no_winner_but_preserves(tmp_path: Path) -> None:
    # No probe-error, but the model never produced an evaluable reproducer:
    # route human-review WITHOUT quarantining the existing reproducer, and record
    # the failed sweep to attempts/ (not the canonical sidecar it must protect).
    b = _seed_bundle(tmp_path)
    (b / "reproducer.nix").write_text("existing\n")
    adapter = QueueAdapter("claude-sonnet-4-5-20250929", ["junk\n", "more junk\n"])
    # Probe should never be called (both draws malformed).
    code = rs.run(_args(b, overwrite=True), _adapter_factory=lambda m: adapter,
                  _probe_fn=lambda *a: _DISC)
    assert code == rs.EXIT_NO_WINNER
    assert (b / "reproducer.nix").read_text() == "existing\n"
    assert not (b / ".reproducer-sampling-quarantine").exists()
    assert not (b / "reproducer-sampling.json").is_file()
    assert list((b / ".reproducer-sampling-attempts").glob("attempt-*.json"))


def test_run_fresh_all_malformed_writes_canonical_sidecar(tmp_path: Path) -> None:
    # A FRESH bundle (no existing reproducer) with an all-malformed sweep has no
    # prior provenance to protect, so the null-winner record IS canonical.
    b = _seed_bundle(tmp_path)
    adapter = QueueAdapter("claude-sonnet-4-5-20250929", ["junk\n", "more junk\n"])
    code = rs.run(_args(b), _adapter_factory=lambda m: adapter, _probe_fn=lambda *a: _DISC)
    assert code == rs.EXIT_NO_WINNER
    sidecar = json.loads((b / "reproducer-sampling.json").read_text())
    assert sidecar["winner"] is None
    assert not (b / ".reproducer-sampling-attempts").exists()


def test_run_infra_preserves_prior_canonical_sidecar(tmp_path: Path) -> None:
    # A prior winning sweep's sidecar must survive an infra-failed resample.
    b = _seed_bundle(tmp_path)
    (b / "reproducer.nix").write_text("existing\n")
    (b / "reproducer-sampling.json").write_text('{"winner": {"draw_index": 7}}\n')
    adapter = QueueAdapter("claude-sonnet-4-5-20250929", [_repro_output(), _repro_output()])

    def boom(*a: Any) -> ProbeVerdict:
        raise RuntimeError("store down")

    code = rs.run(_args(b, overwrite=True), _adapter_factory=lambda m: adapter, _probe_fn=boom)
    assert code == rs.EXIT_PROBE_INFRA
    # The canonical sidecar still describes the reproducer on disk, untouched.
    assert json.loads((b / "reproducer-sampling.json").read_text())["winner"]["draw_index"] == 7


def test_validate_finalized_bundle_requires_replay(tmp_path: Path) -> None:
    b = _seed_bundle(tmp_path)  # has bundle.json but no replay.json
    assert "not finalized" in rs._validate_finalized_bundle(b)


def test_validate_finalized_bundle_requires_patcher_in_replay(tmp_path: Path) -> None:
    b = _seed_bundle(tmp_path)
    (b / "replay.json").write_text(json.dumps({"roles": []}))  # no patcher
    assert "cross-family" in rs._validate_finalized_bundle(b)


def test_validate_finalized_bundle_accepts_complete(tmp_path: Path) -> None:
    b = _seed_bundle(tmp_path)
    _finalize_replay(b)
    assert rs._validate_finalized_bundle(b) is None


def test_validate_finalized_bundle_rejects_edited_input(tmp_path: Path) -> None:
    # An input edited after finalize (its on-disk hash no longer matches the
    # manifest) must be refused before any model spend.
    import hashlib

    b = _seed_bundle(tmp_path)
    _finalize_replay(b)
    # Manifest claims a hash for finding.json that the on-disk file won't match.
    wrong = "a" * 64
    real = hashlib.sha256((b / "finding.json").read_bytes()).hexdigest()
    assert wrong != real
    (b / "bundle.json").write_text(json.dumps({
        "bundle_id": "x",
        "files": {"finding.json": {
            "sha256": wrong, "bytes": 1,
            "producer_role": "scout", "replay_critical": True}},
    }))
    assert "edited after finalize" in rs._validate_finalized_bundle(b)


def test_validate_finalized_bundle_accepts_matching_input_hash(tmp_path: Path) -> None:
    import hashlib

    b = _seed_bundle(tmp_path)
    _finalize_replay(b)
    real = hashlib.sha256((b / "finding.json").read_bytes()).hexdigest()
    (b / "bundle.json").write_text(json.dumps({
        "bundle_id": "x",
        "files": {"finding.json": {
            "sha256": real, "bytes": 1,
            "producer_role": "scout", "replay_critical": True}},
    }))
    assert rs._validate_finalized_bundle(b) is None


def test_run_rejects_temperature_ignoring_model(tmp_path: Path) -> None:
    # pass@K on a model whose adapter drops temperature would draw K identical
    # candidates; reject before any spend.
    b = _seed_bundle(tmp_path)
    code = rs.run(_args(b, model="claude-opus-4-8"),
                  _adapter_factory=lambda m: None, _probe_fn=lambda *a: _DISC)
    assert code == rs.EXIT_USAGE


def test_run_real_probe_rejects_non_git_checkout(tmp_path: Path) -> None:
    # A --nixpkgs-checkout that is not a git tree must fail before model spend.
    b = _seed_bundle(tmp_path)
    _finalize_replay(b)
    plain = tmp_path / "not-a-checkout"
    plain.mkdir()
    code = rs.run(_args(b, nixpkgs_checkout=plain), _adapter_factory=lambda m: None)
    assert code == rs.EXIT_USAGE


# ─── _validate_checkout preconditions ─────────────────────────────────────


def _git_checkout(tmp_path: Path, *, rev_file_content: str = "pristine\n") -> Path:
    import subprocess

    co = tmp_path / "nixpkgs"
    co.mkdir()
    (co / "pkg.nix").write_text(rev_file_content)
    for a in (
        ["git", "-C", str(co), "init", "-q"],
        ["git", "-C", str(co), "add", "."],
        ["git", "-C", str(co), "-c", "user.email=t@t", "-c", "user.name=t",
         "commit", "-qm", "init"],
    ):
        subprocess.run(a, check=True, capture_output=True)
    return co


def _head_sha(co: Path) -> str:
    import subprocess

    return subprocess.run(["git", "-C", str(co), "rev-parse", "HEAD"],
                          capture_output=True, text=True).stdout.strip()


def test_validate_checkout_accepts_clean_matching(tmp_path: Path) -> None:
    b = _seed_bundle(tmp_path)
    co = _git_checkout(tmp_path)
    (b / "bundle.json").write_text(json.dumps({
        "bundle_id": "x", "nixpkgs_rev": _head_sha(co)}))
    assert rs._validate_checkout(co, b) is None


def test_validate_checkout_rejects_non_git(tmp_path: Path) -> None:
    b = _seed_bundle(tmp_path)
    plain = tmp_path / "plain"
    plain.mkdir()
    assert "not a git checkout" in rs._validate_checkout(plain, b)


def test_validate_checkout_rejects_dirty_tree(tmp_path: Path) -> None:
    b = _seed_bundle(tmp_path)
    co = _git_checkout(tmp_path)
    (b / "bundle.json").write_text(json.dumps({"nixpkgs_rev": _head_sha(co)}))
    (co / "pkg.nix").write_text("uncommitted edit\n")  # dirty
    assert "uncommitted changes" in rs._validate_checkout(co, b)


def test_validate_checkout_rejects_wrong_rev(tmp_path: Path) -> None:
    b = _seed_bundle(tmp_path)
    co = _git_checkout(tmp_path)
    (b / "bundle.json").write_text(json.dumps({"nixpkgs_rev": "f" * 40}))
    assert "wrong tree" in rs._validate_checkout(co, b)


def test_validate_checkout_skips_rev_when_bundle_has_none(tmp_path: Path) -> None:
    b = _seed_bundle(tmp_path)
    co = _git_checkout(tmp_path)
    (b / "bundle.json").write_text(json.dumps({"bundle_id": "x"}))  # no rev
    (b / "finding.json").write_text(json.dumps({"cve_id": "C", "affected": []}))
    assert rs._validate_checkout(co, b) is None


def test_run_enforces_cross_family_rule(tmp_path: Path) -> None:
    b = _seed_bundle(tmp_path)
    # Record a Sonnet Patcher in replay.json; a Sonnet Reproducer must be refused.
    (b / "replay.json").write_text(json.dumps({
        "roles": [{"role": "patcher", "invocations": [
            {"model": {"model_id": "claude-sonnet-4-5-20250929", "family": "anthropic-sonnet"}}
        ]}]
    }))
    code = rs.run(_args(b, model="claude-sonnet-4-5-20250929"),
                  _adapter_factory=lambda m: None, _probe_fn=lambda *a: _DISC)
    assert code == rs.EXIT_USAGE
