"""Tests for `agents.scorers.reproducer_scorers`.

The five v0 reproducer scorers, locked in `docs/REPRODUCER_V1.md` §9:

  1. repro-schema-valid           (pre-Builder, non-advisory)
  2. repro-unpatched-fails        (post-Builder, non-advisory; n/a for proxy)
  3. repro-patched-passes         (post-Builder, non-advisory; applies for proxy)
  4. repro-passthru-recorded      (post-Builder, non-advisory)
  5. repro-signal-specificity     (post-Builder, advisory)

Pre-Builder note: scorers 2, 3, 4, 5 require build.json. Without it
they record applies=False with a structured notes message — the honest
v0 report. The schema-valid scorer fires pre-Builder against the parsed
on-disk artifacts.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from agents.scorers.reproducer_scorers import (
    ReproPassthruRecordedScorer,
    ReproPatchedPassesScorer,
    ReproSchemaValidScorer,
    ReproSignalSpecificityScorer,
    ReproUnpatchedFailsScorer,
    reproducer_scorer_names,
)


# ─── canonical fixture content ────────────────────────────────────────────


_NIX = """\
{ pkgs ? import <nixpkgs> { } }:

let
  unpatched = pkgs.demo;
  patched = pkgs.demo;
in
{
  inherit unpatched patched;

  test = pkgs.runCommand "repro-CVE-0000-0001" { } ''
    echo "vuln-triggered: out-of-bounds-read in deserialise() on malformed length-prefix"
    echo "rejected-malformed-length-prefix-as-expected-from-CVE-0000-0001"
  '';
}
"""

_LOG = """\
The CVE concerns deserialise() reading past the buffer end on a malformed length-prefix.

=== unpatched ===
Unpatched binary triggers the out-of-bounds-read.
SIGNAL_UNPATCHED: vuln-triggered: out-of-bounds-read in deserialise() on malformed length-prefix
EXIT: 1

=== patched ===
Patched binary rejects the malformed input.
SIGNAL_PATCHED: rejected-malformed-length-prefix-as-expected-from-CVE-0000-0001
EXIT: 0
"""

_PASSTHRU_TWO = """\
[
  { "name": "passthru.tests.basic", "drv_path": null, "kind": "passthru.tests" },
  { "name": "nixosTests.demo-smoke", "drv_path": null, "kind": "nixosTests" }
]
"""


def _bundle(
    tmp_path: Path,
    *,
    nix: str = _NIX,
    log: str = _LOG,
    passthru: str = _PASSTHRU_TWO,
    finding_summary: str = "out-of-bounds read in demo's deserialise() on malformed length-prefix",
    fix_commit_message: str = "deserialise: bound length-prefix before reading",
) -> Path:
    """Assemble a bundle dir with the seven files the scorers read."""
    b = tmp_path / "bundle"
    b.mkdir()
    (b / "reproducer.nix").write_text(nix)
    (b / "reproducer-log.txt").write_text(log)
    (b / "passthru-tests.json").write_text(passthru)
    (b / "finding.json").write_text(json.dumps({
        "cve_id": "CVE-0000-0001",
        "summary": finding_summary,
    }))
    (b / "upstream-ref.json").write_text(json.dumps({
        "cve_id": "CVE-0000-0001",
        "current_version": "1.0.0",
        "target_version": "1.0.1",
        "upstream_fix_commits": [{
            "repo_url": "https://github.com/example/demo",
            "commit_sha": "deadbeef",
            "message": fix_commit_message,
        }],
    }))
    return b


def _invocation_for(kind: str) -> dict[str, Any]:
    if kind == "reproducer":
        return {
            "outputs": [
                {"path": "reproducer.nix", "sha256": "0" * 64},
                {"path": "reproducer-log.txt", "sha256": "0" * 64},
                {"path": "passthru-tests.json", "sha256": "0" * 64},
            ],
        }
    if kind == "refusal":
        return {"outputs": [{"path": "reproducer-refusal.json", "sha256": "0" * 64}]}
    return {"outputs": []}


def _write_build_json(
    bundle_dir: Path,
    *,
    unpatched_signal_present: bool = True,
    patched_signal_present: bool = True,
    passthru_ground_truth: list | None = None,
) -> None:
    """Write a Builder-shaped build.json with controllable signals.

    The scorer consumes:
        build.unpatched.stdout_stderr (str), build.unpatched.exit_code
        build.patched.stdout_stderr   (str), build.patched.exit_code
        build.passthru_tests_ground_truth (list)
    """
    if passthru_ground_truth is None:
        passthru_ground_truth = [
            {"name": "passthru.tests.basic", "kind": "passthru.tests"},
            {"name": "nixosTests.demo-smoke", "kind": "nixosTests"},
        ]
    sig_u = "vuln-triggered: out-of-bounds-read in deserialise() on malformed length-prefix"
    sig_p = "rejected-malformed-length-prefix-as-expected-from-CVE-0000-0001"
    build = {
        "unpatched": {
            "exit_code": 1,
            "stdout_stderr": (
                f"+ run unpatched\n{sig_u}\n" if unpatched_signal_present
                else "+ run unpatched\n(no specific signal observed)\n"
            ),
        },
        "patched": {
            "exit_code": 0,
            "stdout_stderr": (
                f"+ run patched\n{sig_p}\n" if patched_signal_present
                else "+ run patched\n(no specific signal observed)\n"
            ),
        },
        "passthru_tests_ground_truth": passthru_ground_truth,
    }
    (bundle_dir / "build.json").write_text(json.dumps(build))


# ─── canonical name set + ordering ───────────────────────────────────────


def test_reproducer_scorer_names_locked() -> None:
    names = reproducer_scorer_names()
    assert names == (
        "repro-schema-valid",
        "repro-unpatched-fails",
        "repro-patched-passes",
        "repro-passthru-recorded",
        "repro-signal-specificity",
    )


# ─── 1. repro-schema-valid ────────────────────────────────────────────────


def test_schema_valid_score_one_for_well_formed(tmp_path: Path) -> None:
    b = _bundle(tmp_path)
    res = ReproSchemaValidScorer().score(
        bundle_dir=b, invocation=_invocation_for("reproducer"),
    )
    assert res.applies is True
    assert res.score == 1.0
    assert res.advisory is False
    assert res.details and res.details.get("is_proxy") is False


def test_schema_valid_score_zero_when_passthru_malformed(tmp_path: Path) -> None:
    bad = '[{"name": "x", "kind": "checkPhase"}]\n'  # invalid kind
    b = _bundle(tmp_path, passthru=bad)
    res = ReproSchemaValidScorer().score(
        bundle_dir=b, invocation=_invocation_for("reproducer"),
    )
    assert res.applies is True
    assert res.score == 0.0


def test_schema_valid_handles_refusal_path(tmp_path: Path) -> None:
    b = tmp_path / "bundle"
    b.mkdir()
    (b / "reproducer-refusal.json").write_text(json.dumps({
        "rule": 3,
        "reason": "vuln class is not locally-reproducible (CAP_SYS_ADMIN required)",
    }))
    res = ReproSchemaValidScorer().score(
        bundle_dir=b, invocation=_invocation_for("refusal"),
    )
    assert res.applies is True
    assert res.score == 1.0
    assert res.details and res.details.get("refusal_rule") == 3


@pytest.mark.parametrize("rule", [0, 9, 99])
def test_schema_valid_rejects_refusal_rule_out_of_range(tmp_path: Path, rule: int) -> None:
    b = tmp_path / "bundle"
    b.mkdir()
    (b / "reproducer-refusal.json").write_text(json.dumps({
        "rule": rule, "reason": "out of range probe",
    }))
    res = ReproSchemaValidScorer().score(
        bundle_dir=b, invocation=_invocation_for("refusal"),
    )
    assert res.applies is True
    assert res.score == 0.0


def test_schema_valid_returns_na_for_unknown_outputs(tmp_path: Path) -> None:
    b = tmp_path / "bundle"
    b.mkdir()
    res = ReproSchemaValidScorer().score(
        bundle_dir=b, invocation=_invocation_for("unknown"),
    )
    assert res.applies is False
    assert res.score is None


def test_schema_valid_proxy_path(tmp_path: Path) -> None:
    proxy_nix = """\
{ pkgs ? import <nixpkgs> { } }:
let
  unpatched = pkgs.demo;
  patched = pkgs.demo;
in {
  inherit unpatched patched;
  test = pkgs.runCommand "p" { } ''true'' // {
    meta = {
      proxy = true;
      proxy_reason = "sandbox-cannot-trigger";
      why_not_full_repro = "Full chain requires CAP_SYS_ADMIN; only patched-rejection is locally verifiable.";
      expected_limitations = "Verifies parser rejection only, not the privilege-escalation path.";
    };
  };
}
"""
    proxy_log = """\
=== unpatched ===
Out of scope.
SIGNAL_UNPATCHED: proxy-test: full-chain unpatched evidence intentionally omitted (CAP_SYS_ADMIN)
EXIT: 0

=== patched ===
Patched.
SIGNAL_PATCHED: rejected-malformed-length-prefix-as-expected-from-CVE-0000-0001
EXIT: 0

=== proxy ===
proxy_reason: sandbox-cannot-trigger
why_not_full_repro: Full chain requires CAP_SYS_ADMIN; only patched-rejection is locally verifiable.
expected_limitations: Verifies parser rejection only, not the privilege-escalation path.
"""
    b = _bundle(tmp_path, nix=proxy_nix, log=proxy_log, passthru="[]\n")
    res = ReproSchemaValidScorer().score(
        bundle_dir=b, invocation=_invocation_for("reproducer"),
    )
    assert res.score == 1.0
    assert res.details and res.details.get("is_proxy") is True
    assert res.details.get("proxy_reason") == "sandbox-cannot-trigger"


# ─── 2. repro-unpatched-fails ─────────────────────────────────────────────


def test_unpatched_fails_score_one_when_signal_present(tmp_path: Path) -> None:
    b = _bundle(tmp_path)
    _write_build_json(b, unpatched_signal_present=True)
    res = ReproUnpatchedFailsScorer().score(
        bundle_dir=b, invocation=_invocation_for("reproducer"),
    )
    assert res.applies is True
    assert res.score == 1.0
    assert res.details and res.details.get("signal_present") is True


def test_unpatched_fails_score_zero_when_signal_absent(tmp_path: Path) -> None:
    b = _bundle(tmp_path)
    _write_build_json(b, unpatched_signal_present=False)
    res = ReproUnpatchedFailsScorer().score(
        bundle_dir=b, invocation=_invocation_for("reproducer"),
    )
    assert res.applies is True
    assert res.score == 0.0


def test_unpatched_fails_na_pre_builder(tmp_path: Path) -> None:
    b = _bundle(tmp_path)
    # No build.json written
    res = ReproUnpatchedFailsScorer().score(
        bundle_dir=b, invocation=_invocation_for("reproducer"),
    )
    assert res.applies is False
    assert res.score is None
    assert "Builder has not run yet" in res.notes


def test_unpatched_fails_na_for_proxy(tmp_path: Path) -> None:
    proxy_nix = """\
{ pkgs ? import <nixpkgs> { } }:
let
  unpatched = pkgs.demo;
  patched = pkgs.demo;
in {
  inherit unpatched patched;
  test = pkgs.runCommand "p" { } ''true'' // {
    meta = {
      proxy = true;
      proxy_reason = "sandbox-cannot-trigger";
      why_not_full_repro = "Full chain requires CAP_SYS_ADMIN; only patched-rejection is locally verifiable.";
      expected_limitations = "Verifies parser rejection only.";
    };
  };
}
"""
    proxy_log = """\
=== unpatched ===
Out of scope.
SIGNAL_UNPATCHED: proxy-test: full-chain unpatched evidence intentionally omitted (cap)
EXIT: 0

=== patched ===
Patched.
SIGNAL_PATCHED: rejected-malformed-length-prefix-as-expected-from-CVE-0000-0001
EXIT: 0

=== proxy ===
proxy_reason: sandbox-cannot-trigger
why_not_full_repro: Full chain requires CAP_SYS_ADMIN; only patched-rejection is locally verifiable.
expected_limitations: Verifies parser rejection only.
"""
    b = _bundle(tmp_path, nix=proxy_nix, log=proxy_log, passthru="[]\n")
    _write_build_json(b)
    res = ReproUnpatchedFailsScorer().score(
        bundle_dir=b, invocation=_invocation_for("reproducer"),
    )
    assert res.applies is False
    assert res.score is None
    assert "proxy" in res.notes


def test_unpatched_fails_na_for_refusal(tmp_path: Path) -> None:
    b = tmp_path / "b"
    b.mkdir()
    (b / "reproducer-refusal.json").write_text(json.dumps({"rule": 3, "reason": "x"}))
    res = ReproUnpatchedFailsScorer().score(
        bundle_dir=b, invocation=_invocation_for("refusal"),
    )
    assert res.applies is False
    assert res.score is None


# ─── 3. repro-patched-passes ──────────────────────────────────────────────


def test_patched_passes_score_one_when_signal_present(tmp_path: Path) -> None:
    b = _bundle(tmp_path)
    _write_build_json(b, patched_signal_present=True)
    res = ReproPatchedPassesScorer().score(
        bundle_dir=b, invocation=_invocation_for("reproducer"),
    )
    assert res.applies is True
    assert res.score == 1.0


def test_patched_passes_score_zero_when_signal_absent(tmp_path: Path) -> None:
    b = _bundle(tmp_path)
    _write_build_json(b, patched_signal_present=False)
    res = ReproPatchedPassesScorer().score(
        bundle_dir=b, invocation=_invocation_for("reproducer"),
    )
    assert res.applies is True
    assert res.score == 0.0


def test_patched_passes_applies_for_proxy(tmp_path: Path) -> None:
    """Per the contract, repro-patched-passes APPLIES even for proxy
    bundles — proxies must still demonstrate their narrower patched-
    state evidence."""
    proxy_nix = """\
{ pkgs ? import <nixpkgs> { } }:
let
  unpatched = pkgs.demo;
  patched = pkgs.demo;
in {
  inherit unpatched patched;
  test = pkgs.runCommand "p" { } ''true'' // {
    meta = {
      proxy = true;
      proxy_reason = "sandbox-cannot-trigger";
      why_not_full_repro = "Full chain requires CAP_SYS_ADMIN; only patched-rejection is locally verifiable.";
      expected_limitations = "Verifies parser rejection only.";
    };
  };
}
"""
    proxy_log = """\
=== unpatched ===
Out of scope.
SIGNAL_UNPATCHED: proxy-test: full-chain unpatched evidence intentionally omitted (cap)
EXIT: 0

=== patched ===
Patched.
SIGNAL_PATCHED: rejected-malformed-length-prefix-as-expected-from-CVE-0000-0001
EXIT: 0

=== proxy ===
proxy_reason: sandbox-cannot-trigger
why_not_full_repro: Full chain requires CAP_SYS_ADMIN; only patched-rejection is locally verifiable.
expected_limitations: Verifies parser rejection only.
"""
    b = _bundle(tmp_path, nix=proxy_nix, log=proxy_log, passthru="[]\n")
    _write_build_json(b)
    res = ReproPatchedPassesScorer().score(
        bundle_dir=b, invocation=_invocation_for("reproducer"),
    )
    assert res.applies is True
    assert res.score == 1.0
    assert res.details and res.details.get("is_proxy") is True


def test_patched_passes_na_pre_builder(tmp_path: Path) -> None:
    b = _bundle(tmp_path)
    res = ReproPatchedPassesScorer().score(
        bundle_dir=b, invocation=_invocation_for("reproducer"),
    )
    assert res.applies is False
    assert res.score is None


# ─── 4. repro-passthru-recorded ───────────────────────────────────────────


def test_passthru_recorded_full_match(tmp_path: Path) -> None:
    b = _bundle(tmp_path)
    _write_build_json(b)  # default ground-truth matches the model's two entries
    res = ReproPassthruRecordedScorer().score(
        bundle_dir=b, invocation=_invocation_for("reproducer"),
    )
    assert res.applies is True
    assert res.score == 1.0


def test_passthru_recorded_partial_recall(tmp_path: Path) -> None:
    b = _bundle(tmp_path, passthru=json.dumps([
        {"name": "passthru.tests.basic", "drv_path": None, "kind": "passthru.tests"},
    ]) + "\n")
    _write_build_json(b)  # 2 ground-truth, model lists 1
    res = ReproPassthruRecordedScorer().score(
        bundle_dir=b, invocation=_invocation_for("reproducer"),
    )
    assert res.applies is True
    assert res.score == 0.5


def test_passthru_recorded_empty_both_sides(tmp_path: Path) -> None:
    b = _bundle(tmp_path, passthru="[]\n")
    _write_build_json(b, passthru_ground_truth=[])
    res = ReproPassthruRecordedScorer().score(
        bundle_dir=b, invocation=_invocation_for("reproducer"),
    )
    assert res.applies is True
    assert res.score == 1.0


def test_passthru_recorded_invented_entries_score_zero(tmp_path: Path) -> None:
    b = _bundle(tmp_path)  # model lists 2 entries
    _write_build_json(b, passthru_ground_truth=[])  # ground truth is empty
    res = ReproPassthruRecordedScorer().score(
        bundle_dir=b, invocation=_invocation_for("reproducer"),
    )
    assert res.applies is True
    assert res.score == 0.0
    assert "invented" in res.notes


def test_passthru_recorded_na_pre_builder(tmp_path: Path) -> None:
    b = _bundle(tmp_path)
    res = ReproPassthruRecordedScorer().score(
        bundle_dir=b, invocation=_invocation_for("reproducer"),
    )
    assert res.applies is False
    assert res.score is None


# ─── 5. repro-signal-specificity (advisory) ──────────────────────────────


def test_signal_specificity_full_score(tmp_path: Path) -> None:
    b = _bundle(tmp_path)
    _write_build_json(b)
    res = ReproSignalSpecificityScorer().score(
        bundle_dir=b, invocation=_invocation_for("reproducer"),
    )
    assert res.applies is True
    assert res.advisory is True
    # All three axes hit: length≥32, no extended-generic, contains "deserialise" keyword
    assert res.score == 1.0


def test_signal_specificity_misses_keyword_axis(tmp_path: Path) -> None:
    """No CVE keyword in the signal text scores 2/3 ≈ 0.667."""
    log = (
        "=== unpatched ===\n"
        "SIGNAL_UNPATCHED: anomaly-detected-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n"
        "EXIT: 1\n"
        "\n"
        "=== patched ===\n"
        "SIGNAL_PATCHED: anomaly-rejected-bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\n"
        "EXIT: 0\n"
    )
    b = _bundle(tmp_path, log=log)
    _write_build_json(b)
    res = ReproSignalSpecificityScorer().score(
        bundle_dir=b, invocation=_invocation_for("reproducer"),
    )
    assert res.applies is True
    # length ok, not generic, but no CVE keyword
    assert res.score == pytest.approx(2 / 3, rel=1e-2)


def test_signal_specificity_na_pre_builder(tmp_path: Path) -> None:
    b = _bundle(tmp_path)
    res = ReproSignalSpecificityScorer().score(
        bundle_dir=b, invocation=_invocation_for("reproducer"),
    )
    assert res.applies is False
    assert res.score is None
