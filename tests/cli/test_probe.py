"""`trace bundle probe`: run the committed reproducer through the real two-arm
Builder locally and bind the verdict to the fixture bytes it judged.

See docs/specs/reproducer-probe-gate.md. The Builder is driven through
FakeBuildRunner; run_builder invokes it three times in order: unpatched.test,
patched-build, patched.test.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from agents.builder.protocol import BuildOutcome, FakeBuildRunner
from tools.trace_cli.probe import (
    EXIT_NO_DISCRIMINATION,
    EXIT_PROBE_ERROR,
    EXIT_REFUSED,
    ProbeRefused,
    check_probe,
    probe_bundle,
)

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
_PASSTHRU = (
    '[{"name": "passthru.tests.basic", "drv_path": null, "kind": "passthru.tests"}]\n'
)
SIG_U = "vuln-triggered: deserialise() out-of-bounds for malformed length-prefix"
SIG_P = "rejected-malformed-length-prefix-as-expected-from-CVE-2026-99999"


def _bundle(tmp_path: Path) -> Path:
    b = tmp_path / "bundle"
    b.mkdir()
    (b / "finding.json").write_text(
        json.dumps(
            {
                "cve_id": "CVE-2026-99999",
                "summary": "out-of-bounds read in demo's deserialise() on malformed length-prefix",
                "affected": [{"attr_path": "demo"}],
            }
        )
    )
    (b / "upstream-ref.json").write_text(
        json.dumps(
            {
                "cve_id": "CVE-2026-99999",
                "current_version": "1.0.0",
                "target_version": "1.0.1",
                "upstream_fix_commits": [
                    {
                        "repo_url": "https://github.com/example/demo",
                        "commit_sha": "deadbeef",
                        "message": "bound the prefix",
                    }
                ],
            }
        )
    )
    (b / "impact.json").write_text(json.dumps({"rebuild_count": 1}))
    (b / "maintainers.json").write_text(json.dumps({"maintainers": []}))
    (b / "package.nix").write_text("{ }\n")
    (b / "patch.diff").write_text(
        "--- a/pkgs/demo/default.nix\n+++ b/pkgs/demo/default.nix\n"
    )
    (b / "patch-rationale.md").write_text("bounds the length prefix\n")
    (b / "bundle.json").write_text(
        json.dumps(
            {
                "bundle_id": "CVE-2026-99999--demo",
                "nixpkgs_rev": "0" * 40,
                "kind": "human-review-required",
            }
        )
    )
    (b / "reproducer.nix").write_text(_NIX)
    (b / "reproducer-log.txt").write_text(_LOG)
    (b / "passthru-tests.json").write_text(_PASSTHRU)
    return b


def _out(stdout: str, code: int) -> BuildOutcome:
    return BuildOutcome(
        exit_code=code,
        drv_path="/nix/store/x.drv",
        out_path="/nix/store/x",
        stdout_stderr=stdout,
        elapsed_seconds=0.1,
    )


def _discriminating_runner() -> FakeBuildRunner:
    return FakeBuildRunner(
        responses=[
            _out(f"+ unpatched\n{SIG_U}\n", 1),
            _out("+ patched-build OK\n", 0),
            _out(f"+ patched\n{SIG_P}\n", 0),
        ]
    )


def _sha(p: Path) -> str:
    return hashlib.sha256(p.read_bytes()).hexdigest()


def test_discriminating_fixture_records_a_green_probe(tmp_path):
    b = _bundle(tmp_path)
    code, verdict = probe_bundle(
        b, build_runner=_discriminating_runner(), nixpkgs_checkout=None
    )
    assert code == 0
    assert verdict["discriminates"] is True
    saved = json.loads((b / "probe.json").read_text())
    assert saved["discriminates"] is True
    assert saved["reproducer_sha256"] == _sha(b / "reproducer.nix")
    assert saved["reproducer_log_sha256"] == _sha(b / "reproducer-log.txt")
    assert saved["nixpkgs_rev"] == "0" * 40
    assert (b / "probe-build.json").exists()


def test_probe_never_writes_the_bundles_build_json(tmp_path):
    """The cert's build.json is the one that gets installed; the probe's arms run
    on the operator's host and must not masquerade as it."""
    b = _bundle(tmp_path)
    probe_bundle(b, build_runner=_discriminating_runner(), nixpkgs_checkout=None)
    assert not (b / "build.json").exists()


def test_unpatched_arm_that_never_fires_is_not_discrimination(tmp_path):
    b = _bundle(tmp_path)
    runner = FakeBuildRunner(
        responses=[
            _out("+ unpatched\n(nothing happened)\n", 0),
            _out("+ patched-build OK\n", 0),
            _out(f"+ patched\n{SIG_P}\n", 0),
        ]
    )
    code, verdict = probe_bundle(b, build_runner=runner, nixpkgs_checkout=None)
    assert code == EXIT_NO_DISCRIMINATION
    assert verdict["discriminates"] is False
    assert verdict["signal_unpatched_present"] is False
    assert json.loads((b / "probe.json").read_text())["discriminates"] is False


def test_infrastructure_failure_is_a_probe_error_not_a_verdict(tmp_path):
    """A build that never exercised the fixture says nothing about it."""
    b = _bundle(tmp_path)
    infra = "error: unable to download 'https://cache.nixos.org/x.narinfo': HTTP error 503\n"
    runner = FakeBuildRunner(response=_out(infra, 1))
    code, verdict = probe_bundle(b, build_runner=runner, nixpkgs_checkout=None)
    assert code == EXIT_PROBE_ERROR
    assert not (b / "probe.json").exists()
    assert "infrastructure" in verdict["error"]


def test_check_passes_only_while_the_fixture_is_unchanged(tmp_path):
    b = _bundle(tmp_path)
    probe_bundle(b, build_runner=_discriminating_runner(), nixpkgs_checkout=None)
    ok, why = check_probe(b)
    assert ok, why

    (b / "reproducer.nix").write_text(_NIX + "# edited\n")
    ok, why = check_probe(b)
    assert not ok and "reproducer.nix" in why


def test_check_fails_when_the_log_changed(tmp_path):
    b = _bundle(tmp_path)
    probe_bundle(b, build_runner=_discriminating_runner(), nixpkgs_checkout=None)
    (b / "reproducer-log.txt").write_text(_LOG.replace("EXIT: 1", "EXIT: 2"))
    ok, why = check_probe(b)
    assert not ok and "reproducer-log.txt" in why


def test_check_fails_without_a_probe(tmp_path):
    b = _bundle(tmp_path)
    ok, why = check_probe(b)
    assert not ok and "probe.json" in why


def test_check_fails_on_a_red_probe(tmp_path):
    b = _bundle(tmp_path)
    runner = FakeBuildRunner(
        responses=[
            _out("+ unpatched\n(nothing)\n", 0),
            _out("ok\n", 0),
            _out(f"{SIG_P}\n", 0),
        ]
    )
    probe_bundle(b, build_runner=runner, nixpkgs_checkout=None)
    ok, why = check_probe(b)
    assert not ok and "unpatched signal" in why


@pytest.mark.parametrize(
    "missing", ["reproducer.nix", "reproducer-log.txt", "passthru-tests.json"]
)
def test_refuses_without_a_complete_reproducer(tmp_path, missing):
    b = _bundle(tmp_path)
    (b / missing).unlink()
    with pytest.raises(ProbeRefused, match=missing):
        probe_bundle(b, build_runner=_discriminating_runner(), nixpkgs_checkout=None)


def test_refuses_a_patcher_refusal(tmp_path):
    b = _bundle(tmp_path)
    (b / "refusal.json").write_text("{}")
    with pytest.raises(ProbeRefused, match="refusal"):
        probe_bundle(b, build_runner=_discriminating_runner(), nixpkgs_checkout=None)


def test_refuses_a_dirty_or_wrong_rev_checkout(tmp_path):
    import subprocess

    b = _bundle(tmp_path)
    checkout = tmp_path / "nixpkgs"
    checkout.mkdir()
    (checkout / "pkg.nix").write_text("x\n")
    for args in (
        ["init", "-q"],
        ["add", "."],
        ["-c", "user.email=t@t", "-c", "user.name=t", "commit", "-qm", "init"],
    ):
        subprocess.run(
            ["git", "-C", str(checkout), *args], check=True, capture_output=True
        )
    # HEAD is not the bundle's pinned rev of all zeros
    with pytest.raises(ProbeRefused, match="nixpkgs_rev"):
        probe_bundle(
            b, build_runner=_discriminating_runner(), nixpkgs_checkout=checkout
        )

    head = subprocess.run(
        ["git", "-C", str(checkout), "rev-parse", "HEAD"],
        capture_output=True,
        text=True,
        check=True,
    ).stdout.strip()
    bj = json.loads((b / "bundle.json").read_text())
    bj["nixpkgs_rev"] = head
    (b / "bundle.json").write_text(json.dumps(bj))
    (checkout / "pkg.nix").write_text("dirty\n")
    with pytest.raises(ProbeRefused, match="uncommitted"):
        probe_bundle(
            b, build_runner=_discriminating_runner(), nixpkgs_checkout=checkout
        )


def test_exit_codes_are_distinct():
    assert len({0, EXIT_NO_DISCRIMINATION, EXIT_PROBE_ERROR, EXIT_REFUSED}) == 4


def test_check_requires_the_build_record_and_rederives_the_verdict(tmp_path):
    """probe.json is a claim about probe-build.json. --check must verify the
    record exists, matches the recorded hash, and itself shows discrimination,
    so a hand-written probe.json with discriminates=true is refused."""
    b = _bundle(tmp_path)
    probe_bundle(b, build_runner=_discriminating_runner(), nixpkgs_checkout=None)
    ok, _ = check_probe(b)
    assert ok

    (b / "probe-build.json").unlink()
    ok, why = check_probe(b)
    assert not ok and "probe-build.json" in why


def test_check_rejects_a_forged_green_probe(tmp_path):
    b = _bundle(tmp_path)
    runner = FakeBuildRunner(
        responses=[
            _out("+ unpatched\n(nothing)\n", 0),
            _out("ok\n", 0),
            _out(f"{SIG_P}\n", 0),
        ]
    )
    probe_bundle(b, build_runner=runner, nixpkgs_checkout=None)
    record = json.loads((b / "probe.json").read_text())
    record["discriminates"] = True
    record["signal_unpatched_present"] = True
    (b / "probe.json").write_text(json.dumps(record))
    ok, why = check_probe(b)
    assert not ok


def test_check_binds_the_patch_and_package_too(tmp_path):
    """The arms build the patched tree from patch.diff and package.nix, so a
    probe says nothing about a bundle whose patch changed afterwards."""
    b = _bundle(tmp_path)
    probe_bundle(b, build_runner=_discriminating_runner(), nixpkgs_checkout=None)
    (b / "patch.diff").write_text("--- a/x\n+++ b/x\n+changed\n")
    ok, why = check_probe(b)
    assert not ok and "patch.diff" in why


def test_probe_build_record_is_redacted(tmp_path):
    """The arms' output is committed to a public repository. Secret-shaped
    tokens that reach it, whatever the route, must not be written verbatim."""
    b = _bundle(tmp_path)
    leaky = f"+ unpatched\nANTHROPIC_API_KEY=sk-ant-api03-{'a' * 40}\n{SIG_U}\n"
    runner = FakeBuildRunner(
        responses=[
            _out(leaky, 1),
            _out("+ patched-build OK\n", 0),
            _out(f"+ patched\n{SIG_P}\n", 0),
        ]
    )
    probe_bundle(b, build_runner=runner, nixpkgs_checkout=None)
    text = (b / "probe-build.json").read_text()
    assert "sk-ant-api03" not in text
    assert "REDACTED" in text


def test_redaction_covers_nix_access_tokens_lines():
    from tools.trace_cli.probe import redact_secrets

    text = "access-tokens = github.com=abcdefghijklmnopqrstuvwxyz0123456789ABCD\nSIGNAL_PATCHED: ok\n"
    out = redact_secrets(text)
    assert "abcdefghijklmnop" not in out
    assert "SIGNAL_PATCHED: ok" in out


# --- signal hygiene: an arm that emitted its signal without having run ---
# svgo CVE-2026-73650; see agents/reproducer/signal_hygiene.py for the shape.

_VACUOUS_PATCHED = (
    "error: unknown option '--enable=removeScripts'\n"
    "grep: namespaced-out.svg: No such file or directory\n"
    f"{SIG_P}\n"
)


def _vacuous_patched_runner() -> FakeBuildRunner:
    return FakeBuildRunner(
        responses=[
            _out(f"+ unpatched\n{SIG_U}\n", 1),
            _out("+ patched-build OK\n", 0),
            _out(_VACUOUS_PATCHED, 0),
        ]
    )


def test_probe_records_hygiene_on_an_honest_fixture(tmp_path):
    b = _bundle(tmp_path)
    probe_bundle(b, build_runner=_discriminating_runner(), nixpkgs_checkout=None)
    saved = json.loads((b / "probe.json").read_text())
    assert saved["signal_hygiene_ok"] is True


def test_probe_flags_a_signal_emitted_over_a_run_that_never_happened(tmp_path):
    b = _bundle(tmp_path)
    probe_bundle(b, build_runner=_vacuous_patched_runner(), nixpkgs_checkout=None)
    saved = json.loads((b / "probe.json").read_text())
    assert saved["signal_patched_present"] is True, "the signal really is in the log"
    assert saved["signal_hygiene_ok"] is False
    assert "namespaced-out.svg" in saved["signal_hygiene_notes"]


def test_probe_command_itself_fails_on_a_vacuous_signal(tmp_path):
    """The probe command is the gate an operator actually runs; it must not print
    "discriminates" and exit 0 for a fixture whose patched arm never ran."""
    b = _bundle(tmp_path)
    code, verdict = probe_bundle(
        b, build_runner=_vacuous_patched_runner(), nixpkgs_checkout=None
    )
    assert code == EXIT_NO_DISCRIMINATION
    assert verdict["signal_hygiene_ok"] is False


def test_a_usage_line_alone_does_not_refuse(tmp_path):
    """A tool may print help while still doing its work, and an option rejection
    may be the behaviour under test. One mark alone is recorded and shown to the
    operator; only the pair, a refused invocation AND a predicate that then read
    the output it never wrote, gates."""
    b = _bundle(tmp_path)
    runner = FakeBuildRunner(
        responses=[
            _out(f"+ unpatched\n{SIG_U}\n", 1),
            _out("+ patched-build OK\n", 0),
            _out(f"usage: demo [options]\nprocessed 2 files\n{SIG_P}\n", 0),
        ]
    )
    code, verdict = probe_bundle(b, build_runner=runner, nixpkgs_checkout=None)
    assert code == 0
    assert verdict["signal_hygiene_ok"] is True
    assert "advisory" in verdict["signal_hygiene_notes"]
    ok, _ = check_probe(b)
    assert ok is True


def test_check_refuses_a_vacuous_patched_signal(tmp_path):
    """Both signals present is not enough: the gate must refuse a fixture whose
    patched arm never ran. This is the cert gate, so it is the one that counts."""
    b = _bundle(tmp_path)
    probe_bundle(b, build_runner=_vacuous_patched_runner(), nixpkgs_checkout=None)
    ok, why = check_probe(b)
    assert ok is False
    assert "never happened" in why
    assert "patched" in why


def test_check_refuses_even_when_probe_json_claims_hygiene(tmp_path):
    """The verdict is re-derived from the build record, so editing probe.json
    does not buy a pass."""
    b = _bundle(tmp_path)
    probe_bundle(b, build_runner=_vacuous_patched_runner(), nixpkgs_checkout=None)
    p = b / "probe.json"
    record = json.loads(p.read_text())
    record["signal_hygiene_ok"] = True
    record["signal_hygiene_notes"] = "looks fine to me"
    p.write_text(json.dumps(record, indent=2) + "\n")
    ok, why = check_probe(b)
    assert ok is False
    assert "never happened" in why


def test_a_failing_arm_is_not_scanned(tmp_path):
    """An arm that emitted no signal is claiming nothing, and its diagnostics are
    usually the honest reason it failed. Only a signal-emitting arm is suspect."""
    from agents.reproducer.signal_hygiene import scan_build

    build = {
        "unpatched": {"stdout_stderr": "foo: unrecognized option '--nope'\n"},
        "patched": {"stdout_stderr": "parsed 2 files\nSIGNAL_PATCHED: clean\n"},
    }
    assert scan_build(build, signals={"unpatched": False, "patched": True}) == {}
    assert "unpatched" in scan_build(
        build, signals={"unpatched": True, "patched": True}
    )


def test_an_incidental_missing_file_alone_does_not_refuse(tmp_path):
    """A healthy fixture that cats an optional file must still pass. A false
    positive here blocks honest work; a false negative costs only what we had
    before the check existed."""
    b = _bundle(tmp_path)
    runner = FakeBuildRunner(
        responses=[
            _out(f"+ unpatched\n{SIG_U}\n", 1),
            _out("+ patched-build OK\n", 0),
            _out(
                f"cat: optional.txt: No such file or directory\ndemo wrote result\n{SIG_P}\n",
                0,
            ),
        ]
    )
    code, verdict = probe_bundle(b, build_runner=runner, nixpkgs_checkout=None)
    assert code == 0
    assert verdict["signal_hygiene_ok"] is True
    ok, _ = check_probe(b)
    assert ok is True


def test_a_recorded_override_lets_a_flagged_fixture_through(tmp_path):
    """The gate is fail-closed, but an operator who has read the log and judged
    the marks a false positive says so, and the reason travels with the bundle."""
    b = _bundle(tmp_path)
    code, verdict = probe_bundle(
        b,
        build_runner=_vacuous_patched_runner(),
        nixpkgs_checkout=None,
        allow_signal_marks="the missing file is an optional cache probe, not the predicate's input",
    )
    assert code == 0
    assert verdict["signal_hygiene_ok"] is False, (
        "the marks are still recorded honestly"
    )
    assert "optional cache probe" in verdict["signal_hygiene_override"]
    ok, why = check_probe(b)
    assert ok is True, why


def test_an_empty_override_does_not_count(tmp_path):
    b = _bundle(tmp_path)
    probe_bundle(
        b,
        build_runner=_vacuous_patched_runner(),
        nixpkgs_checkout=None,
        allow_signal_marks="   ",
    )
    ok, why = check_probe(b)
    assert ok is False
    assert "never happened" in why


def test_a_non_string_override_is_refused_not_a_crash(tmp_path):
    """check_probe is the gate; malformed artifact data is a refusal, never an
    exception."""
    b = _bundle(tmp_path)
    probe_bundle(b, build_runner=_vacuous_patched_runner(), nixpkgs_checkout=None)
    p = b / "probe.json"
    record = json.loads(p.read_text())
    record["signal_hygiene_override"] = True
    p.write_text(json.dumps(record, indent=2) + "\n")
    ok, why = check_probe(b)
    assert ok is False
    assert "never happened" in why


def test_a_whitespace_override_fails_the_probe_command_too(tmp_path):
    """The probe command and --check must agree on what counts as a reason, or
    automation reads a green probe that the gate will later reject."""
    b = _bundle(tmp_path)
    code, verdict = probe_bundle(
        b,
        build_runner=_vacuous_patched_runner(),
        nixpkgs_checkout=None,
        allow_signal_marks="   ",
    )
    assert code == EXIT_NO_DISCRIMINATION
    assert verdict["signal_hygiene_override"] is None
