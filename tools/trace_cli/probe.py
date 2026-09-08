"""`trace bundle probe`: run the committed reproducer through the real two-arm
Builder on this host and bind the verdict to the fixture bytes it judged.

The Reproducer's own log is a claim. This is the check. It reuses the same probe
the pass@K sampler uses, so a green here means the fixture behaves the way the
cert will judge it, and it writes `probe.json` beside the bundle rather than
`build.json`, which is reserved for the cert's own record.

See docs/specs/reproducer-probe-gate.md.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import shutil
import tempfile
from datetime import datetime, timezone
from pathlib import Path

EXIT_OK = 0
EXIT_REFUSED = 2
EXIT_NO_DISCRIMINATION = 3
EXIT_PROBE_ERROR = 4

from agents.reproducer.signal_hygiene import (
    describe as describe_hygiene,
    refuses as hygiene_refuses,
    scan_build,
)

PROBE_SCHEMA_VERSION = "1.0.0"
_REQUIRED = ("reproducer.nix", "reproducer-log.txt", "passthru-tests.json")
# Everything the arms are built from. A probe describes exactly these bytes.
_BOUND = {
    "reproducer_sha256": "reproducer.nix",
    "reproducer_log_sha256": "reproducer-log.txt",
    "passthru_tests_sha256": "passthru-tests.json",
    "patch_diff_sha256": "patch.diff",
    "package_nix_sha256": "package.nix",
}

# The arms' output is committed to a public repository. Whatever route a secret
# took into it, it must not be written verbatim. High-signal shapes only, the
# same stance the pre-commit secret guard takes.
_SECRET_RES = (
    re.compile(r"sk-ant-[A-Za-z0-9_-]{16,}"),
    re.compile(r"sk-[A-Za-z0-9]{32,}"),
    re.compile(r"gh[pousr]_[A-Za-z0-9]{30,}"),
    re.compile(r"github_pat_[A-Za-z0-9_]{40,}"),
    re.compile(r"hf_[A-Za-z0-9]{30,}"),
    re.compile(r"AKIA[0-9A-Z]{16}"),
    re.compile(r"xox[baprs]-[A-Za-z0-9-]{20,}"),
    re.compile(r"(?im)^(\s*access-tokens\s*=\s*)\S+.*$"),
    re.compile(r"(?i)\b([A-Z0-9_]*(?:KEY|TOKEN|SECRET|PASSWORD|PASSWD|CREDENTIALS?))=([^\s\"']+)"),
)


def redact_secrets(text: str) -> str:
    for rx in _SECRET_RES:
        if rx.groups:
            text = rx.sub(lambda m: f"{m.group(1)}{'' if m.group(1).rstrip().endswith('=') else '='}REDACTED", text)
        else:
            text = rx.sub("REDACTED", text)
    return text


class ProbeRefused(Exception):
    """A precondition failed before any build ran."""


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _pinned_rev(bundle_dir: Path) -> str | None:
    for name in ("bundle.json", "finding.json"):
        p = bundle_dir / name
        if p.is_file():
            try:
                rev = json.loads(p.read_text()).get("nixpkgs_rev")
            except json.JSONDecodeError:
                rev = None
            if rev:
                return rev
    return None


def _refuse_unless_probeable(bundle_dir: Path, nixpkgs_checkout: Path | None) -> None:
    if not bundle_dir.is_dir():
        raise ProbeRefused(f"{bundle_dir} is not a directory")
    for name in _REQUIRED:
        if not (bundle_dir / name).is_file():
            raise ProbeRefused(f"{bundle_dir} has no {name}; run the Reproducer first")
    if (bundle_dir / "refusal.json").is_file():
        raise ProbeRefused("bundle carries a Patcher refusal.json; there is no patch to probe")
    bj = bundle_dir / "bundle.json"
    if bj.is_file():
        try:
            if json.loads(bj.read_text()).get("kind") == "advisory-only":
                raise ProbeRefused("bundle is advisory-only; nothing to reproduce")
        except json.JSONDecodeError:
            pass
    if nixpkgs_checkout is not None:
        from tools.trace_cli.checkout import validate_checkout

        problem = validate_checkout(nixpkgs_checkout, bundle_dir)
        if problem:
            raise ProbeRefused(problem)


def _honest(verdict, hygiene: dict, override_reason: str) -> bool:
    """Both signals fired, and either no arm shows it never ran or an operator has
    recorded why those marks are a false positive here."""
    signals = verdict.signal_unpatched_present and verdict.signal_patched_present
    return bool(signals and (not hygiene_refuses(hygiene) or override_reason))


def probe_bundle(
    bundle_dir: Path,
    *,
    build_runner,
    nixpkgs_checkout: Path | None,
    timeout_seconds_per_build: int = 1800,
    allow_signal_marks: str | None = None,
) -> tuple[int, dict]:
    """Run both arms once over the bundle's own fixture. Returns (exit code, verdict).

    A verdict is written to probe.json only when the build actually exercised the
    fixture. An infrastructure failure returns EXIT_PROBE_ERROR with no probe.json,
    because a build that never ran says nothing about the fixture.
    """
    from agents.reproducer.sampling import build_probe_fn

    _refuse_unless_probeable(bundle_dir, nixpkgs_checkout)

    probe_fn = build_probe_fn(
        bundle_dir=bundle_dir,
        build_runner=build_runner,
        nixpkgs_checkout=nixpkgs_checkout,
        timeout_seconds_per_build=timeout_seconds_per_build,
    )
    nix_bytes = (bundle_dir / "reproducer.nix").read_bytes()
    log_bytes = (bundle_dir / "reproducer-log.txt").read_bytes()
    json_bytes = (bundle_dir / "passthru-tests.json").read_bytes()

    with tempfile.TemporaryDirectory(prefix="trace-probe-") as tmp:
        probe_dir = Path(tmp) / "workspace"
        try:
            verdict = probe_fn(probe_dir, nix_bytes, log_bytes, json_bytes)
        except RuntimeError as e:
            return EXIT_PROBE_ERROR, {"error": str(e)}
        probe_build = probe_dir / "build.json"
        build_sha = None
        if probe_build.is_file():
            redacted = redact_secrets(probe_build.read_text())
            (bundle_dir / "probe-build.json").write_text(redacted)
            build_sha = _sha256(bundle_dir / "probe-build.json")

    # One normalisation, used by both the exit code and the record, so the probe
    # command and the later --check cannot disagree about what counts as a reason.
    override_reason = (allow_signal_marks or "").strip()
    hygiene: dict = {}
    probe_build_path = bundle_dir / "probe-build.json"
    if probe_build_path.is_file():
        try:
            hygiene = scan_build(
                json.loads(probe_build_path.read_text()),
                signals={
                    "unpatched": verdict.signal_unpatched_present,
                    "patched": verdict.signal_patched_present,
                },
            )
        except json.JSONDecodeError:
            hygiene = {}

    record = {
        "schema_version": PROBE_SCHEMA_VERSION,
        "probed_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        **{key: _sha256(bundle_dir / name) for key, name in _BOUND.items() if (bundle_dir / name).is_file()},
        "nixpkgs_rev": _pinned_rev(bundle_dir),
        "discriminates": _honest(verdict, hygiene, override_reason),
        "signal_unpatched_present": verdict.signal_unpatched_present,
        "signal_patched_present": verdict.signal_patched_present,
        "signal_specificity_ok": verdict.signal_specificity_ok,
        "signal_hygiene_ok": not hygiene_refuses(hygiene),
        "signal_hygiene_notes": describe_hygiene(hygiene),
        "signal_hygiene_override": override_reason or None,
        "detail": verdict.detail,
        "build_json_sha256": build_sha,
    }
    (bundle_dir / "probe.json").write_text(json.dumps(record, indent=2) + "\n")
    # A signal emitted over an arm that never ran is not discrimination, whatever
    # the scorers found in the log, so it must fail the probe command itself and
    # not merely the later --check.
    return (
        EXIT_OK if _honest(verdict, hygiene, override_reason) else EXIT_NO_DISCRIMINATION
    ), record


def check_probe(bundle_dir: Path) -> tuple[bool, str]:
    """The gate form: the build record exists, matches the probe, still describes
    the current bundle bytes, and itself shows discrimination.

    Nothing here trusts a boolean stored in probe.json. The verdict is re-derived
    from probe-build.json with the same scorers the cert uses, so a hand-written
    record cannot pass.
    """
    p = bundle_dir / "probe.json"
    if not p.is_file():
        return False, f"{bundle_dir} has no probe.json; run `trace bundle probe` first"
    try:
        record = json.loads(p.read_text())
    except json.JSONDecodeError as e:
        return False, f"probe.json is not valid JSON: {e}"

    build_record = bundle_dir / "probe-build.json"
    if not build_record.is_file():
        return False, "probe-build.json is missing; the probe's build record must accompany probe.json"
    if _sha256(build_record) != record.get("build_json_sha256"):
        return False, "probe-build.json does not match the hash recorded in probe.json"

    for key, name in _BOUND.items():
        f = bundle_dir / name
        if not f.is_file():
            if key in record:
                return False, f"{name} is missing but the probe recorded it"
            continue
        if _sha256(f) != record.get(key):
            return False, f"{name} changed since the probe; re-run `trace bundle probe`"

    from agents.scorers.reproducer_scorers import (
        ReproPatchedPassesScorer,
        ReproUnpatchedFailsScorer,
    )

    with tempfile.TemporaryDirectory(prefix="trace-probe-check-") as tmp:
        ws = Path(tmp)
        for name in _REQUIRED:
            shutil.copyfile(bundle_dir / name, ws / name)
        shutil.copyfile(build_record, ws / "build.json")
        invocation = {"outputs": [{"path": n} for n in _REQUIRED]}
        unpatched = ReproUnpatchedFailsScorer().score(bundle_dir=ws, invocation=invocation)
        patched = ReproPatchedPassesScorer().score(bundle_dir=ws, invocation=invocation)
    if not (unpatched.applies and unpatched.score == 1.0):
        return False, f"the recorded build does not show the unpatched signal: {unpatched.notes}"
    if not (patched.applies and patched.score == 1.0):
        return False, f"the recorded build does not show the patched signal: {patched.notes}"

    # Both signals are present. That is not yet proof both arms ran: an absence
    # predicate fires over an output file the tool never wrote. Re-derive the
    # hygiene marks from the build record rather than trusting probe.json.
    hygiene = scan_build(
        json.loads(build_record.read_text()),
        signals={"unpatched": True, "patched": True},
    )
    if hygiene_refuses(hygiene):
        # The gate is fail-closed by design: a false positive here is loud and
        # names the two log lines it saw, while a false negative ships a fixture
        # that never ran into a signed bundle. An operator who has read the log
        # and disagrees records why, and the exception travels with the bundle.
        raw_override = record.get("signal_hygiene_override")
        override = raw_override.strip() if isinstance(raw_override, str) else ""
        if not override:
            return False, describe_hygiene(hygiene)
    return True, "probe is green and current"


def add_parser(subs: argparse._SubParsersAction) -> None:
    p = subs.add_parser(
        "probe",
        help="run the committed reproducer through the two-arm Builder on this host",
        description=(
            "Build both arms of the bundle's own reproducer.nix locally and record "
            "whether they discriminate, in probe.json, bound to the fixture's bytes. "
            "With --check, run no build and only verify a green, current probe exists."
        ),
    )
    p.add_argument("bundle_dir", type=Path)
    p.add_argument("--nixpkgs-checkout", type=Path, default=None,
                   help="clean git checkout at the bundle's pinned nixpkgs_rev")
    p.add_argument("--timeout-seconds-per-build", type=int, default=1800)
    p.add_argument("--allow-signal-marks", default=None, metavar="REASON",
                   help="record why an arm's hygiene marks are a false positive here, "
                        "and let the probe pass despite them")
    p.add_argument("--check", action="store_true",
                   help="gate form: exit 0 only if probe.json is green and matches the current fixture")


def run(args: argparse.Namespace) -> int:
    if args.check:
        ok, why = check_probe(args.bundle_dir)
        print(("ok: " if ok else "refused: ") + why)
        return EXIT_OK if ok else EXIT_REFUSED

    if args.nixpkgs_checkout is None:
        print("error: --nixpkgs-checkout is required to build the arms (a clean checkout at the pinned rev)")
        return EXIT_REFUSED
    from agents.builder import LocalNixBuildRunner

    try:
        code, verdict = probe_bundle(
            args.bundle_dir,
            build_runner=LocalNixBuildRunner(),
            nixpkgs_checkout=args.nixpkgs_checkout,
            timeout_seconds_per_build=args.timeout_seconds_per_build,
            allow_signal_marks=args.allow_signal_marks,
        )
    except ProbeRefused as e:
        print(f"refused: {e}")
        return EXIT_REFUSED
    if code == EXIT_PROBE_ERROR:
        print(f"probe error: {verdict.get('error')}")
        return code
    if not verdict["discriminates"]:
        state = "does NOT discriminate"
    elif not verdict["signal_hygiene_ok"]:
        state = "signals both fired, but one arm never ran"
    else:
        state = "discriminates"
    print(f"probe: fixture {state}")
    print(f"  unpatched signal: {verdict['signal_unpatched_present']}")
    print(f"  patched signal:   {verdict['signal_patched_present']}")
    print(f"  detail:           {verdict['detail']}")
    if verdict.get("signal_hygiene_notes") and (
        not verdict["signal_hygiene_ok"] or "advisory" in verdict["signal_hygiene_notes"]
    ):
        print(f"  hygiene:          {verdict['signal_hygiene_notes']}")
    print(f"  wrote:            {args.bundle_dir / 'probe.json'} and probe-build.json")
    return code
