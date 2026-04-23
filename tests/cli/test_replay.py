"""replay CLI skeleton tests.

Scope (matches docs/DECISIONS.md 2026-04-23 build-order exception):
  * bundle lookup + plan emission
  * override argument validation (--role/--model; --routing-config)
  * bare --model rejected
  * bare --role rejected
  * --routing-config mutually exclusive with --role/--model
  * frozen inputs: plan reflects replay.json; no role execution
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from tools.trace_cli.cli import (
    EXIT_INVALID,
    EXIT_NOT_FOUND,
    EXIT_OK,
    EXIT_USAGE,
    build_replay_plan,
    main,
)


REPO_ROOT = Path(__file__).resolve().parents[2]
TRACES_ROOT = REPO_ROOT / "traces" / "example"
FIXTURE_BUNDLE_DIR = TRACES_ROOT / "CVE-0000-0000"
FIXTURE_BUNDLE_ID = "0000000000000000"
FIXTURE_CVE_ID = "CVE-0000-0000"


def _run(argv: list[str], capsys: pytest.CaptureFixture[str]) -> tuple[int, str, str]:
    try:
        rc = main(argv)
    except SystemExit as exc:
        # argparse raises SystemExit on usage errors (e.g. invalid enum choice).
        rc = int(exc.code) if isinstance(exc.code, int) else EXIT_USAGE
    captured = capsys.readouterr()
    return rc, captured.out, captured.err


# ─── bundle lookup ───────────────────────────────────────────────────────────


def test_replay_by_bundle_id(capsys):
    rc, out, _ = _run(
        ["replay", FIXTURE_BUNDLE_ID, "--traces-root", str(TRACES_ROOT), "--format", "json"],
        capsys,
    )
    assert rc == EXIT_OK
    plan = json.loads(out)
    assert plan["bundle_id"] == FIXTURE_BUNDLE_ID
    assert plan["cve_id"] == FIXTURE_CVE_ID
    assert plan["executor"] == "stub"


def test_replay_by_cve_id(capsys):
    rc, out, _ = _run(
        ["replay", FIXTURE_CVE_ID, "--traces-root", str(TRACES_ROOT), "--format", "json"],
        capsys,
    )
    assert rc == EXIT_OK
    plan = json.loads(out)
    assert plan["bundle_id"] == FIXTURE_BUNDLE_ID


def test_replay_by_fixture_dir_path(capsys):
    rc, out, _ = _run(
        ["replay", str(FIXTURE_BUNDLE_DIR), "--format", "json"],
        capsys,
    )
    assert rc == EXIT_OK
    plan = json.loads(out)
    assert plan["cve_id"] == FIXTURE_CVE_ID


def test_replay_not_found(capsys):
    rc, _, err = _run(
        ["replay", "ffffffffffffffff", "--traces-root", str(TRACES_ROOT)],
        capsys,
    )
    assert rc == EXIT_NOT_FOUND
    assert "not found" in err


# ─── override validation ─────────────────────────────────────────────────────


def test_replay_bare_model_rejected(capsys):
    rc, _, err = _run(
        ["replay", FIXTURE_BUNDLE_ID, "--traces-root", str(TRACES_ROOT), "--model", "foo-1"],
        capsys,
    )
    assert rc == EXIT_USAGE
    assert "--model requires --role" in err


def test_replay_bare_role_rejected(capsys):
    rc, _, err = _run(
        ["replay", FIXTURE_BUNDLE_ID, "--traces-root", str(TRACES_ROOT), "--role", "patcher"],
        capsys,
    )
    assert rc == EXIT_USAGE
    assert "--role requires --model" in err


def test_replay_role_with_model_accepted(capsys):
    rc, out, _ = _run(
        [
            "replay", FIXTURE_BUNDLE_ID,
            "--traces-root", str(TRACES_ROOT),
            "--role", "scout",
            "--model", "alternate-scout-model",
            "--format", "json",
        ],
        capsys,
    )
    assert rc == EXIT_OK
    plan = json.loads(out)
    assert plan["overrides_requested"] == {"scout": {"model_id": "alternate-scout-model"}}
    scout_invocations = [i for i in plan["invocations"] if i["role"] == "scout"]
    assert scout_invocations, "expected at least one scout invocation in the fixture"
    for inv in scout_invocations:
        assert inv.get("override_model") == {"model_id": "alternate-scout-model"}


def test_replay_role_not_in_enum_rejected(capsys):
    rc, _, err = _run(
        ["replay", FIXTURE_BUNDLE_ID, "--traces-root", str(TRACES_ROOT),
         "--role", "not-a-role", "--model", "x"],
        capsys,
    )
    assert rc != EXIT_OK
    assert "invalid choice" in err or "argument --role" in err


# ─── routing-config ──────────────────────────────────────────────────────────


def _write_routing_config(tmp_path: Path, data: dict) -> Path:
    p = tmp_path / "routing.json"
    p.write_text(json.dumps(data))
    return p


def test_replay_routing_config_accepted(capsys, tmp_path):
    rc_path = _write_routing_config(tmp_path, {
        "patcher": {"model_id": "alt-patcher", "family": "openai"},
        "reviewer": {"model_id": "alt-reviewer", "family": "anthropic"},
    })
    rc, out, _ = _run(
        ["replay", FIXTURE_BUNDLE_ID, "--traces-root", str(TRACES_ROOT),
         "--routing-config", str(rc_path), "--format", "json"],
        capsys,
    )
    assert rc == EXIT_OK
    plan = json.loads(out)
    assert plan["overrides_requested"]["patcher"]["model_id"] == "alt-patcher"
    assert plan["overrides_requested"]["reviewer"]["family"] == "anthropic"


def test_replay_routing_config_mutually_exclusive_with_role(capsys, tmp_path):
    rc_path = _write_routing_config(tmp_path, {"patcher": {"model_id": "x"}})
    rc, _, err = _run(
        ["replay", FIXTURE_BUNDLE_ID, "--traces-root", str(TRACES_ROOT),
         "--routing-config", str(rc_path),
         "--role", "scout", "--model", "y"],
        capsys,
    )
    assert rc == EXIT_USAGE
    assert "mutually exclusive" in err


def test_replay_routing_config_unknown_role_rejected(capsys, tmp_path):
    rc_path = _write_routing_config(tmp_path, {"not-a-role": {"model_id": "x"}})
    rc, _, err = _run(
        ["replay", FIXTURE_BUNDLE_ID, "--traces-root", str(TRACES_ROOT),
         "--routing-config", str(rc_path)],
        capsys,
    )
    assert rc == EXIT_USAGE
    assert "not a known role" in err


def test_replay_routing_config_missing_model_id_rejected(capsys, tmp_path):
    rc_path = _write_routing_config(tmp_path, {"patcher": {"family": "anthropic"}})
    rc, _, err = _run(
        ["replay", FIXTURE_BUNDLE_ID, "--traces-root", str(TRACES_ROOT),
         "--routing-config", str(rc_path)],
        capsys,
    )
    assert rc == EXIT_USAGE
    assert "model_id" in err


def test_replay_routing_config_unknown_key_rejected(capsys, tmp_path):
    rc_path = _write_routing_config(tmp_path, {
        "patcher": {"model_id": "x", "temperature": 0.0}
    })
    rc, _, err = _run(
        ["replay", FIXTURE_BUNDLE_ID, "--traces-root", str(TRACES_ROOT),
         "--routing-config", str(rc_path)],
        capsys,
    )
    assert rc == EXIT_USAGE
    assert "unknown keys" in err


def test_replay_routing_config_empty_rejected(capsys, tmp_path):
    rc_path = _write_routing_config(tmp_path, {})
    rc, _, err = _run(
        ["replay", FIXTURE_BUNDLE_ID, "--traces-root", str(TRACES_ROOT),
         "--routing-config", str(rc_path)],
        capsys,
    )
    assert rc == EXIT_USAGE
    assert "empty" in err


def test_replay_routing_config_not_json_rejected(capsys, tmp_path):
    rc_path = tmp_path / "broken.json"
    rc_path.write_text("{not: json}")
    rc, _, err = _run(
        ["replay", FIXTURE_BUNDLE_ID, "--traces-root", str(TRACES_ROOT),
         "--routing-config", str(rc_path)],
        capsys,
    )
    assert rc == EXIT_USAGE
    assert "not valid JSON" in err


# ─── frozen inputs / stub executor ───────────────────────────────────────────


def test_replay_plan_reflects_frozen_inputs_exactly():
    bundle = json.loads((FIXTURE_BUNDLE_DIR / "bundle.json").read_text())
    replay = json.loads((FIXTURE_BUNDLE_DIR / "replay.json").read_text())

    plan = build_replay_plan(bundle, replay, overrides={}, bundle_dir=FIXTURE_BUNDLE_DIR)

    # Every invocation from replay.json is present with status=stub.
    expected_count = sum(len(r["invocations"]) for r in replay["roles"])
    assert len(plan["invocations"]) == expected_count

    for entry in plan["invocations"]:
        assert entry["status"] == "stub"
        assert entry.get("override_model") is None
        # Hashes are copied verbatim from replay.json, not recomputed.
        assert isinstance(entry["prompt_sha256"], str)
        assert len(entry["prompt_sha256"]) == 64

    # Ordering matches replay.json traversal (role-major, invocation-minor).
    flat = [
        (r["role"], inv["invocation_id"])
        for r in replay["roles"]
        for inv in r["invocations"]
    ]
    assert [(e["role"], e["invocation_id"]) for e in plan["invocations"]] == flat


def test_replay_human_format_prints_bundle_metadata(capsys):
    rc, out, _ = _run(
        ["replay", FIXTURE_BUNDLE_ID, "--traces-root", str(TRACES_ROOT)],
        capsys,
    )
    assert rc == EXIT_OK
    assert f"bundle_id:   {FIXTURE_BUNDLE_ID}" in out
    assert f"cve_id:      {FIXTURE_CVE_ID}" in out
    assert "executor:    stub" in out
    assert "no model calls, no network" in out
