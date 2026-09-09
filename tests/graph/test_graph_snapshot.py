"""graph-snapshot schema + Rust stub smoke test.

Shape layer (always runs):
  * `policy/graph-snapshot-schema.json` is itself a well-formed Draft 2020-12 schema.
  * A hand-rolled minimal snapshot dict validates.

Smoke layer (runs when `cargo` is on PATH):
  * `cargo run --quiet --manifest-path graph/Cargo.toml` exits 0.
  * Its stdout is valid JSON and validates against the schema.
  * `--rev <sha>` is honored end-to-end.
  * `cargo test --quiet --manifest-path graph/Cargo.toml` passes.

Behavior under `TRACE_REQUIRE_CARGO=1`:
  * Missing `cargo` becomes a hard fail instead of a skip.
  * CI sets this to ensure the Rust contract is exercised.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator

from tests.schema.validate import REPO_ROOT


SCHEMA_PATH = REPO_ROOT / "policy" / "graph-snapshot-schema.json"
GRAPH_CRATE = REPO_ROOT / "graph"
MANIFEST = GRAPH_CRATE / "Cargo.toml"


@pytest.fixture(scope="module")
def schema() -> dict:
    return json.loads(SCHEMA_PATH.read_text())


@pytest.fixture(scope="module")
def validator(schema) -> Draft202012Validator:
    return Draft202012Validator(schema)


@pytest.fixture(scope="session")
def cargo_available() -> bool:
    available = shutil.which("cargo") is not None
    if not available and os.environ.get("TRACE_REQUIRE_CARGO") == "1":
        pytest.fail(
            "TRACE_REQUIRE_CARGO=1 but `cargo` is not on PATH. "
            "Enter the graph dev shell (`nix develop .#graph`) or install cargo."
        )
    return available


# ─── shape layer ────────────────────────────────────────────────────────────


def test_schema_is_well_formed(schema):
    Draft202012Validator.check_schema(schema)


def test_minimal_snapshot_validates(validator):
    snap = {
        "schema_version": "1.0.0",
        "nixpkgs_rev": "0" * 40,
        "nodes": [
            {
                "attr_path": "libexample",
                "drv_path": "/nix/store/00000000000000000000000000000001-libexample-1.4.7.drv",
                "pname": "libexample",
                "version": "1.4.7",
            }
        ],
    }
    errors = [e.message for e in validator.iter_errors(snap)]
    assert not errors


def test_snapshot_missing_schema_version_rejected(validator):
    snap = {
        "nixpkgs_rev": "0" * 40,
        "nodes": [],
    }
    errors = list(validator.iter_errors(snap))
    assert errors, "schema must require schema_version"


def test_unknown_top_level_field_rejected(validator):
    snap = {
        "schema_version": "1.0.0",
        "nixpkgs_rev": "0" * 40,
        "nodes": [],
        "some_new_field": True,
    }
    errors = list(validator.iter_errors(snap))
    assert errors


def test_node_with_unknown_field_rejected(validator):
    snap = {
        "schema_version": "1.0.0",
        "nixpkgs_rev": "0" * 40,
        "nodes": [
            {
                "attr_path": "libexample",
                "drv_path": "/nix/store/00000000000000000000000000000001-libexample-1.4.7.drv",
                "pname": "libexample",
                "version": "1.4.7",
                "risk_score": 0.3,
            }
        ],
    }
    errors = list(validator.iter_errors(snap))
    assert errors


# ─── smoke layer (cargo-gated) ──────────────────────────────────────────────


def _run_cargo(args: list[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["cargo", *args, "--quiet", "--manifest-path", str(MANIFEST)],
        capture_output=True,
        text=True,
        check=False,
    )


def test_cargo_build_then_emit_snapshot_validates(validator, cargo_available):
    if not cargo_available:
        pytest.skip(
            "cargo not on PATH; set TRACE_REQUIRE_CARGO=1 to make this a failure"
        )

    build = _run_cargo(["build"])
    assert build.returncode == 0, f"cargo build failed: {build.stderr}"

    run = _run_cargo(["run"])
    assert run.returncode == 0, f"cargo run failed: {run.stderr}"

    try:
        snap = json.loads(run.stdout)
    except json.JSONDecodeError as exc:
        pytest.fail(
            f"graph-builder stdout is not valid JSON: {exc}\n{run.stdout[:500]}"
        )

    errors = [e.message for e in validator.iter_errors(snap)]
    assert not errors, f"emitted snapshot failed schema: {errors}"
    assert snap["schema_version"] == "1.0.0"
    assert snap["nixpkgs_rev"] == "0" * 40


def test_cargo_run_honors_rev_flag(validator, cargo_available):
    if not cargo_available:
        pytest.skip("cargo not on PATH")

    run = subprocess.run(
        [
            "cargo",
            "run",
            "--quiet",
            "--manifest-path",
            str(MANIFEST),
            "--",
            "--rev",
            "abcdef0123456789abcdef0123456789abcdef01",
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    assert run.returncode == 0, f"cargo run --rev failed: {run.stderr}"
    snap = json.loads(run.stdout)
    assert snap["nixpkgs_rev"] == "abcdef0123456789abcdef0123456789abcdef01"
    errors = [e.message for e in validator.iter_errors(snap)]
    assert not errors


def test_cargo_tests_pass(cargo_available):
    if not cargo_available:
        pytest.skip("cargo not on PATH")
    t = _run_cargo(["test"])
    assert t.returncode == 0, f"cargo test failed:\n{t.stdout}\n{t.stderr}"
