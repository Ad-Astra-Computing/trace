"""trace-graph-builder `extract` end-to-end test against real nixpkgs.

Gated on cargo + nix. Skips locally when either is absent; fails hard under
TRACE_REQUIRE_NIX=1 (CI). The extraction runs against the project's pinned
nixpkgs (flake.lock) and a tiny attr sample (`zlib`, `curl`) so reverse-
closure detection is exercised by a real dependency (`curl` buildInputs
include `zlib`).

Assertions:
  * The emitted snapshot validates against policy/graph-snapshot-schema.json.
  * Each sampled attr appears as a node with pname, version, drv_path,
    maintainers.
  * reverse_closure is computed within the sample — zlib -> [curl].
  * The emitted snapshot can feed Scout's CannedGraphLookup via the same
    schema shape, proving the graph builder can replace canned fixtures.
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
GRAPH_MANIFEST = REPO_ROOT / "graph" / "Cargo.toml"
FLAKE_LOCK = REPO_ROOT / "flake.lock"


@pytest.fixture(scope="module")
def validator() -> Draft202012Validator:
    return Draft202012Validator(json.loads(SCHEMA_PATH.read_text()))


@pytest.fixture(scope="session")
def extract_prereqs_available() -> tuple[str, str] | None:
    """Returns (nixpkgs_rev, nixpkgs_store_path) or skips/fails."""
    require = os.environ.get("TRACE_REQUIRE_NIX") == "1"

    missing: list[str] = []
    if shutil.which("cargo") is None:
        missing.append("cargo")
    if shutil.which("nix") is None:
        missing.append("nix")
    if missing:
        msg = f"missing prerequisites for live extraction: {missing}"
        if require:
            pytest.fail(f"TRACE_REQUIRE_NIX=1 but {msg}")
        pytest.skip(msg)

    lock = json.loads(FLAKE_LOCK.read_text())
    try:
        rev = lock["nodes"]["nixpkgs"]["locked"]["rev"]
    except KeyError as exc:
        pytest.fail(f"flake.lock missing nixpkgs lock: {exc}")

    archive = subprocess.run(
        ["nix", "flake", "archive", "--json"],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    if archive.returncode != 0:
        msg = f"`nix flake archive --json` failed: {archive.stderr.strip()}"
        if require:
            pytest.fail(msg)
        pytest.skip(msg)
    try:
        store = json.loads(archive.stdout)["inputs"]["nixpkgs"]["path"]
    except (KeyError, json.JSONDecodeError) as exc:
        pytest.fail(f"parsing nix flake archive output: {exc}")

    return rev, store


def _extract(rev: str, nixpkgs_store: str, attrs: list[str]) -> dict:
    proc = subprocess.run(
        [
            "cargo",
            "run",
            "--quiet",
            "--manifest-path",
            str(GRAPH_MANIFEST),
            "--",
            "extract",
            "--rev",
            rev,
            "--nixpkgs",
            nixpkgs_store,
            "--attrs",
            ",".join(attrs),
        ],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode == 0, (
        f"extract exited {proc.returncode}\n"
        f"--- stdout ---\n{proc.stdout}\n--- stderr ---\n{proc.stderr}"
    )
    return json.loads(proc.stdout)


# ─── tests ──────────────────────────────────────────────────────────────────


def test_extract_single_attr_validates(validator, extract_prereqs_available):
    rev, store = extract_prereqs_available
    snap = _extract(rev, store, ["hello"])
    errs = [
        f"{'/'.join(str(p) for p in e.absolute_path)}: {e.message}"
        for e in validator.iter_errors(snap)
    ]
    assert not errs, f"live snapshot failed schema: {errs}"
    assert snap["nixpkgs_rev"] == rev
    nodes = {n["attr_path"]: n for n in snap["nodes"]}
    assert "hello" in nodes
    hello = nodes["hello"]
    assert hello["pname"] == "hello"
    assert hello["version"], "hello must have a non-empty version"
    assert hello["drv_path"].endswith(".drv")
    assert hello["maintainers"], "hello has declared maintainers in nixpkgs"


def test_extract_reverse_closure_within_sample(validator, extract_prereqs_available):
    """curl build-depends on zlib, so zlib.reverse_closure within the {zlib,curl} sample must include 'curl'."""
    rev, store = extract_prereqs_available
    snap = _extract(rev, store, ["zlib", "curl"])
    errs = [
        f"{'/'.join(str(p) for p in e.absolute_path)}: {e.message}"
        for e in validator.iter_errors(snap)
    ]
    assert not errs
    by_attr = {n["attr_path"]: n for n in snap["nodes"]}
    assert set(by_attr.keys()) == {"zlib", "curl"}
    assert "curl" in by_attr["zlib"]["reverse_closure"]
    assert by_attr["curl"]["reverse_closure"] == []


def test_extract_reverse_closure_is_transitive(validator, extract_prereqs_available):
    """openssl ← curl ← git within the sample: openssl's reverse_closure must include BOTH curl (direct) and git (transitive via curl)."""
    rev, store = extract_prereqs_available
    snap = _extract(rev, store, ["openssl", "curl", "git"])
    by_attr = {n["attr_path"]: n for n in snap["nodes"]}
    assert set(by_attr.keys()) == {"openssl", "curl", "git"}
    openssl_rc = set(by_attr["openssl"]["reverse_closure"])
    assert {"curl", "git"}.issubset(openssl_rc), (
        f"openssl's transitive reverse_closure must include curl AND git; got {openssl_rc}"
    )
    assert "git" in by_attr["curl"]["reverse_closure"]
    assert by_attr["git"]["reverse_closure"] == []


def test_extract_output_feeds_scout_canned_lookup(validator, extract_prereqs_available):
    """The emitted snapshot can seed Scout's graph lookup without further transformation — proves the Rust output can replace canned fixtures."""
    from agents.scout import CannedGraphLookup, scan
    from agents.scout.graph_lookup import GraphMatch

    rev, store = extract_prereqs_available
    snap = _extract(rev, store, ["hello"])
    matches = [
        GraphMatch(
            attr_path=n["attr_path"],
            drv_path=n["drv_path"],
            pname=n["pname"],
            version=n["version"],
            cpes=tuple(n.get("cpes") or ()),
            purls=tuple(n.get("purls") or ()),
            src_url=n.get("src_url"),
            src_hash=n.get("src_hash"),
        )
        for n in snap["nodes"]
    ]
    graph = CannedGraphLookup(matches)

    # Scout input: a pname_hint that matches the extracted node.
    feed = {
        "feed": "nvd",
        "cve_id": "CVE-0000-4001",
        "published_at": "2026-04-23T00:00:00Z",
        "severity": {"rating": "high", "cvss_v3_score": 7.5},
        "pname_hints": ["hello"],
    }
    result = scan(feed, graph)
    assert result["status"] == "finding"
    finding = result["finding"]
    assert finding["affected"][0]["attr_path"] == "hello"
    assert finding["mapping"]["method"] == "pname-heuristic"


def test_extract_rejects_bad_rev(extract_prereqs_available):
    """CLI-level guard: --rev must be 40-hex. Doesn't actually launch nix."""
    proc = subprocess.run(
        [
            "cargo",
            "run",
            "--quiet",
            "--manifest-path",
            str(GRAPH_MANIFEST),
            "--",
            "extract",
            "--rev",
            "notahash",
            "--nixpkgs",
            "/does/not/matter",
            "--attrs",
            "hello",
        ],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode == 2
    assert "--rev" in proc.stderr
