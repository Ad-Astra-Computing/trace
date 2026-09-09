"""Mixed-mode end-to-end test: same normalized advisory, same expected finding,
once against a canned graph and once against a live-extracted graph snapshot.

Purpose (per the accuracy/semantic-honesty thread): prove the Rust graph
builder's output is a drop-in replacement for the canned test fixtures
Scout has been using. Any shape drift in the live pipeline that would
change Scout's result will fail this test.

Gated on cargo + nix — skips locally when either is absent; fails under
TRACE_REQUIRE_NIX=1 (CI), same as tests/graph/test_graph_extract.py.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
from pathlib import Path

import pytest

from agents.scout import CannedGraphLookup, scan
from agents.scout.graph_lookup import GraphMatch
from tests.schema.validate import REPO_ROOT


GRAPH_MANIFEST = REPO_ROOT / "graph" / "Cargo.toml"
FLAKE_LOCK = REPO_ROOT / "flake.lock"


@pytest.fixture(scope="session")
def extract_prereqs() -> tuple[str, str] | None:
    if shutil.which("cargo") is None or shutil.which("nix") is None:
        msg = "cargo or nix missing; mixed-mode test skipped"
        if os.environ.get("TRACE_REQUIRE_NIX") == "1":
            pytest.fail(f"TRACE_REQUIRE_NIX=1 but {msg}")
        pytest.skip(msg)
    lock = json.loads(FLAKE_LOCK.read_text())
    rev = lock["nodes"]["nixpkgs"]["locked"]["rev"]
    archive = subprocess.run(
        ["nix", "flake", "archive", "--json"],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        check=True,
    )
    store = json.loads(archive.stdout)["inputs"]["nixpkgs"]["path"]
    return rev, store


def _live_snapshot(rev: str, store: str, attrs: list[str]) -> dict:
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
            store,
            "--attrs",
            ",".join(attrs),
        ],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        check=True,
    )
    return json.loads(proc.stdout)


def _snapshot_to_canned_lookup(snap: dict) -> CannedGraphLookup:
    return CannedGraphLookup(
        [
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
    )


def _normalized_advisory(pname: str) -> dict:
    """A minimal scout-input-shaped advisory keyed off a pname hint so the
    match lands via the pname-heuristic layer (identifier-free by design — the
    point of this test is that Scout agrees regardless of graph source)."""
    return {
        "feed": "nvd",
        "cve_id": "CVE-0000-5001",
        "published_at": "2026-04-23T00:00:00Z",
        "severity": {"rating": "high", "cvss_v3_score": 7.5},
        "pname_hints": [pname],
    }


def _normalize_finding_for_comparison(finding: dict) -> dict:
    """Strip fields that can vary legitimately between a hand-built canned
    graph (arbitrary drv_path/version) and the live-extracted graph (real
    drv_path/version from nixpkgs). Asserted equality covers only the fields
    Scout actually decides: mapping method, confidence, affected attr_path,
    cve_id, source_feeds, severity. drv_path and version are informational
    for a pname-heuristic finding."""
    return {
        "cve_id": finding["cve_id"],
        "source_feeds": finding["source_feeds"],
        "severity": finding["severity"],
        "mapping_method": finding["mapping"]["method"],
        "affected_attrs": [
            {"attr_path": a["attr_path"], "confidence": a["confidence"]}
            for a in finding["affected"]
        ],
    }


def test_scout_agrees_between_canned_and_live_graph(extract_prereqs):
    """Same advisory, two graphs, one finding shape. Proves the graph-builder
    output can replace canned fixtures without changing Scout's decisions."""
    rev, store = extract_prereqs

    # Canned graph: a hand-rolled GraphMatch for `hello`.
    canned = CannedGraphLookup(
        [
            GraphMatch(
                attr_path="hello",
                drv_path="/nix/store/00000000000000000000000000000001-hello-stub.drv",
                pname="hello",
                version="0.0.0-stub",
            )
        ]
    )

    # Live graph: the Rust builder extracts `hello` from real nixpkgs.
    live_snap = _live_snapshot(rev, store, ["hello"])
    live = _snapshot_to_canned_lookup(live_snap)

    advisory = _normalized_advisory("hello")

    canned_result = scan(advisory, canned)
    live_result = scan(advisory, live)

    # Both paths must succeed identically.
    assert canned_result["status"] == "finding"
    assert live_result["status"] == "finding"

    canned_shape = _normalize_finding_for_comparison(canned_result["finding"])
    live_shape = _normalize_finding_for_comparison(live_result["finding"])
    assert canned_shape == live_shape, (
        f"Scout produced different finding shapes against canned vs live graphs.\n"
        f"canned: {canned_shape}\nlive:   {live_shape}"
    )

    # The live-extracted node carries the real nixpkgs drv_path; the canned
    # one carries a stub. Asserting inequality here isn't useful — the point
    # is Scout's decision is identical despite the difference.
    live_hello = next(n for n in live_snap["nodes"] if n["attr_path"] == "hello")
    assert live_hello["drv_path"].startswith("/nix/store/")
    assert live_hello["drv_path"].endswith(".drv")
    assert live_hello["pname"] == "hello"


def test_scout_mapping_failure_agrees_between_graphs(extract_prereqs):
    """Parity check for the mapping-failure path: if the pname doesn't exist
    in either graph, both should yield mapping-failure identically."""
    rev, store = extract_prereqs

    empty_canned = CannedGraphLookup([])

    live_snap = _live_snapshot(rev, store, ["hello"])
    live = _snapshot_to_canned_lookup(live_snap)

    # Advisory for a pname that neither graph knows about.
    advisory = _normalized_advisory("trace-ghost-package-that-does-not-exist")

    canned_result = scan(advisory, empty_canned)
    live_result = scan(advisory, live)

    assert canned_result["status"] == "mapping-failure"
    assert live_result["status"] == "mapping-failure"
    assert (
        canned_result["mapping_failure"]["reason"]
        == live_result["mapping_failure"]["reason"]
    )
