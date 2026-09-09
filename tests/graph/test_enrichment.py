"""PURL enrichment tests.

Three layers, same gating pattern as test_graph_extract.py:

  * Shape (always): purl-enrichment-schema.json is well-formed;
    graph/enrichment/purls.json validates; the extended graph-snapshot-schema
    accepts snapshots with/without an `enrichment` block.

  * Smoke (cargo-gated): `cargo run -- extract ... --enrichment <path>` merges
    the manifest into node.purls and records provenance in snapshot.enrichment.

  * Live PURL-exact (cargo+nix-gated): extract `hello` with enrichment; pipe
    the live snapshot into Scout with a purl-matched advisory; assert a
    purl-exact finding lands.
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


MANIFEST_PATH = REPO_ROOT / "graph" / "enrichment" / "purls.json"
SCHEMA_PATH = REPO_ROOT / "policy" / "purl-enrichment-schema.json"
SNAPSHOT_SCHEMA_PATH = REPO_ROOT / "policy" / "graph-snapshot-schema.json"
GRAPH_MANIFEST = REPO_ROOT / "graph" / "Cargo.toml"
FLAKE_LOCK = REPO_ROOT / "flake.lock"


@pytest.fixture(scope="module")
def enrichment_validator() -> Draft202012Validator:
    return Draft202012Validator(json.loads(SCHEMA_PATH.read_text()))


@pytest.fixture(scope="module")
def snapshot_validator() -> Draft202012Validator:
    return Draft202012Validator(json.loads(SNAPSHOT_SCHEMA_PATH.read_text()))


@pytest.fixture(scope="session")
def extract_prereqs() -> tuple[str, str] | None:
    require = os.environ.get("TRACE_REQUIRE_NIX") == "1"
    missing = []
    if shutil.which("cargo") is None:
        missing.append("cargo")
    if shutil.which("nix") is None:
        missing.append("nix")
    if missing:
        msg = f"missing prerequisites: {missing}"
        if require:
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


def _errors(v: Draft202012Validator, doc) -> list[str]:
    return [
        f"{'/'.join(str(p) for p in e.absolute_path)}: {e.message}"
        for e in v.iter_errors(doc)
    ]


# ─── shape layer ────────────────────────────────────────────────────────────


def test_enrichment_schema_is_well_formed(enrichment_validator):
    Draft202012Validator.check_schema(json.loads(SCHEMA_PATH.read_text()))


def test_seed_manifest_validates(enrichment_validator):
    doc = json.loads(MANIFEST_PATH.read_text())
    errs = _errors(enrichment_validator, doc)
    assert not errs, f"seed manifest failed schema: {errs}"


def test_manifest_requires_confidence_and_source(enrichment_validator):
    bad = {
        "schema_version": "1.0.0",
        "mappings": [
            {
                "attr_path": "hello",
                "purls": [{"value": "pkg:gnu/hello@2"}],
            }
        ],
    }
    assert _errors(enrichment_validator, bad), (
        "schema should require source + confidence"
    )


def test_snapshot_with_enrichment_validates(snapshot_validator):
    snap = {
        "schema_version": "1.0.0",
        "nixpkgs_rev": "0" * 40,
        "nodes": [
            {
                "attr_path": "hello",
                "drv_path": "/nix/store/00000000000000000000000000000001-hello.drv",
                "pname": "hello",
                "version": "2.12.3",
                "purls": ["pkg:gnu/hello@2.12.3"],
            }
        ],
        "enrichment": {
            "sources": [{"path": "graph/enrichment/purls.json", "sha256": "a" * 64}],
            "purl_mappings_applied": [
                {
                    "attr_path": "hello",
                    "purl": "pkg:gnu/hello@2.12.3",
                    "template": "pkg:gnu/hello@{version}",
                    "source": "manual",
                    "confidence": "high",
                }
            ],
        },
    }
    assert not _errors(snapshot_validator, snap)


# ─── cargo-gated smoke ──────────────────────────────────────────────────────


def _run_extract(
    rev: str, store: str, attrs: list[str], enrichment: Path | None = None
) -> dict:
    cmd = [
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
    ]
    if enrichment is not None:
        cmd.extend(["--enrichment", str(enrichment)])
    proc = subprocess.run(
        cmd, cwd=REPO_ROOT, capture_output=True, text=True, check=False
    )
    assert proc.returncode == 0, f"stdout: {proc.stdout}\nstderr: {proc.stderr}"
    return json.loads(proc.stdout)


def test_extract_without_enrichment_has_no_audit_block(
    extract_prereqs, snapshot_validator
):
    rev, store = extract_prereqs
    snap = _run_extract(rev, store, ["hello"], enrichment=None)
    assert not _errors(snapshot_validator, snap)
    assert "enrichment" not in snap
    assert snap["nodes"][0]["purls"] == []


def test_extract_with_enrichment_merges_and_audits(extract_prereqs, snapshot_validator):
    rev, store = extract_prereqs
    snap = _run_extract(rev, store, ["hello"], enrichment=MANIFEST_PATH)
    assert not _errors(snapshot_validator, snap)

    hello = snap["nodes"][0]
    # Template filled in from the real extracted version.
    real_version = hello["version"]
    assert hello["purls"] == [f"pkg:gnu/hello@{real_version}"]

    audit = snap["enrichment"]
    assert len(audit["sources"]) == 1
    assert audit["sources"][0]["path"].endswith("purls.json")
    assert len(audit["sources"][0]["sha256"]) == 64

    mappings = audit["purl_mappings_applied"]
    assert len(mappings) == 1
    assert mappings[0]["attr_path"] == "hello"
    assert mappings[0]["purl"] == f"pkg:gnu/hello@{real_version}"
    assert mappings[0]["template"] == "pkg:gnu/hello@{version}"
    assert mappings[0]["source"] == "manual"
    assert mappings[0]["confidence"] == "high"


def test_extract_with_enrichment_leaves_unmatched_attrs_alone(extract_prereqs):
    rev, store = extract_prereqs
    snap = _run_extract(rev, store, ["hello", "cowsay"], enrichment=MANIFEST_PATH)
    by_attr = {n["attr_path"]: n for n in snap["nodes"]}
    # hello is enriched
    assert by_attr["hello"]["purls"]
    # cowsay is not in the seed manifest → unchanged (empty)
    assert by_attr["cowsay"]["purls"] == []
    # Audit only lists the attrs that actually got enriched.
    attrs_applied = {
        m["attr_path"] for m in snap["enrichment"]["purl_mappings_applied"]
    }
    assert attrs_applied == {"hello"}


# ─── live PURL-exact Scout path ─────────────────────────────────────────────


def test_live_enriched_graph_produces_purl_exact_finding(extract_prereqs):
    """The architectural proof: one live PURL-exact Scout path, driven by a
    trace-curated enrichment entry, against a real nixpkgs extraction."""
    from agents.scout import CannedGraphLookup, scan
    from agents.scout.graph_lookup import GraphMatch

    rev, store = extract_prereqs
    snap = _run_extract(rev, store, ["hello"], enrichment=MANIFEST_PATH)
    hello_version = snap["nodes"][0]["version"]
    expected_purl = f"pkg:gnu/hello@{hello_version}"

    graph = CannedGraphLookup(
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

    # Advisory that hits the enriched PURL directly — purl-exact path.
    advisory = {
        "feed": "osv",
        "cve_id": "CVE-0000-6001",
        "published_at": "2026-04-23T00:00:00Z",
        "severity": {"rating": "high", "cvss_v3_score": 7.5},
        "purl_matches": [expected_purl],
    }
    result = scan(advisory, graph)
    assert result["status"] == "finding", f"expected finding, got {result}"
    finding = result["finding"]
    # Scout treats the enriched PURL exactly like a native-feed PURL —
    # provenance lives in the snapshot, not in Scout's policy.
    assert finding["mapping"]["method"] == "purl-exact"
    assert finding["affected"][0]["confidence"] == "high"
    assert finding["affected"][0]["attr_path"] == "hello"
