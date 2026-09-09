"""Proof that an enrichment manifest's hash is captured as a replay input.

Constructs a minimal bundle in tmp_path where Cartographer's invocation
declares `graph/enrichment/purls.json` as one of its inputs alongside
finding.json and graph.json. replay.json and provenance.jsonl both carry
the real sha256 of the live manifest bytes. Steward (rule-5) must allow.
Corrupting the purls.json sha256 in replay.json — but not in provenance —
must flip Steward to deny, proving the manifest really is on the hook.

Stopping rule (per 2026-04-23 note in this thread):
  Once one enriched replay path is recorded and replay-verifiable, stop
  enrichment work until the eval corpus exists.

Gated on opa; skips locally if absent, fails in CI (TRACE_REQUIRE_OPA=1).
"""

from __future__ import annotations

import hashlib
import json
import shutil
import subprocess
import uuid
from pathlib import Path
from typing import Any

import pytest

from tests.schema.validate import REPO_ROOT


MANIFEST_PATH = REPO_ROOT / "graph" / "enrichment" / "purls.json"
STEWARD_REGO = REPO_ROOT / "policy" / "steward.rego"


@pytest.fixture(scope="module")
def manifest_sha256() -> str:
    return hashlib.sha256(MANIFEST_PATH.read_bytes()).hexdigest()


@pytest.fixture(scope="session")
def opa_required() -> bool:
    import os

    if shutil.which("opa") is None:
        if os.environ.get("TRACE_REQUIRE_OPA") == "1":
            pytest.fail("TRACE_REQUIRE_OPA=1 but opa not on PATH")
        pytest.skip("opa not on PATH")
    return True


def _sha(body: bytes) -> str:
    return hashlib.sha256(body).hexdigest()


def _canonical(obj: Any) -> bytes:
    return json.dumps(
        obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


def _finding() -> dict:
    return {
        "schema_version": "1.0.0",
        "cve_id": "CVE-0000-8001",
        "source_feeds": ["nvd"],
        "severity": {"rating": "high", "cvss_v3_score": 7.5},
        "published_at": "2026-04-23T00:00:00Z",
        "affected": [
            {
                "attr_path": "hello",
                "drv_path": "/nix/store/00000000000000000000000000000001-hello-2.12.3.drv",
                "pname": "hello",
                "version": "2.12.3",
                "confidence": "high",
            }
        ],
        "mapping": {"method": "purl-exact", "purl": ["pkg:gnu/hello@2.12.3"]},
        "replay_critical": True,
    }


def _upstream_ref_ineligible() -> dict:
    return {
        "schema_version": "1.0.0",
        "cve_id": "CVE-0000-8001",
        "current_version": "2.12.3",
        "eligibility": {
            "verdict": "ineligible-no-fix-available",
            "verdict_reason": "fixture — advisory-only path, pinning enrichment provenance test",
        },
        "replay_critical": True,
    }


def _graph_json(manifest_sha: str) -> dict:
    """A minimal schema-valid graph snapshot. Embeds the manifest sha256 in its own enrichment.sources[] block; the whole graph.json is ALSO hashed as a cartographer input, so the manifest hash is captured both transitively (via graph.json contents) AND explicitly (via a separate input listing)."""
    return {
        "schema_version": "1.0.0",
        "nixpkgs_rev": "0000000000000000000000000000000000000000",
        "nodes": [
            {
                "attr_path": "hello",
                "drv_path": "/nix/store/00000000000000000000000000000001-hello-2.12.3.drv",
                "pname": "hello",
                "version": "2.12.3",
                "purls": ["pkg:gnu/hello@2.12.3"],
            }
        ],
        "enrichment": {
            "sources": [
                {"path": "graph/enrichment/purls.json", "sha256": manifest_sha}
            ],
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


def _build_bundle(tmp: Path, manifest_sha: str) -> tuple[dict, dict, list[dict]]:
    finding = _finding()
    upstream = _upstream_ref_ineligible()
    graph = _graph_json(manifest_sha)
    manifest_bytes = MANIFEST_PATH.read_bytes()
    graph_bytes = _canonical(graph)
    finding_bytes = _canonical(finding)

    f_sha = _sha(finding_bytes)
    g_sha = _sha(graph_bytes)
    m_sha = manifest_sha
    u_sha = _sha(_canonical(upstream))

    # Write the physical input files that Cartographer's invocation references.
    (tmp / "finding.json").write_bytes(finding_bytes)
    (tmp / "graph.json").write_bytes(graph_bytes)
    (tmp / "purls.json").write_bytes(manifest_bytes)

    invocation_id = str(uuid.uuid4())
    invocation = {
        "invocation_id": invocation_id,
        "role": "cartographer",
        "started_at": "2026-04-23T00:00:00Z",
        "ended_at": "2026-04-23T00:00:01Z",
        "model": {
            "family": "deterministic-no-model",
            "vendor": "internal",
            "model_id": "cartographer-deterministic",
            "version": "1.0.0",
            "sampling": {"temperature": 0, "top_p": 1, "max_tokens": 1},
        },
        "prompt": {"path": "prompts/cartographer.v1.md", "sha256": "7" * 64},
        "inputs": [
            {"path": "finding.json", "sha256": f_sha},
            {"path": "graph.json", "sha256": g_sha},
            # The enrichment manifest is declared explicitly as a replay input,
            # not just transitively via graph.json. This is the property under test.
            {"path": "graph/enrichment/purls.json", "sha256": m_sha},
        ],
        "outputs": [
            {"path": "impact.json", "sha256": "d" * 64},
            {"path": "maintainers.json", "sha256": "e" * 64},
        ],
        "rng_seed": None,
        "validators_passed": ["graph-snapshot-shape"],
        "network_policy_applied": "none",
    }

    replay = {
        "schema_version": "1.0.0",
        "bundle_id": "0000000000008001",
        "cve_id": "CVE-0000-8001",
        "nixpkgs_rev": "0" * 40,
        "policy_version": "0" * 64,
        "bundle_schema_sha256": "1" * 64,
        "routing_config_sha256": "2" * 64,
        "tool_manifest": {
            "flake_lock_sha256": "3" * 64,
            "tools": [{"name": "nix", "version": "2.24.0"}],
        },
        "cross_family_rule_honored": True,
        "roles": [{"role": "cartographer", "invocations": [invocation]}],
    }

    bundle = {
        "schema_version": "1.0.0",
        "bundle_id": "0000000000008001",
        "cve_id": "CVE-0000-8001",
        "nixpkgs_rev": "0" * 40,
        "kind": "advisory-only",
        "kind_reason": "ineligible-no-fix-available",
        "created_at": "2026-04-23T00:00:00Z",
        "policy_version": "0" * 64,
        "bundle_schema_version": "1" * 64,
        "files": {
            "bundle.json": {
                "sha256": "a" * 64,
                "bytes": 1,
                "producer_role": "steward",
                "replay_critical": True,
            },
            "finding.json": {
                "sha256": f_sha,
                "bytes": len(finding_bytes),
                "producer_role": "scout",
                "replay_critical": True,
            },
            "impact.json": {
                "sha256": "d" * 64,
                "bytes": 1,
                "producer_role": "cartographer",
                "replay_critical": True,
            },
            "maintainers.json": {
                "sha256": "e" * 64,
                "bytes": 1,
                "producer_role": "cartographer",
                "replay_critical": True,
            },
            "upstream-ref.json": {
                "sha256": u_sha,
                "bytes": 1,
                "producer_role": "upstream-ref-resolver",
                "replay_critical": True,
            },
            "replay.json": {
                "sha256": "f" * 64,
                "bytes": 1,
                "producer_role": "steward",
                "replay_critical": True,
            },
            "provenance.jsonl": {
                "sha256": "0" * 64,
                "bytes": 1,
                "producer_role": "steward",
                "replay_critical": False,
            },
            "bundle.sig": {
                "sha256": "9" * 64,
                "bytes": 1,
                "producer_role": "steward",
                "replay_critical": False,
            },
        },
        "signed_manifest": {
            "algorithm": "sigstore-cosign-v1",
            "signer": "fixture@example.invalid",
            "signed_files": [
                {"path": "bundle.json", "sha256": "a" * 64},
                {"path": "finding.json", "sha256": f_sha},
                {"path": "impact.json", "sha256": "d" * 64},
                {"path": "maintainers.json", "sha256": "e" * 64},
                {"path": "upstream-ref.json", "sha256": u_sha},
                {"path": "replay.json", "sha256": "f" * 64},
            ],
        },
    }

    provenance_lines = [
        {
            "ts": "2026-04-23T00:00:00Z",
            "seq": 0,
            "role": "cartographer",
            "action_type": "role_enter",
        },
        {
            "ts": "2026-04-23T00:00:01Z",
            "seq": 1,
            "role": "cartographer",
            "action_type": "model_invocation",
            "invocation_id": invocation_id,
            "model": {
                "family": "deterministic-no-model",
                "model_id": "cartographer-deterministic",
            },
            "prompt_sha256": "7" * 64,
            "input_sha256s": [f_sha, g_sha, m_sha],
            "output_sha256s": ["d" * 64, "e" * 64],
        },
        {
            "ts": "2026-04-23T00:00:01Z",
            "seq": 2,
            "role": "cartographer",
            "action_type": "role_exit",
        },
    ]

    return bundle, replay, provenance_lines


def _opa_input(bundle: dict, replay: dict, provenance: list[dict]) -> dict:
    # Steward's rule-5 also needs a finding and upstream-ref in input; use a trivial shape
    # matching the one written to disk above.
    return {
        "bundle": bundle,
        "finding": _finding(),
        "upstream_ref": _upstream_ref_ineligible(),
        "replay": replay,
        "provenance": provenance,
    }


def _run_opa(input_doc: dict) -> dict:
    proc = subprocess.run(
        [
            "opa",
            "eval",
            "--format=json",
            "--data",
            str(STEWARD_REGO),
            "--stdin-input",
            "data.trace.steward",
        ],
        input=json.dumps(input_doc),
        capture_output=True,
        text=True,
        check=True,
    )
    return json.loads(proc.stdout)["result"][0]["expressions"][0]["value"]


# ─── tests ──────────────────────────────────────────────────────────────────


def test_enrichment_manifest_hash_flows_through_replay(
    tmp_path, manifest_sha256, opa_required
):
    bundle, replay, prov = _build_bundle(tmp_path, manifest_sha256)
    # Every input-sha256 in provenance has a matching input in replay — rule-5 allows.
    decision = _run_opa(_opa_input(bundle, replay, prov))
    assert decision["allow"] is True, (
        f"Steward denied cleanly-provenanced bundle: {decision['deny']}"
    )

    # Sanity: the manifest path is really listed as an input.
    invocation_inputs = [
        i["path"] for i in replay["roles"][0]["invocations"][0]["inputs"]
    ]
    assert "graph/enrichment/purls.json" in invocation_inputs
    input_shas = [i["sha256"] for i in replay["roles"][0]["invocations"][0]["inputs"]]
    assert manifest_sha256 in input_shas


def test_manifest_hash_tampering_is_caught_by_steward(
    tmp_path, manifest_sha256, opa_required
):
    bundle, replay, prov = _build_bundle(tmp_path, manifest_sha256)

    # Corrupt the manifest sha in replay.json's inputs — but leave the
    # provenance.jsonl model_invocation line alone. This simulates a replay
    # manifest that claims to depend on a different enrichment.json than the
    # one actually used during the run. Steward rule-5 MUST deny.
    invocation = replay["roles"][0]["invocations"][0]
    for i in invocation["inputs"]:
        if i["path"] == "graph/enrichment/purls.json":
            i["sha256"] = "f" * 64
            break

    decision = _run_opa(_opa_input(bundle, replay, prov))
    assert decision["allow"] is False, (
        "Steward must reject a bundle whose recorded enrichment hash diverges from provenance"
    )
    rule_ids = {d["rule_id"] for d in decision["deny"]}
    assert "rule-5-provenance-replay-must-agree" in rule_ids, (
        f"expected rule-5 to fire; got rules {rule_ids}"
    )


def test_manifest_bytes_match_recorded_sha(manifest_sha256):
    """Sanity: the hash we use in the tests is literally sha256 of the live manifest file bytes. No off-by-something."""
    recomputed = hashlib.sha256(MANIFEST_PATH.read_bytes()).hexdigest()
    assert recomputed == manifest_sha256
