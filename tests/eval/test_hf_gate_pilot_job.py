"""Tests for lora/hf_gate_pilot_job.py's run-provenance helpers.

hf_gate_pilot_job.py is a standalone PEP 723 `hf jobs uv run` script (torch /
peft / transformers / huggingface_hub deps) — those heavy imports are
deferred into main() specifically so this module stays importable, and its
manifest/serialization logic testable, without a GPU or those packages
installed. Loaded by path (spec_from_file_location) to match the convention
in tests/eval/test_score_gate_pilot.py.
"""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path

_spec = importlib.util.spec_from_file_location(
    "hf_gate_pilot_job",
    Path(__file__).resolve().parents[2] / "lora" / "hf_gate_pilot_job.py",
)
job = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(job)


def test_module_importable_without_ml_deps():
    # If this test file collected at all, the exec_module() above already
    # succeeded without torch/peft/transformers/huggingface_hub installed —
    # that's the load-bearing assertion (heavy imports are deferred to
    # main()). This just makes the intent explicit.
    assert hasattr(job, "main")


def test_sha256_bytes_matches_hashlib():
    import hashlib

    data = b"hello gate pilot"
    assert job.sha256_bytes(data) == hashlib.sha256(data).hexdigest()


def test_sha256_text_matches_bytes_encoding():
    text = "some user turn content"
    assert job.sha256_text(text) == job.sha256_bytes(text.encode())


def test_build_response_row_schema_unchanged():
    """Backward-compat: this is the schema score_gate_pilot.py already
    consumes. Adding provenance elsewhere must not touch this shape."""
    prov = {
        "cve_id": "CVE-2022-37434",
        "attr_path": "zlib",
        "bundle_id": "dc5657a2a24de9f8",
        "mutation_type": None,
    }
    row = job.build_response_row(
        prov=prov, label="positive", split="canary",
        user_text="the user turn", generated="=== BEGIN review.md ===\naccept",
    )
    assert set(row.keys()) == {
        "cve_id", "attr_path", "bundle_id", "label", "split",
        "mutation_type", "user_sha256", "generated",
    }
    assert row["cve_id"] == "CVE-2022-37434"
    assert row["label"] == "positive"
    assert row["split"] == "canary"
    assert row["generated"] == "=== BEGIN review.md ===\naccept"
    assert row["user_sha256"] == job.sha256_text("the user turn")


def test_build_response_row_generated_text_untruncated():
    long_text = "x" * 10_000
    row = job.build_response_row(
        prov={}, label="negative", split="test", user_text="u", generated=long_text,
    )
    assert row["generated"] == long_text
    assert len(row["generated"]) == 10_000


def test_build_decode_settings_greedy_nulls_sampling_params():
    decode = job.build_decode_settings(
        do_sample=False, max_new_tokens=1024, temperature=0.7, top_p=0.9, pad_token_id=151643,
    )
    # temperature/top_p are not consulted by generate() under greedy decode;
    # recording the passed-in defaults would misrepresent what happened.
    assert decode == {
        "do_sample": False,
        "max_new_tokens": 1024,
        "temperature": None,
        "top_p": None,
        "seed": None,
        "pad_token_id": 151643,
    }


def test_build_decode_settings_sampling_keeps_params():
    decode = job.build_decode_settings(
        do_sample=True, max_new_tokens=512, temperature=0.7, top_p=0.9, seed=42,
    )
    assert decode["do_sample"] is True
    assert decode["temperature"] == 0.7
    assert decode["top_p"] == 0.9
    assert decode["seed"] == 42


def test_manifest_path_for_nested_responses_path():
    assert job.manifest_path_for("gate_pilot_responses/corpus-v2-control/responses.jsonl") == (
        "gate_pilot_responses/corpus-v2-control/run_manifest.json"
    )


def test_manifest_path_for_top_level_responses_path():
    assert job.manifest_path_for("responses.jsonl") == "run_manifest.json"


def test_build_run_manifest_ties_full_provenance_together():
    decode = job.build_decode_settings(do_sample=False, max_new_tokens=1024, pad_token_id=0)
    manifest = job.build_run_manifest(
        task="reviewer-lora-gate-pilot",
        timestamp="2026-07-28T00:00:00Z",
        base_model="Qwen/Qwen2.5-Coder-14B-Instruct",
        base_model_revision=job.BASE_REVISION,
        adapter_repo="adastracomputing/reviewer-lora-v1.10",
        adapter_revision="abc123",
        decode=decode,
        input_filename="gate-pilot.jsonl",
        input_sha256="deadbeef" * 8,
        row_count=26,
        responses_path="gate_pilot_responses/corpus-v2-control/responses.jsonl",
        response_sha256="feedface" * 8,
    )
    assert manifest["task"] == "reviewer-lora-gate-pilot"
    assert manifest["timestamp"] == "2026-07-28T00:00:00Z"
    assert manifest["base_model_revision"] == job.BASE_REVISION
    assert manifest["adapter_repo"] == "adastracomputing/reviewer-lora-v1.10"
    assert manifest["adapter_revision"] == "abc123"
    assert manifest["decode"] == decode
    assert manifest["input_filename"] == "gate-pilot.jsonl"
    assert manifest["input_sha256"] == "deadbeef" * 8
    assert manifest["row_count"] == 26
    assert manifest["response_sha256"] == "feedface" * 8
    # Round-trips through json (this is what actually gets uploaded).
    assert json.loads(json.dumps(manifest)) == manifest


def test_build_run_manifest_defaults_missing_adapter_revision_to_unknown():
    manifest = job.build_run_manifest(
        task="t", timestamp="unknown", base_model="m", base_model_revision="r",
        adapter_repo="repo", adapter_revision=None, decode={}, input_filename="f",
        input_sha256="s", row_count=0, responses_path="p", response_sha256="rs",
    )
    assert manifest["adapter_revision"] == "unknown"


def test_write_jsonl_one_row_per_line(tmp_path):
    rows = [{"a": 1}, {"a": 2}, {"a": 3}]
    out = tmp_path / "out.jsonl"
    job.write_jsonl(out, rows)
    lines = out.read_text().splitlines()
    assert len(lines) == 3
    assert [json.loads(l) for l in lines] == rows


def test_write_json_round_trips(tmp_path):
    obj = {"k": "v", "n": 1}
    out = tmp_path / "manifest.json"
    job.write_json(out, obj)
    assert json.loads(out.read_text()) == obj


# --- assert_responses_path_free (multi-seed overwrite guard) -----------------


class _FakeApi:
    def __init__(self, files, raises=False):
        self._files = files
        self._raises = raises

    def list_repo_files(self, repo_id, repo_type):  # noqa: ARG002
        if self._raises:
            raise RuntimeError("listing blew up")
        return list(self._files)


def test_overwrite_guard_raises_when_path_exists():
    api = _FakeApi(["gate_pilot_responses/responses.jsonl"])
    try:
        job.assert_responses_path_free(
            api,
            repo_id="org/adapter",
            path_in_repo="gate_pilot_responses/responses.jsonl",
            allow_overwrite=False,
        )
    except RuntimeError as e:
        assert "refusing to overwrite" in str(e)
    else:
        raise AssertionError("expected RuntimeError on existing path")


def test_overwrite_guard_allows_fresh_path():
    api = _FakeApi(["gate_pilot_responses/other.jsonl"])
    job.assert_responses_path_free(
        api,
        repo_id="org/adapter",
        path_in_repo="gate_pilot_responses/seed1.jsonl",
        allow_overwrite=False,
    )


def test_overwrite_guard_respects_explicit_opt_in():
    api = _FakeApi(["gate_pilot_responses/responses.jsonl"])
    job.assert_responses_path_free(
        api,
        repo_id="org/adapter",
        path_in_repo="gate_pilot_responses/responses.jsonl",
        allow_overwrite=True,
    )


def test_overwrite_guard_never_aborts_run_on_listing_failure():
    # A finished inference run must not be lost to a transient listing error.
    api = _FakeApi([], raises=True)
    job.assert_responses_path_free(
        api,
        repo_id="org/adapter",
        path_in_repo="gate_pilot_responses/responses.jsonl",
        allow_overwrite=False,
    )
