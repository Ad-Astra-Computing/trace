"""Tests for lora/fetch_gate_pilot_run.py.

fetch_run() takes an injected download_fn so these tests never touch
huggingface_hub or the network — they use a fake in-memory "hub" instead.
"""

from __future__ import annotations

import hashlib
import importlib.util
import json
from pathlib import Path

import pytest

_spec = importlib.util.spec_from_file_location(
    "fetch_gate_pilot_run",
    Path(__file__).resolve().parents[2] / "lora" / "fetch_gate_pilot_run.py",
)
fetch_mod = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(fetch_mod)


def _fake_hub(tmp_path: Path, files: dict[str, bytes]):
    """Returns a download_fn backed by a dict of {path_in_repo: bytes},
    writing each requested file to its own tmp location on first access
    (mimicking huggingface_hub's local cache behavior closely enough for
    this module's needs) and raising FileNotFoundError for anything else."""
    hub_dir = tmp_path / "fake_hub_cache"
    hub_dir.mkdir()

    def download_fn(repo_id: str, path_in_repo: str, repo_type: str) -> Path:
        if path_in_repo not in files:
            raise FileNotFoundError(f"{path_in_repo} not in fake hub for {repo_id}")
        dest = hub_dir / path_in_repo.replace("/", "__")
        dest.write_bytes(files[path_in_repo])
        return dest

    return download_fn


def test_default_manifest_path_for_nested():
    assert (
        fetch_mod.default_manifest_path_for(
            "gate_pilot_responses/corpus-v2-control/responses.jsonl"
        )
        == "gate_pilot_responses/corpus-v2-control/run_manifest.json"
    )


def test_default_manifest_path_for_top_level():
    assert fetch_mod.default_manifest_path_for("responses.jsonl") == "run_manifest.json"


def test_fetch_run_downloads_and_verifies(tmp_path):
    responses_bytes = b'{"bundle_id": "abc", "generated": "accept"}\n'
    response_sha256 = hashlib.sha256(responses_bytes).hexdigest()
    manifest_bytes = json.dumps(
        {"response_sha256": response_sha256, "row_count": 1}
    ).encode()

    download_fn = _fake_hub(
        tmp_path,
        {
            "gate_pilot_responses/responses.jsonl": responses_bytes,
            "gate_pilot_responses/run_manifest.json": manifest_bytes,
        },
    )

    out_dir = tmp_path / "local_run"
    summary = fetch_mod.fetch_run(
        adapter_repo="adastracomputing/reviewer-lora-v1.10",
        responses_path="gate_pilot_responses/responses.jsonl",
        out_dir=out_dir,
        download_fn=download_fn,
    )

    assert (out_dir / "responses.jsonl").read_bytes() == responses_bytes
    assert (out_dir / "run_manifest.json").read_bytes() == manifest_bytes
    assert summary["manifest_present"] is True
    assert summary["verified"] is True
    assert summary["response_sha256"] == response_sha256


def test_fetch_run_raises_on_sha256_mismatch(tmp_path):
    responses_bytes = b'{"bundle_id": "abc"}\n'
    manifest_bytes = json.dumps({"response_sha256": "0" * 64}).encode()

    download_fn = _fake_hub(
        tmp_path,
        {
            "gate_pilot_responses/responses.jsonl": responses_bytes,
            "gate_pilot_responses/run_manifest.json": manifest_bytes,
        },
    )

    with pytest.raises(RuntimeError, match="sha256 mismatch"):
        fetch_mod.fetch_run(
            adapter_repo="repo",
            responses_path="gate_pilot_responses/responses.jsonl",
            out_dir=tmp_path / "local_run",
            download_fn=download_fn,
        )


def test_fetch_run_no_verify_skips_mismatch_check(tmp_path):
    responses_bytes = b'{"bundle_id": "abc"}\n'
    manifest_bytes = json.dumps({"response_sha256": "0" * 64}).encode()

    download_fn = _fake_hub(
        tmp_path,
        {
            "gate_pilot_responses/responses.jsonl": responses_bytes,
            "gate_pilot_responses/run_manifest.json": manifest_bytes,
        },
    )

    summary = fetch_mod.fetch_run(
        adapter_repo="repo",
        responses_path="gate_pilot_responses/responses.jsonl",
        out_dir=tmp_path / "local_run",
        download_fn=download_fn,
        verify=False,
    )
    assert summary["verified"] is None


def test_fetch_run_missing_manifest_is_not_fatal(tmp_path):
    """Older runs (predating this instrumentation) have no run_manifest.json.
    The download must still succeed, just report manifest_present=False."""
    responses_bytes = b'{"bundle_id": "abc"}\n'
    download_fn = _fake_hub(
        tmp_path,
        {
            "gate_pilot_responses/responses.jsonl": responses_bytes,
        },
    )

    summary = fetch_mod.fetch_run(
        adapter_repo="repo",
        responses_path="gate_pilot_responses/responses.jsonl",
        out_dir=tmp_path / "local_run",
        download_fn=download_fn,
    )
    assert summary["manifest_present"] is False
    assert summary["verified"] is None
    assert (tmp_path / "local_run" / "responses.jsonl").exists()
    assert not (tmp_path / "local_run" / "run_manifest.json").exists()


def test_fetch_run_custom_manifest_path(tmp_path):
    responses_bytes = b"{}\n"
    manifest_bytes = json.dumps(
        {"response_sha256": hashlib.sha256(responses_bytes).hexdigest()}
    ).encode()
    download_fn = _fake_hub(
        tmp_path,
        {
            "responses.jsonl": responses_bytes,
            "custom/manifest.json": manifest_bytes,
        },
    )

    summary = fetch_mod.fetch_run(
        adapter_repo="repo",
        responses_path="responses.jsonl",
        manifest_path="custom/manifest.json",
        out_dir=tmp_path / "local_run",
        download_fn=download_fn,
    )
    assert summary["manifest_path"] == "custom/manifest.json"
    assert summary["verified"] is True
