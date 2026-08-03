"""Pull a gate-pilot run's raw artifacts down into a durable local directory.

lora/hf_gate_pilot_job.py pushes gate_pilot_responses/responses.jsonl (raw
per-row model output — untruncated `generated` text + `user_sha256`) and,
alongside it, run_manifest.json (decode settings, base model + revision,
adapter repo + resolved revision, input filename/sha256, response_sha256,
timestamp) to the adapter's HF model repo. Both are ephemeral there: a later
run can overwrite the same path (several submit_hf_gate_pilot_*.sh scripts
reuse gate_pilot_responses/responses.jsonl), and neither file is committed to
this repo unless someone downloads it. This script does that download, and
verifies the downloaded responses.jsonl really is the file the manifest
describes before treating it as trustworthy local provenance.

Usage:
  python3 lora/fetch_gate_pilot_run.py \\
    --adapter-repo adastracomputing/reviewer-lora-v1.10 \\
    --responses-path gate_pilot_responses/corpus-v2-control/responses.jsonl \\
    --out-dir data/reports/raw-runs/reviewer-lora-v1.10-control

Then commit --out-dir alongside the corresponding scored report under
data/reports/, following the existing `data/reports/*-responses.jsonl`
convention (see docs/DECISIONS.md for prior examples).
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Callable

# (repo_id, path_in_repo, repo_type) -> local filesystem Path of the
# downloaded file. Injected so fetch_run() is testable without
# huggingface_hub installed or any network access.
DownloadFn = Callable[[str, str, str], Path]


def sha256_of(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def default_manifest_path_for(responses_path: str) -> str:
    """run_manifest.json lives alongside responses.jsonl in the same repo dir
    (see lora/hf_gate_pilot_job.py's manifest_path_for, the same convention)."""
    parent = Path(responses_path).parent
    return "run_manifest.json" if str(parent) == "." else str(parent / "run_manifest.json")


def fetch_run(
    *,
    adapter_repo: str,
    responses_path: str,
    out_dir: Path,
    download_fn: DownloadFn,
    manifest_path: str | None = None,
    verify: bool = True,
) -> dict:
    """Download responses.jsonl (+ run_manifest.json, if present) into
    out_dir. Raises RuntimeError if verify=True and the downloaded
    responses.jsonl doesn't match the manifest's recorded response_sha256 —
    that mismatch means the local copy is not the run the manifest
    describes, and treating it as provenance would be worse than having
    none. Missing manifest (older runs, predating this instrumentation) is
    not an error: manifest_present=False is reported instead."""
    manifest_path = manifest_path or default_manifest_path_for(responses_path)
    out_dir.mkdir(parents=True, exist_ok=True)

    downloaded_responses = download_fn(adapter_repo, responses_path, "model")
    dest_responses = out_dir / "responses.jsonl"
    dest_responses.write_bytes(Path(downloaded_responses).read_bytes())
    actual_sha256 = sha256_of(dest_responses)

    manifest_obj = None
    try:
        downloaded_manifest = download_fn(adapter_repo, manifest_path, "model")
        dest_manifest = out_dir / "run_manifest.json"
        dest_manifest.write_bytes(Path(downloaded_manifest).read_bytes())
        manifest_obj = json.loads(dest_manifest.read_text())
    except Exception:
        manifest_obj = None

    verified = None
    if verify and manifest_obj and manifest_obj.get("response_sha256"):
        expected = manifest_obj["response_sha256"]
        verified = actual_sha256 == expected
        if not verified:
            raise RuntimeError(
                f"responses.jsonl sha256 mismatch: manifest says {expected}, "
                f"downloaded file hashes to {actual_sha256} — refusing to "
                "treat this local copy as verified run provenance."
            )

    return {
        "adapter_repo": adapter_repo,
        "responses_path": responses_path,
        "manifest_path": manifest_path,
        "out_dir": str(out_dir),
        "response_sha256": actual_sha256,
        "manifest_present": manifest_obj is not None,
        "verified": verified,
    }


def _hf_hub_download_fn(repo_id: str, path_in_repo: str, repo_type: str) -> Path:
    from huggingface_hub import hf_hub_download

    return Path(hf_hub_download(repo_id=repo_id, filename=path_in_repo, repo_type=repo_type))


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--adapter-repo", required=True, help="e.g. adastracomputing/reviewer-lora-v1.10")
    ap.add_argument("--responses-path", default="gate_pilot_responses/responses.jsonl",
                     help="path in the adapter repo, as passed to RESPONSES_PATH at dispatch")
    ap.add_argument("--manifest-path", default=None,
                     help="defaults to run_manifest.json alongside --responses-path")
    ap.add_argument("--out-dir", required=True, type=Path)
    ap.add_argument("--no-verify", action="store_true",
                     help="skip response_sha256 verification against the manifest")
    args = ap.parse_args()

    summary = fetch_run(
        adapter_repo=args.adapter_repo,
        responses_path=args.responses_path,
        manifest_path=args.manifest_path,
        out_dir=args.out_dir,
        download_fn=_hf_hub_download_fn,
        verify=not args.no_verify,
    )
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()
