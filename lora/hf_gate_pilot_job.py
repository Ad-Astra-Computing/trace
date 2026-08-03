# /// script
# requires-python = ">=3.10"
# dependencies = [
#   "torch==2.5.1",
#   "transformers==4.47.1",
#   "accelerate==1.2.1",
#   "peft==0.14.0",
#   "bitsandbytes==0.45.0",
#   "huggingface-hub>=0.26.0",
# ]
# ///
"""
Reviewer-LoRA mixed gate pilot — inference on test split (positives + negatives).

Reads gate-pilot.jsonl from /data (uploaded before job submission), runs the
adapter, pushes gate_pilot_responses/responses.jsonl to the adapter repo.
Score locally with eval/score_gate_pilot.py.

Gate: 0 false rejects (positives → accept) + 0 false accepts (negatives → reject).

Alongside responses.jsonl this job also pushes run_manifest.json (decode
settings, base model + revision, adapter repo + resolved revision, input
sha256, timestamp) so a run stays fully re-scorable offline without
re-pulling artifacts or re-running: pull both files down with
lora/fetch_gate_pilot_run.py after the job completes and keep them under
version control (see docs/REVIEWER_LORA_PILOT.md). responses.jsonl's schema
is unchanged from prior versions of this script — the manifest is a purely
additive artifact.

Submission:
  hf jobs uv run --flavor l40sx1 --namespace odoom \\
    --secrets HF_TOKEN \\
    -v hf://datasets/adastracomputing/reviewer-lora-data:/data:ro \\
    -e DATA_DIR=/data -e HF_HOME=/tmp/hf \\
    -e ADAPTER_REPO=adastracomputing/reviewer-lora-v1.1 \\
    lora/hf_gate_pilot_job.py

Optional env vars (all additive / backward compatible):
  RUN_TIMESTAMP    - timestamp for run_manifest.json, e.g. from the
                      submitting shell (`date -u +%Y-%m-%dT%H:%M:%SZ`).
                      Never computed inside this script (matches
                      lora/hf_job.py's TRACE_COMMIT/DATASET_COMMIT
                      env-var-provenance convention: the caller passes
                      in provenance, the job script does not invent it).
                      Defaults to "unknown" if not supplied.
  ADAPTER_REVISION - pin the adapter commit sha to record in the manifest.
                      If unset, resolved via HfApi().model_info(...).sha at
                      runtime (falls back to "unknown" on failure, e.g. no
                      network).
"""
import hashlib
import json
import os
from pathlib import Path

BASE_MODEL = "Qwen/Qwen2.5-Coder-14B-Instruct"
BASE_REVISION = "aedcc2d42b622764e023cf882b6652e646b95671"
MAX_NEW_TOKENS = 1024


# --- Pure helpers (stdlib only) -------------------------------------------
#
# Deliberately free of torch/peft/transformers/huggingface_hub imports so
# this module can be loaded (spec_from_file_location + exec_module) and its
# manifest/serialization logic unit-tested without GPU deps or network. The
# heavy ML imports are deferred into main() below for the same reason. This
# script is still uploaded and run standalone via `hf jobs uv run` (PEP 723,
# no sibling-module imports work remotely), so all logic used by main() must
# live in this one file.


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_text(text: str) -> str:
    return sha256_bytes(text.encode())


def build_response_row(*, prov: dict, label, split, user_text: str, generated: str) -> dict:
    """The existing (unchanged) per-row schema pushed to responses.jsonl."""
    return {
        "cve_id": prov.get("cve_id"),
        "attr_path": prov.get("attr_path"),
        "bundle_id": prov.get("bundle_id"),
        "label": label,
        "split": split,
        "mutation_type": prov.get("mutation_type"),
        "user_sha256": sha256_text(user_text),
        "generated": generated,
    }


def build_decode_settings(
    *,
    do_sample: bool,
    max_new_tokens: int,
    temperature: float | None = None,
    top_p: float | None = None,
    seed: int | None = None,
    pad_token_id=None,
) -> dict:
    """Decode settings actually used for generation. temperature/top_p are
    recorded as None when do_sample is False (greedy decoding) — they are
    not consulted by generate() in that mode, so recording a stale default
    would misrepresent what happened."""
    return {
        "do_sample": do_sample,
        "max_new_tokens": max_new_tokens,
        "temperature": temperature if do_sample else None,
        "top_p": top_p if do_sample else None,
        "seed": seed,
        "pad_token_id": pad_token_id,
    }


def assert_responses_path_free(
    api,
    repo_id: str,
    path_in_repo: str,
    allow_overwrite: bool,
) -> None:
    """Refuse to clobber an existing responses file.

    The multi-seed v1.11 design runs the SAME submit script several times (2 arms
    x 3 training seeds). `RESPONSES_PATH` is a fixed string in those scripts, so a
    second run silently overwrites the first's raw responses in the adapter repo —
    which is precisely how the 2026-07-28 v1.10 control run became unrecoverable.
    Fail loudly instead, unless the caller explicitly opts in via
    ALLOW_RESPONSES_OVERWRITE=1. Best-effort: a listing failure must never abort a
    completed inference run, so we warn and continue.
    """
    if allow_overwrite:
        return
    try:
        existing = set(api.list_repo_files(repo_id=repo_id, repo_type="model"))
    except Exception as e:  # noqa: BLE001 - never lose a finished run to a listing error
        print(f"WARNING: could not list {repo_id} to check for overwrite: {e}", flush=True)
        return
    if path_in_repo in existing:
        raise RuntimeError(
            f"refusing to overwrite existing {repo_id}/{path_in_repo}. "
            "Set a per-run RESPONSES_PATH (recommended: include the seed/arm), "
            "or set ALLOW_RESPONSES_OVERWRITE=1 to override deliberately."
        )


def manifest_path_for(responses_path_in_repo: str) -> str:
    """run_manifest.json lives alongside responses.jsonl in the same repo dir."""
    parent = Path(responses_path_in_repo).parent
    return "run_manifest.json" if str(parent) == "." else str(parent / "run_manifest.json")


def build_run_manifest(
    *,
    task: str,
    timestamp: str,
    base_model: str,
    base_model_revision: str,
    adapter_repo: str,
    adapter_revision: str | None,
    decode: dict,
    input_filename: str,
    input_sha256: str,
    row_count: int,
    responses_path: str,
    response_sha256: str,
) -> dict:
    """Ties a gate-pilot inference run to its full provenance: mirrors the
    run_manifest.json convention in lora/hf_job.py (training). input_sha256
    reuses the SAME hash the harness already pins via EXPECTED_INPUT_SHA256 —
    there is no second hashing scheme."""
    return {
        "task": task,
        "timestamp": timestamp,
        "base_model": base_model,
        "base_model_revision": base_model_revision,
        "adapter_repo": adapter_repo,
        "adapter_revision": adapter_revision or "unknown",
        "decode": decode,
        "input_filename": input_filename,
        "input_sha256": input_sha256,
        "row_count": row_count,
        "responses_path": responses_path,
        "response_sha256": response_sha256,
    }


def write_jsonl(path: Path, rows) -> None:
    path.write_text("\n".join(json.dumps(r) for r in rows) + "\n")


def write_json(path: Path, obj: dict) -> None:
    path.write_text(json.dumps(obj, indent=2))


# --- Job entrypoint (heavy ML imports deferred to here) --------------------


def main():
    import torch
    from huggingface_hub import HfApi
    from peft import PeftModel
    from transformers import AutoModelForCausalLM, AutoTokenizer, BitsAndBytesConfig

    data_dir = Path(os.environ.get("DATA_DIR", "/data"))
    adapter_repo = os.environ.get("ADAPTER_REPO", "adastracomputing/reviewer-lora-v1.1")

    pilot_path = data_dir / "gate-pilot.jsonl"
    if not pilot_path.exists():
        raise FileNotFoundError(f"{pilot_path} not found in mounted dataset")
    pilot_bytes = pilot_path.read_bytes()
    actual_input_sha256 = sha256_bytes(pilot_bytes)
    expected_input_sha256 = os.environ.get("EXPECTED_INPUT_SHA256")
    if expected_input_sha256 and actual_input_sha256 != expected_input_sha256:
        raise RuntimeError(
            f"EXPECTED_INPUT_SHA256 mismatch for {pilot_path}: "
            f"expected {expected_input_sha256}, got {actual_input_sha256} "
            "(the mounted dataset file may have changed since dispatch)"
        )
    records = [json.loads(l) for l in pilot_bytes.decode().splitlines() if l.strip()]
    print(f"Gate pilot: {len(records)} examples  adapter={adapter_repo}", flush=True)

    tokenizer = AutoTokenizer.from_pretrained(BASE_MODEL, revision=BASE_REVISION)
    bnb_config = BitsAndBytesConfig(
        load_in_4bit=True,
        bnb_4bit_quant_type="nf4",
        bnb_4bit_compute_dtype=torch.bfloat16,
        bnb_4bit_use_double_quant=True,
    )
    base = AutoModelForCausalLM.from_pretrained(
        BASE_MODEL, revision=BASE_REVISION,
        quantization_config=bnb_config, device_map="auto",
    )
    model = PeftModel.from_pretrained(base, adapter_repo)
    model.eval()

    do_sample = False
    responses = []
    for i, rec in enumerate(records):
        msgs = rec["messages"][:2]  # system + user only
        text = tokenizer.apply_chat_template(msgs, tokenize=False, add_generation_prompt=True)
        inputs = tokenizer(text, return_tensors="pt").to(model.device)
        with torch.inference_mode():
            out = model.generate(
                **inputs,
                max_new_tokens=MAX_NEW_TOKENS,
                do_sample=do_sample,
                pad_token_id=tokenizer.eos_token_id,
            )
        response_ids = out[0][inputs["input_ids"].shape[-1]:]
        response = tokenizer.decode(response_ids, skip_special_tokens=True).strip()
        prov = rec.get("provenance", {})
        user_text = next(
            (m["content"] for m in rec.get("messages", []) if m.get("role") == "user"), ""
        )
        entry = build_response_row(
            prov=prov, label=rec.get("label"), split=rec.get("split"),
            user_text=user_text, generated=response,
        )
        responses.append(entry)
        print(f"[{i+1}/{len(records)}] {prov.get('cve_id')} ({rec.get('label')}) done", flush=True)

    out_path = Path("/tmp/gate_pilot_responses.jsonl")
    write_jsonl(out_path, responses)
    path_in_repo = os.environ.get("RESPONSES_PATH", "gate_pilot_responses/responses.jsonl")
    assert_responses_path_free(
        HfApi(),
        repo_id=adapter_repo,
        path_in_repo=path_in_repo,
        allow_overwrite=os.environ.get("ALLOW_RESPONSES_OVERWRITE") == "1",
    )
    HfApi().upload_file(
        path_or_fileobj=str(out_path),
        path_in_repo=path_in_repo,
        repo_id=adapter_repo,
        repo_type="model",
    )
    response_sha256 = sha256_bytes(out_path.read_bytes())
    print(f"response_sha256={response_sha256} adapter={adapter_repo}", flush=True)
    print(f"Pushed {len(responses)} responses to {adapter_repo}/{path_in_repo}", flush=True)

    # Adapter revision: pin via env var if supplied, else resolve at runtime.
    adapter_revision = os.environ.get("ADAPTER_REVISION")
    if not adapter_revision:
        try:
            adapter_revision = HfApi().model_info(adapter_repo).sha
        except Exception as e:  # noqa: BLE001 - best-effort provenance, never fatal
            print(f"WARNING: could not resolve adapter_revision for {adapter_repo}: {e}", flush=True)
            adapter_revision = "unknown"

    decode = build_decode_settings(
        do_sample=do_sample,
        max_new_tokens=MAX_NEW_TOKENS,
        pad_token_id=tokenizer.eos_token_id,
    )
    manifest = build_run_manifest(
        task="reviewer-lora-gate-pilot",
        timestamp=os.environ.get("RUN_TIMESTAMP", "unknown"),
        base_model=BASE_MODEL,
        base_model_revision=BASE_REVISION,
        adapter_repo=adapter_repo,
        adapter_revision=adapter_revision,
        decode=decode,
        input_filename=pilot_path.name,
        input_sha256=actual_input_sha256,
        row_count=len(responses),
        responses_path=path_in_repo,
        response_sha256=response_sha256,
    )
    manifest_local = Path("/tmp/gate_pilot_run_manifest.json")
    write_json(manifest_local, manifest)
    manifest_path_in_repo = manifest_path_for(path_in_repo)
    HfApi().upload_file(
        path_or_fileobj=str(manifest_local),
        path_in_repo=manifest_path_in_repo,
        repo_id=adapter_repo,
        repo_type="model",
    )
    print("Manifest:\n" + json.dumps(manifest, indent=2), flush=True)
    print(f"Pushed manifest to {adapter_repo}/{manifest_path_in_repo}", flush=True)


if __name__ == "__main__":
    main()
