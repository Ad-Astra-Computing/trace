# /// script
# requires-python = ">=3.10"
# dependencies = [
#   "torch==2.5.1",
#   "transformers==4.47.1",
#   "peft==0.14.0",
#   "bitsandbytes==0.45.0",
#   "datasets==3.2.0",
#   "accelerate==1.2.1",
#   "huggingface-hub>=0.26.0",
# ]
# ///
"""DPO on-policy generation pass — surface the authoring-LoRA guard-clip failures.

Samples the SFT seed adapter K times per TRAINING prompt at temperature, so the
guard-clip attractor (insert a separate clamp/guard instead of folding the existing
condition) shows up in the sample distribution even where greedy is correct. The
sampled generations are the RAW material for DPO `rejected`; the reference fix (the
assistant turn) is the `chosen`. Local harvest (lora/build_dpo_guard_clip.py) filters
these to wrong + clip-shaped pairs — this job only generates and logs.

Prompts are the seed's own training prompts (authoring-lora-data-v10-clean, 68 rows),
disjoint from the 4 eval canaries, so the held-out canary eval stays clean. Each row is
tagged `comparison_bearing` (the ref modifies/introduces a comparison) so the filter and
its counts are transparent.

Outputs, uploaded to the adapter model repo:
  dpo-gen-train-samples.jsonl : {train_idx, cve_id, attr_path, comparison_bearing,
                                 reference, sample, generated}

Env: ADAPTER_REPO, TRAIN_REPO, GEN_K (default 12), TEMP (0.9), TOP_P (0.95).
"""
import json
import os
import re
from pathlib import Path

import torch
from peft import PeftModel
from transformers import AutoModelForCausalLM, AutoTokenizer, BitsAndBytesConfig

ADAPTER_REPO = os.environ.get("ADAPTER_REPO", "adastracomputing/authoring-lora-v10-clean")
TRAIN_REPO = os.environ.get("TRAIN_REPO", "adastracomputing/authoring-lora-data-v10-clean")
UPLOAD_REPO = os.environ.get("UPLOAD_REPO", ADAPTER_REPO)
BASE_MODEL_ID = "Qwen/Qwen2.5-Coder-14B-Instruct"
MODEL_REVISION = "aedcc2d42b622764e023cf882b6652e646b95671"
MAX_NEW_TOKENS = int(os.environ.get("MAX_NEW_TOKENS", "640"))
K = int(os.environ.get("GEN_K", "12"))
TEMP = float(os.environ.get("TEMP", "0.9"))
TOP_P = float(os.environ.get("TOP_P", "0.95"))

_CMP = re.compile(r"(<=|>=|==|!=|<|>|&&|\|\|)")


def _added(diff):
    return [l[1:] for l in diff.splitlines() if l.startswith("+") and not l.startswith("+++")]


def _removed(diff):
    return [l[1:] for l in diff.splitlines() if l.startswith("-") and not l.startswith("---")]


def _comparison_bearing(ref: str) -> bool:
    """The reference edit modifies or introduces a comparison (fold or add-comparison) —
    the shape class where the guard-clip-vs-condition-fold contrast lives."""
    return any(_CMP.search(x) for x in _added(ref))


def load_train(train_repo: str) -> list:
    from huggingface_hub import hf_hub_download
    path = hf_hub_download(repo_id=train_repo, filename="authoring.train.jsonl", repo_type="dataset")
    return [json.loads(l) for l in Path(path).read_text().splitlines() if l.strip()]


def gen(model, tok, system: str, user: str):
    msgs = [{"role": "system", "content": system}, {"role": "user", "content": user}]
    text = tok.apply_chat_template(msgs, tokenize=False, add_generation_prompt=True)
    inputs = tok(text, return_tensors="pt").to(model.device)
    with torch.no_grad():
        out = model.generate(**inputs, max_new_tokens=MAX_NEW_TOKENS,
                             do_sample=True, temperature=TEMP, top_p=TOP_P)
    return tok.decode(out[0][inputs["input_ids"].shape[1]:], skip_special_tokens=True).strip()


def main():
    train_rows = load_train(TRAIN_REPO)
    n_cb = sum(1 for r in train_rows
               if _comparison_bearing(r["messages"][2]["content"]))
    print(f"Loaded {len(train_rows)} train rows; comparison-bearing={n_cb}; "
          f"K={K} temp={TEMP} top_p={TOP_P}", flush=True)

    bnb = BitsAndBytesConfig(load_in_4bit=True, bnb_4bit_quant_type="nf4",
                             bnb_4bit_compute_dtype=torch.bfloat16, bnb_4bit_use_double_quant=True)
    tok = AutoTokenizer.from_pretrained(BASE_MODEL_ID, revision=MODEL_REVISION)
    base = AutoModelForCausalLM.from_pretrained(BASE_MODEL_ID, revision=MODEL_REVISION,
                                                quantization_config=bnb, device_map="auto")
    print(f"=== Attaching adapter ({ADAPTER_REPO}) ===", flush=True)
    model = PeftModel.from_pretrained(base, ADAPTER_REPO)
    model.eval()

    samples = []
    for i, row in enumerate(train_rows):
        m = row["messages"]
        system, user, ref = m[0]["content"], m[1]["content"], m[2]["content"]
        prov = row.get("provenance") or {}
        cb = _comparison_bearing(ref)
        for s in range(K):
            g = gen(model, tok, system, user)
            samples.append({
                "train_idx": i,
                "cve_id": prov.get("cve_id"),
                "attr_path": prov.get("attr_path"),
                "comparison_bearing": cb,
                "reference": ref,
                "sample": s,
                "generated": g,
            })
        print(f"  [{i+1}/{len(train_rows)}] {prov.get('attr_path')} cb={cb} "
              f"{K} samples done", flush=True)

    out = Path("/tmp/dpo-gen-train-samples.jsonl")
    out.write_text("\n".join(json.dumps(r) for r in samples) + "\n")
    print(f"Wrote {len(samples)} samples", flush=True)

    from huggingface_hub import HfApi
    HfApi().upload_file(path_or_fileobj=str(out), path_in_repo="dpo-gen-train-samples.jsonl",
                        repo_id=UPLOAD_REPO, repo_type="model")
    print(f"Uploaded {UPLOAD_REPO}/dpo-gen-train-samples.jsonl", flush=True)


if __name__ == "__main__":
    main()
