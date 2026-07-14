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
"""Authoring-LoRA pass@K + memorization diagnostic — HF Jobs UV-script (codex/Fable plan).

Two diagnostics from ONE adapter load:

1. MEMORIZATION: regenerate a sample of the adapter's OWN training labels (greedy, same
   prompt). If it cannot reproduce its training edits, the free-form-diff setup is
   capacity/format inefficient (-> search/replace + loss-masking is justified). If it
   can, the ceiling is generalization.

2. pass@K: sample K candidates per canary (original window, temp>0). Scored OFFLINE with
   lora/score_canaries_graded.py (best-of-K). If pass@K >> pass@1, verifier-guided
   sampling is the production lever; if pass@K == 0, a genuine capability gap.

Outputs, uploaded to the adapter model repo:
  passk-responses.jsonl        : {cve_id, variant:"original", sample, generated}
  memcheck-responses.jsonl     : {train_idx, reference, generated}

Env: ADAPTER_REPO, DATASET_REPO (canaries), TRAIN_REPO (train labels), K (default 16),
TEMP (0.8), TOP_P (0.95), N_MEM (10).
"""
import json
import os
import re
from pathlib import Path

import torch
from peft import PeftModel
from transformers import AutoModelForCausalLM, AutoTokenizer, BitsAndBytesConfig

ADAPTER_REPO = os.environ.get("ADAPTER_REPO", "adastracomputing/authoring-lora-v10-clean")
DATASET_REPO = os.environ.get("DATASET_REPO", "adastracomputing/authoring-lora-data-v6")
TRAIN_REPO = os.environ.get("TRAIN_REPO", "adastracomputing/authoring-lora-data-v10-clean")
UPLOAD_REPO = os.environ.get("UPLOAD_REPO", ADAPTER_REPO)
BASE_MODEL_ID = "Qwen/Qwen2.5-Coder-14B-Instruct"
MODEL_REVISION = "aedcc2d42b622764e023cf882b6652e646b95671"
MAX_NEW_TOKENS = 1024
K = int(os.environ.get("PASSK", "16"))
TEMP = float(os.environ.get("TEMP", "0.8"))
TOP_P = float(os.environ.get("TOP_P", "0.95"))
N_MEM = int(os.environ.get("N_MEM", "10"))

CVE_ORDER = ["CVE-2022-37434", "CVE-2026-42250", "CVE-2024-47081", "CVE-2026-48526"]
FENCE_RE = re.compile(r"^(?P<head>.*?```)(?P<lang>\w+)\n(?P<code>.*?)\n```(?P<tail>.*)$", re.DOTALL)


def load_canaries(dataset_repo: str) -> dict:
    from huggingface_hub import hf_hub_download
    path = hf_hub_download(repo_id=dataset_repo, filename="authoring.canary.jsonl", repo_type="dataset")
    out = {}
    for line in Path(path).read_text().splitlines():
        if not line.strip():
            continue
        r = json.loads(line)
        cve = (r.get("provenance") or {}).get("cve_id")
        if not cve:
            m = re.search(r"CVE-\d{4}-\d+", json.dumps(r))
            cve = m.group(0) if m else None
        # keep the first record per cve (canary jsonl may carry 2 per cve)
        out.setdefault(cve, r)
    return out


def load_train(train_repo: str, n: int) -> list:
    from huggingface_hub import hf_hub_download
    path = hf_hub_download(repo_id=train_repo, filename="authoring.train.jsonl", repo_type="dataset")
    rows = [json.loads(l) for l in Path(path).read_text().splitlines() if l.strip()]
    return rows[:n]


def gen(model, tok, system: str, user: str, *, sample: bool):
    msgs = [{"role": "system", "content": system}, {"role": "user", "content": user}]
    text = tok.apply_chat_template(msgs, tokenize=False, add_generation_prompt=True)
    inputs = tok(text, return_tensors="pt").to(model.device)
    kwargs = dict(max_new_tokens=MAX_NEW_TOKENS)
    if sample:
        kwargs.update(do_sample=True, temperature=TEMP, top_p=TOP_P)
    else:
        kwargs.update(do_sample=False, temperature=None, top_p=None)
    with torch.no_grad():
        out = model.generate(**inputs, **kwargs)
    return tok.decode(out[0][inputs["input_ids"].shape[1]:], skip_special_tokens=True).strip()


def main():
    canaries = load_canaries(DATASET_REPO)
    train_rows = load_train(TRAIN_REPO, N_MEM)
    print(f"Loaded {len(canaries)} canaries, {len(train_rows)} train rows for memcheck", flush=True)

    bnb = BitsAndBytesConfig(load_in_4bit=True, bnb_4bit_quant_type="nf4",
                             bnb_4bit_compute_dtype=torch.bfloat16, bnb_4bit_use_double_quant=True)
    tok = AutoTokenizer.from_pretrained(BASE_MODEL_ID, revision=MODEL_REVISION)
    base = AutoModelForCausalLM.from_pretrained(BASE_MODEL_ID, revision=MODEL_REVISION,
                                                quantization_config=bnb, device_map="auto")
    print(f"=== Attaching adapter ({ADAPTER_REPO}) ===", flush=True)
    model = PeftModel.from_pretrained(base, ADAPTER_REPO)
    model.eval()

    # --- memorization (greedy) ---
    mem = []
    for i, row in enumerate(train_rows):
        m = row["messages"]
        system = m[0]["content"]
        user = m[1]["content"]
        ref = m[2]["content"]
        g = gen(model, tok, system, user, sample=False)
        mem.append({"train_idx": i, "reference": ref, "generated": g})
        print(f"  memcheck {i}: {len(g)} chars", flush=True)

    # --- pass@K (sampled) ---
    passk = []
    for cve in CVE_ORDER:
        rec = canaries.get(cve)
        if rec is None:
            print(f"  WARN canary {cve} missing", flush=True)
            continue
        system = rec["messages"][0]["content"]
        user = rec["messages"][1]["content"]
        for s in range(K):
            g = gen(model, tok, system, user, sample=True)
            passk.append({"cve_id": cve, "variant": "original", "sample": s, "generated": g})
        print(f"  pass@{K} {cve}: done", flush=True)

    Path("/tmp/passk-responses.jsonl").write_text("\n".join(json.dumps(r) for r in passk) + "\n")
    Path("/tmp/memcheck-responses.jsonl").write_text("\n".join(json.dumps(r) for r in mem) + "\n")

    from huggingface_hub import HfApi
    api = HfApi()
    for fn in ("passk-responses.jsonl", "memcheck-responses.jsonl"):
        api.upload_file(path_or_fileobj=f"/tmp/{fn}", path_in_repo=fn,
                        repo_id=UPLOAD_REPO, repo_type="model")
        print(f"Uploaded {UPLOAD_REPO}/{fn}", flush=True)


if __name__ == "__main__":
    main()
