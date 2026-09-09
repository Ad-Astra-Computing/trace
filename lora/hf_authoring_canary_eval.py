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
"""Canary eval for the guard-clip DPO — greedy (pass@1) + pass@K on the 4 canaries.

Runs on ANY adapter (SFT seed or the DPO adapter) so the two are scored on an identical
harness. Greedy tests the DPO success metric (did the fold shape move into greedy output);
pass@K is the diversity guardrail (DPO must not collapse the sampling lever).

Outputs, uploaded to the adapter repo:
  canary-greedy-responses.jsonl : {cve_id, variant:"greedy", generated}
  canary-passk-responses.jsonl  : {cve_id, variant:"original", sample, generated}

Score offline: python3 lora/score_canaries_graded.py <canary.jsonl> <greedy>.jsonl <passk>.jsonl

Env: ADAPTER_REPO, DATASET_REPO (canaries), PASSK (16), TEMP (0.9), TOP_P (0.95).
"""

import json
import os
import re
from pathlib import Path

import torch
from peft import PeftModel
from transformers import AutoModelForCausalLM, AutoTokenizer, BitsAndBytesConfig

ADAPTER_REPO = os.environ.get(
    "ADAPTER_REPO", "adastracomputing/authoring-lora-dpo-guard-clip"
)
DATASET_REPO = os.environ.get("DATASET_REPO", "adastracomputing/authoring-lora-data-v6")
BASE_MODEL_ID = "Qwen/Qwen2.5-Coder-14B-Instruct"
MODEL_REVISION = "aedcc2d42b622764e023cf882b6652e646b95671"
# 1024 to match the archived passk harness (pass@16 samples ramble longer than greedy;
# 384 truncates them mid-diff and floors add_recall). Keep configurable.
MAX_NEW_TOKENS = int(os.environ.get("MAX_NEW_TOKENS", "1024"))
K = int(os.environ.get("PASSK", "16"))
TEMP = float(os.environ.get("TEMP", "0.8"))
TOP_P = float(os.environ.get("TOP_P", "0.95"))
CVE_ORDER = ["CVE-2022-37434", "CVE-2026-42250", "CVE-2024-47081", "CVE-2026-48526"]


def load_canaries(dataset_repo: str) -> dict:
    from huggingface_hub import hf_hub_download

    path = hf_hub_download(
        repo_id=dataset_repo, filename="authoring.canary.jsonl", repo_type="dataset"
    )
    out = {}
    for line in Path(path).read_text().splitlines():
        if not line.strip():
            continue
        r = json.loads(line)
        cve = (r.get("provenance") or {}).get("cve_id")
        if not cve:
            m = re.search(r"CVE-\d{4}-\d+", json.dumps(r))
            cve = m.group(0) if m else None
        out.setdefault(cve, r)
    return out


def gen(model, tok, system, user, *, sample, k=1):
    msgs = [{"role": "system", "content": system}, {"role": "user", "content": user}]
    text = tok.apply_chat_template(msgs, tokenize=False, add_generation_prompt=True)
    inputs = tok(text, return_tensors="pt").to(model.device)
    kw = dict(max_new_tokens=MAX_NEW_TOKENS)
    if sample:
        kw.update(do_sample=True, temperature=TEMP, top_p=TOP_P, num_return_sequences=k)
    else:
        kw.update(do_sample=False)
    with torch.no_grad():
        out = model.generate(**inputs, **kw)
    plen = inputs["input_ids"].shape[1]
    return [tok.decode(s[plen:], skip_special_tokens=True).strip() for s in out]


def main():
    canaries = load_canaries(DATASET_REPO)
    bnb = BitsAndBytesConfig(
        load_in_4bit=True,
        bnb_4bit_quant_type="nf4",
        bnb_4bit_compute_dtype=torch.bfloat16,
        bnb_4bit_use_double_quant=True,
    )
    tok = AutoTokenizer.from_pretrained(BASE_MODEL_ID, revision=MODEL_REVISION)
    base = AutoModelForCausalLM.from_pretrained(
        BASE_MODEL_ID,
        revision=MODEL_REVISION,
        quantization_config=bnb,
        device_map="auto",
    )
    print(f"=== Attaching adapter ({ADAPTER_REPO}) ===", flush=True)
    model = PeftModel.from_pretrained(base, ADAPTER_REPO)
    model.eval()

    greedy, passk = [], []
    for cve in CVE_ORDER:
        rec = canaries.get(cve)
        if rec is None:
            print(f"  WARN canary {cve} missing", flush=True)
            continue
        system = rec["messages"][0]["content"]
        user = rec["messages"][1]["content"]
        # locate-then-rewrite arm (Fable): inject an inference-time instruction that
        # steers the edit SHAPE toward a condition-fold and away from a guard-clip.
        # Base64 to keep the multi-line instruction out of shell-escaping.
        import base64

        suffix_b64 = os.environ.get("USER_SUFFIX_B64", "")
        if suffix_b64:
            user = user + "\n\n" + base64.b64decode(suffix_b64).decode()
        g = gen(model, tok, system, user, sample=False)[0]
        greedy.append({"cve_id": cve, "variant": "greedy", "generated": g})
        for s, gg in enumerate(gen(model, tok, system, user, sample=True, k=K)):
            passk.append(
                {"cve_id": cve, "variant": "original", "sample": s, "generated": gg}
            )
        print(f"  {cve}: greedy + pass@{K} done", flush=True)

    from huggingface_hub import HfApi

    api = HfApi()
    tag = os.environ.get("OUTPUT_TAG", "")  # e.g. "lr-" to not clobber the baseline run
    for fn, rows in [
        (f"{tag}canary-greedy-responses.jsonl", greedy),
        (f"{tag}canary-passk-responses.jsonl", passk),
    ]:
        Path(f"/tmp/{fn}").write_text("\n".join(json.dumps(r) for r in rows) + "\n")
        api.upload_file(
            path_or_fileobj=f"/tmp/{fn}",
            path_in_repo=fn,
            repo_id=ADAPTER_REPO,
            repo_type="model",
        )
        print(f"Uploaded {ADAPTER_REPO}/{fn}", flush=True)


if __name__ == "__main__":
    main()
