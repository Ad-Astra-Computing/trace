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
"""Samplability diagnostic for the fold-UNREACHABLE canaries (bzip2, pyjwt).

pass@64 never produced the folds for bzip2 (a single bounds-guard line with a specific
constant) or pyjwt (a functional empty-key guard buried in a 23-line block). Is that
ZERO probability mass (the fix is outside the model's distribution → only training data
containing the shape can reach it) or LOW mass (samplable with a nudge)? Two probes from
one adapter load, on the SFT seed:

1. TEMPERATURE SWEEP (no forcing): K samples per canary at temp {0.3, 1.0, 1.4}. If a
   higher temperature surfaces the fold's functional key line, it's low-mass; if never,
   zero-mass at these budgets.
2. PREFIX-FORCED DECODE: feed the reference diff truncated at a cut point as forced
   decoder tokens, then free-run. If the model COMPLETES the fold given its start, the
   knowledge is present (a decoding/search problem); if it diverges even when started,
   the shape itself is not learned. Cuts at 25/50/75% of the reference diff.

Raw generations are uploaded for offline scoring (grep the functional key line); this
job only generates. This is a DIAGNOSTIC, not a production lever — it does not modify the
production prompt (unlike the retired inference-injection arm).

Env: ADAPTER_REPO, DATASET_REPO (canaries), SWEEP_K (8).
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
BASE_MODEL_ID = "Qwen/Qwen2.5-Coder-14B-Instruct"
MODEL_REVISION = "aedcc2d42b622764e023cf882b6652e646b95671"
MAX_NEW_TOKENS = 512
SWEEP_K = int(os.environ.get("SWEEP_K", "8"))
TEMPS = [0.3, 1.0, 1.4]
CUTS = [0.25, 0.5, 0.75]
# the fold-unreachable canaries
TARGETS = ["CVE-2026-42250", "CVE-2026-48526"]


def load_canaries(dataset_repo):
    from huggingface_hub import hf_hub_download
    path = hf_hub_download(repo_id=dataset_repo, filename="authoring.canary.jsonl", repo_type="dataset")
    out = {}
    for line in Path(path).read_text().splitlines():
        if not line.strip():
            continue
        r = json.loads(line)
        cve = (r.get("provenance") or {}).get("cve_id")
        out.setdefault(cve, r)
    return out


def _prompt_ids(tok, system, user, forced_prefix=""):
    msgs = [{"role": "system", "content": system}, {"role": "user", "content": user}]
    text = tok.apply_chat_template(msgs, tokenize=False, add_generation_prompt=True)
    text += forced_prefix  # forced decoder continuation (prefix-forced decode)
    return tok(text, return_tensors="pt")


def main():
    canaries = load_canaries(DATASET_REPO)
    bnb = BitsAndBytesConfig(load_in_4bit=True, bnb_4bit_quant_type="nf4",
                             bnb_4bit_compute_dtype=torch.bfloat16, bnb_4bit_use_double_quant=True)
    tok = AutoTokenizer.from_pretrained(BASE_MODEL_ID, revision=MODEL_REVISION)
    base = AutoModelForCausalLM.from_pretrained(BASE_MODEL_ID, revision=MODEL_REVISION,
                                                quantization_config=bnb, device_map="auto")
    model = PeftModel.from_pretrained(base, ADAPTER_REPO)
    model.eval()

    rows = []
    for cve in TARGETS:
        rec = canaries.get(cve)
        if rec is None:
            print(f"WARN {cve} missing", flush=True)
            continue
        system = rec["messages"][0]["content"]
        user = rec["messages"][1]["content"]
        ref = rec["messages"][2]["content"]

        # 1. temperature sweep (no forcing)
        for temp in TEMPS:
            ins = _prompt_ids(tok, system, user).to(model.device)
            with torch.no_grad():
                out = model.generate(**ins, max_new_tokens=MAX_NEW_TOKENS, do_sample=True,
                                     temperature=temp, top_p=0.95, num_return_sequences=SWEEP_K)
            plen = ins["input_ids"].shape[1]
            for s in range(SWEEP_K):
                g = tok.decode(out[s][plen:], skip_special_tokens=True).strip()
                rows.append({"cve_id": cve, "probe": "temp_sweep", "temp": temp,
                             "sample": s, "generated": g})
            print(f"  {cve} temp {temp}: {SWEEP_K} done", flush=True)

        # 2. prefix-forced decode (feed reference truncated at each cut, complete greedily)
        ref_lines = ref.splitlines(keepends=True)
        for cut in CUTS:
            n = max(1, int(len(ref_lines) * cut))
            forced = "".join(ref_lines[:n])
            ins = _prompt_ids(tok, system, user, forced_prefix=forced).to(model.device)
            with torch.no_grad():
                out = model.generate(**ins, max_new_tokens=MAX_NEW_TOKENS, do_sample=False)
            plen = ins["input_ids"].shape[1]
            cont = tok.decode(out[0][plen:], skip_special_tokens=True).strip()
            rows.append({"cve_id": cve, "probe": "prefix_force", "cut": cut,
                         "forced": forced, "generated": cont,
                         "reconstructed": forced + cont})
            print(f"  {cve} prefix-force cut {cut}: done", flush=True)

    out_path = Path("/tmp/samplability-responses.jsonl")
    out_path.write_text("\n".join(json.dumps(r) for r in rows) + "\n")
    from huggingface_hub import HfApi
    HfApi().upload_file(path_or_fileobj=str(out_path),
                        path_in_repo="samplability-responses.jsonl",
                        repo_id=ADAPTER_REPO, repo_type="model")
    print(f"Uploaded {len(rows)} probe rows to {ADAPTER_REPO}/samplability-responses.jsonl", flush=True)


if __name__ == "__main__":
    main()
