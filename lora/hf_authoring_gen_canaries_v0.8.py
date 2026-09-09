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
"""
Authoring-LoRA v0.8 canary inference — HF Jobs UV-script.

Loads the v0.8 adapter from adastracomputing/authoring-lora-v0.8, runs inference
on the 4 canary examples from adastracomputing/authoring-lora-data-v5, and uploads
responses to adastracomputing/authoring-lora-v0.8 as canary-responses.jsonl.

Usage (see lora/submit_hf_gen_canaries_v0.8.sh):
  hf jobs uv run --flavor a100-large --namespace odoom \\
    --secrets HF_TOKEN \\
    lora/hf_authoring_gen_canaries_v0.8.py
"""

import json
import os
from pathlib import Path

import torch
from peft import PeftModel
from transformers import AutoModelForCausalLM, AutoTokenizer, BitsAndBytesConfig

ADAPTER_REPO = os.environ.get("ADAPTER_REPO", "adastracomputing/authoring-lora-v0.8")
DATASET_REPO = os.environ.get("DATASET_REPO", "adastracomputing/authoring-lora-data-v5")
BASE_MODEL_ID = "Qwen/Qwen2.5-Coder-14B-Instruct"
MODEL_REVISION = "aedcc2d42b622764e023cf882b6652e646b95671"
MAX_NEW_TOKENS = 1024
TEMPERATURE = 0.0


def load_canary(dataset_repo: str) -> list[dict]:
    from huggingface_hub import hf_hub_download

    path = hf_hub_download(
        repo_id=dataset_repo,
        filename="authoring.canary.jsonl",
        repo_type="dataset",
    )
    with open(path) as f:
        return [json.loads(l) for l in f if l.strip()]


def generate(model, tokenizer, messages: list[dict]) -> str:
    text = tokenizer.apply_chat_template(
        messages[:-1],  # system + user only (no assistant turn for generation)
        tokenize=False,
        add_generation_prompt=True,
    )
    inputs = tokenizer(text, return_tensors="pt").to(model.device)
    with torch.no_grad():
        out = model.generate(
            **inputs,
            max_new_tokens=MAX_NEW_TOKENS,
            do_sample=False,
            temperature=None,
            top_p=None,
            pad_token_id=tokenizer.eos_token_id,
        )
    generated_ids = out[0][inputs["input_ids"].shape[1] :]
    return tokenizer.decode(generated_ids, skip_special_tokens=True).strip()


def main():
    print(f"Loading canary examples from {DATASET_REPO}", flush=True)
    records = load_canary(DATASET_REPO)
    print(f"  {len(records)} canary examples", flush=True)

    bnb_config = BitsAndBytesConfig(
        load_in_4bit=True,
        bnb_4bit_quant_type="nf4",
        bnb_4bit_compute_dtype=torch.bfloat16,
        bnb_4bit_use_double_quant=True,
    )

    print(f"Loading base model {BASE_MODEL_ID} @ {MODEL_REVISION}", flush=True)
    tokenizer = AutoTokenizer.from_pretrained(BASE_MODEL_ID, revision=MODEL_REVISION)
    tokenizer.pad_token = tokenizer.eos_token

    base = AutoModelForCausalLM.from_pretrained(
        BASE_MODEL_ID,
        revision=MODEL_REVISION,
        quantization_config=bnb_config,
        device_map="auto",
    )

    print(f"Loading adapter from {ADAPTER_REPO}", flush=True)
    model = PeftModel.from_pretrained(base, ADAPTER_REPO)
    model.eval()

    responses = []
    for rec in records:
        cve = rec["provenance"]["cve_id"]
        msgs = rec["messages"]
        print(f"Generating for {cve}...", flush=True)
        generated = generate(model, tokenizer, msgs)
        responses.append({"cve_id": cve, "generated": generated})
        print(f"  {len(generated)} chars", flush=True)

    # Write responses locally then upload
    out_path = Path("/tmp/canary-responses.jsonl")
    out_path.write_text("\n".join(json.dumps(r) for r in responses) + "\n")
    print(f"Responses written to {out_path}", flush=True)

    from huggingface_hub import HfApi

    api = HfApi()
    api.upload_file(
        path_or_fileobj=str(out_path),
        path_in_repo="canary-responses.jsonl",
        repo_id=ADAPTER_REPO,
        repo_type="model",
    )
    print(f"Responses uploaded to {ADAPTER_REPO}/canary-responses.jsonl", flush=True)


if __name__ == "__main__":
    main()
