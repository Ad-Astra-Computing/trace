#!/usr/bin/env python3
# /// script
# requires-python = ">=3.11"
# dependencies = [
#   "torch>=2.3",
#   "transformers>=4.43",
#   "peft>=0.11",
#   "huggingface-hub>=0.23",
#   "accelerate>=0.30",
#   "bitsandbytes>=0.43",
# ]
# ///
"""Generate authoring test-split responses using the Authoring-LoRA v0.2 adapter.

Loaded as an HF Job (hf jobs uv run) on A100-large.

Steps:
  1. Load Qwen2.5-Coder-14B-Instruct base model in 4-bit nf4 (QLoRA inference).
  2. Merge the LoRA adapter from adastracomputing/authoring-lora-v0.2.
  3. For each of the 4 test-split records (read from the dataset), generate
     a response at temperature=0.
  4. Save the responses as JSONL + upload to
     adastracomputing/authoring-lora-canary-responses as
     authoring-lora-v0.2-test-split-responses.jsonl
"""
import json
import os
import tempfile
from pathlib import Path

from huggingface_hub import HfApi, hf_hub_download
from peft import PeftModel
from transformers import AutoModelForCausalLM, AutoTokenizer, BitsAndBytesConfig
import torch

HF_TOKEN       = os.environ["HF_TOKEN"]
BASE_MODEL_ID  = "Qwen/Qwen2.5-Coder-14B-Instruct"
BASE_REVISION  = "aedcc2d42b622764e023cf882b6652e646b95671"
ADAPTER_REPO   = "adastracomputing/authoring-lora-v0.2"
DATA_REPO      = "adastracomputing/authoring-lora-data"
TEST_PATH      = "authoring.test.jsonl"
RESPONSES_REPO = "adastracomputing/authoring-lora-canary-responses"
MAX_NEW_TOKENS = 4096

print("Loading test-split records …")
test_file = hf_hub_download(
    repo_id=DATA_REPO,
    filename=TEST_PATH,
    repo_type="dataset",
    token=HF_TOKEN,
)
records = [json.loads(l) for l in Path(test_file).read_text().splitlines() if l.strip()]
print(f"  {len(records)} test-split records loaded")

print("Loading base model in 4-bit nf4 …")
bnb_config = BitsAndBytesConfig(
    load_in_4bit=True,
    bnb_4bit_quant_type="nf4",
    bnb_4bit_compute_dtype=torch.bfloat16,
    bnb_4bit_use_double_quant=True,
)
tokenizer = AutoTokenizer.from_pretrained(
    BASE_MODEL_ID,
    revision=BASE_REVISION,
    trust_remote_code=True,
    token=HF_TOKEN,
)
base = AutoModelForCausalLM.from_pretrained(
    BASE_MODEL_ID,
    revision=BASE_REVISION,
    quantization_config=bnb_config,
    device_map="auto",
    torch_dtype=torch.bfloat16,
    trust_remote_code=True,
    token=HF_TOKEN,
)
print("  base model loaded")

print(f"Loading adapter from {ADAPTER_REPO} …")
model = PeftModel.from_pretrained(base, ADAPTER_REPO, token=HF_TOKEN)
model.eval()
print("  adapter loaded")

responses = []
for rec in records:
    # Records in the dataset have messages with system/user/assistant roles.
    # The assistant turn is the label (upstream-fix.patch) — we generate from
    # system + user only.
    msgs = rec["messages"]
    system = next(m["content"] for m in msgs if m["role"] == "system")
    user   = next(m["content"] for m in msgs if m["role"] == "user")
    # Identify the example: use cve_id from provenance if present, else from messages metadata
    cve = rec.get("provenance", {}).get("cve_id", rec.get("cve_id", f"idx-{len(responses)}"))

    chat = [{"role": "system", "content": system},
            {"role": "user",   "content": user}]
    prompt = tokenizer.apply_chat_template(
        chat, tokenize=False, add_generation_prompt=True
    )
    inputs = tokenizer(prompt, return_tensors="pt").to(model.device)
    with torch.no_grad():
        out = model.generate(
            **inputs,
            max_new_tokens=MAX_NEW_TOKENS,
            temperature=1.0,
            do_sample=False,
            pad_token_id=tokenizer.eos_token_id,
        )
    generated_ids = out[0][inputs["input_ids"].shape[1]:]
    text = tokenizer.decode(generated_ids, skip_special_tokens=True).strip()

    responses.append({"cve_id": cve, "generated": text})
    print(f"  {cve}: {len(text)} chars")

api = HfApi(token=HF_TOKEN)
try:
    api.create_repo(repo_id=RESPONSES_REPO, repo_type="dataset", private=True, exist_ok=True)
except Exception as e:
    print(f"  (repo create: {e})")

with tempfile.NamedTemporaryFile(mode="w", suffix=".jsonl", delete=False) as fh:
    for r in responses:
        fh.write(json.dumps(r) + "\n")
    tmp = fh.name

api.upload_file(
    path_or_fileobj=tmp,
    path_in_repo="authoring-lora-v0.2-test-split-responses.jsonl",
    repo_id=RESPONSES_REPO,
    repo_type="dataset",
    commit_message="authoring-lora-v0.2 test-split responses",
)
print(f"Uploaded {len(responses)} responses to {RESPONSES_REPO}")

print("\n=== RESPONSES ===")
print(json.dumps(responses, indent=2))
