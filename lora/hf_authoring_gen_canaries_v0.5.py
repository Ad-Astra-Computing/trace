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
"""Generate authoring-canary responses using the Authoring-LoRA v0.5 adapter.

Loaded as an HF Job (hf jobs uv run) on A100-large.

v0.5 vs v0.4:
  - Adapter: adastracomputing/authoring-lora-v0.5
  - Output file: authoring-lora-v0.5-responses.jsonl
  - 85 train rows (NLTK + python-jose detect-and-reject added)
"""

import json
import os
import tempfile
from pathlib import Path

from huggingface_hub import HfApi, hf_hub_download
from peft import PeftModel
from transformers import AutoModelForCausalLM, AutoTokenizer, BitsAndBytesConfig
import torch

HF_TOKEN = os.environ["HF_TOKEN"]
BASE_MODEL_ID = "Qwen/Qwen2.5-Coder-14B-Instruct"
BASE_REVISION = "aedcc2d42b622764e023cf882b6652e646b95671"
ADAPTER_REPO = "adastracomputing/authoring-lora-v0.5"
CANARY_REPO = "adastracomputing/authoring-lora-data"
CANARY_PATH = "authoring-canary.jsonl"
RESPONSES_REPO = "adastracomputing/authoring-lora-canary-responses"
MAX_NEW_TOKENS = 4096

print("Loading canary records …")
canary_file = hf_hub_download(
    repo_id=CANARY_REPO,
    filename=CANARY_PATH,
    repo_type="dataset",
    token=HF_TOKEN,
)
records = [
    json.loads(l) for l in Path(canary_file).read_text().splitlines() if l.strip()
]
print(f"  {len(records)} canary records loaded")
for r in records:
    print(f"  - {r['provenance']['cve_id']}")

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
    cve = rec["provenance"]["cve_id"]
    msgs = rec["messages"]
    system = next(m["content"] for m in msgs if m["role"] == "system")
    user = next(m["content"] for m in msgs if m["role"] == "user")

    chat = [{"role": "system", "content": system}, {"role": "user", "content": user}]
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
    generated_ids = out[0][inputs["input_ids"].shape[1] :]
    text = tokenizer.decode(generated_ids, skip_special_tokens=True).strip()

    responses.append({"cve_id": cve, "generated": text})
    print(f"  {cve}: {len(text)} chars")

api = HfApi(token=HF_TOKEN)
try:
    api.create_repo(
        repo_id=RESPONSES_REPO, repo_type="dataset", private=True, exist_ok=True
    )
except Exception as e:
    print(f"  (repo create: {e})")

with tempfile.NamedTemporaryFile(mode="w", suffix=".jsonl", delete=False) as fh:
    for r in responses:
        fh.write(json.dumps(r) + "\n")
    tmp = fh.name

api.upload_file(
    path_or_fileobj=tmp,
    path_in_repo="authoring-lora-v0.5-responses.jsonl",
    repo_id=RESPONSES_REPO,
    repo_type="dataset",
    commit_message="authoring-lora-v0.5 canary responses",
)
print(f"Uploaded {len(responses)} responses to {RESPONSES_REPO}")

print("\n=== RESPONSES ===")
print(json.dumps(responses, indent=2))
