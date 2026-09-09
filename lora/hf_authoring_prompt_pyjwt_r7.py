# /// script
# requires-python = ">=3.10"
# dependencies = [
#   "torch==2.5.1",
#   "transformers==4.47.1",
#   "bitsandbytes==0.45.0",
#   "accelerate==1.2.1",
#   "huggingface-hub>=0.26.0",
# ]
# ///
"""
Prompt-only canary: pyjwt CVE-2026-48526 with system-prompt rule 7.

Uses the base Qwen2.5-Coder-14B-Instruct model (NO LoRA adapter).
Overrides the system message with the v0.7+rule-7 prompt to test whether
the recursive-self-call failure is fixable at the prompt level alone.

Uploads response to adastracomputing/authoring-lora-v0.7 as
prompt-r7-pyjwt-response.jsonl.
"""

import json
import os
from pathlib import Path

import torch
from transformers import AutoModelForCausalLM, AutoTokenizer, BitsAndBytesConfig

DATASET_REPO = os.environ.get("DATASET_REPO", "adastracomputing/authoring-lora-data-v4")
UPLOAD_REPO = os.environ.get("UPLOAD_REPO", "adastracomputing/authoring-lora-v0.7")
BASE_MODEL_ID = "Qwen/Qwen2.5-Coder-14B-Instruct"
MODEL_REVISION = "aedcc2d42b622764e023cf882b6652e646b95671"
MAX_NEW_TOKENS = 1024
TARGET_CVE = "CVE-2026-48526"

SYSTEM_PROMPT_R7 = (
    "You are a security engineer fixing a CVE. You are given the vulnerability "
    "description (symptom only) and the vulnerable source window. Author the "
    "MINIMAL fix as a unified diff. Follow these rules exactly:\n"
    "1. Target ONLY the file named in the `# Vulnerable source (...)` header — "
    "do not invent or substitute file paths.\n"
    "2. Modify ONLY code visible in the shown source window.\n"
    "3. Change as few lines as possible; do not rewrite surrounding logic.\n"
    "4. Output only the unified diff with no other text.\n"
    "5. Prefer the minimal structural change: if an existing condition is missing "
    "a check, add it inline to that condition rather than inserting a new code "
    "block. If existing code is redundant or overcomplicated, replace it — do not "
    "add more code around it.\n"
    "6. Edit the most specific method or class that directly handles the vulnerable "
    "operation — not a base class, interface, or Protocol definition.\n"
    "7. Never introduce a recursive self-call: if you are editing a method named "
    "`foo`, do not call `self.foo(...)` inside it. Add guard logic as new statements "
    "at the top of the existing method body — never by delegating through a renamed "
    "copy of the method or calling the method from within itself."
)


def load_pyjwt_canary(dataset_repo: str) -> dict:
    from huggingface_hub import hf_hub_download

    path = hf_hub_download(
        repo_id=dataset_repo,
        filename="authoring.canary.jsonl",
        repo_type="dataset",
    )
    with open(path) as f:
        for line in f:
            rec = json.loads(line)
            if rec.get("provenance", {}).get("cve_id") == TARGET_CVE:
                return rec
    raise ValueError(f"{TARGET_CVE} not found in canary file")


def generate(model, tokenizer, messages: list[dict]) -> str:
    text = tokenizer.apply_chat_template(
        messages[:-1],  # system + user only
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
    print(f"Loading {TARGET_CVE} canary from {DATASET_REPO}", flush=True)
    rec = load_pyjwt_canary(DATASET_REPO)

    # Replace the system message with the rule-7 prompt; keep the user message as-is
    msgs = rec["messages"]
    user_msg = next(m for m in msgs if m["role"] == "user")
    patched_msgs = [
        {"role": "system", "content": SYSTEM_PROMPT_R7},
        user_msg,
    ]

    print("User message (first 400 chars):", flush=True)
    print(user_msg["content"][:400], flush=True)

    bnb_config = BitsAndBytesConfig(
        load_in_4bit=True,
        bnb_4bit_quant_type="nf4",
        bnb_4bit_compute_dtype=torch.bfloat16,
        bnb_4bit_use_double_quant=True,
    )

    print(
        f"\nLoading base model {BASE_MODEL_ID} @ {MODEL_REVISION} (NO adapter)",
        flush=True,
    )
    tokenizer = AutoTokenizer.from_pretrained(BASE_MODEL_ID, revision=MODEL_REVISION)
    tokenizer.pad_token = tokenizer.eos_token

    model = AutoModelForCausalLM.from_pretrained(
        BASE_MODEL_ID,
        revision=MODEL_REVISION,
        quantization_config=bnb_config,
        device_map="auto",
    )
    model.eval()

    print(f"\nGenerating for {TARGET_CVE}...", flush=True)
    generated = generate(model, tokenizer, patched_msgs)
    print(f"\n=== GENERATED DIFF ===\n{generated}\n=== END ===", flush=True)

    result = {
        "cve_id": TARGET_CVE,
        "system_prompt_version": "v0.7+rule7",
        "adapter": "none (base model only)",
        "generated": generated,
    }

    out_path = Path("/tmp/prompt-r7-pyjwt-response.jsonl")
    out_path.write_text(json.dumps(result) + "\n")
    print(f"\nResponse written to {out_path}", flush=True)

    from huggingface_hub import HfApi

    api = HfApi()
    api.upload_file(
        path_or_fileobj=str(out_path),
        path_in_repo="prompt-r7-pyjwt-response.jsonl",
        repo_id=UPLOAD_REPO,
        repo_type="model",
    )
    print(f"Uploaded to {UPLOAD_REPO}/prompt-r7-pyjwt-response.jsonl", flush=True)


if __name__ == "__main__":
    main()
