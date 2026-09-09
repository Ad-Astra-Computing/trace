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
Reviewer-LoRA v1.0 — shadow pilot inference on post-v1.0 positives.

Runs the LoRA adapter on 16 examples not seen during v1.0 training.
Pushes responses.jsonl to the adapter repo under shadow_pilot_responses/.
Score locally with eval/score_lora_responses.py after download.

Submission (see lora/submit_hf_shadow_pilot.sh):
  hf jobs uv run --flavor l40sx1 --namespace odoom \\
    --secrets HF_TOKEN \\
    -v hf://datasets/adastracomputing/reviewer-lora-data:/data:ro \\
    -e PYTORCH_CUDA_ALLOC_CONF=expandable_segments:True -e HF_HOME=/tmp/hf \\
    -e ADAPTER_REPO=adastracomputing/reviewer-lora-v1.0 \\
    lora/hf_shadow_pilot_job.py
"""

import json
import os
from pathlib import Path

import torch
from peft import PeftModel
from transformers import AutoModelForCausalLM, AutoTokenizer, BitsAndBytesConfig

BASE_MODEL = "Qwen/Qwen2.5-Coder-14B-Instruct"
BASE_REVISION = "aedcc2d42b622764e023cf882b6652e646b95671"
MAX_NEW_TOKENS = 1024


def main():
    data_dir = Path(os.environ.get("DATA_DIR", "/data"))
    adapter_repo = os.environ.get("ADAPTER_REPO", "adastracomputing/reviewer-lora-v1.0")

    shadow_path = data_dir / "shadow-pilot.jsonl"
    if not shadow_path.exists():
        raise FileNotFoundError(f"{shadow_path} not found in mounted dataset")
    records = [json.loads(l) for l in shadow_path.read_text().splitlines() if l.strip()]
    print(f"Shadow pilot: {len(records)} examples  adapter={adapter_repo}", flush=True)

    tokenizer = AutoTokenizer.from_pretrained(BASE_MODEL, revision=BASE_REVISION)
    bnb_config = BitsAndBytesConfig(
        load_in_4bit=True,
        bnb_4bit_quant_type="nf4",
        bnb_4bit_compute_dtype=torch.bfloat16,
        bnb_4bit_use_double_quant=True,
    )
    base = AutoModelForCausalLM.from_pretrained(
        BASE_MODEL,
        revision=BASE_REVISION,
        quantization_config=bnb_config,
        device_map="auto",
    )
    model = PeftModel.from_pretrained(base, adapter_repo)
    model.eval()

    responses = []
    for i, rec in enumerate(records):
        msgs = rec["messages"][:2]  # system + user only
        text = tokenizer.apply_chat_template(
            msgs,
            tokenize=False,
            add_generation_prompt=True,
        )
        inputs = tokenizer(text, return_tensors="pt").to(model.device)
        with torch.inference_mode():
            out = model.generate(
                **inputs,
                max_new_tokens=MAX_NEW_TOKENS,
                do_sample=False,
                pad_token_id=tokenizer.eos_token_id,
            )
        response_ids = out[0][inputs["input_ids"].shape[-1] :]
        response = tokenizer.decode(response_ids, skip_special_tokens=True).strip()
        prov = rec.get("provenance", {})
        entry = {
            "cve_id": prov.get("cve_id"),
            "attr_path": prov.get("attr_path"),
            "bundle_id": prov.get("bundle_id"),
            "split": rec.get("split"),
            "expected_label": rec.get("label"),
            "shadow_pilot": rec.get("shadow_pilot", {}),
            "lora_response": response,
        }
        responses.append(entry)
        print(f"[{i + 1}/{len(records)}] {prov.get('cve_id')} done", flush=True)

    from huggingface_hub import HfApi

    api = HfApi()
    out_path = Path("/tmp/shadow_pilot_responses.jsonl")
    out_path.write_text("\n".join(json.dumps(r) for r in responses) + "\n")
    api.upload_file(
        path_or_fileobj=str(out_path),
        path_in_repo="shadow_pilot_responses/shadow-pilot-responses.jsonl",
        repo_id=adapter_repo,
        repo_type="model",
    )
    print(f"Pushed {len(responses)} responses to {adapter_repo}", flush=True)


if __name__ == "__main__":
    main()
