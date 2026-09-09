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
Reviewer-LoRA v1.0 — HF Jobs inference/eval script

Loads the nf4 base (the quantization the adapter was trained against) + the
LoRA adapter, generates a Reviewer verdict for each held-out TEST example, and
pushes responses.jsonl back to the adapter repo. Scoring is done LOCALLY
(eval/score_lora_responses.py) because parse_reviewer_output lives in the trace
repo, not in this job.

Greedy decode (do_sample=False) to match the frontier baseline's temperature=0.

Submission (see lora/submit_hf_eval.sh):
  hf jobs uv run --flavor l40sx1 --namespace odoom \
    --secrets HF_TOKEN \
    -v hf://datasets/adastracomputing/reviewer-lora-data:/data:ro \
    -e PYTORCH_CUDA_ALLOC_CONF=expandable_segments:True -e HF_HOME=/tmp/hf \
    -e ADAPTER_REPO=adastracomputing/reviewer-lora-v1.0 \
    lora/hf_eval_job.py
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

    test_path = data_dir / "reviewer.test.jsonl"
    if not test_path.exists():
        raise FileNotFoundError(f"{test_path} not found in mounted dataset")
    records = [json.loads(l) for l in test_path.read_text().splitlines() if l.strip()]
    print(f"Eval  test_examples={len(records)}  adapter={adapter_repo}", flush=True)

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
        msgs = rec["messages"]
        # Drop the assistant ground-truth turn; keep system + user.
        prompt_msgs = [m for m in msgs if m["role"] in ("system", "user")]
        gt_assistant = next(
            (m["content"] for m in msgs if m["role"] == "assistant"), ""
        )

        inputs = tokenizer.apply_chat_template(
            prompt_msgs,
            add_generation_prompt=True,
            return_tensors="pt",
        ).to(model.device)
        prompt_len = inputs.shape[1]

        with torch.no_grad():
            out = model.generate(
                inputs,
                max_new_tokens=MAX_NEW_TOKENS,
                do_sample=False,  # greedy == temperature 0
                pad_token_id=tokenizer.eos_token_id,
            )
        gen = tokenizer.decode(out[0][prompt_len:], skip_special_tokens=True)

        # Match key: hash of the user turn, so local scoring can align to the
        # full export regardless of order.
        user_text = next((m["content"] for m in prompt_msgs if m["role"] == "user"), "")
        responses.append(
            {
                "index": i,
                "prompt_len": prompt_len,
                "user_sha256": __import__("hashlib")
                .sha256(user_text.encode())
                .hexdigest(),
                "generated": gen,
                "ground_truth_assistant": gt_assistant,
            }
        )
        print(
            f"  [{i + 1}/{len(records)}] gen_chars={len(gen)} prompt_tok={prompt_len}",
            flush=True,
        )

    out_path = Path("/tmp/responses.jsonl")
    out_path.write_text("\n".join(json.dumps(r) for r in responses) + "\n")

    from huggingface_hub import HfApi

    HfApi().upload_file(
        path_or_fileobj=str(out_path),
        path_in_repo="eval/responses.jsonl",
        repo_id=adapter_repo,
        repo_type="model",
    )
    print(
        f"\nDone. {len(responses)} responses pushed to {adapter_repo}/eval/responses.jsonl",
        flush=True,
    )


if __name__ == "__main__":
    main()
