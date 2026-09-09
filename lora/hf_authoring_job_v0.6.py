# /// script
# requires-python = ">=3.10"
# dependencies = [
#   "torch==2.5.1",
#   "transformers==4.47.1",
#   "trl==0.13.0",
#   "peft==0.14.0",
#   "bitsandbytes==0.45.0",
#   "datasets==3.2.0",
#   "accelerate==1.2.1",
#   "huggingface-hub>=0.26.0",
# ]
# ///
"""
Authoring-LoRA v0.6 — HF Jobs UV-script (mixed-lang dev set + file-grounding system prompt)

Self-contained PEP 723 script run via `hf jobs uv run` on HF GPU infrastructure.
Trains Qwen2.5-Coder-14B-Instruct on the author-from-vuln task.

v0.6 vs v0.5:
  - Dataset: 83 train / 9 dev (authoring-v3 manifest)
    - python-multipart (CVE-2026-40347) and pygments (CVE-2026-4539) moved to dev
    - Dev set: 7 C + 2 Python = mixed-language eval signal
    - Previously: 7 C dev examples only → eval_loss blind to Python generalization
  - System prompt: language-agnostic with explicit file-grounding rules:
    1. Target ONLY the file named in the `# Vulnerable source (...)` header
    2. Modify ONLY code visible in the shown source window
    3. Change as few lines as possible; do not rewrite surrounding logic
    4. Output only the unified diff with no other text
    (Previously: "fixing a CVE in C/C++" — wrong for Python examples)
  - Code fence: correct language per file extension (python for .py, c for .c, etc.)
    (Previously: always ```c regardless of language)
  - max_steps: 550 (unchanged; 550×4/83 ≈ 26.5 passes over 83 train examples)
  - All v0.5 detect-and-reject examples retained:
    1. NLTK (CVE-2026-33236): inline path-traversal guard at function entry
    2. python-jose (CVE-2024-33664): JWE size-limit guard at decrypt() entry
    3. aiohttp (CVE-2024-23334): path normalization fix

Eval canaries: same 4 families (zlib, requests, bzip2, pyjwt) under authoring-v3.
Canary file: exports/authoring-v3/authoring-canary.jsonl (uses new system prompt).

Submission (see lora/submit_hf_authoring_job_v0.6.sh):
  hf jobs uv run --flavor a100-large --namespace odoom \\
    --secrets HF_TOKEN \\
    -v hf://datasets/adastracomputing/authoring-lora-data-v3:/data:ro \\
    -e PYTORCH_CUDA_ALLOC_CONF=expandable_segments:True \\
    -e HF_HOME=/tmp/hf -e ADAPTER_DIR=/tmp/authoring-lora-v0.6 \\
    -e HUB_MODEL_ID=adastracomputing/authoring-lora-v0.6 \\
    lora/hf_authoring_job_v0.6.py
"""

import json
import os
from pathlib import Path

import torch
from datasets import Dataset
from peft import LoraConfig, TaskType
from transformers import (
    AutoModelForCausalLM,
    AutoTokenizer,
    BitsAndBytesConfig,
    set_seed,
)
from trl import SFTConfig, SFTTrainer

# --- Pinned identity (reproducibility) -------------------------------------
MODEL_ID = "Qwen/Qwen2.5-Coder-14B-Instruct"
MODEL_REVISION = "aedcc2d42b622764e023cf882b6652e646b95671"  # main @ 2025-01-12
SEED = 42

# LoRA hyperparameters — identical to v0.1-v0.5 for fair comparison
LORA_RANK = 16
LORA_ALPHA = 16
LORA_DROPOUT = 0.05
LORA_TARGET_MODULES = [
    "q_proj",
    "k_proj",
    "v_proj",
    "o_proj",
    "gate_proj",
    "up_proj",
    "down_proj",
]

# v0.6: 550 steps × grad_accum 4 = 2200 effective steps ≈ 26.5 passes over 83 train examples
MAX_STEPS = int(os.environ.get("MAX_STEPS", "550"))
GRAD_ACCUM = 4
MAX_SEQ_LEN = 16384


def load_jsonl(path: Path) -> list:
    with open(path) as f:
        return [json.loads(line) for line in f if line.strip()]


def make_formatting_func(tok):
    def fmt(examples):
        return [
            tok.apply_chat_template(msgs, tokenize=False, add_generation_prompt=False)
            for msgs in examples["messages"]
        ]

    return fmt


def main():
    set_seed(SEED)

    data_dir = Path(os.environ.get("DATA_DIR", "/data"))
    adapter_dir = Path(os.environ.get("ADAPTER_DIR", "/tmp/authoring-lora-v0.6"))
    hub_model_id = os.environ.get(
        "HUB_MODEL_ID", "adastracomputing/authoring-lora-v0.6"
    )
    adapter_dir.mkdir(parents=True, exist_ok=True)

    train_file = os.environ.get("TRAIN_FILE", "authoring.train.jsonl")
    dev_file = os.environ.get("DEV_FILE", "authoring.dev.jsonl")
    train_path = data_dir / train_file
    valid_path = data_dir / dev_file
    for p in (train_path, valid_path):
        if not p.exists():
            raise FileNotFoundError(f"{p} not found in mounted dataset {data_dir}")

    train_ds = Dataset.from_list(load_jsonl(train_path))
    valid_ds = Dataset.from_list(load_jsonl(valid_path))
    print(f"Data  train={len(train_ds)}  valid={len(valid_ds)}", flush=True)

    # Integrity checks
    train_text = "\n".join(json.dumps(r) for r in load_jsonl(train_path))

    # Canary exclusion: pyjwt must NOT be in training data
    if "CVE-2026-48526" in train_text or "pyjwt" in train_text.lower():
        raise RuntimeError(
            "ABORT: pyjwt canary (CVE-2026-48526) detected in training data. "
            "Re-export authoring.train.jsonl with --split-manifest."
        )
    print("Canary integrity check: pyjwt not in training set", flush=True)

    # v0.6 system prompt: must contain the file-grounding rule
    if "Target ONLY the file named in the" not in train_text:
        raise RuntimeError(
            "ABORT: v0.6 system prompt not found in training data. "
            "Re-export with the updated exporter (language-agnostic system prompt). "
            "Run: python3 -m tools.trace_cli export authoring "
            "--split-manifest data/splits/authoring-v3.json --out exports/authoring-v3/"
        )
    print("v0.6 corpus check: file-grounding system prompt present", flush=True)

    # Critical training examples (detect-and-reject patterns)
    if "CVE-2024-23334" not in train_text and "aiohttp" not in train_text.lower():
        raise RuntimeError(
            "ABORT: aiohttp (CVE-2024-23334) not found in training data. "
            "Re-upload dataset with authoring-v3 manifest."
        )
    print("v0.6 corpus check: aiohttp present in training set", flush=True)

    if "CVE-2026-33236" not in train_text and "nltk" not in train_text.lower():
        raise RuntimeError(
            "ABORT: nltk (CVE-2026-33236) not found in training data. "
            "v0.6 requires the NLTK inline-guard example."
        )
    print("v0.6 corpus check: NLTK inline-guard example present", flush=True)

    if "CVE-2024-33664" not in train_text and "python-jose" not in train_text.lower():
        raise RuntimeError(
            "ABORT: python-jose (CVE-2024-33664) not found in training data. "
            "v0.6 requires the python-jose JWE-size-limit example."
        )
    print("v0.6 corpus check: python-jose inline-guard example present", flush=True)

    # Dev set check: must be mixed-language (9 examples including Python)
    dev_text = "\n".join(json.dumps(r) for r in load_jsonl(valid_path))
    if (
        "python_multipart" not in dev_text
        and "python-multipart" not in dev_text.lower()
    ):
        raise RuntimeError(
            "ABORT: python-multipart (CVE-2026-40347) not found in dev data. "
            "v0.6 requires the mixed-language dev set (authoring-v3 manifest). "
            "Re-export with data/splits/authoring-v3.json."
        )
    print(
        "v0.6 corpus check: python-multipart in dev set (mixed-lang signal)", flush=True
    )

    tokenizer = AutoTokenizer.from_pretrained(MODEL_ID, revision=MODEL_REVISION)
    tokenizer.pad_token = tokenizer.eos_token
    tokenizer.padding_side = "right"

    bnb_config = BitsAndBytesConfig(
        load_in_4bit=True,
        bnb_4bit_quant_type="nf4",
        bnb_4bit_compute_dtype=torch.bfloat16,
        bnb_4bit_use_double_quant=True,
    )

    model = AutoModelForCausalLM.from_pretrained(
        MODEL_ID,
        revision=MODEL_REVISION,
        quantization_config=bnb_config,
        device_map="auto",
    )
    model.config.use_cache = False

    peft_config = LoraConfig(
        r=LORA_RANK,
        lora_alpha=LORA_ALPHA,
        lora_dropout=LORA_DROPOUT,
        target_modules=LORA_TARGET_MODULES,
        task_type=TaskType.CAUSAL_LM,
        bias="none",
    )

    sft_config = SFTConfig(
        output_dir=str(adapter_dir),
        max_steps=MAX_STEPS,
        per_device_train_batch_size=1,
        per_device_eval_batch_size=1,
        prediction_loss_only=True,
        eval_accumulation_steps=1,
        gradient_accumulation_steps=GRAD_ACCUM,
        learning_rate=1e-4,
        lr_scheduler_type="cosine",
        warmup_steps=55,
        bf16=True,
        gradient_checkpointing=True,
        gradient_checkpointing_kwargs={"use_reentrant": False},
        optim="paged_adamw_8bit",
        logging_steps=5,
        eval_strategy="steps",
        eval_steps=25,
        save_strategy="steps",
        save_steps=50,
        save_total_limit=4,
        load_best_model_at_end=True,
        metric_for_best_model="eval_loss",
        max_seq_length=MAX_SEQ_LEN,
        packing=False,
        seed=SEED,
        report_to="none",
        push_to_hub=True,
        hub_model_id=hub_model_id,
        hub_private_repo=True,
        hub_strategy="end",
    )

    trainer = SFTTrainer(
        model=model,
        args=sft_config,
        train_dataset=train_ds,
        eval_dataset=valid_ds,
        peft_config=peft_config,
        formatting_func=make_formatting_func(tokenizer),
        processing_class=tokenizer,
    )

    print(f"Model  {MODEL_ID} @ {MODEL_REVISION}", flush=True)
    print(
        f"LoRA   rank={LORA_RANK} alpha={LORA_ALPHA} dropout={LORA_DROPOUT} QLoRA-nf4",
        flush=True,
    )
    print(
        f"Train  max_steps={MAX_STEPS} grad_accum={GRAD_ACCUM} seed={SEED}", flush=True
    )

    train_result = trainer.train()

    manifest = {
        "task": "authoring-lora-v0.6",
        "base_model": MODEL_ID,
        "base_model_revision": MODEL_REVISION,
        "corpus_freeze_sha": os.environ.get("CORPUS_FREEZE_SHA", "unknown"),
        "dataset_repo": "adastracomputing/authoring-lora-data-v3",
        "dataset_commit": os.environ.get("DATASET_COMMIT", "unknown"),
        "trace_commit": os.environ.get("TRACE_COMMIT", "unknown"),
        "hardware": os.environ.get("HF_JOB_FLAVOR", "a100-large"),
        "seed": SEED,
        "hyperparams": {
            "lora_rank": LORA_RANK,
            "lora_alpha": LORA_ALPHA,
            "lora_dropout": LORA_DROPOUT,
            "target_modules": LORA_TARGET_MODULES,
            "max_steps": MAX_STEPS,
            "gradient_accumulation_steps": GRAD_ACCUM,
            "effective_epochs": round(MAX_STEPS * GRAD_ACCUM / len(train_ds), 1),
            "learning_rate": 1e-4,
            "lr_scheduler": "cosine",
            "warmup_steps": 55,
            "max_seq_length": MAX_SEQ_LEN,
            "quantization": "nf4-4bit-double",
        },
        "train_metrics": {k: v for k, v in train_result.metrics.items()},
    }
    manifest_path = adapter_dir / "run_manifest.json"
    manifest_path.write_text(json.dumps(manifest, indent=2))
    print("Manifest:\n" + json.dumps(manifest, indent=2), flush=True)

    trainer.save_model(str(adapter_dir))
    tokenizer.save_pretrained(str(adapter_dir))

    from huggingface_hub import HfApi

    HfApi().upload_file(
        path_or_fileobj=str(manifest_path),
        path_in_repo="run_manifest.json",
        repo_id=hub_model_id,
        repo_type="model",
    )
    print(f"\nDone. Adapter + manifest pushed to {hub_model_id}", flush=True)


if __name__ == "__main__":
    main()
