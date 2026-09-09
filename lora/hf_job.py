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
Reviewer-LoRA v1.0 — HF Jobs UV-script (canonical remote training run)

Self-contained PEP 723 script run via `hf jobs uv run` on HF GPU infrastructure.
Mirrors lora/hf_train.py's reviewed training core, adapted for remote execution:

  - reads the 3 jsonl splits from a read-only mounted dataset (/data)
  - QLoRA SFT on Qwen2.5-Coder-14B-Instruct (base revision pinned)
  - writes the adapter to a job-local writable dir (/tmp), then pushes to the Hub
  - emits a run manifest tying the run to corpus freeze + dataset + base-model SHAs

Submission (see lora/submit_hf_job.sh):
  hf jobs uv run --flavor a100-large --namespace odoom \
    --secrets HF_TOKEN \
    -v hf://datasets/adastracomputing/reviewer-lora-data:/data:ro \
    -e PYTORCH_CUDA_ALLOC_CONF=expandable_segments:True \
    -e HF_HOME=/tmp/hf -e ADAPTER_DIR=/tmp/reviewer-lora-v1.0 \
    -e HUB_MODEL_ID=adastracomputing/reviewer-lora-v1.0 \
    -e CORPUS_FREEZE_SHA=... -e DATASET_COMMIT=... -e TRACE_COMMIT=... \
    lora/hf_job.py

A100 80GB (not L40S 44GB): the full-vocab cross-entropy on ~15K-token outliers
materializes a ~8.5 GiB fp32 logits tensor that OOMs 44GB. Namespace odoom = billing
(personal credits); HUB_MODEL_ID = adastracomputing org = adapter destination.
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
# Env-overridable for the v1.11 multi-seed design (3 training seeds per arm).
# Default 42 preserves the historical behavior: every consumer (set_seed, the
# SFTConfig seed, the run manifest) reads this one constant, so an unset SEED
# is byte-for-byte the code path all prior adapters trained under.
SEED = int(os.environ.get("SEED", "42"))

# LoRA hyperparameters — match lora/mlx_config.yaml (rank=16, alpha=rank)
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

# 150 optimizer steps × grad_accum 4 ≈ 8.7 epochs over 69 examples.
# Chosen over 500 (=~29 epochs) to avoid overfitting a 14B on 92 examples.
MAX_STEPS = int(os.environ.get("MAX_STEPS", "150"))
GRAD_ACCUM = 4
MAX_SEQ_LEN = 16384


def load_jsonl(path: Path) -> list:
    with open(path) as f:
        return [json.loads(line) for line in f if line.strip()]


def make_formatting_func(tok):
    """Batch-mode chat-template renderer. Loss is over the full conversation;
    acceptable for a 92-example binary SFT where the signal is the assistant turn."""

    def fmt(examples):
        return [
            tok.apply_chat_template(msgs, tokenize=False, add_generation_prompt=False)
            for msgs in examples["messages"]
        ]

    return fmt


def main():
    set_seed(SEED)

    data_dir = Path(os.environ.get("DATA_DIR", "/data"))
    adapter_dir = Path(os.environ.get("ADAPTER_DIR", "/tmp/reviewer-lora-v1.0"))
    hub_model_id = os.environ.get("HUB_MODEL_ID", "adastracomputing/reviewer-lora-v1.0")
    adapter_dir.mkdir(parents=True, exist_ok=True)

    # Dataset mount is read-only; TRAIN_FILE / DEV_FILE let callers pass
    # versioned filenames (e.g. reviewer-v1.6.train.jsonl) without overwriting
    # prior versions on the dataset repo.  Fall back to the legacy names.
    train_file = os.environ.get("TRAIN_FILE", "reviewer.train.jsonl")
    dev_file = os.environ.get("DEV_FILE", "reviewer.dev.jsonl")
    train_path = data_dir / train_file
    valid_path = data_dir / dev_file
    for p in (train_path, valid_path):
        if not p.exists():
            raise FileNotFoundError(f"{p} not found in mounted dataset {data_dir}")

    train_ds = Dataset.from_list(load_jsonl(train_path))
    valid_ds = Dataset.from_list(load_jsonl(valid_path))
    print(f"Data  train={len(train_ds)}  valid={len(valid_ds)}", flush=True)

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
        # Eval batch MUST be 1: the default 8 materializes [8, ~15K, 152K-vocab]
        # fp32 logits (~40 GiB) and OOMs even an 80GB A100. We only consume
        # eval_loss, so prediction_loss_only avoids retaining logits at all.
        per_device_eval_batch_size=1,
        prediction_loss_only=True,
        eval_accumulation_steps=1,
        gradient_accumulation_steps=GRAD_ACCUM,
        learning_rate=1e-4,
        lr_scheduler_type="cosine",
        warmup_steps=15,  # ~10% of 150
        bf16=True,
        gradient_checkpointing=True,
        # use_reentrant=False is the stable path for QLoRA + grad checkpointing;
        # TRL 0.13 forwards this into prepare_model_for_kbit_training.
        gradient_checkpointing_kwargs={"use_reentrant": False},
        optim="paged_adamw_8bit",
        logging_steps=5,
        eval_strategy="steps",
        eval_steps=25,
        save_strategy="steps",
        save_steps=50,
        save_total_limit=3,
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
        # Pass our tokenizer explicitly: TRL tokenizes the formatted strings with
        # processing_class. Without this it reloads one from the model path,
        # dropping our pad_token / padding_side="right" setup.
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

    # Run manifest — ties the adapter to its full provenance.
    manifest = {
        "task": "reviewer-lora-v1.0",
        "base_model": MODEL_ID,
        "base_model_revision": MODEL_REVISION,
        "corpus_freeze_sha": os.environ.get("CORPUS_FREEZE_SHA", "unknown"),
        "dataset_repo": "adastracomputing/reviewer-lora-data",
        "dataset_commit": os.environ.get("DATASET_COMMIT", "unknown"),
        "trace_commit": os.environ.get("TRACE_COMMIT", "unknown"),
        "hardware": os.environ.get("HF_JOB_FLAVOR", "l40sx1"),
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
            "warmup_steps": 15,
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

    # push_to_hub=True + hub_strategy=end already pushed the adapter; also push
    # the manifest so provenance travels with the model repo.
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
