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
Authoring-LoRA v1.1 — HF Jobs UV-script (condition-refine data arc)

Self-contained PEP 723 script run via `hf jobs uv run` on HF GPU infrastructure.
Trains Qwen2.5-Coder-14B-Instruct on the author-from-vuln task.

v1.1 vs v1.0:
  - Dataset: 91 train / 6 dev (authoring-lora-data-v7: v6 + 3 condition-refine examples)
  - New training examples: bzip2 CVE-2019-12900, libssh2 CVE-2019-3863, FFmpeg CVE-2025-69693
  - Each demonstrates || upper-bound / && pre-check extending an existing condition
    rather than inserting a separate guard block (targets the guard-clip attractor)
  - System prompt: 6 rules (rule 7 absent — identical to v1.0)
  - max_steps: 375 (identical to v1.0)
  - All other hyperparameters identical to v0.7/v1.0

Hypothesis: adding 3 condition-refine examples pulls the model off the guard-clip
attractor on zlib (CVE-2022-37434). bfloat16 hardware non-determinism put v1.0 on
a decision boundary; new examples should provide enough signal to prefer the
inline-condition strategy consistently.

Expected canary outcome: bzip2 PASS, zlib PASS, requests FAIL, pyjwt FAIL.

Submission (see lora/submit_hf_authoring_job_v1.1.sh):
  hf jobs uv run --flavor a100-large --namespace odoom \\
    --secrets HF_TOKEN \\
    -v hf://datasets/adastracomputing/authoring-lora-data-v7:/data:ro \\
    -e PYTORCH_CUDA_ALLOC_CONF=expandable_segments:True \\
    -e HF_HOME=/tmp/hf -e ADAPTER_DIR=/tmp/authoring-lora-v1.1 \\
    -e HUB_MODEL_ID=adastracomputing/authoring-lora-v1.1 \\
    lora/hf_authoring_job_v1.1.py
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

# LoRA hyperparameters — identical to v0.1-v1.0 for fair comparison
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

# v1.1: 375 steps × grad_accum 4 = 1500 effective steps ≈ 4.1 passes over 91 train examples
MAX_STEPS = int(os.environ.get("MAX_STEPS", "375"))
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
    adapter_dir = Path(os.environ.get("ADAPTER_DIR", "/tmp/authoring-lora-v1.1"))
    hub_model_id = os.environ.get(
        "HUB_MODEL_ID", "adastracomputing/authoring-lora-v1.1"
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

    # --- Integrity checks ---
    train_text = "\n".join(json.dumps(r) for r in load_jsonl(train_path))

    # Canary exclusion: none of the 4 canary families may be in training data
    for cve, name in [
        ("CVE-2026-48526", "pyjwt"),
        ("CVE-2022-37434", "zlib"),
        ("CVE-2024-47081", "requests"),
        ("CVE-2026-42250", "bzip2-canary"),
    ]:
        if cve in train_text:
            raise RuntimeError(
                f"ABORT: canary {cve} ({name}) detected in training data. "
                "Re-export authoring.train.jsonl with the v7 dataset."
            )
    print("Canary integrity check: all 4 canaries absent from training set", flush=True)

    # v1.1 system prompt: rules 5 and 6 present; rule 7 must NOT be present
    if "Prefer the minimal structural change" not in train_text:
        raise RuntimeError(
            "ABORT: v1.1 system prompt rule 5 not found in training data."
        )
    print(
        "v1.1 corpus check: rule 5 (minimal structural change) system prompt present",
        flush=True,
    )

    if "most specific method or class" not in train_text:
        raise RuntimeError(
            "ABORT: v1.1 system prompt rule 6 not found in training data."
        )
    print(
        "v1.1 corpus check: rule 6 (most specific class) system prompt present",
        flush=True,
    )

    if "recursive self-call" in train_text:
        raise RuntimeError(
            "ABORT: rule 7 (recursive self-call) found in training data but must be ABSENT for v1.1."
        )
    print("v1.1 corpus check: rule 7 correctly absent", flush=True)

    # v1.1 condition-refine examples must be present
    for cve, label in [
        ("CVE-2019-12900", "bzip2 nSelectors OOB"),
        ("CVE-2019-3863", "libssh2 channel-flush OOB"),
        ("CVE-2025-69693", "FFmpeg rv60dec qp OOB"),
    ]:
        if cve not in train_text:
            raise RuntimeError(
                f"ABORT: {cve} ({label}) condition-refine example not found in training data. "
                "Rebuild the v7 dataset with lora/build_authoring_dataset_v7.py."
            )
    print("v1.1 corpus check: all 3 condition-refine examples present", flush=True)

    # Train set size: v7 should have 91 train examples
    if len(train_ds) < 91:
        raise RuntimeError(
            f"ABORT: expected >= 91 train examples (v7 = v6 91 + 3 new), got {len(train_ds)}. "
            "Re-upload authoring-lora-data-v7 from exports/authoring-v7-lora/."
        )
    print(f"v1.1 corpus check: train size {len(train_ds)} >= 91", flush=True)

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

    warmup_steps = 35
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
        warmup_steps=warmup_steps,
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
        f"Train  max_steps={MAX_STEPS} grad_accum={GRAD_ACCUM} warmup={warmup_steps} seed={SEED}",
        flush=True,
    )

    train_result = trainer.train()

    manifest = {
        "task": "authoring-lora-v1.1",
        "base_model": MODEL_ID,
        "base_model_revision": MODEL_REVISION,
        "corpus_freeze_sha": os.environ.get("CORPUS_FREEZE_SHA", "unknown"),
        "dataset_repo": "adastracomputing/authoring-lora-data-v7",
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
            "warmup_steps": warmup_steps,
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

    api = HfApi()
    api.upload_file(
        path_or_fileobj=str(manifest_path),
        path_in_repo="run_manifest.json",
        repo_id=hub_model_id,
        repo_type="model",
    )
    print(f"Adapter + manifest pushed to {hub_model_id}", flush=True)


if __name__ == "__main__":
    main()
