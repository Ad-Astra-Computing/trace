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
Authoring-LoRA loss-masking experiment — HF Jobs UV-script.

Isolates the ONE training-objective lever the authoring arc left explicitly
untested (DECISIONS 2026-07-14; the SR-format run was caveated "no loss-masking,
greedy only"). Everything here is byte-identical to hf_authoring_job_v10_clean.py
(same v10-clean corpus, same Qwen2.5-Coder-14B base + revision, same LoRA
hyperparameters, same seed 42, same steps) EXCEPT the loss target:

  * v10-clean and every prior authoring run compute loss over the FULL rendered
    conversation (prompt + completion). Measured on the v10-clean corpus, the
    completion (the fix diff) is a median 17.6% / mean 20% of characters, so
    ~80% of the gradient models the long source-context PROMPT, not the fix.
  * This run masks the prompt to -100 via DataCollatorForCompletionOnlyLM and
    trains loss ONLY on the assistant turn (the fix diff), roughly 5x-ing the
    effective weight on the tokens that carry edit-precision.

Hypothesis: the byte-exact 0/4 canary ceiling (insensitive to +data, SR-format,
DPO) is a training-OBJECTIVE artifact (prompt tokens diluting the loss), not a
fundamental capability limit. If so, completion-only loss should move
edit-precision where those levers could not.

Eval plan (kills BOTH recorded caveats in one run; peer-amended 2026-09-01):
  * score greedy AND best-of-n sampling (n=16, temp 0.7) on the 4 frozen
    canaries, so a null cannot be blamed on greedy decoding;
  * report GRADED metrics (edit-distance-to-target, hunk-level match, add/rem
    recall) via lora/score_canaries_graded.py, not just byte-exact — a partial
    move must be visible.

Pre-committed kill criterion: if completion-only loss + sampled + graded eval
shows NO movement over the v10-clean baseline on the graded metrics, the
authoring-LoRA capability lane is retired with no remaining recorded caveats.
Do not re-litigate "more data" / format / objective after this.

Submission: lora/submit_hf_authoring_job_lossmask.sh
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
from trl import SFTConfig, SFTTrainer, DataCollatorForCompletionOnlyLM

# --- Pinned identity (reproducibility) -------------------------------------
MODEL_ID = "Qwen/Qwen2.5-Coder-14B-Instruct"
MODEL_REVISION = "aedcc2d42b622764e023cf882b6652e646b95671"  # main @ 2025-01-12
SEED = 42

# LoRA hyperparameters — identical to v10-clean for a clean A/B on the loss target
LORA_RANK = 16
LORA_ALPHA = 16
LORA_DROPOUT = 0.05
LORA_TARGET_MODULES = [
    "q_proj", "k_proj", "v_proj", "o_proj",
    "gate_proj", "up_proj", "down_proj",
]

MAX_STEPS = int(os.environ.get("MAX_STEPS", "375"))
GRAD_ACCUM = 4
MAX_SEQ_LEN = 16384

# Qwen2.5 chat template: the assistant turn opens with this marker. Loss is
# masked (-100) up to and including it, so only the fix-diff tokens contribute.
RESPONSE_TEMPLATE = "<|im_start|>assistant\n"


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
    adapter_dir = Path(os.environ.get("ADAPTER_DIR", "/tmp/authoring-lora-lossmask"))
    hub_model_id = os.environ.get("HUB_MODEL_ID", "adastracomputing/authoring-lora-lossmask")
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

    # --- Integrity checks (identical to v10-clean) ---
    train_text = "\n".join(json.dumps(r) for r in load_jsonl(train_path))

    for cve, name in [("CVE-2026-48526", "pyjwt"), ("CVE-2022-37434", "zlib"),
                      ("CVE-2024-47081", "requests"), ("CVE-2026-42250", "bzip2-canary")]:
        if cve in train_text:
            raise RuntimeError(
                f"ABORT: canary {cve} ({name}) detected in training data. "
                "Re-export authoring.train.jsonl with the v10-clean dataset."
            )
    print("Canary integrity check: all 4 canaries absent from training set", flush=True)

    if len(train_ds) < 60:
        raise RuntimeError(
            f"ABORT: expected >= 60 train examples in the clean corpus, got {len(train_ds)}. "
            "Re-upload authoring-lora-data-v10-clean from exports/authoring-lora/."
        )
    print(f"corpus check: train size {len(train_ds)} (>= 60 floor)", flush=True)

    tokenizer = AutoTokenizer.from_pretrained(MODEL_ID, revision=MODEL_REVISION)
    tokenizer.pad_token = tokenizer.eos_token
    tokenizer.padding_side = "right"

    # Completion-only loss: mask everything up to and including the assistant
    # marker. This is the SOLE change vs v10-clean.
    collator = DataCollatorForCompletionOnlyLM(
        response_template=RESPONSE_TEMPLATE,
        tokenizer=tokenizer,
    )

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
        data_collator=collator,
        processing_class=tokenizer,
    )

    print(f"Model  {MODEL_ID} @ {MODEL_REVISION}", flush=True)
    print(f"LoRA   rank={LORA_RANK} alpha={LORA_ALPHA} dropout={LORA_DROPOUT} QLoRA-nf4", flush=True)
    print("Loss   COMPLETION-ONLY (prompt masked to -100 via response template)", flush=True)
    print(f"Train  max_steps={MAX_STEPS} grad_accum={GRAD_ACCUM} warmup={warmup_steps} seed={SEED}", flush=True)

    train_result = trainer.train()

    manifest = {
        "task": "authoring-lora-lossmask",
        "experiment": "completion-only-loss vs v10-clean full-conversation-loss",
        "base_model": MODEL_ID,
        "base_model_revision": MODEL_REVISION,
        "corpus_freeze_sha": os.environ.get("CORPUS_FREEZE_SHA", "unknown"),
        "dataset_repo": "adastracomputing/authoring-lora-data-v13-diversefold",
        "dataset_commit": os.environ.get("DATASET_COMMIT", "unknown"),
        "trace_commit": os.environ.get("TRACE_COMMIT", "unknown"),
        "hardware": os.environ.get("HF_JOB_FLAVOR", "a100-large"),
        "seed": SEED,
        "loss_target": "completion-only",
        "response_template": RESPONSE_TEMPLATE,
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
