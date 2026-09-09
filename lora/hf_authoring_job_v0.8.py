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
Authoring-LoRA v0.8 — HF Jobs UV-script (rule 7 + same corpus as v0.7)

Self-contained PEP 723 script run via `hf jobs uv run` on HF GPU infrastructure.
Trains Qwen2.5-Coder-14B-Instruct on the author-from-vuln task.

v0.8 vs v0.7:
  - Dataset: 88 train / 6 dev (authoring-lora-data-v5, same split as v4)
    - No new corpus bundles added — same 88 training examples
    - System prompt gains rule 7 (no recursive self-call)
  - System prompt rule 7 added:
    "Never introduce a recursive self-call: if you are editing a method named
    `foo`, do not call `self.foo(...)` inside it. Add guard logic as new
    statements at the top of the existing method body."
  - max_steps: 375 (unchanged from v0.7 — same corpus size, same epoch budget)
  - All other hyperparameters identical to v0.7

Root cause addressed:
  - pyjwt v0.7 failure: model generated HMACAlgorithm.prepare_key that called
    self.prepare_key(key) recursively — infinite recursion. Rule 7 targets this.
  - requests v0.7 failure: Python simplify/replace (ri.netloc.split → ri.hostname).
    Cross-language grub2 signal (2 C simplify/replace examples) tested for
    generalization — no new Python examples available in the surveyed landscape.

Eval canaries: same 4 families (zlib, requests, bzip2, pyjwt) from authoring-v4.
Expected: pyjwt improves on recursive-call check; requests baseline from v0.7.

Submission (see lora/submit_hf_authoring_job_v0.8.sh):
  hf jobs uv run --flavor a100-large --namespace odoom \\
    --secrets HF_TOKEN \\
    -v hf://datasets/adastracomputing/authoring-lora-data-v5:/data:ro \\
    -e PYTORCH_CUDA_ALLOC_CONF=expandable_segments:True \\
    -e HF_HOME=/tmp/hf -e ADAPTER_DIR=/tmp/authoring-lora-v0.8 \\
    -e HUB_MODEL_ID=adastracomputing/authoring-lora-v0.8 \\
    lora/hf_authoring_job_v0.8.py
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

# LoRA hyperparameters — identical to v0.1-v0.7 for fair comparison
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

# v0.8: 375 steps × grad_accum 4 = 1500 effective steps ≈ 4.3 passes over 88 train examples
# Identical to v0.7 — same corpus size, same epoch budget
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
    adapter_dir = Path(os.environ.get("ADAPTER_DIR", "/tmp/authoring-lora-v0.8"))
    hub_model_id = os.environ.get(
        "HUB_MODEL_ID", "adastracomputing/authoring-lora-v0.8"
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
        ("CVE-2026-42250", "bzip2"),
    ]:
        if cve in train_text:
            raise RuntimeError(
                f"ABORT: canary {cve} ({name}) detected in training data. "
                "Re-export authoring.train.jsonl with --split-manifest data/splits/authoring-v5.json."
            )
    print("Canary integrity check: all 4 canaries absent from training set", flush=True)

    # v0.8 system prompt: must contain rules 5, 6, and 7
    if "Prefer the minimal structural change" not in train_text:
        raise RuntimeError(
            "ABORT: v0.8 system prompt rule 5 not found in training data. "
            "Re-export with the v0.8 exporter (export.py with updated _AUTHORING_SYSTEM). "
            "Run: python3 -m tools.trace_cli export authoring "
            "--split-manifest data/splits/authoring-v5.json --out exports/authoring-v5/ "
            "&& python3 eval/package_authoring_lora.py "
            "--export-dir exports/authoring-v5/ --out-dir exports/authoring-v5-lora/"
        )
    print(
        "v0.8 corpus check: rule 5 (minimal structural change) system prompt present",
        flush=True,
    )

    if "most specific method or class" not in train_text:
        raise RuntimeError(
            "ABORT: v0.8 system prompt rule 6 not found in training data. "
            "Re-export with the v0.8 exporter."
        )
    print(
        "v0.8 corpus check: rule 6 (most specific class) system prompt present",
        flush=True,
    )

    if "recursive self-call" not in train_text:
        raise RuntimeError(
            "ABORT: v0.8 system prompt rule 7 not found in training data. "
            "Re-export with the v0.8 exporter (export.py _AUTHORING_SYSTEM with rule 7)."
        )
    print(
        "v0.8 corpus check: rule 7 (no recursive self-call) system prompt present",
        flush=True,
    )

    # Required training examples: grub2 simplify/replace patterns
    if "CVE-2024-45781" not in train_text:
        raise RuntimeError(
            "ABORT: CVE-2024-45781 (grub2-ufs strlcpy) not found in training data. "
            "Re-export with data/splits/authoring-v5.json."
        )
    print(
        "v0.8 corpus check: CVE-2024-45781 (grub2-ufs, simplify/replace) present",
        flush=True,
    )

    if "CVE-2024-45782" not in train_text:
        raise RuntimeError(
            "ABORT: CVE-2024-45782 (grub2-hfs strlcpy) not found in training data. "
            "Re-export with data/splits/authoring-v5.json."
        )
    print(
        "v0.8 corpus check: CVE-2024-45782 (grub2-hfs, simplify/replace) present",
        flush=True,
    )

    if "CVE-2026-33236" not in train_text and "nltk" not in train_text.lower():
        raise RuntimeError(
            "ABORT: nltk (CVE-2026-33236) not found in training data. "
            "v0.8 requires the NLTK inline-guard example."
        )
    print("v0.8 corpus check: NLTK inline-guard example present", flush=True)

    if "CVE-2024-33664" not in train_text and "python-jose" not in train_text.lower():
        raise RuntimeError(
            "ABORT: python-jose (CVE-2024-33664) not found in training data. "
            "v0.8 requires the python-jose JWE-size-limit example."
        )
    print("v0.8 corpus check: python-jose inline-guard example present", flush=True)

    # Dev set integrity
    dev_text = "\n".join(json.dumps(r) for r in load_jsonl(valid_path))
    if (
        "python_multipart" not in dev_text
        and "python-multipart" not in dev_text.lower()
    ):
        raise RuntimeError(
            "ABORT: python-multipart not found in dev data. "
            "v0.8 dev set must include Python examples for mixed-language eval signal."
        )
    print("v0.8 corpus check: python-multipart in dev set", flush=True)

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
        "task": "authoring-lora-v0.8",
        "base_model": MODEL_ID,
        "base_model_revision": MODEL_REVISION,
        "corpus_freeze_sha": os.environ.get("CORPUS_FREEZE_SHA", "unknown"),
        "dataset_repo": "adastracomputing/authoring-lora-data-v5",
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
