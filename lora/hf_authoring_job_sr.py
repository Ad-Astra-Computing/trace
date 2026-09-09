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
Authoring-LoRA v1.3 — HF Jobs UV-script (honest scale-up data arc)

Self-contained PEP 723 script run via `hf jobs uv run` on HF GPU infrastructure.
Trains Qwen2.5-Coder-14B-Instruct on the author-from-vuln task.

v1.3 vs v1.2:
  - Dataset: 109 train / 6 dev (authoring-lora-data-v9: v8 + 15 real-diff examples)
  - 15 new hand-authored, gate-checked training examples spanning a
    localization + edit-precision stratification matrix (fix-site position,
    distractor density, edit type, language, function size, signal shape,
    token rarity): libtiff CVE-2015-8784, tcpdump CVE-2017-12898/CVE-2017-13024,
    libpng CVE-2018-13785, file CVE-2019-18218, nginx CVE-2021-23017,
    Pillow CVE-2021-28677, lz4 CVE-2021-3520, openjpeg CVE-2021-3575,
    libssh CVE-2023-3603, c-ares CVE-2024-25629, libarchive CVE-2024-37407,
    Werkzeug CVE-2024-49766, cJSON CVE-2025-57052, gpac CVE-2026-7135
  - System prompt: 6 rules (rule 7 absent — identical to v1.0/v1.1/v1.2)
  - max_steps: 375 (identical to v1.0/v1.1/v1.2)
  - ALL hyperparameters identical to v1.0/v1.1/v1.2 — this run isolates the
    data lever (dataset size + localization/precision coverage) and nothing else

Hypothesis: the v1.0-v1.2 arc held hyperparameters fixed while incrementally
growing the real-diff supplement set (3 -> 6 examples) without flipping a canary.
v1.3 is the definitive test of the *data lever*: a 15-example stratified scale-up
that spans the localization (where in the window the edit lands, how many
distractor functions surround it) and edit-precision (constant tighten, inline
condition, bounds guard, null check) axes the canaries probe. If more, more
diverse, correctly-localized training data is what the model needs, this batch
is where it should show — either a canary flips to PASS or the narrowed-window
localization ablation improves qualitatively. If v1.3 also fails to move a
canary, the data lever is falsified for this shape and the next arc is a
prompt/architecture change, not more data.

Expected outcome / prediction: this is the definitive test of the data lever.
Success = ANY canary (pyjwt / zlib / requests / bzip2-canary) flips to PASS, OR
a clear qualitative localization improvement on the narrowed-window ablation
shape. A null result (no canary flips, no ablation improvement) falsifies "more
data fixes it" for this shape and redirects the next arc away from data.

Submission (see lora/submit_hf_authoring_job_v1.3.sh):
  hf jobs uv run --flavor a100-large --namespace odoom \\
    --secrets HF_TOKEN \\
    -v hf://datasets/adastracomputing/authoring-lora-data-v9:/data:ro \\
    -e PYTORCH_CUDA_ALLOC_CONF=expandable_segments:True \\
    -e HF_HOME=/tmp/hf -e ADAPTER_DIR=/tmp/authoring-lora-v1.3 \\
    -e HUB_MODEL_ID=adastracomputing/authoring-lora-v1.3 \\
    lora/hf_authoring_job_v1.3.py
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

# LoRA hyperparameters — identical to v0.1-v1.2 for fair comparison
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

# v1.3: 375 steps × grad_accum 4 = 1500 effective steps ≈ 3.4 passes over 109 train examples
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
    adapter_dir = Path(os.environ.get("ADAPTER_DIR", "/tmp/authoring-lora-v1.3"))
    hub_model_id = os.environ.get(
        "HUB_MODEL_ID", "adastracomputing/authoring-lora-v1.3"
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
                "Re-export authoring.train.jsonl with the v9 dataset."
            )
    print("Canary integrity check: all 4 canaries absent from training set", flush=True)

    # SR variant: labels are search/replace blocks (not free-form unified diffs).
    if "<<<<<<< SEARCH" not in train_text or ">>>>>>> REPLACE" not in train_text:
        raise RuntimeError(
            "ABORT: search/replace markers not found — expected SR-format labels."
        )
    print("SR corpus check: search/replace-format labels present", flush=True)

    # v10-clean: report how many of the known v9 real-diff supplements survive the
    # 2026-07-13 integrity fix (informative, NOT a hard gate — the re-baseline trains
    # on whatever the honest corpus contains; the exporter now excludes any pair that
    # became ungrounded/duplicate/self-leaked). See docs/FINDINGS_LORA.md.
    _known_supplements = [
        "CVE-2019-12900",
        "CVE-2019-3863",
        "CVE-2025-69693",
        "CVE-2017-12652",
        "CVE-2020-15503",
        "CVE-2025-5917",
        "CVE-2015-8784",
        "CVE-2017-12898",
        "CVE-2017-13024",
        "CVE-2018-13785",
        "CVE-2019-18218",
        "CVE-2021-23017",
        "CVE-2021-28677",
        "CVE-2021-3520",
        "CVE-2021-3575",
        "CVE-2023-3603",
        "CVE-2024-25629",
        "CVE-2024-37407",
        "CVE-2024-49766",
        "CVE-2025-57052",
        "CVE-2026-7135",
    ]
    _present = sum(1 for c in _known_supplements if c in train_text)
    print(
        f"v10-clean corpus check: {_present}/{len(_known_supplements)} known real-diff "
        "supplements survive the integrity fix",
        flush=True,
    )

    # Sanity floor for the CLEAN corpus (integrity-gated 91->79 rows, ~68 train).
    # Catches a broken/empty upload without hardcoding the old v9 count.
    if len(train_ds) < 50:
        raise RuntimeError(
            f"ABORT: expected >= 50 train examples in the SR corpus, got {len(train_ds)}. "
            "Re-upload authoring-lora-data-v10-clean from exports/authoring-lora/."
        )
    print(
        f"v10-clean corpus check: train size {len(train_ds)} (>= 60 floor)", flush=True
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
        "task": "authoring-lora-sr",
        "base_model": MODEL_ID,
        "base_model_revision": MODEL_REVISION,
        "corpus_freeze_sha": os.environ.get("CORPUS_FREEZE_SHA", "unknown"),
        "dataset_repo": "adastracomputing/authoring-lora-data-sr",
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
