#!/usr/bin/env python3
"""
Reviewer-LoRA v1.0 — HuggingFace/TRL training script

Fine-tunes Qwen2.5-Coder-14B-Instruct on the binary accept/reject task
via LoRA (full BF16) or QLoRA (4-bit nf4, default).

Requirements:
    nix develop .#lora   # or: pip install -r lora/requirements-hf.txt

Usage:
    # From repo root, after running lora/prepare_mlx_data.sh to generate exports/lora/
    python3 lora/hf_train.py

    # Override data dir or adapter output:
    python3 lora/hf_train.py --data exports/lora --adapter-path lora/adapters/reviewer-v1.0

    # Full BF16 LoRA on A100 40GB+:
    python3 lora/hf_train.py --no-qlora

Hyperparameters mirror lora/mlx_config.yaml so results are comparable.
"""
import argparse
import json
from pathlib import Path

import torch
from datasets import Dataset
from peft import LoraConfig, TaskType
from transformers import AutoModelForCausalLM, AutoTokenizer, BitsAndBytesConfig
from trl import SFTConfig, SFTTrainer

MODEL_ID = "Qwen/Qwen2.5-Coder-14B-Instruct"

# LoRA hyperparameters — match mlx_config.yaml (rank=16, scale=1.0 → alpha=rank)
LORA_RANK = 16
LORA_ALPHA = 16
LORA_DROPOUT = 0.05
# Attention + MLP projections for Qwen2.5
LORA_TARGET_MODULES = [
    "q_proj", "k_proj", "v_proj", "o_proj",
    "gate_proj", "up_proj", "down_proj",
]


def load_jsonl(path: Path) -> list:
    with open(path) as f:
        return [json.loads(line) for line in f if line.strip()]


def make_formatting_func(tok):
    """Return a batch-mode formatting function for SFTTrainer.

    Using formatting_func (rather than the auto-messages path) because it lets
    us apply Qwen2.5's chat template explicitly and verify the rendered output.
    Loss is computed over all tokens (system + user + assistant); acceptable for
    a 92-example binary SFT where the signal is entirely in the assistant turn.
    """
    def fmt(examples):
        # examples is a dict of lists: {"messages": [[...], [...], ...]}
        return [
            tok.apply_chat_template(msgs, tokenize=False, add_generation_prompt=False)
            for msgs in examples["messages"]
        ]
    return fmt


def main():
    parser = argparse.ArgumentParser(description="Reviewer-LoRA v1.0 fine-tune")
    parser.add_argument("--data", default="exports/lora",
                        help="Directory with train.jsonl / valid.jsonl (default: exports/lora)")
    parser.add_argument("--adapter-path", default="lora/adapters/reviewer-v1.0",
                        help="Where to save LoRA adapter weights")
    parser.add_argument("--qlora", dest="qlora", action="store_true", default=True,
                        help="Use 4-bit QLoRA (default)")
    parser.add_argument("--no-qlora", dest="qlora", action="store_false",
                        help="Disable QLoRA; use full BF16 LoRA (requires ≥40GB VRAM)")
    parser.add_argument("--max-steps", type=int, default=150,
                        help="Optimizer steps (default: 150; with grad_accum=4 this is "
                             "~8.7 epochs over 69 train examples. 500 = ~29 epochs overfits a 14B.)")
    args = parser.parse_args()

    data_dir = Path(args.data)
    adapter_path = Path(args.adapter_path)
    adapter_path.mkdir(parents=True, exist_ok=True)

    # Validate data files exist
    for name in ("train.jsonl", "valid.jsonl"):
        p = data_dir / name
        if not p.exists():
            raise FileNotFoundError(
                f"{p} not found. Run: bash lora/prepare_mlx_data.sh"
            )

    train_records = load_jsonl(data_dir / "train.jsonl")
    valid_records = load_jsonl(data_dir / "valid.jsonl")
    train_ds = Dataset.from_list(train_records)
    valid_ds = Dataset.from_list(valid_records)
    print(f"Data  train={len(train_ds)}  valid={len(valid_ds)}")

    # Qwen2.5 is natively supported by transformers >= 4.44; no trust_remote_code needed.
    tokenizer = AutoTokenizer.from_pretrained(MODEL_ID)
    tokenizer.pad_token = tokenizer.eos_token
    tokenizer.padding_side = "right"

    bnb_config = None
    if args.qlora:
        bnb_config = BitsAndBytesConfig(
            load_in_4bit=True,
            bnb_4bit_quant_type="nf4",
            bnb_4bit_compute_dtype=torch.bfloat16,
            bnb_4bit_use_double_quant=True,
        )

    model = AutoModelForCausalLM.from_pretrained(
        MODEL_ID,
        quantization_config=bnb_config,
        device_map="auto",
        torch_dtype=torch.bfloat16 if not args.qlora else None,
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

    bf16_supported = torch.cuda.is_available() and torch.cuda.is_bf16_supported()
    sft_config = SFTConfig(
        output_dir=str(adapter_path),
        max_steps=args.max_steps,
        per_device_train_batch_size=1,
        # Gradient accumulation: effective batch=4 for CUDA training stability.
        # With 69 train examples, 500 optimizer steps × 4 accum = ~29 epochs.
        gradient_accumulation_steps=4,
        learning_rate=1e-4,
        lr_scheduler_type="cosine",
        warmup_steps=50,
        bf16=bf16_supported,
        fp16=(not bf16_supported and torch.cuda.is_available()),
        # gradient_checkpointing: essential for 14B at max_seq_len=16384 on 24GB VRAM.
        gradient_checkpointing=True,
        # use_reentrant=False is the stable QLoRA + checkpointing path.
        gradient_checkpointing_kwargs={"use_reentrant": False},
        # paged_adamw_8bit: bitsandbytes paged optimizer, avoids OOM spikes on 4090.
        optim="paged_adamw_8bit",
        logging_steps=10,
        eval_strategy="steps",
        eval_steps=50,
        save_strategy="steps",
        save_steps=100,
        save_total_limit=3,
        load_best_model_at_end=True,
        metric_for_best_model="eval_loss",
        max_seq_length=16384,
        packing=False,
        report_to="none",
    )

    trainer = SFTTrainer(
        model=model,
        args=sft_config,
        train_dataset=train_ds,
        eval_dataset=valid_ds,
        peft_config=peft_config,
        formatting_func=make_formatting_func(tokenizer),
        # TRL tokenizes the formatted strings with processing_class; pass ours
        # so pad_token / padding_side="right" aren't dropped.
        processing_class=tokenizer,
    )

    mode = "QLoRA 4-bit nf4" if args.qlora else "full BF16 LoRA"
    print(f"Model  {MODEL_ID}")
    print(f"LoRA   rank={LORA_RANK}  alpha={LORA_ALPHA}  dropout={LORA_DROPOUT}  mode={mode}")
    print(f"Train  max_steps={args.max_steps}  lr=1e-4  warmup=50")
    print(f"Out    {adapter_path}")

    trainer.train()
    trainer.save_model(str(adapter_path))
    tokenizer.save_pretrained(str(adapter_path))
    print(f"\nDone. Adapter saved to {adapter_path}")


if __name__ == "__main__":
    main()
