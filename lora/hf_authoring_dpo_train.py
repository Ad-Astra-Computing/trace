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
"""DPO on the authoring-LoRA guard-clip failure — HF Jobs UV-script.

Continues from the SFT seed (authoring-lora-v10-clean) and trains a DPO LoRA to prefer
the condition-fold edit shape over the guard-clip shape. Preference pairs come from
lora/build_dpo_guard_clip.py (chosen = reference fold, rejected = the model's own
guard-clip generation).

Reference-policy handling: load the base in bf16 (fits a100-large), MERGE the SFT adapter
into it so the merged model IS the SFT policy, then attach a fresh DPO LoRA. With
ref_model=None + peft_config, TRL uses the DPO-adapter-DISABLED model (= merged SFT) as
the frozen reference — i.e. DPO stays anchored to the SFT policy, exactly as intended.

Eval is offline: greedy canary generation + lora/score_canaries_graded.py (add_recall,
norm_exact, key_token) with pass@16 as a diversity guardrail (see docs/DPO_GUARD_CLIP_PLAN.md).

Env: DPO_DATA_REPO (dataset with dpo.jsonl), SFT_ADAPTER, HUB_MODEL_ID, BETA (0.1),
LR (5e-6), EPOCHS (2), SEED (42).
"""

import json
import os
from pathlib import Path

import torch
from datasets import Dataset
from peft import LoraConfig, PeftModel, TaskType
from transformers import AutoModelForCausalLM, AutoTokenizer
from trl import DPOConfig, DPOTrainer

BASE_MODEL_ID = "Qwen/Qwen2.5-Coder-14B-Instruct"
MODEL_REVISION = "aedcc2d42b622764e023cf882b6652e646b95671"
SFT_ADAPTER = os.environ.get("SFT_ADAPTER", "adastracomputing/authoring-lora-v10-clean")
DPO_DATA_REPO = os.environ.get(
    "DPO_DATA_REPO", "adastracomputing/authoring-dpo-guard-clip-data"
)
HUB_MODEL_ID = os.environ.get(
    "HUB_MODEL_ID", "adastracomputing/authoring-lora-dpo-guard-clip"
)
ADAPTER_DIR = Path(os.environ.get("ADAPTER_DIR", "/tmp/authoring-lora-dpo-guard-clip"))

BETA = float(os.environ.get("BETA", "0.1"))
LR = float(os.environ.get("LR", "5e-6"))
EPOCHS = float(os.environ.get("EPOCHS", "2"))
SEED = int(os.environ.get("SEED", "42"))
LORA_RANK, LORA_ALPHA, LORA_DROPOUT = 16, 16, 0.05
LORA_TARGET_MODULES = [
    "q_proj",
    "k_proj",
    "v_proj",
    "o_proj",
    "gate_proj",
    "up_proj",
    "down_proj",
]


def load_pairs() -> Dataset:
    from huggingface_hub import hf_hub_download

    p = hf_hub_download(
        repo_id=DPO_DATA_REPO, filename="dpo.jsonl", repo_type="dataset"
    )
    rows = [json.loads(l) for l in Path(p).read_text().splitlines() if l.strip()]
    print(f"Loaded {len(rows)} DPO preference pairs", flush=True)
    return Dataset.from_list(rows)


def main():
    ds = load_pairs()
    tok = AutoTokenizer.from_pretrained(BASE_MODEL_ID, revision=MODEL_REVISION)
    if tok.pad_token is None:
        tok.pad_token = tok.eos_token

    print("Loading base (bf16) + merging SFT adapter -> reference policy", flush=True)
    base = AutoModelForCausalLM.from_pretrained(
        BASE_MODEL_ID,
        revision=MODEL_REVISION,
        torch_dtype=torch.bfloat16,
        device_map="auto",
    )
    merged = PeftModel.from_pretrained(base, SFT_ADAPTER)
    merged = merged.merge_and_unload()  # merged now == SFT policy

    peft_config = LoraConfig(
        r=LORA_RANK,
        lora_alpha=LORA_ALPHA,
        lora_dropout=LORA_DROPOUT,
        target_modules=LORA_TARGET_MODULES,
        bias="none",
        task_type=TaskType.CAUSAL_LM,
    )

    args = DPOConfig(
        output_dir=str(ADAPTER_DIR),
        num_train_epochs=EPOCHS,
        per_device_train_batch_size=2,
        gradient_accumulation_steps=2,
        learning_rate=LR,
        beta=BETA,
        max_prompt_length=1024,
        max_length=1536,
        lr_scheduler_type="cosine",
        warmup_ratio=0.1,
        logging_steps=5,
        save_strategy="epoch",
        save_total_limit=2,
        bf16=True,
        seed=SEED,
        report_to="none",
        push_to_hub=True,
        hub_model_id=HUB_MODEL_ID,
        gradient_checkpointing=True,
    )

    trainer = DPOTrainer(
        model=merged,
        ref_model=None,  # peft => DPO-adapter-disabled (merged SFT) is the reference
        args=args,
        train_dataset=ds,
        processing_class=tok,
        peft_config=peft_config,
    )
    print(
        f"DPO: pairs={len(ds)} beta={BETA} lr={LR} epochs={EPOCHS} seed={SEED}",
        flush=True,
    )
    trainer.train()

    trainer.save_model(str(ADAPTER_DIR))
    trainer.push_to_hub()
    (ADAPTER_DIR / "dpo-provenance.json").write_text(
        json.dumps(
            {
                "sft_seed": SFT_ADAPTER,
                "dpo_data": DPO_DATA_REPO,
                "pairs": len(ds),
                "beta": BETA,
                "lr": LR,
                "epochs": EPOCHS,
                "seed": SEED,
            },
            indent=2,
        )
    )
    print(f"Pushed DPO adapter -> {HUB_MODEL_ID}", flush=True)


if __name__ == "__main__":
    main()
