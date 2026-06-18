# Reviewer-LoRA v1.0 — training runbook

**Task**: binary accept/reject SFT on Qwen2.5-Coder-14B-Instruct  
**Data**: `exports/reviewer-v1.0/reviewer.jsonl` — 92 examples (69 train / 12 dev / 11 test)  
**Frontier baseline**: `data/reports/frontier-baseline-v1.0.json` — 90.9% accuracy, 0 false-accepts  
**Corpus freeze HEAD**: `e70b3ff` (re-run `trace export reviewer --out exports/reviewer-v1.0` to regenerate)

---

## Path A: mlx-lm on Apple Silicon (perdurabo)

### Prerequisites

```bash
pip install mlx-lm huggingface_hub
```

Check mlx-lm is installed:

```bash
python3 -m mlx_lm.lora --help
```

### Setup + train

```bash
# From repo root (run once per session)
bash lora/prepare_mlx_data.sh

# Train (logs to stdout; adapters written to lora/adapters/reviewer-v1.0/)
python3 -m mlx_lm.lora --config lora/mlx_config.yaml
```

Expected duration on M-series 64GB: ~20-40 min for 500 iters at batch_size=1, max_seq_len=16384.

### Evaluate after training

```bash
# Run eval on test fold using the trained adapter
python3 -m mlx_lm.lora \
  --model Qwen/Qwen2.5-Coder-14B-Instruct \
  --adapter-path lora/adapters/reviewer-v1.0 \
  --data exports/lora \
  --test

# Then run the baseline harness against the fine-tuned model
# (requires serving the adapter or converting to GGUF first — see below)
```

### Convert for inference comparison

```bash
# Fuse adapter into model weights for comparison vs frontier baseline
python3 -m mlx_lm.fuse \
  --model Qwen/Qwen2.5-Coder-14B-Instruct \
  --adapter-path lora/adapters/reviewer-v1.0 \
  --save-path lora/fused/reviewer-v1.0
```

---

## Path B: HuggingFace (cloud GPU)

Use TRL SFTTrainer with QLoRA. The data is already in OpenAI chat format.

Compute: `RunPod RTX 4090 (24GB)` with QLoRA (4-bit), or `A100 40GB` with full LoRA BF16.

See `lora/hf_train.py` (to be written if perdurabo path fails).

---

## Comparison methodology

After training, re-run `eval/frontier_baseline.py` with the fine-tuned model against the
**same 11-example test fold** and compare:

| metric | frontier target | LoRA goal |
|---|---|---|
| verdict accuracy | 90.9% | ≥ 90.9% |
| false_accept_count | 0 | 0 |
| false_reject_count | 0 | ≤ 1 |
| parse_failure_count | 1 | 0 |

A LoRA that eliminates the parse failure (11/11 accuracy) without introducing false accepts
is a clear win. A LoRA that introduces false accepts on negatives is a regression regardless
of accuracy.
