#!/usr/bin/env bash
# Submit the pass@K + memorization diagnostic (codex/Fable plan, 2026-07-14) against the
# v10-clean adapter. One GPU job: greedy regeneration of N_MEM own-train labels
# (memorization) + K sampled generations per canary (pass@K). Scored offline with
# lora/score_canaries_graded.py. See DECISIONS 2026-07-14 + docs/FINDINGS_LORA.md.
set -euo pipefail
cd "$(dirname "$0")/.."
set -a && source .env && set +a
: "${HF_TOKEN:?HF_TOKEN not set}"
export HF_TOKEN
command -v hf >/dev/null 2>&1 || { echo "hf not on PATH — run via nix develop .#lora" >&2; exit 1; }

echo "Submitting pass@K + memcheck (adapter authoring-lora-v10-clean, K=${K:-16})"
hf jobs uv run \
  --flavor "a100-large" \
  --namespace "odoom" \
  --timeout 2h \
  --detach \
  --secrets HF_TOKEN \
  -e "ADAPTER_REPO=adastracomputing/authoring-lora-v10-clean" \
  -e "DATASET_REPO=adastracomputing/authoring-lora-data-v6" \
  -e "TRAIN_REPO=adastracomputing/authoring-lora-data-v10-clean" \
  -e "K=${K:-16}" \
  -e "N_MEM=10" \
  -e "PYTORCH_CUDA_ALLOC_CONF=expandable_segments:True" \
  -e "HF_HOME=/tmp/hf" \
  lora/hf_authoring_passk_memcheck.py
