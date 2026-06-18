#!/usr/bin/env bash
# Submit the Reviewer-LoRA v1.0 eval (inference) as an HF Job.
# Generates verdicts for the 11 held-out test examples; pushes responses.jsonl
# to the adapter repo. Score locally afterward with eval/score_lora_responses.py.
#
# Inference is light (no training-loss logits spike), but prompts run to ~15K
# tokens, so l40sx1 (48GB) gives comfortable headroom. Short job ≈ a few min.
set -euo pipefail
cd "$(dirname "$0")/.."

set -a && source .env && set +a
: "${HF_TOKEN:?HF_TOKEN not set}"
export HF_TOKEN

FLAVOR="l40sx1"
NAMESPACE="odoom"
DATASET="adastracomputing/reviewer-lora-data"
ADAPTER_REPO="adastracomputing/reviewer-lora-v1.0"

echo "Submitting Reviewer-LoRA v1.0 EVAL job (flavor ${FLAVOR}, namespace ${NAMESPACE})"

hf jobs uv run \
  --flavor "${FLAVOR}" \
  --namespace "${NAMESPACE}" \
  --timeout 40m \
  --detach \
  --secrets HF_TOKEN \
  -v "hf://datasets/${DATASET}:/data:ro" \
  -e PYTORCH_CUDA_ALLOC_CONF=expandable_segments:True \
  -e HF_HOME=/tmp/hf \
  -e DATA_DIR=/data \
  -e ADAPTER_REPO="${ADAPTER_REPO}" \
  lora/hf_eval_job.py
