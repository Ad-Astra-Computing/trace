#!/usr/bin/env bash
# Submit Reviewer-LoRA v1.2 training run as an HF Job.
#
# v1.2 changes vs v1.1:
#   - 110 examples (77 pos + 33 neg) vs 104 (v1.1)
#   - 6 new source-backport-specific negatives (reversed-hunk, missing-hunk, partial-hunk)
#   - procps positive (CVE-2023-4016) is a hard prefetch-failure-distractor positive
#   - System prompt: prompts/reviewer.v4.md (vs v2 used at v1.0/v1.1 export time)
#   - Split manifest: data/splits/reviewer-v1.2.json
#   - MAX_STEPS=165 (~7.5 effective epochs at train_n=88, grad_accum=4)
#   - Adapter published to adastracomputing/reviewer-lora-v1.2
#
# Hardware: a100-large (1x A100 80GB). L40S OOM'd at v1.0 on logits spike.
# Expected wall-clock ~75 min ≈ $2-3.
set -euo pipefail
cd "$(dirname "$0")/.."

set -a && source .env && set +a
: "${HF_TOKEN:?HF_TOKEN not set}"
export HF_TOKEN

FLAVOR="a100-large"
NAMESPACE="odoom"
DATASET="adastracomputing/reviewer-lora-data"
HUB_MODEL_ID="adastracomputing/reviewer-lora-v1.2"
CORPUS_FREEZE_SHA="$(git rev-parse HEAD)"
TRACE_COMMIT="${CORPUS_FREEZE_SHA}"
# train_n=88, grad_accum=4 → steps_per_epoch=22; 7.5 epochs → 165 steps
MAX_STEPS=165

JSONL_DIR="exports/reviewer-v1.2"
JSONL="${JSONL_DIR}/reviewer.jsonl"

if [[ ! -f "${JSONL}" ]]; then
  echo "Generating v1.2 training JSONL ..."
  PYTHONPATH="tools:agents:." python3 -m trace_cli export reviewer \
    --out "${JSONL_DIR}" \
    --reviewer-prompt prompts/reviewer.v4.md \
    --split-manifest data/splits/reviewer-v1.2.json
fi

echo "Uploading v1.2 training JSONL to hf://datasets/${DATASET} ..."
nix-shell -p python3Packages.huggingface-hub --run \
  "hf upload ${DATASET} ${JSONL} train.jsonl --repo-type dataset"

echo
echo "Submitting Reviewer-LoRA v1.2 HF Job"
echo "  flavor:         ${FLAVOR}"
echo "  namespace:      ${NAMESPACE}"
echo "  dataset:        ${DATASET}"
echo "  push adapter →  ${HUB_MODEL_ID}"
echo "  max_steps:      ${MAX_STEPS} (~7.5 effective epochs, train_n=88)"
echo "  trace commit:   ${TRACE_COMMIT}"

nix-shell -p python3Packages.huggingface-hub --run "
hf jobs uv run \
  --flavor '${FLAVOR}' \
  --namespace '${NAMESPACE}' \
  --timeout 2h \
  --detach \
  --secrets HF_TOKEN \
  -v 'hf://datasets/${DATASET}:/data:ro' \
  -e PYTORCH_CUDA_ALLOC_ALLOC_CONF=expandable_segments:True \
  -e HF_HOME=/tmp/hf \
  -e DATA_DIR=/data \
  -e ADAPTER_DIR=/tmp/reviewer-lora-v1.2 \
  -e HUB_MODEL_ID='${HUB_MODEL_ID}' \
  -e HF_JOB_FLAVOR='${FLAVOR}' \
  -e CORPUS_FREEZE_SHA='${CORPUS_FREEZE_SHA}' \
  -e TRACE_COMMIT='${TRACE_COMMIT}' \
  -e MAX_STEPS='${MAX_STEPS}' \
  lora/hf_job.py
"
