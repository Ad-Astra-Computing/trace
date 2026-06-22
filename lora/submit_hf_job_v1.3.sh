#!/usr/bin/env bash
# Submit Reviewer-LoRA v1.3 training run as an HF Job.
#
# v1.3 changes vs v1.2:
#   - 111 examples (77 pos + 34 neg), 89 train (vs 88)
#   - Required ## Patch comparison section in all source-backport reviews
#   - 9 source-backport train negatives (all with PC sections)
#   - 28 source-backport train positives (all with PC sections)
#   - System prompt: prompts/reviewer.v5.md (adds PC requirement)
#   - Split manifest: data/splits/reviewer-v1.3.json
#   - MAX_STEPS=175 (~7.5 effective epochs at train_n=89, grad_accum=4)
#   - Adapter published to adastracomputing/reviewer-lora-v1.3
#
# Motivation: v1.2 gate pilot failed with 2 false accepts on source-backport
# negatives (reversed-hunk, partial-hunk). Root cause: model hallucinated
# patch content from narrative context rather than reading +/- lines.
# v1.3 adds explicit PC sections forcing line-by-line comparison reasoning.
#
# Hardware: a100-large (1x A100 80GB).
# Expected wall-clock ~75 min.
set -euo pipefail
cd "$(dirname "$0")/.."

set -a && source .env && set +a
: "${HF_TOKEN:?HF_TOKEN not set}"
export HF_TOKEN

FLAVOR="a100-large"
NAMESPACE="odoom"
DATASET="adastracomputing/reviewer-lora-data"
HUB_MODEL_ID="adastracomputing/reviewer-lora-v1.3"
CORPUS_FREEZE_SHA="$(git rev-parse HEAD)"
TRACE_COMMIT="${CORPUS_FREEZE_SHA}"
# train_n=89, grad_accum=4 → steps_per_epoch≈23; 7.5 epochs → 175 steps
MAX_STEPS=175

JSONL_DIR="exports/reviewer-v1.3"
JSONL="${JSONL_DIR}/reviewer.jsonl"

if [[ ! -f "${JSONL}" ]]; then
  echo "Generating v1.3 training JSONL ..."
  python3 -m tools.trace_cli export reviewer \
    --out "${JSONL_DIR}" \
    --reviewer-prompt prompts/reviewer.v5.md \
    --split-manifest data/splits/reviewer-v1.3.json
fi

echo "Uploading v1.3 training JSONL to hf://datasets/${DATASET} ..."
nix-shell -p python3Packages.huggingface-hub --run \
  "hf upload ${DATASET} ${JSONL} train.jsonl --repo-type dataset"

echo
echo "Submitting Reviewer-LoRA v1.3 HF Job"
echo "  flavor:         ${FLAVOR}"
echo "  namespace:      ${NAMESPACE}"
echo "  dataset:        ${DATASET}"
echo "  push adapter →  ${HUB_MODEL_ID}"
echo "  max_steps:      ${MAX_STEPS} (~7.5 effective epochs, train_n=89)"
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
  -e ADAPTER_DIR=/tmp/reviewer-lora-v1.3 \
  -e HUB_MODEL_ID='${HUB_MODEL_ID}' \
  -e HF_JOB_FLAVOR='${FLAVOR}' \
  -e CORPUS_FREEZE_SHA='${CORPUS_FREEZE_SHA}' \
  -e TRACE_COMMIT='${TRACE_COMMIT}' \
  -e MAX_STEPS='${MAX_STEPS}' \
  lora/hf_job.py
"
