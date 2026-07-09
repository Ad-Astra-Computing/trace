#!/usr/bin/env bash
# Submit the Authoring-LoRA v0.7 training run as an HF Job.
#
# v0.7 purpose: fix-pattern rebalancing + v0.7 system prompt
#   - Dataset: 88 train / 6 dev (authoring-v4 manifest)
#     - +2 simplify/replace grub2 examples (CVE-2024-45781, CVE-2024-45782)
#     - grub family forced to train (3 previously-dev examples shifted)
#   - System prompt: +rule 5 (minimal structural change / inline condition extension)
#                   +rule 6 (edit most specific class, not base/Protocol)
#   - max_steps: 375 (reduced from 550 to stop before V-shape overfitting at epoch 4.77)
#   - Dataset repo: adastracomputing/authoring-lora-data-v4
#
# Prereqs:
#   HF_TOKEN in .env (write scope, member of adastracomputing org)
#   v4 dataset already uploaded (see adastracomputing/authoring-lora-data-v4)
set -euo pipefail
cd "$(dirname "$0")/.."

set -a && source .env && set +a
: "${HF_TOKEN:?HF_TOKEN not set}"
export HF_TOKEN

FLAVOR="a100-large"
NAMESPACE="odoom"
DATASET="adastracomputing/authoring-lora-data-v4"
HUB_MODEL_ID="adastracomputing/authoring-lora-v0.7"
CORPUS_FREEZE_SHA="$(git rev-parse HEAD)"
TRACE_COMMIT="$(git rev-parse HEAD)"
DATASET_COMMIT="${DATASET_COMMIT:-2af5ff906e0f9fe56dee2e4bc45ae3c8a649b868}"

if command -v hf >/dev/null 2>&1; then
    HF=hf
else
    HF=/nix/store/6g571970xp5kpa650cxp0fc5x11mp5sw-python3.13-huggingface-hub-1.10.2/bin/hf
fi

echo "Submitting Authoring-LoRA v0.7 HF Job"
echo "  flavor:         ${FLAVOR}"
echo "  namespace:      ${NAMESPACE}"
echo "  dataset:        ${DATASET} @ ${DATASET_COMMIT}"
echo "  push adapter →  ${HUB_MODEL_ID}"
echo "  trace commit:   ${TRACE_COMMIT}"

$HF jobs uv run \
  --flavor "${FLAVOR}" \
  --namespace "${NAMESPACE}" \
  --timeout 2h \
  --detach \
  --secrets HF_TOKEN \
  -v "hf://datasets/${DATASET}:/data:ro" \
  -e PYTORCH_CUDA_ALLOC_CONF=expandable_segments:True \
  -e HF_HOME=/tmp/hf \
  -e DATA_DIR=/data \
  -e ADAPTER_DIR=/tmp/authoring-lora-v0.7 \
  -e HUB_MODEL_ID="${HUB_MODEL_ID}" \
  -e HF_JOB_FLAVOR="${FLAVOR}" \
  -e CORPUS_FREEZE_SHA="${CORPUS_FREEZE_SHA}" \
  -e DATASET_COMMIT="${DATASET_COMMIT}" \
  -e TRACE_COMMIT="${TRACE_COMMIT}" \
  lora/hf_authoring_job_v0.7.py
