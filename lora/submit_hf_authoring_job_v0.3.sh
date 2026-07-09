#!/usr/bin/env bash
# Submit the Authoring-LoRA v0.3 training run as an HF Job.
#
# v0.3 purpose: diagnostic clean-canary run
#   - Uses the CORRECTED authoring-lora-data (pyjwt properly excluded)
#   - Same hyperparams as v0.2 for fair comparison
#   - Adds a runtime integrity check that aborts if pyjwt leaks in
#
# Prereqs:
#   HF_TOKEN in .env (write scope, member of adastracomputing org)
#   Dataset already uploaded to adastracomputing/authoring-lora-data with
#   the corrected authoring.train.jsonl (82 rows, pyjwt excluded).
#
# Hardware: a100-large (1x A100 80GB). ~30-35 min. ~$2-4.
# Billing namespace: odoom (personal HF Jobs credits).
set -euo pipefail
cd "$(dirname "$0")/.."

set -a && source .env && set +a
: "${HF_TOKEN:?HF_TOKEN not set}"
export HF_TOKEN

FLAVOR="a100-large"
NAMESPACE="odoom"
DATASET="adastracomputing/authoring-lora-data"
HUB_MODEL_ID="adastracomputing/authoring-lora-v0.3"
CORPUS_FREEZE_SHA="$(git rev-parse HEAD)"
TRACE_COMMIT="$(git rev-parse HEAD)"
DATASET_COMMIT="${DATASET_COMMIT:-$(python3 -c "
from huggingface_hub import HfApi
import os
api = HfApi(token=os.environ['HF_TOKEN'])
info = api.dataset_info('adastracomputing/authoring-lora-data')
print(info.sha or 'unknown')
" 2>/dev/null || echo unknown)}"

echo "Submitting Authoring-LoRA v0.3 HF Job"
echo "  flavor:         ${FLAVOR}"
echo "  namespace:      ${NAMESPACE}"
echo "  dataset:        ${DATASET} @ ${DATASET_COMMIT}"
echo "  push adapter →  ${HUB_MODEL_ID}"
echo "  trace commit:   ${TRACE_COMMIT}"

hf jobs uv run \
  --flavor "${FLAVOR}" \
  --namespace "${NAMESPACE}" \
  --timeout 2h \
  --detach \
  --secrets HF_TOKEN \
  -v "hf://datasets/${DATASET}:/data:ro" \
  -e PYTORCH_CUDA_ALLOC_CONF=expandable_segments:True \
  -e HF_HOME=/tmp/hf \
  -e DATA_DIR=/data \
  -e ADAPTER_DIR=/tmp/authoring-lora-v0.3 \
  -e HUB_MODEL_ID="${HUB_MODEL_ID}" \
  -e HF_JOB_FLAVOR="${FLAVOR}" \
  -e CORPUS_FREEZE_SHA="${CORPUS_FREEZE_SHA}" \
  -e DATASET_COMMIT="${DATASET_COMMIT}" \
  -e TRACE_COMMIT="${TRACE_COMMIT}" \
  lora/hf_authoring_job_v0.3.py
