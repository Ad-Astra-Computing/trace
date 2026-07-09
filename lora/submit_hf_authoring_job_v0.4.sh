#!/usr/bin/env bash
# Submit the Authoring-LoRA v0.4 training run as an HF Job.
#
# v0.4 purpose: Python detect-and-reject corpus expansion
#   - Adds aiohttp CVE-2024-23334 (normpath path-traversal) as 6th Python example
#   - 83 train rows (vs 82 for v0.3)
#   - 500 steps (vs 400 for v0.3 — +25% budget for expanded corpus)
#   - Tests pyjwt canary generalization with richer Python detect-and-reject signal
#
# Prereqs:
#   HF_TOKEN in .env (write scope, member of adastracomputing org)
#   Dataset uploaded to adastracomputing/authoring-lora-data with
#   authoring.train.jsonl = 83 rows (aiohttp included, pyjwt excluded).
#
# Hardware: a100-large (1x A100 80GB). ~35-40 min. ~$2-4.
# Billing namespace: odoom (personal HF Jobs credits).
set -euo pipefail
cd "$(dirname "$0")/.."

set -a && source .env && set +a
: "${HF_TOKEN:?HF_TOKEN not set}"
export HF_TOKEN

FLAVOR="a100-large"
NAMESPACE="odoom"
DATASET="adastracomputing/authoring-lora-data"
HUB_MODEL_ID="adastracomputing/authoring-lora-v0.4"
CORPUS_FREEZE_SHA="$(git rev-parse HEAD)"
TRACE_COMMIT="$(git rev-parse HEAD)"
DATASET_COMMIT="${DATASET_COMMIT:-unknown}"

echo "Submitting Authoring-LoRA v0.4 HF Job"
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
  -e ADAPTER_DIR=/tmp/authoring-lora-v0.4 \
  -e HUB_MODEL_ID="${HUB_MODEL_ID}" \
  -e HF_JOB_FLAVOR="${FLAVOR}" \
  -e CORPUS_FREEZE_SHA="${CORPUS_FREEZE_SHA}" \
  -e DATASET_COMMIT="${DATASET_COMMIT}" \
  -e TRACE_COMMIT="${TRACE_COMMIT}" \
  lora/hf_authoring_job_v0.4.py
