#!/usr/bin/env bash
# Submit the Authoring-LoRA v0.1 training run as an HF Job.
#
# Prereqs:
#   1. Package the data:
#        python3 eval/package_authoring_lora.py
#   2. Upload to HF dataset repo (first-time only):
#        hf upload adastracomputing/authoring-lora-data exports/authoring-lora/ \
#          --repo-type dataset
#   3. HF_TOKEN in .env (write scope, member of adastracomputing org)
#
# Hardware: a100-large (1x A100 80GB). Long source diffs + 16K seq len need 80GB;
# L40S 44GB OOMs on outlier examples. Expected wall-clock <1h ≈ $1.5-2.5.
#
# Billing namespace: odoom (personal HF Jobs credits).
# Adapter destination: adastracomputing/authoring-lora-v0.1 (org repo, private).
set -euo pipefail
cd "$(dirname "$0")/.."

set -a && source .env && set +a
: "${HF_TOKEN:?HF_TOKEN not set}"
export HF_TOKEN

FLAVOR="a100-large"
NAMESPACE="odoom"
DATASET="adastracomputing/authoring-lora-data"
HUB_MODEL_ID="adastracomputing/authoring-lora-v0.1"
CORPUS_FREEZE_SHA="$(git rev-parse HEAD)"
TRACE_COMMIT="$(git rev-parse HEAD)"
DATASET_COMMIT="${DATASET_COMMIT:-$(hf api "datasets/${DATASET}" 2>/dev/null | python3 -c 'import json,sys; print(json.load(sys.stdin).get("sha","unknown"))' 2>/dev/null || echo unknown)}"

echo "Submitting Authoring-LoRA v0.1 HF Job"
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
  -e ADAPTER_DIR=/tmp/authoring-lora-v0.1 \
  -e HUB_MODEL_ID="${HUB_MODEL_ID}" \
  -e HF_JOB_FLAVOR="${FLAVOR}" \
  -e CORPUS_FREEZE_SHA="${CORPUS_FREEZE_SHA}" \
  -e DATASET_COMMIT="${DATASET_COMMIT}" \
  -e TRACE_COMMIT="${TRACE_COMMIT}" \
  lora/hf_authoring_job.py
