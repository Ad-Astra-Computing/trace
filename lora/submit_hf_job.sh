#!/usr/bin/env bash
# Submit the Reviewer-LoRA v1.0 training run as an HF Job.
#
# Prereqs:
#   - HF_TOKEN in .env (write scope, member of adastracomputing org)
#   - data already uploaded to dataset repo adastracomputing/reviewer-lora-data
#   - `hf` CLI on PATH (nix: nixpkgs#python3Packages.huggingface-hub)
#
# Hardware: a100-large (1x A100 80GB, $2.50/hr). L40S 44GB OOM'd at step 3 on the
# full-vocab cross-entropy spike (Qwen 152K vocab x ~15K-token outliers => ~8.5 GiB
# logits in fp32). 80GB absorbs it. Expected wall-clock <1h ≈ $1.5-2.5.
#
# Billing vs destination: the job runs in the `odoom` namespace (personal HF Jobs
# credits — the adastracomputing org has none), but the trained adapter is pushed
# to the org repo via HUB_MODEL_ID. Namespace = who pays; HUB_MODEL_ID = where it lands.
set -euo pipefail
cd "$(dirname "$0")/.."

set -a && source .env && set +a
: "${HF_TOKEN:?HF_TOKEN not set}"
export HF_TOKEN

FLAVOR="a100-large"
NAMESPACE="odoom"
DATASET="adastracomputing/reviewer-lora-data"
HUB_MODEL_ID="adastracomputing/reviewer-lora-v1.0"
CORPUS_FREEZE_SHA="e70b3ff"
TRACE_COMMIT="$(git rev-parse HEAD)"
# Latest dataset repo commit (pin the exact data state):
DATASET_COMMIT="${DATASET_COMMIT:-$(hf api "datasets/${DATASET}" 2>/dev/null | python3 -c 'import json,sys; print(json.load(sys.stdin).get("sha","unknown"))' 2>/dev/null || echo unknown)}"

echo "Submitting Reviewer-LoRA v1.0 HF Job"
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
  -e ADAPTER_DIR=/tmp/reviewer-lora-v1.0 \
  -e HUB_MODEL_ID="${HUB_MODEL_ID}" \
  -e HF_JOB_FLAVOR="${FLAVOR}" \
  -e CORPUS_FREEZE_SHA="${CORPUS_FREEZE_SHA}" \
  -e DATASET_COMMIT="${DATASET_COMMIT}" \
  -e TRACE_COMMIT="${TRACE_COMMIT}" \
  lora/hf_job.py
