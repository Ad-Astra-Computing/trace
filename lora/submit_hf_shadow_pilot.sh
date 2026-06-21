#!/usr/bin/env bash
# Submit Reviewer-LoRA v1.0 shadow pilot as an HF Job.
#
# Uploads the 16 post-v1.0 positive examples (exports/reviewer-shadow-pilot/
# shadow-pilot.jsonl) to the HF dataset, then runs inference with the v1.0
# adapter. Responses land in the adapter repo at:
#   shadow_pilot_responses/shadow-pilot-responses.jsonl
#
# Score locally afterward:
#   python3 eval/score_lora_responses.py \
#     --responses shadow_pilot_responses/shadow-pilot-responses.jsonl
#
# Requires: hf CLI  (pip install huggingface_hub[hf_transfer])
set -euo pipefail
cd "$(dirname "$0")/.."

set -a && source .env && set +a
: "${HF_TOKEN:?HF_TOKEN not set}"
export HF_TOKEN

SHADOW_JSONL="exports/reviewer-shadow-pilot/shadow-pilot.jsonl"
if [[ ! -f "${SHADOW_JSONL}" ]]; then
  echo "ERROR: ${SHADOW_JSONL} not found. Re-run:" >&2
  echo "  python3 -m tools.trace_cli export reviewer --shadow-pilot" >&2
  exit 1
fi

FLAVOR="l40sx1"
NAMESPACE="odoom"
DATASET="adastracomputing/reviewer-lora-data"
ADAPTER_REPO="adastracomputing/reviewer-lora-v1.0"

echo "Uploading shadow-pilot.jsonl to hf://datasets/${DATASET} ..."
hf upload "${DATASET}" "${SHADOW_JSONL}" shadow-pilot.jsonl --repo-type dataset

echo "Submitting shadow pilot inference job (flavor ${FLAVOR}, namespace ${NAMESPACE})"
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
  lora/hf_shadow_pilot_job.py

echo "Job submitted. When complete, download responses and score:"
echo "  hf download ${ADAPTER_REPO} shadow_pilot_responses/shadow-pilot-responses.jsonl --repo-type model"
echo "  python3 eval/score_lora_responses.py --responses shadow-pilot-responses.jsonl"
