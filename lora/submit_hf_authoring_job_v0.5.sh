#!/usr/bin/env bash
# Submit the Authoring-LoRA v0.5 training run as an HF Job.
#
# v0.5 purpose: inline-guard detect-and-reject training (2 examples: NLTK + python-jose)
#   - Uses authoring-v2 manifest: NLTK (CVE-2026-33236) + python-jose (CVE-2024-33664) → train
#   - 85 train rows (vs 83 for v0.4; 2 detect-and-reject Python examples added)
#   - 550 steps (vs 500 for v0.4 — +10% budget for extra examples)
#   - Tests pyjwt canary generalization with 2 inline-guard detect-and-reject examples
#
# Prereqs:
#   HF_TOKEN in .env (write scope, member of adastracomputing org)
#   Dataset uploaded to adastracomputing/authoring-lora-data with
#   authoring.train.jsonl = 85 rows (NLTK + python-jose + aiohttp included, pyjwt excluded).
#   Use: python3 -m tools.trace_cli export authoring \
#          --split-manifest data/splits/authoring-v2.json --out exports/authoring/
#       python3 eval/package_authoring_lora.py
#       hf upload adastracomputing/authoring-lora-data exports/authoring-lora/ --repo-type dataset
#
# Hardware: a100-large (1x A100 80GB). ~40-45 min. ~$2-4.
# Billing namespace: odoom (personal HF Jobs credits).
set -euo pipefail
cd "$(dirname "$0")/.."

set -a && source .env && set +a
: "${HF_TOKEN:?HF_TOKEN not set}"
export HF_TOKEN

FLAVOR="a100-large"
NAMESPACE="odoom"
DATASET="adastracomputing/authoring-lora-data"
HUB_MODEL_ID="adastracomputing/authoring-lora-v0.5"
CORPUS_FREEZE_SHA="$(git rev-parse HEAD)"
TRACE_COMMIT="$(git rev-parse HEAD)"
DATASET_COMMIT="${DATASET_COMMIT:-unknown}"

echo "Submitting Authoring-LoRA v0.5 HF Job"
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
  -e ADAPTER_DIR=/tmp/authoring-lora-v0.5 \
  -e HUB_MODEL_ID="${HUB_MODEL_ID}" \
  -e HF_JOB_FLAVOR="${FLAVOR}" \
  -e CORPUS_FREEZE_SHA="${CORPUS_FREEZE_SHA}" \
  -e DATASET_COMMIT="${DATASET_COMMIT}" \
  -e TRACE_COMMIT="${TRACE_COMMIT}" \
  lora/hf_authoring_job_v0.5.py
