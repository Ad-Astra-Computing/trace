#!/usr/bin/env bash
# Submit Reviewer-LoRA v1.1 training run as an HF Job.
#
# v1.1 changes vs v1.0:
#   - 104 examples (77 pos + 27 neg) vs 92 (v1.0) / 102 freeze
#   - sqlite (CVE-2022-46908) moved to train via data/splits/reviewer-v1.1.json
#   - 2 new targeted negatives: sqlite extra-unrelated-hunk, procps extra-unrelated-hunk
#   - MAX_STEPS=158 (~7.5 effective epochs at train_n=82, grad_accum=4)
#   - adapter published to adastracomputing/reviewer-lora-v1.1
#
# Hardware: a100-large (1x A100 80GB). L40S OOM'd at v1.0 on logits spike.
# Expected wall-clock <1h ≈ $1.5-2.5.
set -euo pipefail
cd "$(dirname "$0")/.."

set -a && source .env && set +a
: "${HF_TOKEN:?HF_TOKEN not set}"
export HF_TOKEN

FLAVOR="a100-large"
NAMESPACE="odoom"
DATASET="adastracomputing/reviewer-lora-data"
HUB_MODEL_ID="adastracomputing/reviewer-lora-v1.1"
CORPUS_FREEZE_SHA="$(git rev-parse HEAD)"
TRACE_COMMIT="${CORPUS_FREEZE_SHA}"
MAX_STEPS=158

JSONL="exports/reviewer-v1.1/reviewer.jsonl"
if [[ ! -f "${JSONL}" ]]; then
  echo "ERROR: ${JSONL} not found. Run:" >&2
  echo "  python3 -m tools.trace_cli export reviewer --out exports/reviewer-v1.1 --split-manifest data/splits/reviewer-v1.1.json" >&2
  exit 1
fi

echo "Uploading v1.1 training JSONL to hf://datasets/${DATASET} ..."
nix-shell -p python3Packages.huggingface-hub --run \
  "hf upload ${DATASET} ${JSONL} train.jsonl --repo-type dataset"

echo
echo "Submitting Reviewer-LoRA v1.1 HF Job"
echo "  flavor:         ${FLAVOR}"
echo "  namespace:      ${NAMESPACE}"
echo "  dataset:        ${DATASET}"
echo "  push adapter →  ${HUB_MODEL_ID}"
echo "  max_steps:      ${MAX_STEPS} (~7.5 effective epochs, train_n=82)"
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
  -e ADAPTER_DIR=/tmp/reviewer-lora-v1.1 \
  -e HUB_MODEL_ID='${HUB_MODEL_ID}' \
  -e HF_JOB_FLAVOR='${FLAVOR}' \
  -e CORPUS_FREEZE_SHA='${CORPUS_FREEZE_SHA}' \
  -e TRACE_COMMIT='${TRACE_COMMIT}' \
  -e MAX_STEPS='${MAX_STEPS}' \
  lora/hf_job.py
"
