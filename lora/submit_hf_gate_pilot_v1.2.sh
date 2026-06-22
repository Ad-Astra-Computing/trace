#!/usr/bin/env bash
# Submit Reviewer-LoRA v1.2 gate pilot (inference job).
#
# Gate = 0 FR + 0 FA on 5 canary + 11 test = 16 examples.
# Canary: sqlite + procps positives (v1.0 false-rejects), 3 source-backport negatives.
# Test: 11 examples from data/splits/reviewer-v1.2.json test fold.
#
# After job completes, download responses and score:
#   python3 eval/score_gate_pilot.py \
#     --pilot exports/reviewer-v1.2/gate-pilot.jsonl \
#     --responses <downloaded_responses.jsonl> \
#     --out data/reports/lora-gate-pilot-v1.2.json
set -euo pipefail
cd "$(dirname "$0")/.."

set -a && source .env && set +a
: "${HF_TOKEN:?HF_TOKEN not set}"
export HF_TOKEN

FLAVOR="l40sx1"
NAMESPACE="odoom"
DATASET="adastracomputing/reviewer-lora-data"
ADAPTER_REPO="adastracomputing/reviewer-lora-v1.2"
PILOT_JSONL="exports/reviewer-v1.2/gate-pilot.jsonl"

if [[ ! -f "${PILOT_JSONL}" ]]; then
  echo "ERROR: ${PILOT_JSONL} not found. Run build step first." >&2
  exit 1
fi

N=$(wc -l < "${PILOT_JSONL}")
echo "Uploading gate-pilot.jsonl (${N} examples) to hf://datasets/${DATASET} ..."
nix-shell -p python3Packages.huggingface-hub --run \
  "hf upload ${DATASET} ${PILOT_JSONL} gate-pilot.jsonl --repo-type dataset"

echo
echo "Submitting gate pilot inference job"
echo "  flavor:       ${FLAVOR}"
echo "  adapter:      ${ADAPTER_REPO}"
echo "  dataset:      ${DATASET}"
echo "  input file:   gate-pilot.jsonl (${N} examples: 5 canary + 11 test)"

nix-shell -p python3Packages.huggingface-hub --run "
hf jobs uv run \
  --flavor '${FLAVOR}' \
  --namespace '${NAMESPACE}' \
  --timeout 1h \
  --detach \
  --secrets HF_TOKEN \
  -v 'hf://datasets/${DATASET}:/data:ro' \
  -e HF_HOME=/tmp/hf \
  -e DATA_DIR=/data \
  -e ADAPTER_REPO='${ADAPTER_REPO}' \
  lora/hf_gate_pilot_job.py
"
