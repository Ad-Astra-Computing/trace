#!/usr/bin/env bash
# Submit Reviewer-LoRA v1.1 mixed gate pilot (inference job).
#
# Reads gate-pilot.jsonl from the dataset mount (uploaded in advance),
# runs the v1.1 adapter on all 13 examples (7 test pos + 4 test neg + 2 retest),
# pushes responses to adastracomputing/reviewer-lora-v1.1/gate_pilot_responses/.
#
# After job completes:
#   python3 eval/score_gate_pilot.py \
#     --pilot exports/reviewer-v1.1/gate-pilot.jsonl \
#     --responses <downloaded_responses.jsonl> \
#     --out data/reports/lora-gate-pilot-v1.1.json
set -euo pipefail
cd "$(dirname "$0")/.."

set -a && source .env && set +a
: "${HF_TOKEN:?HF_TOKEN not set}"
export HF_TOKEN

FLAVOR="l40sx1"
NAMESPACE="odoom"
DATASET="adastracomputing/reviewer-lora-data"
ADAPTER_REPO="adastracomputing/reviewer-lora-v1.1"

echo "Submitting gate pilot inference job"
echo "  flavor:       ${FLAVOR}"
echo "  adapter:      ${ADAPTER_REPO}"
echo "  dataset:      ${DATASET}"
echo "  input file:   gate-pilot.jsonl (13 examples)"

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
