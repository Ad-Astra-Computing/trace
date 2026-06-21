#!/usr/bin/env bash
# Download gate pilot responses from adapter repo and score locally.
# Run after submit_hf_gate_pilot.sh job completes.
#
# Usage: bash lora/run_gate_pilot_score.sh [adapter_repo]
set -euo pipefail
cd "$(dirname "$0")/.."

set -a && source .env && set +a
: "${HF_TOKEN:?HF_TOKEN not set}"
export HF_TOKEN

ADAPTER_REPO="${1:-adastracomputing/reviewer-lora-v1.1}"
RESPONSES_LOCAL="/tmp/gate-pilot-responses.jsonl"
REPORT="data/reports/lora-gate-pilot-v1.1.json"

echo "Downloading gate pilot responses from ${ADAPTER_REPO} ..."
nix-shell -p python3Packages.huggingface-hub --run "
hf download ${ADAPTER_REPO} gate_pilot_responses/responses.jsonl \
  --repo-type model --local-dir /tmp/gate_pilot_dl 2>&1
"
cp /tmp/gate_pilot_dl/gate_pilot_responses/responses.jsonl "${RESPONSES_LOCAL}"
echo "Downloaded → ${RESPONSES_LOCAL}"
wc -l "${RESPONSES_LOCAL}"

echo
echo "Scoring ..."
python3 eval/score_gate_pilot.py \
  --pilot exports/reviewer-v1.1/gate-pilot.jsonl \
  --responses "${RESPONSES_LOCAL}" \
  --out "${REPORT}"

echo
echo "Full report → ${REPORT}"
