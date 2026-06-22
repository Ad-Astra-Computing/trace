#!/usr/bin/env bash
# Download v1.3 gate pilot responses from adapter repo and score locally.
# Run after submit_hf_gate_pilot_v1.3.sh job completes.
set -euo pipefail
cd "$(dirname "$0")/.."

set -a && source .env && set +a
: "${HF_TOKEN:?HF_TOKEN not set}"
export HF_TOKEN

ADAPTER_REPO="${1:-adastracomputing/reviewer-lora-v1.3}"
RESPONSES_LOCAL="/tmp/gate-pilot-v1.3-responses.jsonl"
REPORT="data/reports/lora-gate-pilot-v1.3.json"

echo "Downloading gate pilot responses from ${ADAPTER_REPO} ..."
nix-shell -p python3Packages.huggingface-hub --run "
HF_TOKEN=${HF_TOKEN} hf download ${ADAPTER_REPO} gate_pilot_responses/responses.jsonl \
  --repo-type model --local-dir /tmp/gate_pilot_dl_v1.3
"
cp /tmp/gate_pilot_dl_v1.3/gate_pilot_responses/responses.jsonl "${RESPONSES_LOCAL}"

echo "Scoring ..."
python3 eval/score_gate_pilot.py \
  --pilot exports/reviewer-v1.3/gate-pilot.jsonl \
  --responses "${RESPONSES_LOCAL}" \
  --out "${REPORT}"

echo
cat "${REPORT}" | python3 -m json.tool
