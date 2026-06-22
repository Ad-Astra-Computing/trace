#!/usr/bin/env bash
# Download v1.6 gate pilot responses from adapter repo and score locally.
set -euo pipefail
cd "$(dirname "$0")/.."

set -a && source .env && set +a
: "${HF_TOKEN:?HF_TOKEN not set}"
export HF_TOKEN

ADAPTER_REPO="${1:-adastracomputing/reviewer-lora-v1.6}"
REPORT="data/reports/lora-gate-pilot-v1.6.json"

echo "Downloading gate pilot responses from ${ADAPTER_REPO} ..."
nix-shell -p python3Packages.huggingface-hub --run "
HF_TOKEN=${HF_TOKEN} hf download ${ADAPTER_REPO} gate_pilot_responses/responses.jsonl \
  --repo-type model --local-dir /tmp/gate_pilot_dl_v1.6
"

echo "Scoring (gate: 9/9 canary + 0 pc_consistency_errors + 0 pc_file_grounding_errors) ..."
python3 eval/score_gate_pilot.py \
  --pilot exports/reviewer-v1.6/gate-pilot.jsonl \
  --responses /tmp/gate_pilot_dl_v1.6/gate_pilot_responses/responses.jsonl \
  --out "${REPORT}"

echo
cat "${REPORT}" | python3 -m json.tool
