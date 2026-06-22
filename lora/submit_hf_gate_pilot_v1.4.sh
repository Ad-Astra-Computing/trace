#!/usr/bin/env bash
# Submit Reviewer-LoRA v1.4 gate pilot (inference job).
#
# Gate: ALL canary rows correct (0 FR + 0 FA on 9 canary + 11 test = 20 examples).
# Canary:
#   Positives (4): zlib, jq-backport, jq-nul-backport, jq-oob-backport (all unseen in training)
#   Mutations (5): zlib reversed-hunk, zlib condition-mutation, zlib missing-hunk,
#                  jq off-by-one, jq missing-line
#   (none of these CVEs appear in the training set — canary isolation)
#
# After job completes, score with:
#   python3 eval/score_gate_pilot.py \
#     --pilot exports/reviewer-v1.4/gate-pilot.jsonl \
#     --responses <downloaded_responses.jsonl> \
#     --out data/reports/lora-gate-pilot-v1.4.json
set -euo pipefail
cd "$(dirname "$0")/.."

set -a && source .env && set +a
: "${HF_TOKEN:?HF_TOKEN not set}"
export HF_TOKEN

FLAVOR="l40sx1"
NAMESPACE="odoom"
DATASET="adastracomputing/reviewer-lora-data"
ADAPTER_REPO="adastracomputing/reviewer-lora-v1.4"
PILOT_JSONL="exports/reviewer-v1.4/gate-pilot.jsonl"

if [[ ! -f "${PILOT_JSONL}" ]]; then
  echo "ERROR: ${PILOT_JSONL} not found. Build with:" >&2
  echo "  python3 scripts/build_gate_pilot.py \\" >&2
  echo "    --export exports/reviewer-v1.4 \\" >&2
  echo "    --manifest data/splits/reviewer-v1.4.json \\" >&2
  echo "    --out ${PILOT_JSONL}" >&2
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
echo "  input file:   gate-pilot.jsonl (${N} examples: 9 canary + 11 test)"

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
