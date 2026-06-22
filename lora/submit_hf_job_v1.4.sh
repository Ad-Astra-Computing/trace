#!/usr/bin/env bash
# Submit Reviewer-LoRA v1.4 training run as an HF Job.
#
# v1.4 changes vs v1.3:
#   - Canary isolation: zlib + jq families excluded from training entirely
#     (split=canary); new gate uses zlib+jq mutations for canary instead of
#     sqlite+procps. Addresses v1.3 memorization root cause.
#   - 88 train / 10 dev / 11 test (canary CVEs removed from train: -3 jq + 0 zlib
#     since zlib was already dev; sqlite still overridden to train)
#   - 2 new condition mutation training examples: bzip2 (>= MAX vs >= MAX-1)
#     and giflib (> vs >=); total negatives = 36 (was 34)
#   - MAX_STEPS=175 (unchanged for comparability; ~7.5 epochs, train_n=88)
#   - System prompt: prompts/reviewer.v5.md (unchanged)
#   - Split manifest: data/splits/reviewer-v1.4.json
#   - Adapter published to adastracomputing/reviewer-lora-v1.4
#   - Data upload FIXED: uploads reviewer.train.jsonl + reviewer.dev.jsonl
#     (hf_job.py reads these split files, not train.jsonl)
#
# Gate canary: zlib (reversed/condition/missing) + jq (off-by-one/missing-line)
# + 4 canary positives (zlib, jq-backport, jq-nul, jq-oob) = 9 canary total.
#
# Hardware: a100-large (1x A100 80GB). Expected wall-clock ~75 min.
set -euo pipefail
cd "$(dirname "$0")/.."

set -a && source .env && set +a
: "${HF_TOKEN:?HF_TOKEN not set}"
export HF_TOKEN

FLAVOR="a100-large"
NAMESPACE="odoom"
DATASET="adastracomputing/reviewer-lora-data"
HUB_MODEL_ID="adastracomputing/reviewer-lora-v1.4"
CORPUS_FREEZE_SHA="$(git rev-parse HEAD)"
TRACE_COMMIT="${CORPUS_FREEZE_SHA}"
MAX_STEPS=175

JSONL_DIR="exports/reviewer-v1.4"

if [[ ! -f "${JSONL_DIR}/reviewer.jsonl" ]]; then
  echo "Generating v1.4 training JSONL ..."
  python3 -m tools.trace_cli export reviewer \
    --out "${JSONL_DIR}" \
    --reviewer-prompt prompts/reviewer.v5.md \
    --split-manifest data/splits/reviewer-v1.4.json
fi

# Generate per-split files (hf_job.py reads reviewer.train.jsonl + reviewer.dev.jsonl)
if [[ ! -f "${JSONL_DIR}/reviewer.train.jsonl" ]]; then
  echo "Generating per-split JSONL files ..."
  python3 -c "
import json
from pathlib import Path
out = Path('${JSONL_DIR}')
rows = [json.loads(l) for l in (out / 'reviewer.jsonl').read_text().splitlines() if l.strip()]
for s in ('train', 'dev'):
    rows_s = [r for r in rows if r['split'] == s]
    (out / f'reviewer.{s}.jsonl').write_text('\n'.join(json.dumps(r, sort_keys=True) for r in rows_s) + '\n')
    print(f'{s}: {len(rows_s)} examples')
"
fi

echo "Uploading v1.4 training JSONLs to hf://datasets/${DATASET} ..."
nix-shell -p python3Packages.huggingface-hub --run \
  "hf upload ${DATASET} ${JSONL_DIR}/reviewer.train.jsonl reviewer.train.jsonl --repo-type dataset"
nix-shell -p python3Packages.huggingface-hub --run \
  "hf upload ${DATASET} ${JSONL_DIR}/reviewer.dev.jsonl reviewer.dev.jsonl --repo-type dataset"

echo
echo "Submitting Reviewer-LoRA v1.4 HF Job"
echo "  flavor:         ${FLAVOR}"
echo "  namespace:      ${NAMESPACE}"
echo "  dataset:        ${DATASET}"
echo "  push adapter →  ${HUB_MODEL_ID}"
echo "  max_steps:      ${MAX_STEPS} (~7.5 effective epochs, train_n=88)"
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
  -e ADAPTER_DIR=/tmp/reviewer-lora-v1.4 \
  -e HUB_MODEL_ID='${HUB_MODEL_ID}' \
  -e HF_JOB_FLAVOR='${FLAVOR}' \
  -e CORPUS_FREEZE_SHA='${CORPUS_FREEZE_SHA}' \
  -e TRACE_COMMIT='${TRACE_COMMIT}' \
  -e MAX_STEPS='${MAX_STEPS}' \
  lora/hf_job.py
"
