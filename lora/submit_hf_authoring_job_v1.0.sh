#!/usr/bin/env bash
# Submit Authoring-LoRA v1.0 training job to HF.
#
# v1.0: same corpus as v0.7/v0.8 (88 train / 6 dev), rule 7 reverted, 250 steps.
# Controlled rerun to isolate whether rule 7 caused the v0.8 zlib regression.
set -euo pipefail
cd "$(dirname "$0")/.."

set -a && source .env && set +a
: "${HF_TOKEN:?HF_TOKEN not set}"
export HF_TOKEN

if command -v hf >/dev/null 2>&1; then
    HF=hf
else
    HF=/nix/store/6g571970xp5kpa650cxp0fc5x11mp5sw-python3.13-huggingface-hub-1.10.2/bin/hf
fi

TRACE_COMMIT=$(git rev-parse HEAD)
echo "Submitting authoring-lora v1.0 (corpus sha: $TRACE_COMMIT)"

$HF jobs uv run \
  --flavor "a100-large" \
  --namespace "odoom" \
  --timeout 120m \
  --detach \
  --secrets HF_TOKEN \
  -v "hf://datasets/adastracomputing/authoring-lora-data-v6:/data:ro" \
  -e "PYTORCH_CUDA_ALLOC_CONF=expandable_segments:True" \
  -e "HF_HOME=/tmp/hf" \
  -e "ADAPTER_DIR=/tmp/authoring-lora-v1.0" \
  -e "HUB_MODEL_ID=adastracomputing/authoring-lora-v1.0" \
  -e "CORPUS_FREEZE_SHA=$TRACE_COMMIT" \
  lora/hf_authoring_job_v1.0.py
