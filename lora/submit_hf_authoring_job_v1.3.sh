#!/usr/bin/env bash
# Submit Authoring-LoRA v1.3 training job to HF.
#
# v1.3: dataset v9 (109 train / 6 dev = v8 base + 15 real-diff examples).
# Honest scale-up batch: 15 gate-checked hand-authored examples spanning a
# localization + edit-precision stratification matrix. This is the definitive
# test of the data lever — success = any canary flips to PASS or a clear
# qualitative localization improvement on the narrowed-window ablation shape.
# ALL hyperparameters identical to v1.0/v1.1/v1.2.
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
echo "Submitting authoring-lora v1.3 (corpus sha: $TRACE_COMMIT)"

$HF jobs uv run \
  --flavor "a100-large" \
  --namespace "odoom" \
  --timeout 120m \
  --detach \
  --secrets HF_TOKEN \
  -v "hf://datasets/adastracomputing/authoring-lora-data-v9:/data:ro" \
  -e "PYTORCH_CUDA_ALLOC_CONF=expandable_segments:True" \
  -e "HF_HOME=/tmp/hf" \
  -e "ADAPTER_DIR=/tmp/authoring-lora-v1.3" \
  -e "HUB_MODEL_ID=adastracomputing/authoring-lora-v1.3" \
  -e "CORPUS_FREEZE_SHA=$TRACE_COMMIT" \
  lora/hf_authoring_job_v1.3.py
