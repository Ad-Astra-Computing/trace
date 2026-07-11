#!/usr/bin/env bash
# Submit Authoring-LoRA v1.2 training job to HF.
#
# v1.2: dataset v8 (94 train / 6 dev = v7 base + 3 real-diff examples).
# Hypothesis: libpng/libraw/libarchive real-diff examples (incl. the libarchive
# ustar off-by-one minimal-constant-edit shape twin) consolidate the
# inline-condition strategy and pass the bzip2 canary. All other hyperparameters
# identical to v1.1.
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
echo "Submitting authoring-lora v1.2 (corpus sha: $TRACE_COMMIT)"

$HF jobs uv run \
  --flavor "a100-large" \
  --namespace "odoom" \
  --timeout 120m \
  --detach \
  --secrets HF_TOKEN \
  -v "hf://datasets/adastracomputing/authoring-lora-data-v8:/data:ro" \
  -e "PYTORCH_CUDA_ALLOC_CONF=expandable_segments:True" \
  -e "HF_HOME=/tmp/hf" \
  -e "ADAPTER_DIR=/tmp/authoring-lora-v1.2" \
  -e "HUB_MODEL_ID=adastracomputing/authoring-lora-v1.2" \
  -e "CORPUS_FREEZE_SHA=$TRACE_COMMIT" \
  lora/hf_authoring_job_v1.2.py
