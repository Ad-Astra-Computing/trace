#!/usr/bin/env bash
# Submit Authoring-LoRA v1.3 canary inference as an HF Job.
#
# Prereqs: authoring-lora-v1.3 adapter must be pushed (training job 6a52a9d0e4a4e82c0b58e346).
# Reuses the v1.1 gen script, retargeting it at the v1.3 adapter via ADAPTER_REPO.
# Canary JSONL is read from authoring-lora-data-v6 (canaries unchanged across v6/v7/v8/v9).
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

echo "Submitting Authoring-LoRA v1.3 canary inference"
$HF jobs uv run \
  --flavor "a100-large" \
  --namespace "odoom" \
  --timeout 1h \
  --detach \
  --secrets HF_TOKEN \
  -e "ADAPTER_REPO=adastracomputing/authoring-lora-v1.3" \
  lora/hf_authoring_gen_canaries_v1.1.py
