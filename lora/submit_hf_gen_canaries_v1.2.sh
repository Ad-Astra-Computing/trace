#!/usr/bin/env bash
# Submit Authoring-LoRA v1.2 canary inference as an HF Job.
#
# Prereqs: authoring-lora-v1.2 adapter must be pushed (training job 6a51dfade4a4e82c0b58d374).
# Reuses the v1.1 gen script, retargeting it at the v1.2 adapter via ADAPTER_REPO.
# Canary JSONL is read from authoring-lora-data-v6 (canaries unchanged across v6/v7/v8).
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

echo "Submitting Authoring-LoRA v1.2 canary inference"
$HF jobs uv run \
  --flavor "a100-large" \
  --namespace "odoom" \
  --timeout 1h \
  --detach \
  --secrets HF_TOKEN \
  -e "ADAPTER_REPO=adastracomputing/authoring-lora-v1.2" \
  lora/hf_authoring_gen_canaries_v1.1.py
