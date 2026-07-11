#!/usr/bin/env bash
# Submit Authoring-LoRA v1.1 canary inference as an HF Job.
#
# Prereqs: authoring-lora-v1.1 adapter must be pushed (job 6a513ae8e4a4e82c0b58c12e).
# Canary JSONL is read from authoring-lora-data-v6 (canaries unchanged from v6 → v7).
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

echo "Submitting Authoring-LoRA v1.1 canary inference"
$HF jobs uv run \
  --flavor "a100-large" \
  --namespace "odoom" \
  --timeout 1h \
  --detach \
  --secrets HF_TOKEN \
  lora/hf_authoring_gen_canaries_v1.1.py
