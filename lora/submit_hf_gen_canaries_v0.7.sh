#!/usr/bin/env bash
# Submit Authoring-LoRA v0.7 canary inference as an HF Job.
#
# Prereqs:
#   - authoring-lora-v0.7 adapter must be pushed to adastracomputing/authoring-lora-v0.7
#   - v0.7 canary JSONL must be in adastracomputing/authoring-lora-data-v4
#     (export with: python3 -m tools.trace_cli export authoring
#       --split-manifest data/splits/authoring-v4.json --out exports/authoring-v4/)
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

echo "Submitting Authoring-LoRA v0.7 canary inference"
$HF jobs uv run \
  --flavor "a100-large" \
  --namespace "odoom" \
  --timeout 1h \
  --detach \
  --secrets HF_TOKEN \
  lora/hf_authoring_gen_canaries_v0.7.py
