#!/usr/bin/env bash
# Submit the base-model CONTROL pass of the zlib positional-bias ablation.
#
# Runs {original, narrowed, reordered-hint} against the bare base model
# Qwen/Qwen2.5-Coder-14B-Instruct (no adapter attached), same nf4 quant + greedy
# generation, and uploads zlib-ablation-base-responses.jsonl to
# adastracomputing/authoring-lora-v1.1 (does NOT clobber the v1.0/v1.1 artifact).
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

echo "Submitting zlib ablation BASE-MODEL control pass"
$HF jobs uv run \
  --flavor "a100-large" \
  --namespace "odoom" \
  --timeout 1h \
  --detach \
  --secrets HF_TOKEN \
  --env INCLUDE_BASE=1 \
  --env ADAPTERS= \
  --env UPLOAD_FILENAME=zlib-ablation-base-responses.jsonl \
  lora/hf_authoring_zlib_ablation.py
