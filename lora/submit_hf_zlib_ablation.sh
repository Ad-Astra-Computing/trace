#!/usr/bin/env bash
# Submit the Authoring-LoRA zlib positional-bias ablation as an HF Job.
#
# Tests whether removing the EXLEN distractor block (variant "narrowed") and/or
# appending an EXTRA-case location hint (variant "reordered-hint") shifts the
# model's edit to the true CVE-2022-37434 fix site. Runs {original, narrowed,
# reordered-hint} x {v1.0, v1.1} = 6 greedy generations and uploads
# zlib-ablation-responses.jsonl to adastracomputing/authoring-lora-v1.1.
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

echo "Submitting Authoring-LoRA zlib positional-bias ablation"
$HF jobs uv run \
  --flavor "a100-large" \
  --namespace "odoom" \
  --timeout 1h \
  --detach \
  --secrets HF_TOKEN \
  lora/hf_authoring_zlib_ablation.py
