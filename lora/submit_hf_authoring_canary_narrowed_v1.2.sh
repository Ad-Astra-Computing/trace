#!/usr/bin/env bash
# Submit the Authoring-LoRA narrowed-window localization ablation as an HF Job.
#
# Falsifier: v1.2 scores 0/4 on the canaries; diagnosed bottleneck is
# localization. Tightly narrow ONLY the source window in each canary to a tight
# excerpt around the true fix site (distractors removed), keep system turn + CVE
# description identical, and run {original, narrowed} x 4 canaries = 8 greedy
# generations against adastracomputing/authoring-lora-v1.2. Uploads
# canary-narrowed-responses.jsonl to that model repo.
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

echo "Submitting Authoring-LoRA narrowed-window localization ablation"
$HF jobs uv run \
  --flavor "a100-large" \
  --namespace "odoom" \
  --timeout 1h \
  --detach \
  --secrets HF_TOKEN \
  lora/hf_authoring_canary_narrowed_v1.2.py
