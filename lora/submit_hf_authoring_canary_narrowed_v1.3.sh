#!/usr/bin/env bash
# Submit the Authoring-LoRA narrowed-window localization ablation for v1.3.
#
# Reuses lora/hf_authoring_canary_narrowed_v1.2.py (parameterized by ADAPTER_REPO)
# retargeted at the v1.3 adapter. Runs {original, narrowed} x 4 canaries = 8 greedy
# generations against adastracomputing/authoring-lora-v1.3 and uploads
# canary-narrowed-responses.jsonl to that model repo. Compared against the v1.2
# baseline (0/8 byte-match but 3/4 relocated to the true site) to measure whether
# the v9 scale-up batch moved localization.
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

echo "Submitting Authoring-LoRA v1.3 narrowed-window localization ablation"
$HF jobs uv run \
  --flavor "a100-large" \
  --namespace "odoom" \
  --timeout 1h \
  --detach \
  --secrets HF_TOKEN \
  -e "ADAPTER_REPO=adastracomputing/authoring-lora-v1.3" \
  lora/hf_authoring_canary_narrowed_v1.2.py
