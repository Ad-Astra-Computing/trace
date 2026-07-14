#!/usr/bin/env bash
# Submit the Authoring-LoRA narrowed-window localization ablation for v10-clean.
#
# Reuses lora/hf_authoring_canary_narrowed_v1.2.py (parameterized by ADAPTER_REPO,
# same 4 frozen canaries + greedy generation as v1.0-v1.3, so results are directly
# comparable) retargeted at the v10 clean-corpus adapter. Runs {original, narrowed}
# x 4 canaries = 8 greedy generations against adastracomputing/authoring-lora-v10-clean
# and uploads canary-narrowed-responses.jsonl to that model repo. Compared against
# v1.3 (0/4 byte-match, zlib localization recovered) to measure whether the
# behaviorally-validated CLEAN corpus (68 train, 0/21 v9 supplements) holds or loses
# the localization lever. See docs/FINDINGS_LORA.md.
set -euo pipefail
cd "$(dirname "$0")/.."

set -a && source .env && set +a
: "${HF_TOKEN:?HF_TOKEN not set}"
export HF_TOKEN

if command -v hf >/dev/null 2>&1; then
    HF=hf
else
    echo "hf not on PATH — run via: nix develop .#lora --command bash $0" >&2
    exit 1
fi

echo "Submitting Authoring-LoRA v10-clean narrowed-window localization ablation"
$HF jobs uv run \
  --flavor "a100-large" \
  --namespace "odoom" \
  --timeout 1h \
  --detach \
  --secrets HF_TOKEN \
  -e "ADAPTER_REPO=adastracomputing/authoring-lora-v10-clean" \
  lora/hf_authoring_canary_narrowed_v1.2.py
