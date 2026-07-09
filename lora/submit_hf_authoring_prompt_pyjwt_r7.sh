#!/usr/bin/env bash
# Submit prompt-only pyjwt rule-7 canary as an HF Job.
#
# Tests whether system-prompt rule 7 (no recursive self-calls) fixes the
# CVE-2026-48526 pyjwt canary without retraining. Uses the base model only.
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

echo "Submitting prompt-only pyjwt rule-7 canary"
$HF jobs uv run \
  --flavor "a100-large" \
  --namespace "odoom" \
  --timeout 30m \
  --detach \
  --secrets HF_TOKEN \
  lora/hf_authoring_prompt_pyjwt_r7.py
