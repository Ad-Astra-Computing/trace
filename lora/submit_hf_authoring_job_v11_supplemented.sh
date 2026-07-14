#!/usr/bin/env bash
# Submit the clean-v9-supplemented re-baseline (v11) training job to HF.
#
# Experiment (codex <redacted-session-id>, 2026-07-14): grafts the 21 integrity-cleaned real-diff
# supplements (tier grounded-unvalidated) back onto the 68 behaviorally-validated rows
# = 89 train. Reuses lora/hf_authoring_job_v10_clean.py BYTE-IDENTICAL (same base, LoRA,
# SFTConfig, seed, prompt), so v10 (validated 68) vs v11 (supplemented 89) isolates the
# SUPPLEMENT effect, and v1.3 (dirty 109) vs v11 (clean 89) isolates CLEANLINESS. Tests
# whether full-window zlib distractor-resistance returns without reintroducing bad
# labels. See docs/FINDINGS_LORA.md + DECISIONS 2026-07-14.
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

TRACE_COMMIT=$(git rev-parse HEAD)
echo "Submitting authoring-lora v11-supplemented (corpus sha: $TRACE_COMMIT)"

$HF jobs uv run \
  --flavor "a100-large" \
  --namespace "odoom" \
  --timeout 120m \
  --detach \
  --secrets HF_TOKEN \
  -v "hf://datasets/adastracomputing/authoring-lora-data-v11-supplemented:/data:ro" \
  -e "PYTORCH_CUDA_ALLOC_CONF=expandable_segments:True" \
  -e "HF_HOME=/tmp/hf" \
  -e "ADAPTER_DIR=/tmp/authoring-lora-v11-supplemented" \
  -e "HUB_MODEL_ID=adastracomputing/authoring-lora-v11-supplemented" \
  -e "CORPUS_FREEZE_SHA=$TRACE_COMMIT" \
  lora/hf_authoring_job_v10_clean.py
