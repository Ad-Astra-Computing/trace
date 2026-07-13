#!/usr/bin/env bash
# Submit the Authoring-LoRA CLEAN-CORPUS re-baseline (v10) training job to HF.
#
# Purpose: re-run the authoring QLoRA on the 2026-07-13 integrity-cleaned corpus
# (91 -> 79 honest rows: per-file grounding + half-patched self-leak + edit-dedup,
# commit 2b74487) to separate corpus noise from the model's edit-precision ceiling.
# v1.3's 0/4 canary results predate the cleanup.
#
# COMPARABILITY (codex <redacted-session-id>, 2026-07-13): reuses lora/hf_authoring_job_v1.3.py
# BYTE-IDENTICAL, so the ONLY difference vs v1.3 is the dataset content. Everything
# else is held fixed by that script: base Qwen2.5-Coder-14B @ aedcc2d4, prompt text,
# MAX_SEQ_LEN 16384, LoRA rank/alpha 16 dropout 0.05, nf4 QLoRA, 375 steps,
# grad_accum 4, lr 1e-4 cosine, warmup 35, seed 42. Same 4 canaries held out
# (authoring-v6 split); score with lora/score_v12_canaries.py.
#
# Clean corpus: 68 train / 5 dev (in exports/authoring-lora/, packaged from the
# authoring-v6 canary-held-out export; 0 over-length; tiers 61+7 train, 4+1 dev).
# NOTE the size confound is deliberate and reported: clean-79 vs v1.3 dirty-115 is a
# NET-cleanup test (all v9 extra rows were later-excluded bad/ungrounded/dup rows).
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

TRACE_COMMIT=$(git rev-parse HEAD)
echo "Submitting authoring-lora v10-clean (corpus sha: $TRACE_COMMIT)"

$HF jobs uv run \
  --flavor "a100-large" \
  --namespace "odoom" \
  --timeout 120m \
  --detach \
  --secrets HF_TOKEN \
  -v "hf://datasets/adastracomputing/authoring-lora-data-v10-clean:/data:ro" \
  -e "PYTORCH_CUDA_ALLOC_CONF=expandable_segments:True" \
  -e "HF_HOME=/tmp/hf" \
  -e "ADAPTER_DIR=/tmp/authoring-lora-v10-clean" \
  -e "HUB_MODEL_ID=adastracomputing/authoring-lora-v10-clean" \
  -e "CORPUS_FREEZE_SHA=$TRACE_COMMIT" \
  lora/hf_authoring_job_v1.3.py
