#!/usr/bin/env bash
# Submit the Authoring-LoRA COMPLETION-ONLY-LOSS experiment to HF.
#
# Isolates the one training-objective lever the authoring arc left untested
# (DECISIONS 2026-07-14; SR run caveated "no loss-masking"). BYTE-IDENTICAL to
# the v10-clean run in every dimension (same authoring-lora-data-v10-clean
# dataset, same Qwen2.5-Coder-14B @ aedcc2d4, same LoRA rank/alpha 16 dropout
# 0.05, nf4 QLoRA, 375 steps, grad_accum 4, lr 1e-4 cosine, warmup 35, seed 42)
# EXCEPT the loss target: hf_authoring_job_lossmask.py masks the prompt to -100
# via DataCollatorForCompletionOnlyLM so loss falls only on the fix diff.
#
# Pre-check (2026-09-01): completions are a median 21.5% of tokens on this corpus
# (validated locally, response template unique in all 78 examples), so ~78% of
# the gradient currently models the prompt. This run 5x-es the effective weight
# on the fix tokens. Hypothesis: the byte-exact 0/4 canary ceiling is a
# training-objective artifact, not a capability limit.
#
# Score the resulting adapter with GREEDY + best-of-16 sampling and the GRADED
# scorer (lora/score_canaries_graded.py), not just byte-exact, per the
# pre-registered plan in docs/FINDINGS_LORA.md. Kill criterion: no graded
# movement over v10-clean => retire the authoring capability lane.
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
echo "Submitting authoring-lora loss-mask (trace commit: $TRACE_COMMIT)"

$HF jobs uv run \
  --flavor "a100-large" \
  --namespace "odoom" \
  --timeout 120m \
  --detach \
  --secrets HF_TOKEN \
  -v "hf://datasets/adastracomputing/authoring-lora-data-v10-clean:/data:ro" \
  -e "PYTORCH_CUDA_ALLOC_CONF=expandable_segments:True" \
  -e "HF_HOME=/tmp/hf" \
  -e "ADAPTER_DIR=/tmp/authoring-lora-lossmask" \
  -e "HUB_MODEL_ID=adastracomputing/authoring-lora-lossmask" \
  -e "CORPUS_FREEZE_SHA=$TRACE_COMMIT" \
  -e "TRACE_COMMIT=$TRACE_COMMIT" \
  lora/hf_authoring_job_lossmask.py
