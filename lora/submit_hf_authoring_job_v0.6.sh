#!/usr/bin/env bash
# Submit the Authoring-LoRA v0.6 training run as an HF Job.
#
# v0.6 purpose: mixed-lang dev set + file-grounding system prompt
#   - Uses authoring-v3 manifest: python-multipart + pygments → dev (9 dev rows)
#   - 83 train rows (vs 85 for v0.5; 2 Python examples moved to dev)
#   - System prompt: language-agnostic with explicit file-grounding rules
#     (pyjwt regression root cause: model ignores `# Vulnerable source (file)` header)
#   - Code fence: correct language per extension (```python for .py files)
#   - 550 steps (≈26.5 passes over 83 examples — same budget as v0.5)
#   - Dataset repo: adastracomputing/authoring-lora-data-v3
#
# Prereqs:
#   HF_TOKEN in .env (write scope, member of adastracomputing org)
#   Export v0.6 training data:
#     python3 -m tools.trace_cli export authoring \
#       --split-manifest data/splits/authoring-v3.json \
#       --out exports/authoring-v3/
#     python3 eval/package_authoring_lora.py \
#       --export-dir exports/authoring-v3/ \
#       --out-dir exports/authoring-v3-lora/
#     hf upload adastracomputing/authoring-lora-data-v3 exports/authoring-v3-lora/ \
#       --repo-type dataset
#
# Hardware: a100-large (1x A100 80GB). ~40-45 min. ~$2-4.
# Billing namespace: odoom (personal HF Jobs credits).
set -euo pipefail
cd "$(dirname "$0")/.."

set -a && source .env && set +a
: "${HF_TOKEN:?HF_TOKEN not set}"
export HF_TOKEN

FLAVOR="a100-large"
NAMESPACE="odoom"
DATASET="adastracomputing/authoring-lora-data-v3"
HUB_MODEL_ID="adastracomputing/authoring-lora-v0.6"
CORPUS_FREEZE_SHA="$(git rev-parse HEAD)"
TRACE_COMMIT="$(git rev-parse HEAD)"
DATASET_COMMIT="${DATASET_COMMIT:-unknown}"
# Resolve hf CLI: prefer PATH, fall back to known Nix store path in this environment
if command -v hf >/dev/null 2>&1; then
    HF=hf
else
    HF=/nix/store/6g571970xp5kpa650cxp0fc5x11mp5sw-python3.13-huggingface-hub-1.10.2/bin/hf
fi

echo "Submitting Authoring-LoRA v0.6 HF Job"
echo "  flavor:         ${FLAVOR}"
echo "  namespace:      ${NAMESPACE}"
echo "  dataset:        ${DATASET} @ ${DATASET_COMMIT}"
echo "  push adapter →  ${HUB_MODEL_ID}"
echo "  trace commit:   ${TRACE_COMMIT}"

$HF jobs uv run \
  --flavor "${FLAVOR}" \
  --namespace "${NAMESPACE}" \
  --timeout 2h \
  --detach \
  --secrets HF_TOKEN \
  -v "hf://datasets/${DATASET}:/data:ro" \
  -e PYTORCH_CUDA_ALLOC_CONF=expandable_segments:True \
  -e HF_HOME=/tmp/hf \
  -e DATA_DIR=/data \
  -e ADAPTER_DIR=/tmp/authoring-lora-v0.6 \
  -e HUB_MODEL_ID="${HUB_MODEL_ID}" \
  -e HF_JOB_FLAVOR="${FLAVOR}" \
  -e CORPUS_FREEZE_SHA="${CORPUS_FREEZE_SHA}" \
  -e DATASET_COMMIT="${DATASET_COMMIT}" \
  -e TRACE_COMMIT="${TRACE_COMMIT}" \
  lora/hf_authoring_job_v0.6.py
