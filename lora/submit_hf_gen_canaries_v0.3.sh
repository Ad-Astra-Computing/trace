#!/usr/bin/env bash
# Submit the Authoring-LoRA v0.3 canary inference job.
#
# Prereqs:
#   HF_TOKEN in .env (write scope)
#   adastracomputing/authoring-lora-v0.3 adapter available on HF
#   adastracomputing/authoring-lora-data dataset has authoring-canary.jsonl
#
# Hardware: a100-large (~10-15 min). ~$0.50-1.
set -euo pipefail
cd "$(dirname "$0")/.."

set -a && source .env && set +a
: "${HF_TOKEN:?HF_TOKEN not set}"
export HF_TOKEN

FLAVOR="a100-large"
NAMESPACE="odoom"

echo "Submitting Authoring-LoRA v0.3 canary inference HF Job"
echo "  flavor:    ${FLAVOR}"
echo "  namespace: ${NAMESPACE}"
echo "  adapter:   adastracomputing/authoring-lora-v0.3"
echo "  output:    adastracomputing/authoring-lora-canary-responses/authoring-lora-v0.3-responses.jsonl"

hf jobs uv run \
  --flavor "${FLAVOR}" \
  --namespace "${NAMESPACE}" \
  --timeout 1h \
  --detach \
  --secrets HF_TOKEN \
  lora/hf_authoring_gen_canaries_v0.3.py
