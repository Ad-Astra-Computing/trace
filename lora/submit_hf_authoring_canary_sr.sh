#!/usr/bin/env bash
# SR-adapter canary gen: override the canary system turn with the SEARCH/REPLACE system
# prompt (the adapter was trained on it; the v6 canary carries the diff-format prompt).
set -euo pipefail
cd "$(dirname "$0")/.."
set -a && source .env && set +a
: "${HF_TOKEN:?}"; export HF_TOKEN
command -v hf >/dev/null 2>&1 || { echo "run via nix develop .#lora" >&2; exit 1; }
SR_B64="$(python3 -c 'import base64,sys; sys.path.insert(0,"lora"); from relabel_search_replace import _SR_SYSTEM; print(base64.b64encode(_SR_SYSTEM.encode()).decode())')"
echo "Submitting SR-system canary gen (adapter authoring-lora-sr)"
hf jobs uv run --flavor a100-large --namespace odoom --timeout 1h --detach --secrets HF_TOKEN \
  -e "ADAPTER_REPO=adastracomputing/authoring-lora-sr" \
  -e "SYSTEM_OVERRIDE_B64=${SR_B64}" \
  lora/hf_authoring_canary_narrowed_v1.2.py
