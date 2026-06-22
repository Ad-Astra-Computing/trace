#!/usr/bin/env bash
# Submit v1.6 gate pilot inference job.
# Uploads gate-pilot.jsonl to the adapter repo and submits an l40sx1 inference job.
set -euo pipefail
cd "$(dirname "$0")/.."

set -a && source .env && set +a
: "${HF_TOKEN:?HF_TOKEN not set}"
export HF_TOKEN

ADAPTER_REPO="${1:-adastracomputing/reviewer-lora-v1.6}"
PILOT_JSONL="exports/reviewer-v1.6/gate-pilot.jsonl"

echo "Generating v1.6 gate pilot JSONL (includes upstream-fix.patch for source-backport canary) ..."
python3 -m tools.trace_cli export reviewer \
  --out "exports/reviewer-v1.6" \
  --reviewer-prompt prompts/reviewer.v6.md \
  --split-manifest data/splits/reviewer-v1.6.json \
  --gate-pilot

# Sanity: canary source-backport records must have upstream-fix.patch
python3 << 'PYEOF'
import json
from pathlib import Path
rows = [json.loads(l) for l in Path("exports/reviewer-v1.6/gate-pilot.jsonl").read_text().splitlines() if l.strip()]
sb_missing = []
for r in rows:
    if r.get("split") != "canary":
        continue
    user_content = r["messages"][1]["content"]
    # Source-backport canary records need upstream-fix.patch
    if "# upstream-fix.patch" not in user_content and "source-backport" in user_content:
        sb_missing.append(r.get("provenance", {}).get("cve_id", "?"))
if sb_missing:
    raise ValueError(f"Gate pilot: {len(sb_missing)} source-backport canary records missing upstream-fix.patch: {sb_missing}")
print(f"Gate pilot sanity: {len(rows)} records, upstream-fix.patch OK for source-backport canary")
PYEOF

echo "Uploading gate-pilot.jsonl to ${ADAPTER_REPO} ..."
nix-shell -p python3Packages.huggingface-hub --run "
HF_TOKEN=${HF_TOKEN} hf upload ${ADAPTER_REPO} ${PILOT_JSONL} gate_pilot_inputs/gate-pilot.jsonl \
  --repo-type model
"

echo "Submitting gate pilot inference job ..."
nix-shell -p python3Packages.huggingface-hub --run "
import json, os, requests

token = os.environ['HF_TOKEN']
headers = {
    'Authorization': f'Bearer {token}',
    'Content-Type': 'application/json',
}
payload = {
    'dockerImage': 'huggingface/inference-toolkit:latest',
    'flavor': 'l40s-x1',
    'env': {
        'ADAPTER_REPO': '${ADAPTER_REPO}',
        'PILOT_FILE': 'gate_pilot_inputs/gate-pilot.jsonl',
        'OUT_FILE': 'gate_pilot_responses/responses.jsonl',
        'MAX_NEW_TOKENS': '4096',
        'HF_TOKEN': token,
    },
    'command': ['python3', 'lora/hf_gate_pilot_job.py'],
    'secrets': ['HF_TOKEN'],
}
print('Not yet wired — use hf_gate_pilot_job.py approach from v1.5')
" 2>/dev/null || true

# Use the same pattern as v1.5: upload + submit via hf jobs uv run
nix-shell -p python3Packages.huggingface-hub --run "
hf jobs uv run \
  --flavor 'l40s-x1' \
  --namespace 'odoom' \
  --timeout 1h \
  --detach \
  --secrets HF_TOKEN \
  -e HF_HOME=/tmp/hf \
  -e ADAPTER_REPO='${ADAPTER_REPO}' \
  -e PILOT_FILE='gate_pilot_inputs/gate-pilot.jsonl' \
  -e OUT_FILE='gate_pilot_responses/responses.jsonl' \
  lora/hf_gate_pilot_job.py
"
