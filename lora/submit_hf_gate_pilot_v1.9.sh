#!/usr/bin/env bash
# Submit v1.9 gate pilot inference job.
# Uploads gate-pilot.jsonl to the DATASET repo and mounts it at /data for the
# inference job (matching lora/hf_gate_pilot_job.py, which reads /data/gate-pilot.jsonl).
# Run AFTER the training job (adastracomputing/reviewer-lora-v1.9) completes.
#
# After the job completes, score with:
#   python3 eval/score_gate_pilot.py \
#     --pilot exports/reviewer-v1.9/gate-pilot.jsonl \
#     --responses <downloaded_responses.jsonl> \
#     --out data/reports/lora-gate-pilot-v1.9.json
set -euo pipefail
cd "$(dirname "$0")/.."

set -a && source .env && set +a
: "${HF_TOKEN:?HF_TOKEN not set}"
export HF_TOKEN

FLAVOR="l40sx1"
NAMESPACE="odoom"
DATASET="adastracomputing/reviewer-lora-data"
ADAPTER_REPO="adastracomputing/reviewer-lora-v1.9"
PILOT_JSONL="exports/reviewer-v1.9/gate-pilot.jsonl"

if [[ ! -f "${PILOT_JSONL}" ]]; then
    echo "ERROR: ${PILOT_JSONL} not found — regenerate with:" >&2
    echo "  python3 lora/rebuild_gate_pilot.py --version v1.9" >&2
    exit 1
fi

echo "Sanity-checking gate pilot JSONL ..."
python3 << 'PYEOF'
import json
from pathlib import Path
rows = [json.loads(l) for l in Path("exports/reviewer-v1.9/gate-pilot.jsonl").read_text().splitlines() if l.strip()]
canary = [r for r in rows if r.get("split") == "canary"]
if len(canary) != 9:
    raise ValueError(f"Expected 9 canary rows, got {len(canary)}")
sb_missing = []
for r in canary:
    user_content = r["messages"][1]["content"]
    if "source-backport" in user_content and "# upstream-fix.patch" not in user_content:
        sb_missing.append(r.get("provenance", {}).get("cve_id", "?"))
if sb_missing:
    raise ValueError(f"Gate pilot: {len(sb_missing)} source-backport canary records missing upstream-fix.patch: {sb_missing}")
# Check v1.9 prompt is present (CTW instruction)
sys_content = rows[0]["messages"][0]["content"]
if "critical token window" not in sys_content:
    raise ValueError("System prompt does not contain CTW instruction — wrong prompt version?")
print(f"Gate pilot: {len(rows)} rows ({len(canary)} canary), upstream-fix.patch OK, CTW prompt OK")
PYEOF

N=$(wc -l < "${PILOT_JSONL}")
echo "Uploading gate-pilot.jsonl (${N} examples) to hf://datasets/${DATASET} ..."
nix-shell -p python3Packages.huggingface-hub --run \
  "hf upload ${DATASET} ${PILOT_JSONL} gate-pilot.jsonl --repo-type dataset"

echo
echo "Submitting v1.9 gate pilot inference job"
echo "  flavor:   ${FLAVOR}"
echo "  adapter:  ${ADAPTER_REPO}"
echo "  dataset:  ${DATASET}"
echo "  input:    gate-pilot.jsonl (${N} examples: 9 canary + 11 test)"

nix-shell -p python3Packages.huggingface-hub --run "
hf jobs uv run \
  --flavor '${FLAVOR}' \
  --namespace '${NAMESPACE}' \
  --timeout 1h \
  --detach \
  --secrets HF_TOKEN \
  -v 'hf://datasets/${DATASET}:/data:ro' \
  -e HF_HOME=/tmp/hf \
  -e DATA_DIR=/data \
  -e ADAPTER_REPO='${ADAPTER_REPO}' \
  lora/hf_gate_pilot_job.py
"
