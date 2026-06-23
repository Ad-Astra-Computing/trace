#!/usr/bin/env bash
# Submit v1.10 gate pilot inference job.
# Builds exports/reviewer-v1.10/gate-pilot.jsonl from the v1.9 pilot by swapping
# the system prompt v8 -> v9 (the held-out canary + test BUNDLE inputs are
# unchanged — only the reviewer prompt version differs between LoRA versions).
# Uploads it to the DATASET repo and mounts it at /data for the inference job
# (lora/hf_gate_pilot_job.py reads /data/gate-pilot.jsonl).
# Run AFTER the training job (adastracomputing/reviewer-lora-v1.10) completes.
#
# After the job completes, score with:
#   python3 eval/score_gate_pilot.py \
#     --pilot exports/reviewer-v1.10/gate-pilot.jsonl \
#     --responses <downloaded_responses.jsonl> \
#     --out data/reports/lora-gate-pilot-v1.10.json
#
# Watch the zlib canary (CVE-2022-37434) specifically: it is a context-difference
# positive and the prime risk for v9's extraction-order fragility. The scorer's
# non-gating `canary_pc_extraction_order_errors` distinguishes an order-artifact
# reject from a genuine placement-defect reject.
set -euo pipefail
cd "$(dirname "$0")/.."

set -a && source .env && set +a
: "${HF_TOKEN:?HF_TOKEN not set}"
export HF_TOKEN

FLAVOR="l40sx1"
NAMESPACE="odoom"
DATASET="adastracomputing/reviewer-lora-data"
ADAPTER_REPO="adastracomputing/reviewer-lora-v1.10"
SRC_PILOT="exports/reviewer-v1.9/gate-pilot.jsonl"
PILOT_JSONL="exports/reviewer-v1.10/gate-pilot.jsonl"

if [[ ! -f "${SRC_PILOT}" ]]; then
    echo "ERROR: ${SRC_PILOT} not found (needed to build the v1.10 pilot)." >&2
    exit 1
fi

echo "Building ${PILOT_JSONL} from ${SRC_PILOT} (system prompt v8 -> v9) ..."
python3 << 'PYEOF'
import json
from pathlib import Path
src = Path("exports/reviewer-v1.9/gate-pilot.jsonl")
out = Path("exports/reviewer-v1.10/gate-pilot.jsonl")
out.parent.mkdir(parents=True, exist_ok=True)
v9 = Path("prompts/reviewer.v9.md").read_text()
rows = [json.loads(l) for l in src.read_text().splitlines() if l.strip()]
for r in rows:
    # Swap ONLY the system turn; the user turn (frozen bundle inputs) is unchanged.
    assert r["messages"][0]["role"] == "system"
    r["messages"][0]["content"] = v9
out.write_text("\n".join(json.dumps(r, sort_keys=True) for r in rows) + "\n")
# Sanity
canary = [r for r in rows if r.get("split") == "canary"]
if len(canary) != 9:
    raise ValueError(f"Expected 9 canary rows, got {len(canary)}")
sb_missing = [r["provenance"].get("cve_id", "?") for r in canary
              if "source-backport" in r["messages"][1]["content"]
              and "# upstream-fix.patch" not in r["messages"][1]["content"]]
if sb_missing:
    raise ValueError(f"Gate pilot: source-backport canary rows missing upstream-fix.patch: {sb_missing}")
sysc = rows[0]["messages"][0]["content"]
if "system prompt v9" not in sysc or "placement/order" not in sysc:
    raise ValueError("System prompt is not reviewer.v9 (missing v9 order-sensitivity markers)")
print(f"Gate pilot v1.10: {len(rows)} rows ({len(canary)} canary), upstream-fix.patch OK, v9 prompt OK")
PYEOF

N=$(wc -l < "${PILOT_JSONL}")
echo "Uploading gate-pilot.jsonl (${N} examples) to hf://datasets/${DATASET} ..."
nix-shell -p python3Packages.huggingface-hub --run \
  "hf upload ${DATASET} ${PILOT_JSONL} gate-pilot.jsonl --repo-type dataset"

echo
echo "Submitting v1.10 gate pilot inference job"
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
