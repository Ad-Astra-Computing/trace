#!/usr/bin/env bash
# Submit Reviewer-LoRA v1.7 training run as an HF Job.
#
# v1.7 changes vs v1.6:
#   - System prompt: prompts/reviewer.v7.md — two-step extraction schema
#     forces explicit ## patch.diff extraction and ## upstream-fix.patch
#     extraction sections BEFORE ## Patch comparison; each section must be
#     populated independently from its source file.
#   - Root cause addressed: v1.6 gate pilot had 3 false accepts:
#     condition-mutation, missing-line (canary), off-by-one — all from
#     cross-artifact hallucination (model copies upstream-fix.patch lines
#     to fill patch.diff extraction instead of reading patch.diff).
#   - Training corpus: 92 train / 10 dev / 11 test (4 new subtle mutation
#     negatives: libssh2 wrong-constant, libssh2 missing-hunk, bzip2
#     wrong-constant, zbar off-by-one; all non-canary families)
#   - All existing review.md files upgraded to v1.7 two-step format via
#     scripts/upgrade_review_to_v7.py
#   - Split manifest: data/splits/reviewer-v1.7.json (same canary: zlib + jq)
#   - Scorer: eval/score_gate_pilot.py updated to validate each extraction
#     section independently (v1.7 grounding checks)
#   - MAX_STEPS=175 (unchanged for comparability)
#   - Gate canary: same 9 rows as v1.6 (4 canary+ zlib+jq, 5 canary-)
#     Gate passes only if ALL 9 correct AND 0 pc_consistency_errors AND
#     0 pc_file_grounding_errors.
#
# Hardware: a100-large (1x A100 80GB). Expected wall-clock ~75-115 min.
set -euo pipefail
cd "$(dirname "$0")/.."

set -a && source .env && set +a
: "${HF_TOKEN:?HF_TOKEN not set}"
export HF_TOKEN

FLAVOR="a100-large"
NAMESPACE="odoom"
DATASET="adastracomputing/reviewer-lora-data"
HUB_MODEL_ID="adastracomputing/reviewer-lora-v1.7"
CORPUS_FREEZE_SHA="$(git rev-parse HEAD)"
TRACE_COMMIT="${CORPUS_FREEZE_SHA}"
MAX_STEPS=175

JSONL_DIR="exports/reviewer-v1.7"

echo "Generating per-split JSONL files ..."
python3 << 'PYEOF'
import json
from pathlib import Path
out = Path("exports/reviewer-v1.7")
rows = [json.loads(l) for l in (out / "reviewer.jsonl").read_text().splitlines() if l.strip()]
for s in ("train", "dev"):
    rows_s = [r for r in rows if r["split"] == s]
    (out / f"reviewer.{s}.jsonl").write_text(
        "\n".join(json.dumps(r, sort_keys=True) for r in rows_s) + "\n"
    )
    print(f"{s}: {len(rows_s)} examples")
    # Sanity: source-backport records must have upstream-fix.patch in user turn
    missing_uf = []
    for r in rows_s:
        user_content = r["messages"][1]["content"]
        if "patch_strategy" in user_content and "source-backport" in user_content:
            if "# upstream-fix.patch" not in user_content:
                missing_uf.append(r.get("provenance", {}).get("cve_id", "?"))
    if missing_uf:
        raise ValueError(f"{s}: {len(missing_uf)} source-backport records missing upstream-fix.patch: {missing_uf[:5]}")
    print(f"  upstream-fix.patch sanity: OK")
    # Sanity: v1.7 format requires extraction sections in assistant turn
    missing_extract = []
    for r in rows_s:
        asst_content = r["messages"][2]["content"] if len(r["messages"]) > 2 else ""
        if "## Patch comparison" in asst_content and "## patch.diff extraction" not in asst_content:
            missing_extract.append(r.get("provenance", {}).get("cve_id", "?"))
    if missing_extract:
        print(f"  WARNING: {len(missing_extract)} examples missing ## patch.diff extraction: {missing_extract[:5]}")
    else:
        print(f"  v1.7 extraction-section sanity: OK")
PYEOF

echo "Uploading v1.7 training JSONLs to hf://datasets/${DATASET} ..."
nix-shell -p python3Packages.huggingface-hub --run \
  "hf upload ${DATASET} ${JSONL_DIR}/reviewer.train.jsonl reviewer-v1.7.train.jsonl --repo-type dataset"
nix-shell -p python3Packages.huggingface-hub --run \
  "hf upload ${DATASET} ${JSONL_DIR}/reviewer.dev.jsonl reviewer-v1.7.dev.jsonl --repo-type dataset"

echo
echo "Submitting Reviewer-LoRA v1.7 HF Job"
echo "  flavor:         ${FLAVOR}"
echo "  namespace:      ${NAMESPACE}"
echo "  dataset:        ${DATASET}"
echo "  push adapter →  ${HUB_MODEL_ID}"
echo "  max_steps:      ${MAX_STEPS} (~6 effective epochs, train_n=92)"
echo "  trace commit:   ${TRACE_COMMIT}"

nix-shell -p python3Packages.huggingface-hub --run "
hf jobs uv run \
  --flavor '${FLAVOR}' \
  --namespace '${NAMESPACE}' \
  --timeout 2h \
  --detach \
  --secrets HF_TOKEN \
  -v 'hf://datasets/${DATASET}:/data:ro' \
  -e PYTORCH_CUDA_ALLOC_ALLOC_CONF=expandable_segments:True \
  -e HF_HOME=/tmp/hf \
  -e DATA_DIR=/data \
  -e ADAPTER_DIR=/tmp/reviewer-lora-v1.7 \
  -e HUB_MODEL_ID='${HUB_MODEL_ID}' \
  -e HF_JOB_FLAVOR='${FLAVOR}' \
  -e CORPUS_FREEZE_SHA='${CORPUS_FREEZE_SHA}' \
  -e TRACE_COMMIT='${TRACE_COMMIT}' \
  -e MAX_STEPS='${MAX_STEPS}' \
  -e TRAIN_FILE=reviewer-v1.7.train.jsonl \
  -e DEV_FILE=reviewer-v1.7.dev.jsonl \
  lora/hf_job.py
"
