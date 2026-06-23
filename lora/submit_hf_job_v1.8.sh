#!/usr/bin/env bash
# Submit Reviewer-LoRA v1.8 training run as an HF Job.
#
# v1.8 changes vs v1.7:
#   - System prompt: prompts/reviewer.v8.md — adds critical-token-window (CTW)
#     sub-bullet to each hunk in each extraction section; the shortest
#     discriminating substring is now a required part of the extraction.
#   - Root cause addressed: v1.7 gate pilot had 2 condition-mutation false
#     accepts where the grounding check passed incorrectly (e.g. `<` matched
#     as substring of `<=`). CTW forces the model to quote the shortest key
#     token explicitly, making 1-token mismatches visible.
#   - Scorer: eval/score_gate_pilot.py updated with token-boundary grounding
#     (_q_in_lines) and effective_verdict mechanism for canary negatives that
#     hallucinate patch.diff extraction.
#   - Training corpus: 97 train / 10 dev / 11 test (+5 new 1-token mutation
#     negatives: libsixel inverted-null-check, busybox condition-mutation,
#     libxmp wrong-constant, pygments wrong-constant, coreutils condition-
#     mutation; all non-canary families)
#   - All existing review.md files with extraction sections upgraded to v1.8
#     CTW format (added critical token window sub-bullets)
#   - Split manifest: data/splits/reviewer-v1.8.json (same canary: zlib + jq)
#   - Gate canary: same 9 rows as v1.7 (4 canary+ zlib+jq, 5 canary-)
#     Gate passes only if ALL 9 canary correct (effective_verdict after
#     grounding check) AND 0 pc_consistency_errors.
#   - MAX_STEPS=175 (unchanged for comparability)
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
HUB_MODEL_ID="adastracomputing/reviewer-lora-v1.8"
CORPUS_FREEZE_SHA="$(git rev-parse HEAD)"
TRACE_COMMIT="${CORPUS_FREEZE_SHA}"
MAX_STEPS=175

JSONL_DIR="exports/reviewer-v1.8"

echo "Generating per-split JSONL files ..."
python3 << 'PYEOF'
import json
from pathlib import Path
out = Path("exports/reviewer-v1.8")
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
    # Sanity: v1.8 format requires extraction sections in assistant turn
    missing_extract = []
    for r in rows_s:
        asst_content = r["messages"][2]["content"] if len(r["messages"]) > 2 else ""
        if "## Patch comparison" in asst_content and "## patch.diff extraction" not in asst_content:
            missing_extract.append(r.get("provenance", {}).get("cve_id", "?"))
    if missing_extract:
        print(f"  WARNING: {len(missing_extract)} examples missing ## patch.diff extraction: {missing_extract[:5]}")
    else:
        print(f"  v1.8 extraction-section sanity: OK")
    # Sanity: source-backport negatives must have CTW
    missing_ctw = []
    for r in rows_s:
        if r.get("label") != "negative":
            continue
        asst_content = r["messages"][2]["content"] if len(r["messages"]) > 2 else ""
        if "## patch.diff extraction" in asst_content and "critical token window" not in asst_content:
            missing_ctw.append(r.get("provenance", {}).get("cve_id", "?"))
    if missing_ctw:
        raise ValueError(f"{s}: {len(missing_ctw)} negative examples missing CTW: {missing_ctw[:5]}")
    print(f"  v1.8 CTW sanity: OK")
PYEOF

echo "Uploading v1.8 training JSONLs to hf://datasets/${DATASET} ..."
nix-shell -p python3Packages.huggingface-hub --run \
  "hf upload ${DATASET} ${JSONL_DIR}/reviewer.train.jsonl reviewer-v1.8.train.jsonl --repo-type dataset"
nix-shell -p python3Packages.huggingface-hub --run \
  "hf upload ${DATASET} ${JSONL_DIR}/reviewer.dev.jsonl reviewer-v1.8.dev.jsonl --repo-type dataset"

echo
echo "Submitting Reviewer-LoRA v1.8 HF Job"
echo "  flavor:         ${FLAVOR}"
echo "  namespace:      ${NAMESPACE}"
echo "  dataset:        ${DATASET}"
echo "  push adapter →  ${HUB_MODEL_ID}"
echo "  max_steps:      ${MAX_STEPS} (~5.4 effective epochs, train_n=97)"
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
  -e ADAPTER_DIR=/tmp/reviewer-lora-v1.8 \
  -e HUB_MODEL_ID='${HUB_MODEL_ID}' \
  -e HF_JOB_FLAVOR='${FLAVOR}' \
  -e CORPUS_FREEZE_SHA='${CORPUS_FREEZE_SHA}' \
  -e TRACE_COMMIT='${TRACE_COMMIT}' \
  -e MAX_STEPS='${MAX_STEPS}' \
  -e TRAIN_FILE=reviewer-v1.8.train.jsonl \
  -e DEV_FILE=reviewer-v1.8.dev.jsonl \
  lora/hf_job.py
"
