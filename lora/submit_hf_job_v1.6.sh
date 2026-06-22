#!/usr/bin/env bash
# Submit Reviewer-LoRA v1.6 training run as an HF Job.
#
# v1.6 changes vs v1.5:
#   - Exporter fix: tools/trace_cli/export.py:_build_user_turn() now passes
#     patch_strategy + upstream_fix_patch for source-backport bundles, so
#     the # upstream-fix.patch section is present in all training examples
#     (matches what live runs receive via execute.py). Previously this section
#     was absent from every training example and gate pilot record, causing
#     the model to hallucinate both sides of the PC comparison from narrative
#     descriptions in finding.json / upstream-ref.json / patch-rationale.md.
#   - System prompt: prompts/reviewer.v6.md (unchanged — already correct)
#   - Scorer: eval/score_gate_pilot.py adds check_pc_file_grounding() (v1.6+
#     gate-failing: per-hunk, match-only, file-aware grounding check)
#   - Split manifest: data/splits/reviewer-v1.6.json (same canary: zlib + jq)
#   - Training corpus unchanged: 88 train / 10 dev / 11 test / canary excluded
#   - MAX_STEPS=175 (unchanged for comparability)
#
# Root cause addressed: v1.5 gate pilot had 2 false accepts:
#   1. zlib source-backport-condition-mutation: model hallucinated correct
#      operator from descriptions; grounding check fired but verdict was accept
#   2. jq source-backport-missing-line: model quoted the fix line from
#      upstream-ref.json description for patch.diff side; global grounding check
#      did not fire (string in user content); file-aware check catches it
# Both failures trace to upstream-fix.patch not being in the training data.
#
# Gate canary: zlib (reversed/condition/missing) + jq (off-by-one/missing-line)
# + 4 canary positives = 9 total. Gate passes only if ALL 9 correct AND
# 0 pc_consistency_errors AND 0 pc_file_grounding_errors.
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
HUB_MODEL_ID="adastracomputing/reviewer-lora-v1.6"
CORPUS_FREEZE_SHA="$(git rev-parse HEAD)"
TRACE_COMMIT="${CORPUS_FREEZE_SHA}"
MAX_STEPS=175

JSONL_DIR="exports/reviewer-v1.6"

echo "Generating v1.6 training JSONL (upstream-fix.patch now included) ..."
python3 -m tools.trace_cli export reviewer \
  --out "${JSONL_DIR}" \
  --reviewer-prompt prompts/reviewer.v6.md \
  --split-manifest data/splits/reviewer-v1.6.json

# Generate per-split files (hf_job.py reads reviewer.train.jsonl + reviewer.dev.jsonl)
echo "Generating per-split JSONL files ..."
python3 << 'PYEOF'
import json
from pathlib import Path
out = Path("exports/reviewer-v1.6")
rows = [json.loads(l) for l in (out / "reviewer.jsonl").read_text().splitlines() if l.strip()]
for s in ("train", "dev"):
    rows_s = [r for r in rows if r["split"] == s]
    (out / f"reviewer.{s}.jsonl").write_text(
        "\n".join(json.dumps(r, sort_keys=True) for r in rows_s) + "\n"
    )
    print(f"{s}: {len(rows_s)} examples")
    # Sanity: source-backport records must have upstream-fix.patch in user turn
    sb_rows = [r for r in rows_s if "upstream-fix.patch" not in r["messages"][1]["content"]]
    # Check which ones are source-backport bundles
    missing_uf = []
    for r in rows_s:
        user_content = r["messages"][1]["content"]
        if "patch_strategy" in user_content and "source-backport" in user_content:
            if "# upstream-fix.patch" not in user_content:
                missing_uf.append(r.get("bundle_id", "?"))
    if missing_uf:
        raise ValueError(f"{s}: {len(missing_uf)} source-backport records missing upstream-fix.patch: {missing_uf[:5]}")
    print(f"  upstream-fix.patch sanity: OK")
PYEOF

echo "Uploading v1.6 training JSONLs to hf://datasets/${DATASET} ..."
nix-shell -p python3Packages.huggingface-hub --run \
  "hf upload ${DATASET} ${JSONL_DIR}/reviewer.train.jsonl reviewer-v1.6.train.jsonl --repo-type dataset"
nix-shell -p python3Packages.huggingface-hub --run \
  "hf upload ${DATASET} ${JSONL_DIR}/reviewer.dev.jsonl reviewer-v1.6.dev.jsonl --repo-type dataset"

echo
echo "Submitting Reviewer-LoRA v1.6 HF Job"
echo "  flavor:         ${FLAVOR}"
echo "  namespace:      ${NAMESPACE}"
echo "  dataset:        ${DATASET}"
echo "  push adapter →  ${HUB_MODEL_ID}"
echo "  max_steps:      ${MAX_STEPS} (~7.5 effective epochs, train_n=88)"
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
  -e ADAPTER_DIR=/tmp/reviewer-lora-v1.6 \
  -e HUB_MODEL_ID='${HUB_MODEL_ID}' \
  -e HF_JOB_FLAVOR='${FLAVOR}' \
  -e CORPUS_FREEZE_SHA='${CORPUS_FREEZE_SHA}' \
  -e TRACE_COMMIT='${TRACE_COMMIT}' \
  -e MAX_STEPS='${MAX_STEPS}' \
  -e TRAIN_FILE=reviewer-v1.6.train.jsonl \
  -e DEV_FILE=reviewer-v1.6.dev.jsonl \
  lora/hf_job.py
"
