#!/usr/bin/env bash
# Submit Reviewer-LoRA v1.9 training run as an HF Job.
#
# v1.9 changes vs v1.8 (CORPUS-ONLY — prompt + scorer unchanged):
#   - Adds 8 structurally-reorganized POSITIVE examples (context-reshape) under
#     traces/positives-reorg/, all real-Reviewer ACCEPT (sonnet-4-5 + reviewer.v8).
#     They teach CTW-equivalence under reordering — the invariance the v1.8 gate
#     pilot's zlib false-reject lacked (canary 8/9: zlib positive wrongly rejected
#     because the model treated a context-line-count difference as a mismatch).
#   - Bundles: bzip2, giflib, libxmp, requests, pygments, coreutils, libsixel,
#     sqlite (non-canary embedded source-backports; zlib + jq NOT reshaped, so
#     canary isolation holds — export shows canary=0).
#   - Prompt: prompts/reviewer.v8.md (unchanged). Split: data/splits/reviewer-v1.8.json
#     (unchanged; same canary zlib+jq). Scorer: eval/score_gate_pilot.py (unchanged).
#   - Corpus: 105 train / 10 dev / 11 test (was 97/10/11; +8 reorg positives in train).
#   - MAX_STEPS=190 (was 175) to hold ~7.2 effective epochs at train_n=105.
#   - --timeout 3h (was 2h): v1.8 at 175 steps pushed the adapter ~seconds before
#     the 2h kill; more data + steps needs headroom.
#
# Expected outcome (cost-discipline prediction): the v1.9 gate pilot's held-out
# zlib positive should now ACCEPT (canary 9/9). If zlib still rejects, the
# reshaping-augmentation hypothesis is wrong and adding more of the same transform
# is wasted spend (per codex 2026-06-23).
#
# Hardware: a100-large (1x A100 80GB). Expected wall-clock ~80-120 min.
set -euo pipefail
cd "$(dirname "$0")/.."

set -a && source .env && set +a
: "${HF_TOKEN:?HF_TOKEN not set}"
export HF_TOKEN

FLAVOR="a100-large"
NAMESPACE="odoom"
DATASET="adastracomputing/reviewer-lora-data"
HUB_MODEL_ID="adastracomputing/reviewer-lora-v1.9"
CORPUS_FREEZE_SHA="$(git rev-parse HEAD)"
TRACE_COMMIT="${CORPUS_FREEZE_SHA}"
MAX_STEPS=190

JSONL_DIR="exports/reviewer-v1.9"

echo "Exporting v1.9 reviewer corpus (includes traces/positives-reorg/) ..."
python3 -m tools.trace_cli export reviewer \
  --out "${JSONL_DIR}" \
  --reviewer-prompt prompts/reviewer.v8.md \
  --split-manifest data/splits/reviewer-v1.8.json

echo "Generating per-split JSONL files ..."
python3 << 'PYEOF'
import json
from pathlib import Path
out = Path("exports/reviewer-v1.9")
rows = [json.loads(l) for l in (out / "reviewer.jsonl").read_text().splitlines() if l.strip()]
# Sanity: the 8 reorg positives must be present, in train, accept-labeled.
reorg = [r for r in rows if r.get("provenance", {}).get("positive_source") == "reorg"]
if len(reorg) != 8:
    raise ValueError(f"expected 8 reorg positives, got {len(reorg)}")
if any(r["split"] != "train" or r["label"] != "positive" for r in reorg):
    raise ValueError("reorg positives must all be train/positive")
print(f"reorg positives: {len(reorg)} (all train/positive) OK")
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
    print(f"  CTW sanity: OK")
PYEOF

echo "Uploading v1.9 training JSONLs to hf://datasets/${DATASET} ..."
nix-shell -p python3Packages.huggingface-hub --run \
  "hf upload ${DATASET} ${JSONL_DIR}/reviewer.train.jsonl reviewer-v1.9.train.jsonl --repo-type dataset"
nix-shell -p python3Packages.huggingface-hub --run \
  "hf upload ${DATASET} ${JSONL_DIR}/reviewer.dev.jsonl reviewer-v1.9.dev.jsonl --repo-type dataset"

echo
echo "Submitting Reviewer-LoRA v1.9 HF Job"
echo "  flavor:         ${FLAVOR}"
echo "  push adapter →  ${HUB_MODEL_ID}"
echo "  max_steps:      ${MAX_STEPS} (~7.2 effective epochs, train_n=105)"
echo "  trace commit:   ${TRACE_COMMIT}"

nix-shell -p python3Packages.huggingface-hub --run "
hf jobs uv run \
  --flavor '${FLAVOR}' \
  --namespace '${NAMESPACE}' \
  --timeout 3h \
  --detach \
  --secrets HF_TOKEN \
  -v 'hf://datasets/${DATASET}:/data:ro' \
  -e PYTORCH_CUDA_ALLOC_ALLOC_CONF=expandable_segments:True \
  -e HF_HOME=/tmp/hf \
  -e DATA_DIR=/data \
  -e ADAPTER_DIR=/tmp/reviewer-lora-v1.9 \
  -e HUB_MODEL_ID='${HUB_MODEL_ID}' \
  -e HF_JOB_FLAVOR='${FLAVOR}' \
  -e CORPUS_FREEZE_SHA='${CORPUS_FREEZE_SHA}' \
  -e TRACE_COMMIT='${TRACE_COMMIT}' \
  -e MAX_STEPS='${MAX_STEPS}' \
  -e TRAIN_FILE=reviewer-v1.9.train.jsonl \
  -e DEV_FILE=reviewer-v1.9.dev.jsonl \
  lora/hf_job.py
"
