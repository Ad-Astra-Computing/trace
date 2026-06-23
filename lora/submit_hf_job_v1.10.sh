#!/usr/bin/env bash
# Submit Reviewer-LoRA v1.10 training run as an HF Job.
#
# v1.10 changes vs v1.9 (PROMPT + CORPUS):
#   - Prompt v8 -> v9: order/placement-sensitive `comparison:`. A token that is
#     PRESENT but mis-placed (guard after use, declaration after read) is now
#     `mismatch (placement/order)`, not `match`. This makes the `## Patch
#     comparison` conclusion EQUAL the verdict on the zlib-style reversed-hunk —
#     the PC-consistency axis the v1.9 gate failed (2 pc_consistency_errors).
#   - Adds 4 token-preserving-misplacement NEGATIVES (coreutils + procps
#     decl-after-use, opensc + giflib guard-inverted) under traces/negatives/,
#     all real-Reviewer REJECT under v9 with `mismatch (placement/order)` and a
#     PC conclusion == verdict. They teach the missing case: CTW token matches
#     yet the fix is broken by placement.
#   - A-full regeneration: every source-backport target re-reviewed under v9 so
#     the whole SB corpus carries v9-format CTW + ordered-PC (the v8 CTW
#     requirement was previously satisfied by ~zero targets — they were generated
#     under v2-v4 via the stale REVIEWER_PROMPT_PATH_DEFAULT). Per codex
#     A-full, 2026-06-23. zlib + jq stay held-out canaries (export shows canary=0).
#   - Split: data/splits/reviewer-v1.8.json (unchanged; same canary zlib+jq).
#     Scorer: eval/score_gate_pilot.py (unchanged).
#   - Corpus: 107 train / 10 dev / 11 test (v1.9 was 105/10/11; -2 dropped
#     reshape positives that v9 correctly rejects as placement-defective,
#     +4 token-preserving-misplacement negatives). 79 positive / 49 negative.
#   - MAX_STEPS=194 (v1.9 was 190 at train_n=105; scaled to train_n=107 to hold
#     ~7.2 effective epochs).
#   - --timeout 3h: more data + steps needs headroom (v1.8 at 175 pushed the
#     adapter ~seconds before its 2h kill).
#
# Expected outcome (cost-discipline prediction): canary 9/9 AND
# pc_consistency_errors == 0 (the v1.9 gate's failing bar). The misplacement
# negatives + v9 ordered-PC should make the model's PC conclusion track its
# verdict on the held-out zlib reversed-hunk. If pc_consistency_errors persist,
# the order-sensitivity did not generalize — stop and reassess before more spend.
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
HUB_MODEL_ID="adastracomputing/reviewer-lora-v1.10"
CORPUS_FREEZE_SHA="$(git rev-parse HEAD)"
TRACE_COMMIT="${CORPUS_FREEZE_SHA}"
MAX_STEPS=194

JSONL_DIR="exports/reviewer-v1.10"

echo "Exporting v1.10 reviewer corpus (includes traces/positives-reorg/) ..."
python3 -m tools.trace_cli export reviewer \
  --out "${JSONL_DIR}" \
  --reviewer-prompt prompts/reviewer.v9.md \
  --split-manifest data/splits/reviewer-v1.8.json

echo "Generating per-split JSONL files ..."
python3 << 'PYEOF'
import json
from pathlib import Path
out = Path("exports/reviewer-v1.10")
rows = [json.loads(l) for l in (out / "reviewer.jsonl").read_text().splitlines() if l.strip()]
# Sanity: the 6 surviving reorg positives must be present, in train, accept-
# labeled (requests + libxmp reshapes were dropped: v9 correctly rejects them
# as placement-defective — the context-reshape transform reordered change lines).
reorg = [r for r in rows if r.get("provenance", {}).get("positive_source") == "reorg"]
if len(reorg) != 6:
    raise ValueError(f"expected 6 reorg positives, got {len(reorg)}")
if any(r["split"] != "train" or r["label"] != "positive" for r in reorg):
    raise ValueError("reorg positives must all be train/positive")
print(f"reorg positives: {len(reorg)} (all train/positive) OK")
# Sanity: the 4 token-preserving-misplacement negatives must be present, in
# train, reject-labeled — the v1.10 consistency-targeted case.
mis = [r for r in rows if r.get("provenance", {}).get("mutation_type") == "token-preserving-misplacement"]
if len(mis) != 4:
    raise ValueError(f"expected 4 misplacement negatives, got {len(mis)}")
if any(r["split"] != "train" or r["label"] != "negative" for r in mis):
    raise ValueError("misplacement negatives must all be train/negative")
print(f"misplacement negatives: {len(mis)} (all train/negative) OK")
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

echo "Uploading v1.10 training JSONLs to hf://datasets/${DATASET} ..."
nix-shell -p python3Packages.huggingface-hub --run \
  "hf upload ${DATASET} ${JSONL_DIR}/reviewer.train.jsonl reviewer-v1.10.train.jsonl --repo-type dataset"
nix-shell -p python3Packages.huggingface-hub --run \
  "hf upload ${DATASET} ${JSONL_DIR}/reviewer.dev.jsonl reviewer-v1.10.dev.jsonl --repo-type dataset"

echo
echo "Submitting Reviewer-LoRA v1.10 HF Job"
echo "  flavor:         ${FLAVOR}"
echo "  push adapter →  ${HUB_MODEL_ID}"
echo "  max_steps:      ${MAX_STEPS} (~7.2 effective epochs, train_n=107)"
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
  -e ADAPTER_DIR=/tmp/reviewer-lora-v1.10 \
  -e HUB_MODEL_ID='${HUB_MODEL_ID}' \
  -e HF_JOB_FLAVOR='${FLAVOR}' \
  -e CORPUS_FREEZE_SHA='${CORPUS_FREEZE_SHA}' \
  -e TRACE_COMMIT='${TRACE_COMMIT}' \
  -e MAX_STEPS='${MAX_STEPS}' \
  -e TRAIN_FILE=reviewer-v1.10.train.jsonl \
  -e DEV_FILE=reviewer-v1.10.dev.jsonl \
  lora/hf_job.py
"
