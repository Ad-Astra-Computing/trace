#!/usr/bin/env bash
# Submit Reviewer-LoRA v1.11 training run as an HF Job.
#
# v1.11 changes vs v1.10 (CORPUS ONLY):
#   - v1.10 is gate-saturated (canary 9/9, test 11/11) and no longer
#     discriminates further prompt or data changes on the existing gate. v1.11
#     tests whether MORE examples on the SAME task measurably help, using the
#     new held-out compound-guard probe (data/probes/compound-guard-probe.jsonl,
#     2 unseen families: libwebp CVE-2023-4863, ffmpeg_5 CVE-2023-49502) as the
#     signal, scored against a v1.10 control run on the identical probe.
#   - Clean-experiment invariant: prompt v9 (prompts/reviewer.v9.md) and split
#     manifest reviewer-v1.8.json (data/splits/reviewer-v1.8.json) are held
#     CONSTANT, identical to v1.10. Only the underlying corpus differs (it grew
#     since the v1.10 A-full regeneration). Changing prompt or split alongside
#     corpus would confound any v1.10-vs-v1.11 delta on the probe — we would
#     not know whether an improvement (or regression) came from more data or
#     from a different task framing. The freeze-faithful alternative (default
#     split + prompt v2) was considered and rejected for exactly this reason.
#   - Corpus: local dry export under these exact params (2026-07-28), AFTER the
#     v9/v10 contract-drift exclusion below, gives 134 eligible examples / 113
#     train / 10 dev / 11 test / 0 canary, 80 positive / 54 negative,
#     family-leakage-free. v1.10 trained on 128 eligible (107 train / 10 dev /
#     11 test, 79 positive / 49 negative) under this SAME v9 + reviewer-v1.8
#     config. The TRUE delta v1.10 -> v1.11 is +6 train examples (+1 positive,
#     +5 negative); dev and test are UNCHANGED at 10/11. This is a small,
#     negative-heavy intervention, not a large data increase. The 6 reorg
#     positives and 4 token-preserving-misplacement negatives from v1.10 are
#     still present, still train, still correctly labeled.
#   - Contract-drift exclusion: one eligible target (maxima CVE-2024-34490, a
#     train negative added 2026-07-27) carries a ## Equivalence assessment
#     section, which reviewer.v10 introduced and reviewer.v9 never defines.
#     Pairing it with the v9 system prompt is drift, so the per-split block
#     below drops it (codex <redacted-session-id>, 2026-07-28). It is NOT a compound-guard
#     negative; it is an adaptation-lane rejection.
#   - Count reconciliation: the corpus-v2 freeze reports 139 total / 84
#     positive because it used default splits with no canary carve-out; the
#     reviewer-v1.8 manifest holds out 4 gate-pilot canary bundles (zlib +
#     3 jq CVEs, all positive). So 139 = 134 trained + 4 gate-pilot canary
#     (held out) + 1 maxima (v10-shaped target, excluded under v9); 84 pos =
#     80 trained + 4 canary positives (maxima is a negative, so positive
#     counts are unchanged). No examples are silently lost.
#   - MAX_STEPS=203 (v1.10 was 194 at train_n=107; scaled to train_n=113 to
#     hold ~7.2 effective epochs: 203 * 4 / 113 = 7.19).
#   - --timeout 3h: unchanged from v1.10 (more data, same order of magnitude).
#
# Expected outcome (cost-discipline prediction): v1.11 HOLDS the v1.10
# non-regression bar (canary 9/9, pc_consistency_fatal == 0, test 11/11) on
# the existing gate pilot. On the NEW compound-guard probe, v1.11 shows a
# measurable delta over the v1.10 CONTROL (submit_hf_gate_pilot_v1.10_control.sh,
# run FIRST on the identical probe input) only if the control scores lower —
# do NOT assume v1.11 improves just because it passes the probe. If the
# control already passes 6/6, the probe is saturated and v1.11 only
# demonstrates non-regression, not a measurable gain. See the preregistration
# in docs/REVIEWER_LORA_PILOT.md ("v1.11 retrain preregistration") for the
# full delta-interpretation table and the guards on using this probe as a
# selection signal.
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
HUB_MODEL_ID="adastracomputing/reviewer-lora-v1.11"
CORPUS_FREEZE_SHA="$(git rev-parse HEAD)"
TRACE_COMMIT="${CORPUS_FREEZE_SHA}"
MAX_STEPS=203

JSONL_DIR="exports/reviewer-v1.11"

echo "Exporting v1.11 reviewer corpus (prompt v9 + split reviewer-v1.8, held constant vs v1.10) ..."
python3 -m tools.trace_cli export reviewer \
  --out "${JSONL_DIR}" \
  --reviewer-prompt prompts/reviewer.v9.md \
  --split-manifest data/splits/reviewer-v1.8.json

echo "Generating per-split JSONL files ..."
python3 << 'PYEOF'
import json
from pathlib import Path
out = Path("exports/reviewer-v1.11")
rows = [json.loads(l) for l in (out / "reviewer.jsonl").read_text().splitlines() if l.strip()]

# Contract-drift exclusion (codex <redacted-session-id>, 2026-07-28): reviewer.v9 defines
# only ## Verdict / ## Reasoning / ## Patch comparison. The ## Equivalence
# assessment section was introduced in reviewer.v10 (adaptation lane). One
# eligible target (maxima CVE-2024-34490, bundle c3ad8fadc690f28e, a train
# negative added 2026-07-27) carries that v10-only section, so pairing it with
# the v9 system prompt is contract drift. Drop it to keep the v9 retrain a clean
# one-variable comparison vs v1.10; do NOT switch the whole prompt to v10. The
# id-guard makes future corpus drift fail loudly instead of silently shrinking.
V9_FOREIGN_HEADINGS = ("## Equivalence assessment",)
def _v10_shaped(r):
    asst = [m for m in r["messages"] if m["role"] == "assistant"]
    body = asst[0]["content"] if asst else ""
    return any(h in body for h in V9_FOREIGN_HEADINGS)
drifted = [r for r in rows if _v10_shaped(r)]
dropped_ids = {r["provenance"]["bundle_id"] for r in drifted}
if dropped_ids != {"c3ad8fadc690f28e"}:
    raise ValueError(
        f"v9-foreign-heading filter expected to drop exactly maxima "
        f"c3ad8fadc690f28e, got {dropped_ids} ({len(drifted)} rows). "
        "Corpus drift — re-audit before dispatch."
    )
rows = [r for r in rows if not _v10_shaped(r)]
(out / "reviewer.jsonl").write_text(
    "\n".join(json.dumps(r, sort_keys=True) for r in rows) + "\n"
)
print(f"contract-drift exclusion: dropped {len(drifted)} v10-shaped target(s) {dropped_ids}; {len(rows)} rows remain")

# Pre-registered corpus shape (2026-07-28 dry export, post-exclusion). Fail
# loudly if the corpus has drifted from what the v1.11 preregistration assumes.
if len(rows) != 134:
    raise ValueError(f"expected 134 eligible examples, got {len(rows)}")
split_counts = {}
for r in rows:
    split_counts[r["split"]] = split_counts.get(r["split"], 0) + 1
expected_splits = {"train": 113, "dev": 10, "test": 11}
for split, n in expected_splits.items():
    if split_counts.get(split, 0) != n:
        raise ValueError(f"expected {n} {split} examples, got {split_counts.get(split, 0)} ({split_counts})")
if split_counts.get("canary", 0) != 0:
    raise ValueError(f"expected 0 canary examples in the eligible export, got {split_counts.get('canary', 0)}")
label_counts = {}
for r in rows:
    label_counts[r["label"]] = label_counts.get(r["label"], 0) + 1
if label_counts.get("positive", 0) != 80 or label_counts.get("negative", 0) != 54:
    raise ValueError(f"expected 80 positive / 54 negative, got {label_counts}")
print(f"corpus shape: {len(rows)} total, splits={split_counts}, labels={label_counts} OK")

# Sanity: the 6 surviving reorg positives must be present, in train, accept-
# labeled (unchanged from v1.10 — carried forward, not regenerated).
reorg = [r for r in rows if r.get("provenance", {}).get("positive_source") == "reorg"]
if len(reorg) != 6:
    raise ValueError(f"expected 6 reorg positives, got {len(reorg)}")
if any(r["split"] != "train" or r["label"] != "positive" for r in reorg):
    raise ValueError("reorg positives must all be train/positive")
print(f"reorg positives: {len(reorg)} (all train/positive) OK")

# Sanity: the 4 token-preserving-misplacement negatives must be present, in
# train, reject-labeled (unchanged from v1.10).
mis = [r for r in rows if r.get("provenance", {}).get("mutation_type") == "token-preserving-misplacement"]
if len(mis) != 4:
    raise ValueError(f"expected 4 misplacement negatives, got {len(mis)}")
if any(r["split"] != "train" or r["label"] != "negative" for r in mis):
    raise ValueError("misplacement negatives must all be train/negative")
print(f"misplacement negatives: {len(mis)} (all train/negative) OK")

# Absence assertion: the held-out compound-guard probe's two families
# (libwebp CVE-2023-4863, ffmpeg_5 CVE-2023-49502) must not appear ANYWHERE
# in the eligible export, not just train. A leak here would invalidate the
# probe as a held-out measurability signal for the v1.10-vs-v1.11 delta.
probe_cves = {"CVE-2023-4863", "CVE-2023-49502"}
leaked = [r for r in rows if r.get("provenance", {}).get("cve_id") in probe_cves]
if leaked:
    raise ValueError(f"compound-guard-probe CVEs leaked into the export: {leaked}")
print("compound-guard-probe absence (libwebp/ffmpeg_5): confirmed 0 hits OK")

for s in ("train", "dev", "test"):
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

echo "Recording dispatch provenance (prompt SHA, split-manifest SHA, dataset hashes) ..."
PROMPT_SHA="$(git rev-parse HEAD:prompts/reviewer.v9.md)"
SPLIT_MANIFEST_SHA="$(git rev-parse HEAD:data/splits/reviewer-v1.8.json)"
TRAIN_SHA256="$(sha256sum "${JSONL_DIR}/reviewer.train.jsonl" | cut -d' ' -f1)"
DEV_SHA256="$(sha256sum "${JSONL_DIR}/reviewer.dev.jsonl" | cut -d' ' -f1)"
TEST_SHA256="$(sha256sum "${JSONL_DIR}/reviewer.test.jsonl" | cut -d' ' -f1)"
FULL_SHA256="$(sha256sum "${JSONL_DIR}/reviewer.jsonl" | cut -d' ' -f1)"

cat > "${JSONL_DIR}/dispatch-provenance.json" << EOF
{
  "hub_model_id": "${HUB_MODEL_ID}",
  "trace_commit": "${TRACE_COMMIT}",
  "corpus_freeze_sha": "${CORPUS_FREEZE_SHA}",
  "reviewer_prompt_path": "prompts/reviewer.v9.md",
  "reviewer_prompt_sha": "${PROMPT_SHA}",
  "split_manifest_path": "data/splits/reviewer-v1.8.json",
  "split_manifest_sha": "${SPLIT_MANIFEST_SHA}",
  "train_file": "reviewer-v1.11.train.jsonl",
  "train_file_sha256": "${TRAIN_SHA256}",
  "dev_file": "reviewer-v1.11.dev.jsonl",
  "dev_file_sha256": "${DEV_SHA256}",
  "test_file_sha256": "${TEST_SHA256}",
  "full_export_sha256": "${FULL_SHA256}",
  "excluded_v9_v10_drift": ["c3ad8fadc690f28e"],
  "excluded_reason": "maxima CVE-2024-34490 target carries v10-only ## Equivalence assessment section; excluded under v9 prompt",
  "max_steps": ${MAX_STEPS}
}
EOF

echo "Provenance:"
cat "${JSONL_DIR}/dispatch-provenance.json"

echo "Uploading v1.11 training JSONLs to hf://datasets/${DATASET} ..."
nix-shell -p python3Packages.huggingface-hub --run \
  "hf upload ${DATASET} ${JSONL_DIR}/reviewer.train.jsonl reviewer-v1.11.train.jsonl --repo-type dataset"
nix-shell -p python3Packages.huggingface-hub --run \
  "hf upload ${DATASET} ${JSONL_DIR}/reviewer.dev.jsonl reviewer-v1.11.dev.jsonl --repo-type dataset"

echo
echo "Submitting Reviewer-LoRA v1.11 HF Job"
echo "  flavor:         ${FLAVOR}"
echo "  push adapter →  ${HUB_MODEL_ID}"
echo "  max_steps:      ${MAX_STEPS} (~7.19 effective epochs, train_n=113)"
echo "  trace commit:   ${TRACE_COMMIT}"
echo "  prompt SHA:     ${PROMPT_SHA}"
echo "  split SHA:      ${SPLIT_MANIFEST_SHA}"

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
  -e ADAPTER_DIR=/tmp/reviewer-lora-v1.11 \
  -e HUB_MODEL_ID='${HUB_MODEL_ID}' \
  -e HF_JOB_FLAVOR='${FLAVOR}' \
  -e CORPUS_FREEZE_SHA='${CORPUS_FREEZE_SHA}' \
  -e TRACE_COMMIT='${TRACE_COMMIT}' \
  -e MAX_STEPS='${MAX_STEPS}' \
  -e TRAIN_FILE=reviewer-v1.11.train.jsonl \
  -e DEV_FILE=reviewer-v1.11.dev.jsonl \
  lora/hf_job.py
"
