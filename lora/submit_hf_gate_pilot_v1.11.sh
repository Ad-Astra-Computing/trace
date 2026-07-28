#!/usr/bin/env bash
# Submit v1.11 gate pilot + compound-guard-probe inference job.
#
# v1.11 evaluates on TWO held-out inputs in one inference run:
#   1. The existing gate pilot (exports/reviewer-v1.10/gate-pilot.jsonl, 9
#      canary + 11 test, already v9 system prompt) — copied UNCHANGED. This is
#      the non-regression check against the v1.10 gate.
#   2. The new held-out compound-guard probe (data/probes/compound-guard-probe.jsonl,
#      6 rows: 2 unseen-family clean positives + 4 mutated negatives, libwebp
#      CVE-2023-4863 + ffmpeg_5 CVE-2023-49502) — copied UNCHANGED. This is the
#      v1.11 measurability signal.
#
# lora/hf_gate_pilot_job.py reads a FIXED filename: /data/gate-pilot.jsonl (no
# env override). To run both inputs through ONE inference job, we build a
# MERGED file (gate-pilot + probe, 26 rows) and upload it AS gate-pilot.jsonl —
# that is the file the job actually reads. The two source files are ALSO
# uploaded under their own names for provenance/reproducibility, but they are
# not what the model sees; the merged file is. Scoring afterwards treats them
# as two logically separate pilots (score_gate_pilot.py matches by
# (bundle_id, mutation_type), so each scoring pass ignores rows belonging to
# the other pilot) — this does not contradict the "probe is never merged into
# gate-pilot for scoring" rule in docs/REVIEWER_LORA_PILOT.md, which is about
# keeping the two pilots' RESULTS distinct, not about the inference input.
#
# Run submit_hf_gate_pilot_v1.10_control.sh FIRST — the v1.10-vs-v1.11 delta
# on the identical probe input is the actual result; the control establishes
# the baseline this run is compared against.
#
# This script and submit_hf_gate_pilot_v1.10_control.sh build the SAME merged
# file from the SAME sources (identical gate-pilot + probe copies, identical
# sort_keys=True serialization), so MERGED_SHA256 computed here MUST equal the
# one computed in the control script — that equality is what makes the two
# arms' inputs provably identical. The two arms still write responses to
# DISTINCT paths: the control arm scores against gate_pilot_responses/
# corpus-v2-control/responses.jsonl, this (v1.11) arm scores against
# gate_pilot_responses/corpus-v2-eval/responses.jsonl. Do not cross-score them.
#
# Run AFTER the training job (adastracomputing/reviewer-lora-v1.11) completes.
#
# After the job completes, score TWICE (separately, against the two source
# files — the scorer ignores rows for the other pilot by key mismatch):
#   python3 eval/score_gate_pilot.py \
#     --pilot exports/reviewer-v1.11/gate-pilot.jsonl \
#     --responses <downloaded_responses.jsonl> \
#     --out data/reports/lora-gate-pilot-v1.11.json
#   python3 eval/score_gate_pilot.py \
#     --pilot exports/reviewer-v1.11/compound-guard-probe.jsonl \
#     --responses <downloaded_responses.jsonl> \
#     --out data/reports/lora-compound-probe-v1.11.json
set -euo pipefail
cd "$(dirname "$0")/.."

set -a && source .env && set +a
: "${HF_TOKEN:?HF_TOKEN not set}"
export HF_TOKEN

FLAVOR="l40sx1"
NAMESPACE="odoom"
DATASET="adastracomputing/reviewer-lora-data"
ADAPTER_REPO="adastracomputing/reviewer-lora-v1.11"
SRC_GATE_PILOT="exports/reviewer-v1.10/gate-pilot.jsonl"
SRC_PROBE="data/probes/compound-guard-probe.jsonl"
GATE_PILOT_JSONL="exports/reviewer-v1.11/gate-pilot.jsonl"
PROBE_JSONL="exports/reviewer-v1.11/compound-guard-probe.jsonl"
MERGED_JSONL="exports/reviewer-v1.11/gate-pilot-plus-probe.jsonl"

if [[ ! -f "${SRC_GATE_PILOT}" ]]; then
    echo "ERROR: ${SRC_GATE_PILOT} not found (needed to build the v1.11 gate pilot)." >&2
    exit 1
fi
if [[ ! -f "${SRC_PROBE}" ]]; then
    echo "ERROR: ${SRC_PROBE} not found (needed to build the v1.11 compound-guard probe)." >&2
    exit 1
fi

echo "Building ${GATE_PILOT_JSONL} (copy of ${SRC_GATE_PILOT}, unchanged) ..."
mkdir -p "$(dirname "${GATE_PILOT_JSONL}")"
cp "${SRC_GATE_PILOT}" "${GATE_PILOT_JSONL}"

echo "Building ${PROBE_JSONL} (copy of ${SRC_PROBE}, unchanged) ..."
cp "${SRC_PROBE}" "${PROBE_JSONL}"

echo "Verifying inputs and building the merged inference file ..."
python3 << 'PYEOF'
import json
from pathlib import Path

gate_path = Path("exports/reviewer-v1.11/gate-pilot.jsonl")
probe_path = Path("exports/reviewer-v1.11/compound-guard-probe.jsonl")
merged_path = Path("exports/reviewer-v1.11/gate-pilot-plus-probe.jsonl")

gate_rows = [json.loads(l) for l in gate_path.read_text().splitlines() if l.strip()]
probe_rows = [json.loads(l) for l in probe_path.read_text().splitlines() if l.strip()]

# Sanity: gate pilot unchanged shape (9 canary + 11 test).
canary = [r for r in gate_rows if r.get("split") == "canary"]
test = [r for r in gate_rows if r.get("split") == "test"]
if len(canary) != 9:
    raise ValueError(f"Expected 9 canary rows in gate pilot, got {len(canary)}")
if len(test) != 11:
    raise ValueError(f"Expected 11 test rows in gate pilot, got {len(test)}")

# Sanity: probe unchanged shape (6 rows, all split=canary, v9 system prompt).
if len(probe_rows) != 6:
    raise ValueError(f"Expected 6 probe rows, got {len(probe_rows)}")
if any(r.get("split") != "canary" for r in probe_rows):
    raise ValueError("All probe rows must be split=canary")
for r in probe_rows:
    sysc = r["messages"][0]["content"]
    if "system prompt v9" not in sysc:
        raise ValueError(f"Probe row {r['provenance'].get('bundle_id')} is not on reviewer.v9 system prompt")

# Sanity: schema compatibility — both inputs carry system+user only (no
# assistant turn), so hf_gate_pilot_job.py's messages[:2] slice is a no-op on
# both and the merge is safe.
for label, rows in (("gate-pilot", gate_rows), ("probe", probe_rows)):
    for r in rows:
        roles = [m["role"] for m in r["messages"]]
        if roles[:2] != ["system", "user"]:
            raise ValueError(f"{label} row {r.get('provenance', {}).get('bundle_id')} has unexpected message roles {roles}")

# Sanity: bundle_id/mutation_type keys used by the scorer's join must be
# present and non-colliding across the two sources (a collision would cause
# score_gate_pilot.py to silently score the wrong pilot's expectation against
# a probe response, or vice versa).
def key(r):
    return (r["provenance"]["bundle_id"], r["provenance"].get("mutation_type") or "")

gate_keys = {key(r) for r in gate_rows}
probe_keys = {key(r) for r in probe_rows}
overlap = gate_keys & probe_keys
if overlap:
    raise ValueError(f"gate-pilot and probe share (bundle_id, mutation_type) keys: {overlap}")

merged = gate_rows + probe_rows

# Sanity: (bundle_id, mutation_type) must be unique across ALL merged rows,
# not merely non-colliding between the two source files — a duplicate within
# either source alone would also break the scorer's join.
from collections import Counter
key_counts = Counter(key(r) for r in merged)
dupes = {k: c for k, c in key_counts.items() if c > 1}
if dupes:
    raise ValueError(f"duplicate (bundle_id, mutation_type) keys across merged rows: {dupes}")

merged_path.write_text("\n".join(json.dumps(r, sort_keys=True) for r in merged) + "\n")
print(f"Merged inference input: {len(merged)} rows ({len(gate_rows)} gate-pilot + {len(probe_rows)} probe) OK")
print(f"Uniqueness check: {len(key_counts)} distinct (bundle_id, mutation_type) keys across {len(merged)} rows OK")
PYEOF

N=$(wc -l < "${MERGED_JSONL}")
MERGED_SHA256="$(sha256sum "${MERGED_JSONL}" | cut -d' ' -f1)"
echo "Merged file sha256: ${MERGED_SHA256}"
RESPONSES_PATH="gate_pilot_responses/corpus-v2-eval/responses.jsonl"

echo "Uploading gate-pilot-only and probe-only files for provenance ..."
nix-shell -p python3Packages.huggingface-hub --run \
  "hf upload ${DATASET} ${GATE_PILOT_JSONL} reviewer-v1.11-gate-pilot-only.jsonl --repo-type dataset"
nix-shell -p python3Packages.huggingface-hub --run \
  "hf upload ${DATASET} ${PROBE_JSONL} reviewer-v1.11-compound-guard-probe-only.jsonl --repo-type dataset"

echo "Uploading merged file (${N} rows) as gate-pilot.jsonl — the fixed filename hf_gate_pilot_job.py reads ..."
nix-shell -p python3Packages.huggingface-hub --run \
  "hf upload ${DATASET} ${MERGED_JSONL} gate-pilot.jsonl --repo-type dataset"

echo
echo "Submitting v1.11 gate pilot + compound-guard-probe inference job"
echo "  flavor:   ${FLAVOR}"
echo "  adapter:  ${ADAPTER_REPO}"
echo "  dataset:  ${DATASET}"
echo "  input:    gate-pilot.jsonl (${N} examples: 9 canary + 11 test + 6 probe, sha256=${MERGED_SHA256})"
echo "  responses path: ${RESPONSES_PATH}"

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
  -e EXPECTED_INPUT_SHA256='${MERGED_SHA256}' \
  -e RESPONSES_PATH='${RESPONSES_PATH}' \
  lora/hf_gate_pilot_job.py
"

PROVENANCE_JSON="exports/reviewer-v1.11/eval-dispatch-provenance.json"
mkdir -p "$(dirname "${PROVENANCE_JSON}")"
GIT_HEAD_SHA="$(git rev-parse HEAD)"
cat > "${PROVENANCE_JSON}" << EOF
{
  "adapter_repo": "${ADAPTER_REPO}",
  "dataset": "${DATASET}",
  "merged_sha256": "${MERGED_SHA256}",
  "merged_row_count": ${N},
  "responses_path": "${RESPONSES_PATH}",
  "git_head_sha": "${GIT_HEAD_SHA}"
}
EOF
echo "Provenance written to ${PROVENANCE_JSON}:"
cat "${PROVENANCE_JSON}"
