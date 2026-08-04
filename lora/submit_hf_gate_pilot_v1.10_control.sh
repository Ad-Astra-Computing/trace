#!/usr/bin/env bash
# Submit v1.10 CONTROL-arm inference job on the v1.11 held-out inputs.
#
# This is the control arm for the v1.11 retrain comparison. Codex requires
# scoring v1.10 on the SAME probe first, with identical prompt/decoding/scorer,
# before v1.11's result can be read as an improvement rather than noise. RUN
# THIS SCRIPT FIRST, before submit_hf_gate_pilot_v1.11.sh. The v1.11-minus-v1.10
# delta on identical held-out inputs is the actual result — a v1.11 score in
# isolation proves nothing about whether the retrain helped.
#
# Input is the SAME merged gate-pilot + compound-guard-probe file used for
# v1.11 (see submit_hf_gate_pilot_v1.11.sh for the full rationale): the
# existing gate pilot (exports/reviewer-v1.10/gate-pilot.jsonl, 9 canary + 11
# test, v9 system prompt) plus the held-out compound-guard probe
# (data/probes/compound-guard-probe.jsonl, 25 rows / 5 families, frozen at
# data/probes/compound-guard-probe-freeze.json). Both are copied UNCHANGED. lora/hf_gate_pilot_job.py reads a fixed filename
# (/data/gate-pilot.jsonl), so the merged file is uploaded under that name;
# the gate-pilot-only and probe-only files are also uploaded for provenance.
#
# After the job completes, score TWICE (separately, against the two source
# files — the scorer ignores rows for the other pilot by key mismatch):
#   python3 eval/score_gate_pilot.py \
#     --pilot exports/reviewer-v1.11/gate-pilot.jsonl \
#     --responses <downloaded_responses.jsonl> \
#     --out data/reports/lora-gate-pilot-v1.10-control.json
#   python3 eval/score_gate_pilot.py \
#     --pilot exports/reviewer-v1.11/compound-guard-probe.jsonl \
#     --responses <downloaded_responses.jsonl> \
#     --out data/reports/lora-compound-probe-v1.10-control.json
set -euo pipefail
cd "$(dirname "$0")/.."

set -a && source .env && set +a
: "${HF_TOKEN:?HF_TOKEN not set}"
export HF_TOKEN

FLAVOR="l40sx1"
NAMESPACE="odoom"
DATASET="adastracomputing/reviewer-lora-data"
ADAPTER_REPO="adastracomputing/reviewer-lora-v1.10"
SRC_GATE_PILOT="exports/reviewer-v1.10/gate-pilot.jsonl"
SRC_PROBE="data/probes/compound-guard-probe.jsonl"
GATE_PILOT_JSONL="exports/reviewer-v1.11/gate-pilot.jsonl"
PROBE_JSONL="exports/reviewer-v1.11/compound-guard-probe.jsonl"
MERGED_JSONL="exports/reviewer-v1.11/gate-pilot-plus-probe.jsonl"

if [[ ! -f "${SRC_GATE_PILOT}" ]]; then
    echo "ERROR: ${SRC_GATE_PILOT} not found (needed to build the control pilot)." >&2
    exit 1
fi
if [[ ! -f "${SRC_PROBE}" ]]; then
    echo "ERROR: ${SRC_PROBE} not found (needed to build the control probe)." >&2
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

# Sanity: probe matches the FROZEN manifest byte-for-byte. The prereg
# (docs/PREREG_REVIEWER_V1.11.md) binds measurement to this exact freeze;
# dispatching any other probe bytes would run an unregistered experiment.
import hashlib
freeze = json.loads(Path("data/probes/compound-guard-probe-freeze.json").read_text())
actual_sha = hashlib.sha256(probe_path.read_bytes()).hexdigest()
if actual_sha != freeze["probe_sha256"]:
    raise ValueError(
        f"probe sha256 {actual_sha} != frozen {freeze['probe_sha256']} "
        "(probe drifted from data/probes/compound-guard-probe-freeze.json)"
    )
if len(probe_rows) != freeze["row_count"]:
    raise ValueError(f"Expected {freeze['row_count']} probe rows, got {len(probe_rows)}")
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
# present and non-colliding across the two sources.
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
# Per-run uniqueness. The v1.11 design runs this script SIX times (2 arms x 3
# training seeds); a fixed responses path means each run silently overwrites the
# previous one -- which is exactly how the 2026-07-28 control run's raw responses
# became unrecoverable. RUN_TAG makes each dispatch land in its own path, and the
# job now refuses to clobber an existing one (ALLOW_RESPONSES_OVERWRITE=1 to force).
RUN_TIMESTAMP="${RUN_TIMESTAMP:-$(date -u +%Y-%m-%dT%H:%M:%SZ)}"
RUN_TAG="${RUN_TAG:-$(printf '%s' "${RUN_TIMESTAMP}" | tr -c 'A-Za-z0-9' '-')}"
RESPONSES_PATH="gate_pilot_responses/corpus-v2-control/${RUN_TAG}/responses.jsonl"

echo "Uploading gate-pilot-only and probe-only files for provenance ..."
nix-shell -p python3Packages.huggingface-hub --run \
  "hf upload ${DATASET} ${GATE_PILOT_JSONL} reviewer-v1.11-gate-pilot-only.jsonl --repo-type dataset"
nix-shell -p python3Packages.huggingface-hub --run \
  "hf upload ${DATASET} ${PROBE_JSONL} reviewer-v1.11-compound-guard-probe-only.jsonl --repo-type dataset"

echo "Uploading merged file (${N} rows) as gate-pilot.jsonl — the fixed filename hf_gate_pilot_job.py reads ..."
nix-shell -p python3Packages.huggingface-hub --run \
  "hf upload ${DATASET} ${MERGED_JSONL} gate-pilot.jsonl --repo-type dataset"

echo
echo "Submitting v1.10 CONTROL-arm inference job (run this before v1.11)"
echo "  flavor:   ${FLAVOR}"
echo "  adapter:  ${ADAPTER_REPO}"
echo "  dataset:  ${DATASET}"
echo "  input:    gate-pilot.jsonl (${N} examples: 9 canary + 11 test + 25 probe, sha256=${MERGED_SHA256})"
echo "  responses path: ${RESPONSES_PATH} (distinct from v1.10's original gate_pilot_responses/responses.jsonl)"

nix-shell -p python3Packages.huggingface-hub --run "
hf jobs uv run \
  --flavor '${FLAVOR}' \
  --namespace '${NAMESPACE}' \
  --timeout 2h \
  --detach \
  --secrets HF_TOKEN \
  -v 'hf://datasets/${DATASET}:/data:ro' \
  -e HF_HOME=/tmp/hf \
  -e DATA_DIR=/data \
  -e ADAPTER_REPO='${ADAPTER_REPO}' \
  -e EXPECTED_INPUT_SHA256='${MERGED_SHA256}' \
  -e RESPONSES_PATH='${RESPONSES_PATH}' \
  -e RUN_TIMESTAMP='${RUN_TIMESTAMP}' \
  lora/hf_gate_pilot_job.py
"

PROVENANCE_JSON="exports/reviewer-v1.11/control-dispatch-provenance.json"
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

echo
echo "Job dispatched with --detach; raw artifacts are NOT local yet."
echo "When it completes, pull and hash-verify them BEFORE scoring:"
echo "  python3 lora/fetch_gate_pilot_run.py \\"
echo "    --adapter-repo '${ADAPTER_REPO}' \\"
echo "    --responses-path '${RESPONSES_PATH}' \\"
echo "    --out-dir 'data/reports/runs/${RUN_TAG}'"
