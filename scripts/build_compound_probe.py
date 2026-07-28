"""Build the held-out compound-guard generalization probe.

The Reviewer-LoRA v1.10 gate is saturated (canary 9/9, test 11/11) and the 5
existing compound-condition negatives all live in the TRAIN split of the
frozen corpus-v2 (`data/reports/reviewer-corpus-2026-07-27-freeze.json`), so
a v1.11 retrain has no HELD-OUT compound example to measure generalization
against. This script assembles that held-out probe from
`traces/probes/compound-guard/` -- a directory the training exporter never
scans (`trace export reviewer` only globs `traces/example/` and
`traces/negatives/`) -- into a gate-pilot-shaped JSONL, mirroring
`scripts/build_gate_pilot.py`'s row shape and `tools.trace_cli.export`'s
input-assembly machinery (`_build_user_turn`) so the probe is scored by the
existing `eval/score_gate_pilot.py` with zero scorer changes.

Two unseen families (never in corpus-v2 train/dev/test):
  * libwebp   (CVE-2023-4863,  huffman-table backport)
  * ffmpeg_5  (CVE-2023-49502, bwdif backport)

Each family contributes a PAIRED set:
  * one clean, unmutated POSITIVE (probe.json, expected accept) -- the
    control. Without it, a probe that only ever rejects cannot distinguish
    genuine compound-guard discrimination from "reject anything
    compound-shaped."
  * two or more mutated NEGATIVES (mutation.json, expected reject) minted
    with `trace mutate reviewer-negative --mutation condition-drop-conjunct`
    / `condition-operator-mutation` against the SAME base bundle's real
    added compound guard.

Rows are written with split="canary" so `eval/score_gate_pilot.py` applies
its full canary-grade treatment (mandatory correctness, PC-consistency /
pc_file_grounding / pc_role_grounding checks) to the probe when it is scored
as its own isolated --pilot file. This is NOT the v1.10 gate's zlib/jq
canary; the "canary" split label is reused only because it is what unlocks
the scorer's stricter grounding checks, and this probe is always scored via
a separate --pilot/--responses/--out invocation, never mixed into the real
gate-pilot file.

Usage:
  python3 scripts/build_compound_probe.py \\
    --probes traces/probes/compound-guard \\
    --prompt prompts/reviewer.v9.md \\
    --out    data/probes/compound-guard-probe.jsonl
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))


def _load_json(p: Path) -> dict | None:
    try:
        return json.loads(p.read_text())
    except (OSError, json.JSONDecodeError):
        return None


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--probes", type=Path, default=ROOT / "traces" / "probes" / "compound-guard",
                     help="probe bundle root (default traces/probes/compound-guard)")
    ap.add_argument("--prompt", type=Path, default=ROOT / "prompts" / "reviewer.v9.md",
                     help="reviewer system prompt to embed (default prompts/reviewer.v9.md, "
                          "matching REVIEWER_PROMPT_PATH_DEFAULT / the v1.10 gate-pilot build)")
    ap.add_argument("--out", type=Path, default=ROOT / "data" / "probes" / "compound-guard-probe.jsonl",
                     help="output JSONL path")
    args = ap.parse_args()

    from tools.trace_cli.export import _build_user_turn, _normalize_attr, _redact, SCHEMA_VERSION

    if not args.probes.is_dir():
        print(f"error: probe root not found: {args.probes}", file=sys.stderr)
        return 2

    system_prompt = _redact(args.prompt.read_text().rstrip())

    rows: list[dict] = []
    for bd in sorted(p for p in args.probes.iterdir() if p.is_dir()):
        mutation = _load_json(bd / "mutation.json")
        probe_marker = _load_json(bd / "probe.json")
        marker = mutation or probe_marker
        if marker is None or not marker.get("probe"):
            print(f"  SKIP {bd.name} (no probe-marked mutation.json/probe.json)")
            continue

        finding = _load_json(bd / "finding.json")
        bundle = _load_json(bd / "bundle.json") or {}
        if finding is None:
            print(f"  SKIP {bd.name} (no finding.json)")
            continue

        user_turn = _build_user_turn(bd)
        if not user_turn:
            print(f"  SKIP {bd.name} (_build_user_turn failed -- missing package.nix/"
                  f"patch.diff/patch-rationale.md or an assemble_user_content error)")
            continue

        affected = finding.get("affected") or [{}]
        attr = (affected[0].get("attr_path") or "").strip()
        cve_id = finding.get("cve_id", bundle.get("cve_id", ""))
        family = _normalize_attr(attr)

        is_negative = mutation is not None
        label = "negative" if is_negative else "positive"
        expected = marker.get("expected_reviewer_verdict")
        mutation_type = marker.get("mutation_type") if is_negative else None

        provenance = {
            "bundle_id": bundle.get("bundle_id"),
            "cve_id": cve_id,
            "attr_path": attr,
            "split_family": family,
            "kind": bundle.get("kind"),
            "negative_source": "mutation" if is_negative else None,
            "positive_source": None if is_negative else "clean",
            "mutation_type": mutation_type,
            "base_bundle_dir": marker.get("base_bundle_dir"),
            "base_bundle_id": marker.get("base_bundle_id"),
            "probe": True,
            "probe_name": "compound-guard-unseen-family",
            "note": marker.get("probe_note"),
        }

        rows.append({
            "schema_version": SCHEMA_VERSION,
            "scope": "reviewer",
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": _redact(user_turn)},
            ],
            "label": label,
            "split": "canary",
            "eligibility_for_training": False,
            "provenance": provenance,
        })
        print(f"  {label:8s} {cve_id} ({attr}) mt={mutation_type} expected={expected} bundle_id={provenance['bundle_id']}")

    args.out.parent.mkdir(parents=True, exist_ok=True)
    with args.out.open("w") as fh:
        for row in rows:
            fh.write(json.dumps(row, sort_keys=True) + "\n")

    n_pos = sum(1 for r in rows if r["label"] == "positive")
    n_neg = sum(1 for r in rows if r["label"] == "negative")
    families = sorted({r["provenance"]["split_family"] for r in rows})
    print(f"\nCompound-guard probe: {n_pos} positive + {n_neg} negative = {len(rows)} rows")
    print(f"Families: {families}")
    print(f"Written: {args.out}")
    return 0 if rows else 1


if __name__ == "__main__":
    sys.exit(main())
