"""Build gate-pilot.jsonl for a given reviewer export + mutation negatives.

Gate pilot structure:
  canary: positives for canary CVEs + all mutations for canary CVEs
  test:   the held-out test-fold examples from the training export

Usage:
  python3 scripts/build_gate_pilot.py \\
    --export   exports/reviewer-v1.4 \\
    --manifest data/splits/reviewer-v1.4.json \\
    --negatives traces/negatives \\
    --prompts  prompts/reviewer.v5.md \\
    --out      exports/reviewer-v1.4/gate-pilot.jsonl

The script reads canary family keys from the split manifest overrides,
then loads:
  1. The matching positive bundles from traces/example/ (using the same
     reviewer prompt and input-assembly logic as the regular export) as
     canary positives.
  2. All mutation negatives whose base_bundle_dir matches a canary CVE
     from traces/negatives/ as canary mutations.
  3. Test-fold examples from the export JSONL as test examples.

All examples are formatted WITHOUT the assistant turn (gate pilot
sends system+user to the model and scores the model's output).
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument(
        "--export",
        required=True,
        type=Path,
        help="export dir (contains reviewer.jsonl + manifest.json)",
    )
    ap.add_argument("--manifest", required=True, type=Path, help="split manifest JSON")
    ap.add_argument(
        "--negatives",
        default=ROOT / "traces" / "negatives",
        type=Path,
        help="negatives root dir",
    )
    ap.add_argument(
        "--traces",
        default=ROOT / "traces" / "example",
        type=Path,
        help="traces/example root",
    )
    ap.add_argument(
        "--prompt",
        default=ROOT / "prompts" / "reviewer.v5.md",
        type=Path,
        help="reviewer prompt path",
    )
    ap.add_argument(
        "--out", required=True, type=Path, help="output gate-pilot.jsonl path"
    )
    args = ap.parse_args()

    # Load split manifest — find canary families
    manifest = json.loads(args.manifest.read_text())
    canary_families = {
        fam
        for fam, info in manifest.get("overrides", {}).items()
        if (info if isinstance(info, str) else info.get("split")) == "canary"
    }
    if not canary_families:
        print("No canary families in manifest — nothing to build", file=sys.stderr)
        return 1
    print(f"Canary families: {sorted(canary_families)}")

    # Load the full training JSONL to get test examples and canary context
    export_rows = [
        json.loads(l)
        for l in (args.export / "reviewer.jsonl").read_text().splitlines()
        if l.strip()
    ]
    test_rows = [r for r in export_rows if r["split"] == "test"]
    print(f"Test fold: {len(test_rows)} examples")

    # Build canary examples from the canary-split positives in traces/example/
    # We need to re-assemble them using the export machinery
    from tools.trace_cli.export import _example_for_bundle  # type: ignore

    split_overrides = {
        fam: (info if isinstance(info, str) else info.get("split", "canary"))
        for fam, info in manifest.get("overrides", {}).items()
    }
    system_prompt = args.prompt.read_text()

    canary_positives: list[dict] = []
    for bd in sorted(args.traces.glob("CVE-*")):
        if not bd.is_dir():
            continue
        ex, status = _example_for_bundle(bd, system_prompt, split_overrides)
        if ex is None:
            continue
        if ex["split"] != "canary":
            continue
        if ex["label"] != "positive":
            continue
        # Strip assistant turn for gate pilot
        ex_gp = _strip_assistant(ex)
        canary_positives.append(ex_gp)
        print(f"  canary+: {status['cve_id']} ({status['attr_path']})")

    # Load canary mutations from negatives root
    canary_mutations: list[dict] = []
    canary_cve_ids = {ex["provenance"]["cve_id"] for ex in canary_positives}
    for neg_dir in sorted(args.negatives.glob("CVE-*")):
        if not neg_dir.is_dir():
            continue
        mut_json = neg_dir / "mutation.json"
        if not mut_json.is_file():
            continue
        mut = json.loads(mut_json.read_text())
        if mut.get("base_cve_id") not in canary_cve_ids:
            continue
        ex, status = _example_for_bundle(neg_dir, system_prompt, split_overrides)
        if ex is None:
            # Mutation may lack review.md (canary-only mutations) — still include
            ex = _assemble_canary_mutation(neg_dir, system_prompt, split_overrides, mut)
            if ex is None:
                print(f"  SKIP {neg_dir.name} (could not assemble)")
                continue
        ex_gp = _strip_assistant(ex)
        # Force split=canary for gate pilot display
        ex_gp["split"] = "canary"
        canary_mutations.append(ex_gp)
        mt = mut.get("mutation_type", "?")
        print(f"  canary-: {mut['base_cve_id']} mt={mt}")

    pilot_rows = canary_positives + canary_mutations
    # Add test rows (strip assistant turn)
    for r in test_rows:
        r_gp = _strip_assistant(r)
        pilot_rows.append(r_gp)

    print(
        f"\nGate pilot: {len(canary_positives)} canary+, "
        f"{len(canary_mutations)} canary-, {len(test_rows)} test = {len(pilot_rows)} total"
    )

    args.out.parent.mkdir(parents=True, exist_ok=True)
    with args.out.open("w") as fh:
        for row in pilot_rows:
            fh.write(json.dumps(row, sort_keys=True) + "\n")
    print(f"Written: {args.out}")
    return 0


def _strip_assistant(ex: dict) -> dict:
    """Return a copy of the example with the assistant turn removed."""
    import copy

    r = copy.deepcopy(ex)
    r["messages"] = [m for m in r["messages"] if m["role"] != "assistant"]
    return r


def _assemble_canary_mutation(
    neg_dir: Path, system_prompt: str, split_overrides: dict, mut: dict
) -> dict | None:
    """Assemble a gate-pilot row for a canary mutation that has no review.md."""
    try:
        from tools.trace_cli.export import (  # type: ignore
            _build_user_turn,
            _normalize_attr,
            _redact,
            SCHEMA_VERSION,
        )
    except ImportError as e:
        print(f"  import error: {e}")
        return None

    try:
        finding = json.loads((neg_dir / "finding.json").read_text())
    except Exception:
        return None

    affected = finding.get("affected") or [{}]
    attr = (affected[0].get("attr_path") or "").strip() if affected else ""
    cve_id = finding.get("cve_id", "")

    user_turn = _build_user_turn(neg_dir)
    if not user_turn:
        return None

    family = _normalize_attr(attr)
    override_split = split_overrides.get(family)
    split = override_split if override_split else "canary"

    provenance = {
        "bundle_id": mut.get("base_bundle_id", ""),
        "cve_id": cve_id,
        "attr_path": attr,
        "split_family": family,
        "split_override": override_split,
        "kind": "reviewer-attested",
        "negative_source": "mutation",
        "mutation_type": mut.get("mutation_type"),
        "base_bundle_id": mut.get("base_bundle_id"),
    }

    return {
        "schema_version": SCHEMA_VERSION,
        "scope": "reviewer",
        "messages": [
            {"role": "system", "content": _redact(system_prompt.rstrip())},
            {"role": "user", "content": _redact(user_turn)},
        ],
        "label": "negative",
        "split": "canary",
        "eligibility_for_training": False,
        "provenance": provenance,
    }


if __name__ == "__main__":
    sys.exit(main())
