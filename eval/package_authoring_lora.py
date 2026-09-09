"""Package the Authoring exporter output into final LoRA train/dev JSONL.

Reads `exports/authoring/authoring.jsonl` (one record per eligible example,
carrying trace metadata) and writes HF-ready SFT files:

  exports/authoring-lora/authoring.train.jsonl  — {"messages":[sys,user,asst]}
  exports/authoring-lora/authoring.dev.jsonl
  exports/authoring-lora/manifest.json          — counts, tiers, length stats

Unlike the Reviewer task (binary accept/reject), Authoring is a generation task:
the assistant turn is the source-fix diff, not a verdict label. Validation checks
format only (roles, non-empty content, valid split).

Usage: python3 eval/package_authoring_lora.py [--seq-len N]
Exit 1 on any validation failure to gate the HF job submission.
"""

from __future__ import annotations

import argparse
import json
import math
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
SRC = REPO / "exports" / "authoring" / "authoring.jsonl"
OUT = REPO / "exports" / "authoring-lora"
BASE_MODEL = "Qwen2.5-Coder-14B"
_CHARS_PER_TOK = 4
SPLITS = ("train", "dev", "test")


def _est_tokens(record: dict) -> int:
    return math.ceil(
        sum(len(m.get("content", "")) for m in record.get("messages", []))
        / _CHARS_PER_TOK
    )


def _validate(record: dict) -> list[str]:
    errs = []
    roles = [m.get("role") for m in record.get("messages", [])]
    if roles != ["system", "user", "assistant"]:
        errs.append(f"roles {roles} != [system,user,assistant]")
    for m in record.get("messages", []):
        if not (m.get("content") or "").strip():
            errs.append(f"empty {m.get('role')} content")
    if record.get("task") != "author-from-vuln":
        errs.append(f"task {record.get('task')!r} != author-from-vuln")
    if record.get("split") not in SPLITS:
        errs.append(f"split {record.get('split')!r} not in {SPLITS}")
    return errs


def package(seq_len: int, src: Path | None = None, out: Path | None = None) -> dict:
    src = src or SRC
    out = out or OUT
    if not src.is_file():
        raise FileNotFoundError(
            f"run `python3 -m tools.trace_cli export authoring` first; missing {src}"
        )
    rows = [json.loads(l) for l in src.read_text().splitlines() if l.strip()]

    errors: list[str] = []
    for i, r in enumerate(rows):
        errors += [
            f"row {i} ({(r.get('provenance') or {}).get('cve_id')}): {e}"
            for e in _validate(r)
        ]

    out.mkdir(parents=True, exist_ok=True)
    per_split: dict[str, list[dict]] = {s: [] for s in SPLITS}
    for r in rows:
        s = r.get("split")
        if s in per_split:
            per_split[s].append(r)

    over_len = []
    for s, recs in per_split.items():
        path = out / f"authoring.{s}.jsonl"
        with path.open("w") as fh:
            for r in recs:
                fh.write(json.dumps({"messages": r["messages"]}, sort_keys=True) + "\n")
                if _est_tokens(r) > seq_len:
                    over_len.append(
                        {
                            "cve": (r.get("provenance") or {}).get("cve_id"),
                            "split": s,
                            "est_tokens": _est_tokens(r),
                        }
                    )

    # Tier breakdown — cert-green vs behavioral-only is load-bearing provenance
    # for the model card and any downstream gate pilot.
    def _tier_counts(recs: list[dict]) -> dict[str, int]:
        tiers: dict[str, int] = {}
        for r in recs:
            t = (r.get("provenance") or {}).get("authoring_validation_tier", "unknown")
            tiers[t] = tiers.get(t, 0) + 1
        return tiers

    all_rows = sum(per_split.values(), [])
    manifest = {
        "base_model": BASE_MODEL,
        "task": "author-from-vuln-sft",
        "schema_version": "1.0.0",
        "seq_len_budget": seq_len,
        "total": len(rows),
        "splits": {s: len(per_split[s]) for s in SPLITS},
        "tiers": _tier_counts(all_rows),
        "tiers_by_split": {s: _tier_counts(per_split[s]) for s in SPLITS},
        "est_token_stats": {
            "max": max((_est_tokens(r) for r in all_rows), default=0),
            "mean": round(sum(_est_tokens(r) for r in all_rows) / len(all_rows))
            if all_rows
            else 0,
        },
        "over_seq_len": over_len,
        "validation_errors": errors,
        "files": [f"authoring.{s}.jsonl" for s in SPLITS],
    }
    (out / "manifest.json").write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n"
    )
    return manifest


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description="Package Authoring LoRA train/dev JSONL")
    ap.add_argument(
        "--seq-len",
        type=int,
        default=16384,
        help="token budget to flag over-length records (default 16384)",
    )
    ap.add_argument(
        "--export-dir",
        type=Path,
        default=None,
        help="path to authoring.jsonl export dir (default: exports/authoring/)",
    )
    ap.add_argument(
        "--out-dir",
        type=Path,
        default=None,
        help="output directory for packaged JSONL (default: exports/authoring-lora/)",
    )
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args(argv)
    src = (args.export_dir / "authoring.jsonl") if args.export_dir else None
    m = package(args.seq_len, src=src, out=args.out_dir)
    out_dir = args.out_dir or OUT
    if args.json:
        print(json.dumps(m, indent=2, sort_keys=True))
    else:
        print(
            f"Authoring LoRA package -> {out_dir}/authoring.{{train,dev}}.jsonl  (base {m['base_model']})"
        )
        print(f"  total {m['total']}  splits {m['splits']}")
        print(f"  tiers: {m['tiers']}")
        print(
            f"  est tokens: max {m['est_token_stats']['max']} mean {m['est_token_stats']['mean']}"
            f"  over {args.seq_len}: {len(m['over_seq_len'])}"
        )
        if m["validation_errors"]:
            print(f"  VALIDATION ERRORS ({len(m['validation_errors'])}):")
            for e in m["validation_errors"][:10]:
                print(f"    - {e}")
    return 1 if m["validation_errors"] else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
