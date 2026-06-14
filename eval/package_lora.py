"""Package the Reviewer exporter output into final LoRA train/dev/test JSONL.

The integration-gate step that turns `exports/reviewer/reviewer.jsonl` (one record per
example, carrying trace-internal metadata) into HF-ready supervised-fine-tune files:

  exports/lora/reviewer.train.jsonl   — {"messages":[system,user,assistant]} per line
  exports/lora/reviewer.dev.jsonl       (training lines carry ONLY messages — the
  exports/lora/reviewer.test.jsonl       model must never see split/label/provenance)
  exports/lora/manifest.json          — per-split counts + label balance, base model,
                                        reviewer prompt sha, leakage status, length stats

Validation (codex peer 2026-06-14: "surface format/split/tokenization issues before the
fleet reaches 50"): every record has exactly system+user+assistant with non-empty
content; the binary label is carried by the assistant turn (the review verdict), so it is
NOT a separate training field; flags length outliers (no HF tokenizer in this env, so a
chars/4 token estimate) that would truncate at a typical 8k training seq-len.

Read-only on the corpus; writes only under exports/lora/ (gitignored). Exit 1 on any
validation failure so it can gate CI. Usage: python3 eval/package_lora.py [--seq-len N]
"""

from __future__ import annotations

import argparse
import json
import math
import sys
from collections import Counter
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
SRC = REPO / "exports" / "reviewer" / "reviewer.jsonl"
OUT = REPO / "exports" / "lora"
BASE_MODEL = "Qwen2.5-Coder-14B"   # per docs/.../trace-finetuning-plan; LoRA target
_CHARS_PER_TOK = 4                 # rough estimate; no HF tokenizer in this env
SPLITS = ("train", "dev", "test")


def _est_tokens(record: dict) -> int:
    return math.ceil(sum(len(m.get("content", "")) for m in record.get("messages", [])) / _CHARS_PER_TOK)


def _validate(record: dict) -> list[str]:
    errs = []
    roles = [m.get("role") for m in record.get("messages", [])]
    if roles != ["system", "user", "assistant"]:
        errs.append(f"roles {roles} != [system,user,assistant]")
    for m in record.get("messages", []):
        if not (m.get("content") or "").strip():
            errs.append(f"empty {m.get('role')} content")
    if record.get("label") not in ("positive", "negative"):
        errs.append(f"label {record.get('label')!r} not positive/negative")
    if record.get("split") not in SPLITS:
        errs.append(f"split {record.get('split')!r} not in {SPLITS}")
    return errs


def package(seq_len: int) -> dict:
    if not SRC.is_file():
        raise FileNotFoundError(f"run `trace export reviewer` first; missing {SRC}")
    rows = [json.loads(l) for l in SRC.read_text().splitlines() if l.strip()]

    errors: list[str] = []
    for i, r in enumerate(rows):
        errors += [f"row {i} ({(r.get('provenance') or {}).get('cve_id')}): {e}" for e in _validate(r)]

    OUT.mkdir(parents=True, exist_ok=True)
    per_split: dict[str, list[dict]] = {s: [] for s in SPLITS}
    for r in rows:
        s = r.get("split")
        if s in per_split:
            per_split[s].append(r)

    over_len = []
    for s, recs in per_split.items():
        path = OUT / f"reviewer.{s}.jsonl"
        with path.open("w") as fh:
            for r in recs:
                fh.write(json.dumps({"messages": r["messages"]}, sort_keys=True) + "\n")
                if _est_tokens(r) > seq_len:
                    over_len.append({"cve": (r.get("provenance") or {}).get("cve_id"),
                                     "split": s, "est_tokens": _est_tokens(r)})

    # prompt sha + leakage are shared provenance across rows
    prompt_shas = {(r.get("provenance") or {}).get("reviewer_prompt_sha") for r in rows}
    prompt_shas.discard(None)
    manifest = {
        "base_model": BASE_MODEL,
        "task": "reviewer-accept-reject-sft",
        "schema_version": "1.0.0",
        "seq_len_budget": seq_len,
        "total": len(rows),
        "splits": {s: len(per_split[s]) for s in SPLITS},
        "label_balance": {s: dict(Counter(r["label"] for r in per_split[s])) for s in SPLITS},
        "reviewer_prompt_shas": sorted(prompt_shas),
        "est_token_stats": {
            "max": max((_est_tokens(r) for r in rows), default=0),
            "mean": round(sum(_est_tokens(r) for r in rows) / len(rows)) if rows else 0,
        },
        "over_seq_len": over_len,
        "validation_errors": errors,
        "files": [f"reviewer.{s}.jsonl" for s in SPLITS],
    }
    (OUT / "manifest.json").write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n")
    return manifest


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description="Package Reviewer LoRA train/dev/test JSONL")
    ap.add_argument("--seq-len", type=int, default=8192, help="token budget to flag over-length records")
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args(argv)
    m = package(args.seq_len)
    if args.json:
        print(json.dumps(m, indent=2, sort_keys=True))
    else:
        print(f"LoRA package -> {OUT}/reviewer.{{train,dev,test}}.jsonl  (base {m['base_model']})")
        print(f"  total {m['total']}  splits {m['splits']}")
        print(f"  label balance {m['label_balance']}")
        print(f"  est tokens: max {m['est_token_stats']['max']} mean {m['est_token_stats']['mean']}"
              f"  over {args.seq_len}: {len(m['over_seq_len'])}")
        print(f"  reviewer prompt sha(s): {m['reviewer_prompt_shas']}")
        if m["validation_errors"]:
            print(f"  VALIDATION ERRORS ({len(m['validation_errors'])}):")
            for e in m["validation_errors"][:10]:
                print(f"    - {e}")
    return 1 if m["validation_errors"] else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
