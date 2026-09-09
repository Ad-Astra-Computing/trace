"""Build the DPO guard-clip preference dataset from on-policy generations.

Input: dpo-gen-train-samples.jsonl (from lora/hf_authoring_dpo_gen.py) — K sampled
generations per comparison-bearing TRAIN prompt from the SFT seed adapter. Each sample
carries {train_idx, reference, generated}. The prompt (system+user) is rejoined by
train_idx to the seed's training corpus (authoring.train.jsonl).

A sample becomes a `rejected` iff it is BOTH:
  - wrong  : normalized (added, removed) line-sets != the reference (norm_exact == 0), and
  - clip   : guard-clip-shaped — adds a fresh clamp assignment (`x = LIMIT;`) or a new
             `if (...)` guard instead of folding the existing comparison the reference
             modifies. The clip detector is calibrated on the 18 archived canary clips
             (--self-test) so it demonstrably fires on the real failure.
`chosen` is the reference fix (the condition-fold). At most --max-per-prompt distinct
clip generations are kept per prompt so no single prompt dominates.

Output: TRL-conversational DPO JSONL {prompt:[msgs], chosen:[{assistant}], rejected:[{assistant}]}.

Usage:
  python3 lora/build_dpo_guard_clip.py <samples.jsonl> \
      --train exports/authoring-lora/authoring.train.jsonl \
      --out exports/dpo-guard-clip/dpo.jsonl [--max-per-prompt 3] [--self-test]
"""

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def _added(diff: str) -> list[str]:
    return [
        l[1:]
        for l in diff.splitlines()
        if l.startswith("+") and not l.startswith("+++")
    ]


def _removed(diff: str) -> list[str]:
    return [
        l[1:]
        for l in diff.splitlines()
        if l.startswith("-") and not l.startswith("---")
    ]


def _norm(s: str) -> str:
    return re.sub(r"\s+", " ", s.strip())


def _norm_set(lines: list[str]) -> set[str]:
    return {_norm(x) for x in lines if _norm(x)}


def norm_exact(gen: str, ref: str) -> bool:
    """Added AND removed line-sets both equal the reference (edit correct modulo format)."""
    return _norm_set(_added(gen)) == _norm_set(_added(ref)) and _norm_set(
        _removed(gen)
    ) == _norm_set(_removed(ref))


# clip tells: a fresh clamp assignment `<lhs> = <rhs>;` or a new `if (...)`/`if ... :` guard
_ASSIGN_CLAMP = re.compile(r"^\s*[\w\[\]\.\->]+\s*=\s*[\w\[\]\.\->()]+\s*;?\s*$")
_IF_GUARD = re.compile(r"^\s*(?:if|while)\b.*[\(:]")
_CMP = re.compile(r"(<=|>=|==|!=|<|>|&&|\|\|)")


def is_guard_clip(gen: str, ref: str) -> bool:
    """Wrong-and-clip-shaped: the generation adds a standalone clamp/guard instead of
    reproducing the reference's condition edit."""
    ga = _added(gen)
    if not ga:
        return False
    clip = any(_ASSIGN_CLAMP.match(a) or _IF_GUARD.match(a) for a in ga)
    if not clip:
        return False
    # must be wrong AND must NOT already reproduce the reference's comparison edit
    ref_cmp = {_norm(a) for a in _added(ref) if _CMP.search(a)}
    reproduced = ref_cmp and ref_cmp.issubset(_norm_set(ga))
    return not norm_exact(gen, ref) and not reproduced


def _prompt_msgs(train_rows: list, idx: int) -> list | None:
    if idx < 0 or idx >= len(train_rows):
        return None
    m = train_rows[idx]["messages"]
    return [m[0], m[1]]  # system, user


def self_test() -> None:
    """Confirm the clip detector fires on the 18 archived canary guard-clips."""
    CAN = {
        "CVE-2022-37434": "zlib",
        "CVE-2026-42250": "bzip2recover",
        "CVE-2024-47081": "requests",
        "CVE-2026-48526": "pyjwt",
    }
    refs = {}
    for l in open(ROOT / "exports/authoring-lora/authoring-canary.jsonl"):
        r = json.loads(l)
        cve = (r.get("provenance") or {}).get("cve_id", "")
        if cve in CAN:
            refs[cve] = next(
                (m["content"] for m in r["messages"] if m["role"] == "assistant"), ""
            )
    fired = total = 0
    for f in (ROOT / "data/reports").glob("authoring-lora-v*-responses.jsonl"):
        for l in open(f):
            l = l.strip()
            if not l:
                continue
            r = json.loads(l)
            cve = r.get("cve_id")
            if cve not in refs:
                continue
            gen = r.get("generated", "")
            if not gen or norm_exact(gen, refs[cve]):
                continue
            total += 1
            if is_guard_clip(gen, refs[cve]):
                fired += 1
    print(
        f"[self-test] clip detector fired on {fired}/{total} archived wrong canary gens"
    )


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("samples", type=Path)
    ap.add_argument(
        "--train",
        type=Path,
        default=ROOT / "exports/authoring-lora/authoring.train.jsonl",
    )
    ap.add_argument(
        "--out", type=Path, default=ROOT / "exports/dpo-guard-clip/dpo.jsonl"
    )
    ap.add_argument("--max-per-prompt", type=int, default=3)
    ap.add_argument("--self-test", action="store_true")
    args = ap.parse_args()

    if args.self_test:
        self_test()

    train_rows = [
        json.loads(l) for l in args.train.read_text().splitlines() if l.strip()
    ]
    samples = [
        json.loads(l) for l in args.samples.read_text().splitlines() if l.strip()
    ]

    by_idx: dict[int, list] = {}
    for s in samples:
        by_idx.setdefault(s["train_idx"], []).append(s)

    pairs = []
    n_prompts_with_pair = 0
    dropped_no_prompt = 0
    for idx, sl in sorted(by_idx.items()):
        ref = sl[0]["reference"]
        msgs = _prompt_msgs(train_rows, idx)
        if msgs is None:
            dropped_no_prompt += 1
            continue
        seen = set()
        kept = 0
        for s in sl:
            g = s["generated"]
            if not is_guard_clip(g, ref):
                continue
            key = _norm(" ".join(_added(g)))
            if key in seen:
                continue
            seen.add(key)
            pairs.append(
                {
                    "prompt": msgs,
                    "chosen": [{"role": "assistant", "content": ref}],
                    "rejected": [{"role": "assistant", "content": g}],
                }
            )
            kept += 1
            if kept >= args.max_per_prompt:
                break
        if kept:
            n_prompts_with_pair += 1

    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text("\n".join(json.dumps(p) for p in pairs) + "\n")
    print(
        f"samples={len(samples)} prompts={len(by_idx)} "
        f"prompts_with_clip={n_prompts_with_pair} PAIRS={len(pairs)} "
        f"(max {args.max_per_prompt}/prompt)"
    )
    if dropped_no_prompt:
        print(
            f"WARNING {dropped_no_prompt} train_idx had no matching prompt in --train"
        )
    print(f"wrote {args.out}")


if __name__ == "__main__":
    main()
