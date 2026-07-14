"""Graded canary scorer — retires byte-exact-on-free-form-diff as the headline metric.

Motivation (2026-07-14): byte-exact match on a free-form unified diff conflates format
fidelity (reproducing context lines / hunk headers / whitespace byte-for-byte) with
actual edit correctness, and it hid real partial-correctness (pyjwt removed-line recall
1.0, requests added-line recall 1.0) that the 0/4 byte-exact number reported as zero.

This scores each generated diff against the reference upstream fix on a LADDER:
  1. byte_exact       — the old metric (kept for continuity)
  2. rem_recall       — fraction of the reference's REMOVED lines present (whitespace-
                        normalized). "did it delete the right code?"
  3. add_recall       — fraction of the reference's ADDED lines present (normalized).
                        "did it write the right new code?"
  4. norm_exact       — normalized added AND removed line-sets both equal the reference
                        (edit correct modulo formatting)
  5. key_token_frac   — fraction of the fix's distinctive code identifiers present
                        (semantic-concept hit, catches right-concept/different-structure
                        like zlib's extra_max)

When a response file has MULTIPLE generations per cve_id (pass@K sampling, or the
{original,narrowed} variants), each metric is reported as BEST-OF (pass@K semantics).

Usage:
  python3 lora/score_canaries_graded.py <canary.jsonl> <responses.jsonl> [<responses2.jsonl> ...]
Each responses file is {cve_id, variant?, sample?, generated} per line. Labels come from
the file's basename. Writes a JSON report next to the first responses file's dir.
"""
from __future__ import annotations

import json
import re
import sys
from collections import defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from tools.trace_cli.export import _fix_symbols, _parse_fix_diff  # noqa: E402

CANARY_NAMES = {
    "CVE-2022-37434": "zlib", "CVE-2026-42250": "bzip2recover",
    "CVE-2024-47081": "requests", "CVE-2026-48526": "pyjwt",
}


def _norm(line: str) -> str:
    return re.sub(r"\s+", "", line)


def _added_removed(diff: str) -> tuple[set[str], set[str]]:
    p = _parse_fix_diff(diff)
    add = {_norm(l) for v in p["added"].values() for l in v if l.strip()}
    rem = {_norm(l) for v in p["removed"].values() for l in v if l.strip()}
    return add, rem


def grade(gen: str, ref: str, ref_syms: set[str]) -> dict:
    ga, gr = _added_removed(gen)
    ra, rr = _added_removed(ref)
    add_recall = len(ga & ra) / len(ra) if ra else 1.0
    rem_recall = len(gr & rr) / len(rr) if rr else 1.0
    gen_toks = set(re.findall(r"[A-Za-z_][A-Za-z0-9_]{2,}", gen))
    key_frac = (len([s for s in ref_syms if s in gen_toks]) / len(ref_syms)) if ref_syms else 0.0
    return {
        "byte_exact": gen.strip() == ref.strip(),
        "add_recall": round(add_recall, 3),
        "rem_recall": round(rem_recall, 3),
        "norm_exact": ga == ra and gr == rr,
        "key_token_frac": round(key_frac, 3),
    }


def _load_refs(canary_path: Path) -> dict[str, tuple[str, set[str]]]:
    refs = {}
    for line in canary_path.read_text().splitlines():
        if not line.strip():
            continue
        r = json.loads(line)
        cve = (r.get("provenance") or {}).get("cve_id")
        if not cve:
            m = re.search(r"CVE-\d{4}-\d+", json.dumps(r))
            cve = m.group(0) if m else None
        ref_diff = r["messages"][2]["content"]
        refs[cve] = (ref_diff, set(_fix_symbols(ref_diff)))
    return refs


def _best_of(grades: list[dict]) -> dict:
    """pass@K: best value per metric across all generations for a cve_id."""
    return {
        "byte_exact": any(g["byte_exact"] for g in grades),
        "norm_exact": any(g["norm_exact"] for g in grades),
        "add_recall": max(g["add_recall"] for g in grades),
        "rem_recall": max(g["rem_recall"] for g in grades),
        "key_token_frac": max(g["key_token_frac"] for g in grades),
        "k": len(grades),
    }


def main(argv: list[str]) -> int:
    if len(argv) < 2:
        print(__doc__)
        return 2
    canary_path = Path(argv[0])
    refs = _load_refs(canary_path)
    report = {"canary_set": str(canary_path), "models": {}}

    for resp_path in argv[1:]:
        rp = Path(resp_path)
        label = rp.stem
        by_cve: dict[str, list[dict]] = defaultdict(list)
        for line in rp.read_text().splitlines():
            if not line.strip():
                continue
            r = json.loads(line)
            cve = r.get("cve_id")
            if cve not in refs:
                continue
            ref_diff, ref_syms = refs[cve]
            by_cve[cve].append(grade(r["generated"], ref_diff, ref_syms))
        model_report = {cve: _best_of(gs) for cve, gs in by_cve.items()}
        report["models"][label] = model_report

    # print table
    metrics = ["byte_exact", "norm_exact", "rem_recall", "add_recall", "key_token_frac"]
    print(f"\n{'model':22}{'canary':14}{'K':>3} " + " ".join(f"{m:>13}" for m in metrics))
    for label, mr in report["models"].items():
        for cve, g in sorted(mr.items()):
            name = CANARY_NAMES.get(cve, cve)
            vals = " ".join(f"{str(g[m]):>13}" for m in metrics)
            print(f"{label[:21]:22}{name:14}{g['k']:>3} {vals}")
    # summary: best-of add/rem recall per model (the honest 'partial correctness' number)
    print("\n--- per-model means (best-of-K) ---")
    for label, mr in report["models"].items():
        n = len(mr)
        ar = sum(g["add_recall"] for g in mr.values()) / n if n else 0
        rr = sum(g["rem_recall"] for g in mr.values()) / n if n else 0
        be = sum(1 for g in mr.values() if g["byte_exact"])
        ne = sum(1 for g in mr.values() if g["norm_exact"])
        print(f"  {label[:30]:30} byte {be}/{n}  norm {ne}/{n}  mean_add_recall {ar:.2f}  mean_rem_recall {rr:.2f}")

    out = rp.parent / "canary-graded-report.json"
    out.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    print(f"\nwrote {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
