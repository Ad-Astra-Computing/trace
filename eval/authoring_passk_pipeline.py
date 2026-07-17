"""Verifier-guided pass@K authoring pipeline — operationalize the validated lever.

The authoring-LoRA localizes the fix site correctly but rarely emits the exact edit
SHAPE single-shot (greedy add_recall ~0); pass@16 recovers add_recall to 0.36 because
sampling K candidates at the right site produces the correct shape some of the time.
Every attempt to move GREEDY (more data, SR-format, DPO) is a documented negative
(docs/FINDINGS_LORA.md). So the production path is NOT a better single-shot model — it is
**sample K, let a verifier pick the correct one**. This driver is that pipeline:

  for a bundle: take K LoRA candidates -> verifier-filter (structural, then behavioral) ->
  the FIRST candidate that passes IS the authored fix.

Two verifier tiers (reuse eval/score_authoring_pilot):
  - structural (Tier 0/1, pure/offline): format + right-file + region + fix-symbols + hunk
    coverage. Runnable anywhere; a cheap pre-filter and a lower bound.
  - behavioral (Tier 2, needs a Linux nix host + nixpkgs): apply candidate into the bundle,
    build, validate_backport (unpatched-fires / patched-clean). The authoritative gate.

Reports pass@K (did ANY candidate pass) + the index/diff of the first passing candidate.

Usage:
  # structural pass@K, offline (e.g. on archived canary-passk-responses.jsonl):
  python3 eval/authoring_passk_pipeline.py --canaries <canary.jsonl> --responses <passk.jsonl>
  # add the authoritative behavioral gate (Linux nix host):
  python3 eval/authoring_passk_pipeline.py --canaries <c.jsonl> --responses <p.jsonl> \
      --behavioral --nixpkgs <checkout> --traces-root traces/example
"""
from __future__ import annotations

import argparse
import json
import re
from collections import defaultdict
from pathlib import Path

import sys
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from eval.score_authoring_pilot import (  # noqa: E402
    _clean_generated, score_candidate, score_behavioral, _make_build_fn,
)


def _load_jsonl(p: Path) -> list[dict]:
    return [json.loads(l) for l in p.read_text().splitlines() if l.strip()]


def _norm(s: str) -> str:
    return re.sub(r"\s+", " ", s.strip())


def _added(diff: str) -> list[str]:
    return [_norm(l[1:]) for l in diff.splitlines()
            if l.startswith("+") and not l.startswith("+++")]


def _add_recall(gen: str, ref: str) -> float:
    """Fraction of the reference's added lines reproduced (whitespace-normalized) —
    the textual proxy for 'is this the upstream fold'. Used only for the false-accept
    audit binning; NOT the gate (the behavioral verdict is)."""
    ra = _added(ref)
    if not ra:
        return 1.0
    ga = set(_added(gen))
    return sum(1 for x in ra if x in ga) / len(ra)


def _candidates_by_cve(responses: list[dict]) -> dict[str, list[str]]:
    by = defaultdict(list)
    for r in responses:
        by[r.get("cve_id")].append(r.get("generated", ""))
    return by


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--canaries", type=Path, required=True,
                    help="jsonl of canary records (messages[1]=user, messages[2]=reference)")
    ap.add_argument("--responses", type=Path, required=True,
                    help="jsonl of K candidates per cve_id ({cve_id, generated})")
    ap.add_argument("--behavioral", action="store_true",
                    help="also run the authoritative Tier-2 behavioral gate (needs nix)")
    ap.add_argument("--nixpkgs", type=Path, help="nixpkgs checkout (with --behavioral)")
    ap.add_argument("--traces-root", type=Path, default=ROOT / "traces" / "example")
    ap.add_argument("--timeout", type=int, default=1800)
    ap.add_argument("--out", type=Path, default=ROOT / "data/reports/authoring-passk-pipeline.json")
    ap.add_argument("--only", help="restrict to a single cve_id (e.g. for a bounded first run)")
    ap.add_argument("--audit", action="store_true",
                    help="behavioral: run ALL candidates (no short-circuit) and record every "
                         "verdict + add_recall — the false-accept audit. A behavioral pass on a "
                         "candidate with low add_recall (esp. on a fold-unreachable canary) is a "
                         "measured false-accept, the number that gates any auto-merge claim.")
    args = ap.parse_args()

    records = {r["provenance"]["cve_id"]: r for r in _load_jsonl(args.canaries)
               if (r.get("provenance") or {}).get("cve_id")
               and (not args.only or r["provenance"]["cve_id"] == args.only)}
    cands = _candidates_by_cve(_load_jsonl(args.responses))

    build_fn = None
    if args.behavioral:
        if not args.nixpkgs:
            ap.error("--behavioral requires --nixpkgs")
        build_fn = _make_build_fn(args.nixpkgs, args.timeout)

    results = []
    for cve, rec in records.items():
        cl = [_clean_generated(g) for g in cands.get(cve, [])]
        k = len(cl)
        # structural pre-filter: index of every candidate that passes Tier 0/1
        struct_pass_idx = [i for i, g in enumerate(cl)
                           if score_candidate(g, rec)["structural_pass"]]
        entry = {
            "cve_id": cve, "attr_path": rec["provenance"].get("attr_path"),
            "k": k,
            "structural_pass_at_k": bool(struct_pass_idx),
            "structural_pass_count": len(struct_pass_idx),
            "structural_first_idx": struct_pass_idx[0] if struct_pass_idx else None,
        }
        if args.behavioral:
            # run the authoritative gate on structurally-viable candidates first (cheap
            # pre-filter), then any remaining; stop at the first behavioral pass.
            order = struct_pass_idx + [i for i in range(k) if i not in struct_pass_idx]
            ref = rec["messages"][2]["content"]
            beh_first = None
            n_ran = 0            # candidates whose gate actually executed (status == "ran")
            statuses = {}        # non-"ran" statuses → why the gate could not measure them
            audit = []           # per-candidate audit rows (only populated with --audit)
            false_accepts = []   # behavioral-pass candidates with low add_recall (fold-wrong)
            for i in order:
                bv = score_behavioral(cl[i], rec, traces_root=args.traces_root,
                                      build_fn=build_fn)
                st = bv.get("behavioral_status")
                passed = bool(bv.get("behavioral_pass"))
                if args.audit:
                    ar = round(_add_recall(cl[i], ref), 3)
                    audit.append({"idx": i, "structural": i in struct_pass_idx,
                                  "status": st, "behavioral_pass": passed, "add_recall": ar})
                    if passed and ar < 0.5:
                        # passed the build gate but does NOT reproduce the upstream fold:
                        # either an adequate-different-shape fix or a false accept — the
                        # audit flags it for human adjudication (load-bearing).
                        false_accepts.append({"idx": i, "add_recall": ar})
                if st == "ran":
                    n_ran += 1
                    if passed:
                        if beh_first is None:
                            beh_first = i
                        if not args.audit:
                            break       # short-circuit only when NOT auditing
                else:
                    statuses[st] = statuses.get(st, 0) + 1
            # A gate that never executes (precondition_failed / exempt_proxy_reproducer /
            # bundle_not_found / no_unique_embedded_patch) is UNMEASURABLE here, not a
            # behavioral failure — never conflate the two (else 0-ran reads as 0-pass).
            measurable = n_ran > 0 or beh_first is not None
            entry.update(
                behavioral_measurable=measurable,
                behavioral_ran_count=n_ran,
                behavioral_pass_at_k=(beh_first is not None),
                behavioral_first_idx=beh_first,
                behavioral_unmeasurable=statuses,
            )
            if beh_first is not None:
                entry["authored_fix"] = cl[beh_first]
            if args.audit:
                entry["audit"] = audit
                entry["false_accepts"] = false_accepts   # behavioral-pass but fold-wrong
        results.append(entry)

    n = len(results)
    s_pass = sum(1 for r in results if r["structural_pass_at_k"])
    print(f"pass@K authoring pipeline — {n} bundles, K={next(iter(results),{}).get('k','?')}")
    print(f"  structural pass@K : {s_pass}/{n}")
    for r in results:
        line = (f"  {r['cve_id']:16} struct_pass@K={r['structural_pass_at_k']} "
                f"({r['structural_pass_count']}/{r['k']})")
        if args.behavioral:
            if r.get("behavioral_measurable"):
                line += (f"  behavioral_pass@K={r.get('behavioral_pass_at_k')} "
                         f"(ran {r.get('behavioral_ran_count')}/{r['k']})")
            else:
                line += f"  behavioral=UNMEASURABLE {r.get('behavioral_unmeasurable')}"
        print(line)
    if args.behavioral:
        measurable = [r for r in results if r.get("behavioral_measurable")]
        b_pass = sum(1 for r in measurable if r.get("behavioral_pass_at_k"))
        print(f"  behavioral pass@K : {b_pass}/{len(measurable)} measurable "
              f"({n - len(measurable)} unmeasurable in this env)")

    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps({"results": results}, indent=2))
    print(f"wrote {args.out}")


if __name__ == "__main__":
    main()
