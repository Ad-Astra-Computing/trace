"""Composite reviewer scorer: LoRA verdict OR deterministic metadata lint.

trace's thesis is that the *contract layer* is the trust boundary, not the model.
This scores the Reviewer-LoRA the way it would actually ship: the model produces a
verdict, and a deterministic metadata-consistency lint (agents/reviewer/metadata_lint)
runs beside it. The composite verdict is REJECT if either the model rejects OR the
lint fires; ACCEPT only when both pass. The lint is proven zero-false-reject on the
honest-positive corpus, so it can only remove false-accepts, never add false-rejects.

Usage: python3 eval/score_reviewer_composite.py <gate_pilot_responses.jsonl>
Maps each fold example back to its bundle dir to run the lint.
"""
from __future__ import annotations

import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from agents.reviewer.metadata_lint import check_metadata_consistency  # noqa: E402

_V = re.compile(r"##\s*Verdict\s*\n\s*\**\s*(accept|reject|defer)", re.I)


def _lora_verdict(text: str) -> str | None:
    m = _V.search(text or "")
    return m.group(1).lower() if m else None


def _neg_mutation_type(d: Path) -> str | None:
    p = d / "mutation.json"
    if not p.exists():
        return None
    try:
        return json.load(open(p)).get("mutation_type")
    except (json.JSONDecodeError, OSError):
        return None


def _bundle_dir(rec: dict) -> Path | None:
    """Locate the bundle dir for a fold example by cve_id and, for negatives,
    the exact mutation_type (a CVE can have several distinct negatives)."""
    cve = rec.get("cve_id", "")
    if rec.get("label") == "negative":
        cands = [d for d in (ROOT / "traces" / "negatives").glob("*/")
                 if cve in d.name]
        exact = [d for d in cands if _neg_mutation_type(d) == rec.get("mutation_type")]
        if exact:
            return exact[0]
        return cands[0] if cands else None
    cands = [d for d in (ROOT / "traces" / "example").glob("*/") if cve in d.name]
    return cands[0] if cands else None


def main(path: str) -> None:
    rows = [json.loads(l) for l in open(path) if l.strip()]
    n = len(rows)
    lora_correct = comp_correct = 0
    lora_fa = comp_fa = fr = 0
    lint_saves = []
    unmapped = []
    for r in rows:
        expected = "accept" if r["label"] == "positive" else "reject"
        lora = _lora_verdict(r.get("generated", ""))
        d = _bundle_dir(r)
        if d is None:
            unmapped.append((r["cve_id"], r.get("attr_path")))
        lint_hits = check_metadata_consistency(d) if d else []
        # composite: reject if model rejects OR lint fires
        composite = "reject" if (lora == "reject" or lint_hits) else lora

        if lora == expected:
            lora_correct += 1
        elif lora == "accept" and expected == "reject":
            lora_fa += 1

        if composite == expected:
            comp_correct += 1
        elif composite == "accept" and expected == "reject":
            comp_fa += 1
        elif composite == "reject" and expected == "accept":
            fr += 1

        if lint_hits and lora == "accept" and expected == "reject":
            lint_saves.append((r["cve_id"], r.get("mutation_type"),
                               [v.code for v in lint_hits]))

    print(f"n={n}")
    print(f"\nLoRA alone     : substance {lora_correct/n:.3f} ({lora_correct}/{n}), "
          f"false-accept {lora_fa}")
    print(f"LoRA + lint    : substance {comp_correct/n:.3f} ({comp_correct}/{n}), "
          f"false-accept {comp_fa}, false-reject {fr}")
    print(f"\nlint saves (false-accepts the deterministic gate caught): {len(lint_saves)}")
    for cve, mt, codes in lint_saves:
        print(f"  {cve:16} {mt:34} -> {codes}")
    if unmapped:
        print(f"\nWARNING unmapped examples ({len(unmapped)}): {unmapped}")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(__doc__); raise SystemExit(2)
    main(sys.argv[1])
