"""Honest verdict-substance re-scorer for reviewer eval reports.

The strict reviewer parser rejects any output that does not conform to the exact
review.md schema (for example prose before the `=== BEGIN` marker), and counts it as a
parse failure with `verdict=None`. That conflates FORMAT conformance with verdict
CORRECTNESS: a frontier model that writes `## Verdict\nreject` (correct) but adds a
sentence of preamble is scored the same as a wrong answer. The Reviewer-LoRA's headline
"matched frontier" claim turned on exactly this artifact (the LoRA was trained to emit the
schema; frontier was not).

This re-scores a frontier_baseline.py report (which saves `response_text` per example) on
VERDICT SUBSTANCE: extract the model's intended accept/reject/defer from the raw text
however it is phrased, and compare to the expected verdict. Reports both:
  - strict verdict accuracy (schema-conforming, from the original report)
  - lenient verdict-substance accuracy (this scorer)
  - schema-conformance rate (how often the strict parser accepted the format)
so format reliability and verdict correctness are separated, not conflated.

Usage: python3 eval/score_verdict_substance.py <frontier_baseline_report.json> [more.json ...]
"""
from __future__ import annotations

import json
import re
import sys

_VERDICT_RE = re.compile(r"##\s*Verdict\s*\n\s*\**\s*(accept|reject|defer)", re.I)
_FALLBACK_RE = re.compile(r"(?:^|\n)\s*(?:conclusion|verdict)\s*[:=\-]*\s*\**\s*(accept|reject|defer)", re.I)


def lenient_verdict(text: str) -> str | None:
    if not text:
        return None
    m = _VERDICT_RE.search(text)
    if m:
        return m.group(1).lower()
    m = _FALLBACK_RE.search(text)
    if m:
        return m.group(1).lower()
    return None


def _load_examples(path: str) -> tuple[list[dict], str | None]:
    """Return (examples, model). Handles a frontier_baseline report JSON (has
    `examples`) OR a gate-pilot `responses.jsonl` ({cve_id, label, generated} per line),
    for which strict verdict/schema are computed here via the reviewer parser."""
    text = open(path).read().strip()
    if text.startswith("{"):
        d = json.loads(text)
        if "examples" in d:
            return d["examples"], d.get("model") or d.get("model_id")
    # JSONL of gate-pilot responses
    import sys as _sys
    _sys.path.insert(0, str(__import__("pathlib").Path(__file__).resolve().parents[1]))
    from agents.reviewer import ReviewerOutputMalformed, parse_reviewer_output  # noqa
    ex = []
    for line in text.splitlines():
        if not line.strip():
            continue
        r = json.loads(line)
        gen = r.get("generated", "")
        expected = "accept" if r.get("label") == "positive" else "reject"
        strict_v = None
        schema_ok = False
        try:
            parsed = parse_reviewer_output(gen)
            strict_v = getattr(parsed, "verdict", None) or (parsed.get("verdict") if isinstance(parsed, dict) else None)
            schema_ok = True
        except Exception:
            pass
        ex.append({
            "cve_id": r.get("cve_id"), "label": r.get("label"),
            "expected_verdict": expected, "actual_verdict": strict_v,
            "schema_valid": schema_ok, "verdict_correct": (strict_v == expected),
            "parse_failure": not schema_ok, "response_text": gen,
        })
    return ex, "reviewer-lora (gate-pilot responses)"


def score_report(path: str) -> dict:
    ex, model = _load_examples(path)
    n = len(ex)
    strict_correct = sum(1 for e in ex if e.get("verdict_correct"))
    schema_valid = sum(1 for e in ex if e.get("schema_valid"))
    lenient_correct = 0
    lenient_verdict_found = 0
    fa = fr = 0
    for e in ex:
        expected = e.get("expected_verdict")
        v = lenient_verdict(e.get("response_text", ""))
        if v is not None:
            lenient_verdict_found += 1
        if v == expected:
            lenient_correct += 1
        elif v is not None:
            if expected == "reject" and v == "accept":
                fa += 1
            elif expected == "accept" and v == "reject":
                fr += 1
    return {
        "report": path,
        "model": model,
        "n": n,
        "strict_verdict_accuracy": round(strict_correct / n, 3) if n else 0,
        "schema_conformance_rate": round(schema_valid / n, 3) if n else 0,
        "lenient_verdict_substance_accuracy": round(lenient_correct / n, 3) if n else 0,
        "lenient_verdict_found_rate": round(lenient_verdict_found / n, 3) if n else 0,
        "false_accept": fa,
        "false_reject": fr,
    }


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(__doc__)
        raise SystemExit(2)
    for p in sys.argv[1:]:
        r = score_report(p)
        print(f"\n{r['model']}  (n={r['n']})")
        print(f"  strict verdict accuracy      : {r['strict_verdict_accuracy']:.3f}  (schema-conforming)")
        print(f"  schema conformance rate      : {r['schema_conformance_rate']:.3f}")
        print(f"  VERDICT-SUBSTANCE accuracy   : {r['lenient_verdict_substance_accuracy']:.3f}  (lenient, the honest number)")
        print(f"  verdict extracted rate       : {r['lenient_verdict_found_rate']:.3f}")
        print(f"  false-accept / false-reject  : {r['false_accept']} / {r['false_reject']}")
