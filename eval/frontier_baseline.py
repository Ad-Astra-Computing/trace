"""Frontier Reviewer baseline evaluation.

Runs the current frontier Reviewer model over the held-out test fold
from exports/reviewer-v1.0/reviewer.jsonl and records per-example
scores plus aggregate metrics.

Usage:
    set -a && source .env && set +a
    python3 eval/frontier_baseline.py [--dry-run] [--out data/reports/frontier-baseline-v1.0.json]

The baseline is meant to be compared against the Reviewer-LoRA fine-tune
on the same test fold. Record it ONCE before any fine-tuning begins.

Evaluation methodology (per docs/REVIEWER_LORA_PILOT.md):
  - Use embedded JSONL system prompt (per codex 2026-06-17 review: don't
    replace with the current prompt or you create drift vs the dataset)
  - Drop the assistant ground-truth turn; ask the model to produce a verdict
  - Score: schema_valid, verdict_correct, evidence_cited,
    cross_family_attestation_valid, parse_failure
  - Aggregate: accuracy, false_accept_count, false_reject_count, parse_failure_count

Live-run cost: ~11 calls × $0.03/call ≈ $0.33 total.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(ROOT))

from agents.reviewer import ReviewerOutputMalformed, parse_reviewer_output
from agents.cost import rollup_usage


def _git_head_sha() -> str:
    try:
        return subprocess.check_output(
            ["git", "rev-parse", "HEAD"], cwd=ROOT, text=True
        ).strip()
    except Exception:
        return "unknown"


def _file_sha256(path: Path) -> str:
    h = hashlib.sha256(path.read_bytes()).hexdigest()
    return h


DEFAULT_MODEL = "claude-sonnet-4-5-20250929"
DEFAULT_EXPORT = ROOT / "exports" / "reviewer-v1.0" / "reviewer.jsonl"
DEFAULT_OUT = ROOT / "data" / "reports" / "frontier-baseline-v1.0.json"


def _call_api(model_id: str, system: str, user: str) -> tuple[str, dict]:
    """Call Anthropic API; return (response_text, usage_dict)."""
    if not os.environ.get("ANTHROPIC_API_KEY"):
        raise RuntimeError("ANTHROPIC_API_KEY not set. Source .env first.")
    try:
        import anthropic
    except ImportError:
        raise RuntimeError("anthropic SDK not installed")

    client = anthropic.Anthropic()
    kwargs = dict(
        model=model_id,
        max_tokens=2048,
        system=[
            {"type": "text", "text": system, "cache_control": {"type": "ephemeral"}}
        ],
        messages=[{"role": "user", "content": user}],
    )
    try:
        msg = client.messages.create(temperature=0.0, **kwargs)
    except anthropic.BadRequestError as e:
        # Some models (e.g. opus-4-8) deprecate `temperature`; retry without it.
        if "temperature" in str(e):
            msg = client.messages.create(**kwargs)
        else:
            raise
    text = "".join(
        b.text
        for b in getattr(msg, "content", [])
        if getattr(b, "type", None) == "text"
    )
    usage = {}
    if hasattr(msg, "usage"):
        u = msg.usage
        usage = {
            "input_tokens": getattr(u, "input_tokens", 0),
            "output_tokens": getattr(u, "output_tokens", 0),
            "cache_creation_input_tokens": getattr(u, "cache_creation_input_tokens", 0),
            "cache_read_input_tokens": getattr(u, "cache_read_input_tokens", 0),
        }
    return text, usage


def score_example(
    record: dict,
    response_text: str,
    dry_run: bool = False,
) -> dict:
    """Score a single example response against the ground truth label."""
    label = record["label"]  # "positive" or "negative"
    prov = record.get("provenance", {})
    expected_verdict = "accept" if label == "positive" else "reject"

    result: dict = {
        "cve_id": prov.get("cve_id"),
        "attr_path": prov.get("attr_path"),
        "label": label,
        "mutation_type": prov.get("mutation_type"),
        "expected_verdict": expected_verdict,
        "actual_verdict": None,
        "schema_valid": False,
        "verdict_correct": False,
        "evidence_cited": False,
        "cross_family_attestation_present": False,
        "parse_failure": False,
        "parse_error": None,
        "response_text": response_text if not dry_run else "[dry-run]",
    }

    if dry_run:
        result["parse_failure"] = True
        result["parse_error"] = "dry-run — no API call made"
        return result

    try:
        parsed = parse_reviewer_output(response_text)
    except ReviewerOutputMalformed as exc:
        result["parse_failure"] = True
        result["parse_error"] = str(exc)
        return result

    if parsed.kind == "review":
        actual_verdict = parsed.verdict or "unknown"
        result["actual_verdict"] = actual_verdict
        result["schema_valid"] = True
        result["verdict_correct"] = actual_verdict == expected_verdict
        result["evidence_cited"] = bool(parsed.cited_evidence)
        result["cross_family_attestation_present"] = parsed.cross_family is not None
    elif parsed.kind == "refusal":
        result["actual_verdict"] = "refusal"
        result["schema_valid"] = True
        # A refusal is treated as a wrong verdict for accuracy purposes
        # (the Reviewer should produce accept/reject, not refusal, for these examples)
        result["verdict_correct"] = False
        result["evidence_cited"] = False
    else:
        result["parse_failure"] = True
        result["parse_error"] = f"unexpected kind: {parsed.kind!r}"

    return result


def run_baseline(
    export_path: Path,
    out_path: Path,
    model_id: str,
    dry_run: bool,
) -> dict:
    records = [json.loads(l) for l in export_path.read_text().splitlines() if l.strip()]
    test_records = [r for r in records if r.get("split") == "test"]

    print(
        f"frontier baseline: {len(test_records)} test examples | model={model_id}",
        file=sys.stderr,
    )

    results = []
    total_usage: dict = {"input_tokens": 0, "output_tokens": 0}
    usage_records: list = []

    for i, rec in enumerate(test_records, 1):
        prov = rec.get("provenance", {})
        label = rec["label"]
        msgs = rec.get("messages", [])

        # Extract system and user turns (drop the assistant ground-truth turn)
        system_text = ""
        user_text = ""
        for m in msgs:
            role = m.get("role", "")
            content = m.get("content", "")
            if isinstance(content, list):
                content = "\n".join(
                    c.get("text", "")
                    for c in content
                    if isinstance(c, dict) and c.get("type") == "text"
                )
            if role == "system":
                system_text = content
            elif role == "user":
                user_text = content

        print(
            f"  [{i}/{len(test_records)}] {prov.get('cve_id', '?')}/{prov.get('attr_path', '?')} "
            f"label={label} mutation={prov.get('mutation_type', '-')}",
            file=sys.stderr,
        )

        if dry_run:
            response_text = ""
            usage = {}
        else:
            response_text, usage = _call_api(model_id, system_text, user_text)
            for k, v in usage.items():
                total_usage[k] = total_usage.get(k, 0) + v
            usage_records.append({"model": model_id, **usage})

        scored = score_example(rec, response_text, dry_run=dry_run)
        scored["usage"] = usage
        results.append(scored)
        if not dry_run:
            print(
                f"    verdict={scored['actual_verdict']} correct={scored['verdict_correct']} "
                f"schema_valid={scored['schema_valid']} evidence_cited={scored['evidence_cited']}",
                file=sys.stderr,
            )

    # Aggregate
    n = len(results)
    n_correct = sum(1 for r in results if r["verdict_correct"])
    n_schema_valid = sum(1 for r in results if r["schema_valid"])
    n_evidence_cited = sum(1 for r in results if r["evidence_cited"])
    n_parse_fail = sum(1 for r in results if r["parse_failure"])
    positives = [r for r in results if r["label"] == "positive"]
    negatives = [r for r in results if r["label"] == "negative"]
    false_accepts = [r for r in negatives if r.get("actual_verdict") == "accept"]
    false_rejects = [r for r in positives if r.get("actual_verdict") == "reject"]

    agg = {
        "n": n,
        "verdict_accuracy": n_correct / n if n else 0,
        "schema_valid_rate": n_schema_valid / n if n else 0,
        "evidence_cited_rate": n_evidence_cited / n if n else 0,
        "parse_failure_count": n_parse_fail,
        "false_accept_count": len(false_accepts),
        "false_reject_count": len(false_rejects),
        "false_accepts": [
            {"cve_id": r["cve_id"], "mutation_type": r["mutation_type"]}
            for r in false_accepts
        ],
        "false_rejects": [{"cve_id": r["cve_id"]} for r in false_rejects],
        "positives_n": len(positives),
        "positives_correct": sum(1 for r in positives if r["verdict_correct"]),
        "negatives_n": len(negatives),
        "negatives_correct": sum(1 for r in negatives if r["verdict_correct"]),
    }

    output = {
        "schema_version": "1.0.0",
        "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "model_id": model_id,
        "reviewer_prompt_sha": _file_sha256(ROOT / "prompts" / "reviewer.v3.md"),
        "corpus_freeze_sha": _git_head_sha(),
        "export_path": str(export_path),
        "split": "test",
        "methodology": "embedded-jsonl-system-prompt",
        "dry_run": dry_run,
        "aggregate": agg,
        "total_usage": total_usage,
        "cost": rollup_usage(usage_records),
        "examples": results,
    }

    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(output, indent=2))
    print(f"\nfrontier baseline written -> {out_path}", file=sys.stderr)

    print(f"\n== Frontier baseline results ==", file=sys.stderr)
    print(f"  model: {model_id}", file=sys.stderr)
    print(
        f"  test fold: {n} examples ({agg['positives_n']} pos + {agg['negatives_n']} neg)",
        file=sys.stderr,
    )
    print(
        f"  verdict accuracy: {agg['verdict_accuracy']:.1%}  ({n_correct}/{n})",
        file=sys.stderr,
    )
    print(
        f"  false accepts: {agg['false_accept_count']}  false rejects: {agg['false_reject_count']}",
        file=sys.stderr,
    )
    print(
        f"  schema valid: {agg['schema_valid_rate']:.1%}  evidence cited: {agg['evidence_cited_rate']:.1%}",
        file=sys.stderr,
    )
    print(f"  parse failures: {agg['parse_failure_count']}", file=sys.stderr)

    return output


def main() -> None:
    p = argparse.ArgumentParser(
        description="Frontier Reviewer baseline eval on held-out test fold"
    )
    p.add_argument(
        "--dry-run",
        action="store_true",
        help="Skip API calls; just print what would run",
    )
    p.add_argument(
        "--model", default=DEFAULT_MODEL, help=f"Model id (default: {DEFAULT_MODEL})"
    )
    p.add_argument(
        "--export", type=Path, default=DEFAULT_EXPORT, help="reviewer.jsonl export"
    )
    p.add_argument("--out", type=Path, default=DEFAULT_OUT, help="Output JSON path")
    args = p.parse_args()

    if not args.export.exists():
        print(f"error: export not found: {args.export}", file=sys.stderr)
        print(
            "Run: python3 -m tools.trace_cli export reviewer --out exports/reviewer-v1.0",
            file=sys.stderr,
        )
        sys.exit(1)

    run_baseline(args.export, args.out, args.model, args.dry_run)


if __name__ == "__main__":
    main()
