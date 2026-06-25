#!/usr/bin/env python3
"""Tier 0 + Tier 1 structural scorer for the authoring gate pilot.

The authoring task asks a model to AUTHOR a minimal source fix (a unified diff)
from a CVE summary (vuln-only, fix-symbols scrubbed) plus the pre-fix source
window. This scorer measures a generated diff WITHOUT a build:

  Tier 0  Format / Safety   parses as a patch, no version/hash bump, no test/doc
                            files. Model-agnostic; a fix that fails Tier 0 is not
                            even a well-formed source patch.
  Tier 1  Structural Ref    vs the curated `upstream-fix.patch` label: same impl
                            file(s), grounds in the shown pre-fix window, hits the
                            reference region, carries the reference fix-symbols,
                            covers every reference hunk.

Behavioral validation (Tier 2 — apply to the pre-fix nixpkgs tree, build, run the
reproducer) is DELIBERATELY deferred behind `--behavioral` and reuses
`eval/backport_validation.py`; it costs a Nix build per candidate, so the cheap
structural loop runs first (codex tier plan, 2026-06-25). Report
`format_pass_rate` and `structural_pass_rate` separately so a model that is
structurally promising but behaviorally unproven is never overclaimed.

Usage:
  # score pre-generated responses ({"cve_id": ..., "generated": "<diff>"} per line)
  python3 eval/score_authoring_pilot.py \
      --canary exports/authoring/authoring-canary.jsonl \
      --responses responses.jsonl \
      --out data/reports/authoring-pilot.json

  # generate live from a base model and score (costs API spend)
  python3 eval/score_authoring_pilot.py \
      --canary exports/authoring/authoring-canary.jsonl \
      --generate --model claude-sonnet-4-5-20250929 \
      --out data/reports/authoring-pilot-sonnet.json
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

# Runnable as a standalone script (`python3 eval/score_authoring_pilot.py`): put
# the repo root on sys.path so the `tools`/`agents` packages import.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from tools.trace_cli import backport_patch as bp
from tools.trace_cli.export import (
    _authoring_label_from_patch,
    _file_diff_starts,
    _fix_symbols,
    _patch_grounded,
)
from eval.backport_validation import _VERSION_BUMP_RE

# `_VERSION_BUMP_RE` catches nix-style `version =`/`rev =`/`sha256 =`; add the
# Python `__version__ = "x"` / `VERSION = "x"` shape (the pyjwt release-bump tell).
_PY_VERSION_RE = re.compile(r"""^\+(?!\+\+).*\b_{0,2}version_{0,2}\s*=\s*['"]""", re.IGNORECASE)

# Fraction of the reference's distinctive fix-symbols a candidate must reproduce.
# Not 1.0: a semantically-equivalent fix may name things differently; we want
# "carries the load-bearing guard tokens", not "verbatim identifier match".
_FIX_SYMBOL_THRESHOLD = 0.5
# How close (in shared source lines) a generated hunk must sit to the reference
# to count as hitting the same region — content-based, so it is robust to the
# model numbering hunks against the shown window rather than the full file.
_MIN_REGION_ANCHORS = 1


def _has_version_bump(diff: str) -> bool:
    return any(_VERSION_BUMP_RE.match(ln) or _PY_VERSION_RE.match(ln)
               for ln in diff.splitlines())


def _target_files(diff: str) -> list[str]:
    """Every file the diff targets (incl. non-source), from `+++`/`---` headers.
    Deletions name the file on the `---` side; everything else on `+++`. Used to
    detect unrelated/test files BEFORE the source-only filter drops them."""
    files: list[str] = []
    lines = diff.splitlines()
    for i, ln in enumerate(lines):
        if ln.startswith("+++ "):
            new = ln[4:].strip()
            old = lines[i - 1][4:].strip() if i and lines[i - 1].startswith("--- ") else ""
            path = old if new == "/dev/null" else new
            if path and path != "/dev/null":
                p = path[2:] if path.startswith(("a/", "b/")) else path
                files.append(p)
    return files


def _diff_body_lines(diff: str, fpath: str) -> tuple[set[str], set[str]]:
    """(removed, context) non-blank source lines of `fpath`'s section of a
    canonical (`diff --git`) diff. Content only — no line numbers."""
    removed: set[str] = set()
    context: set[str] = set()
    in_file = False
    for ln in diff.splitlines():
        if ln.startswith("diff --git "):
            m = re.match(r"diff --git a/(.+?) b/(.+)$", ln)
            in_file = bool(m) and (m.group(1) == fpath or m.group(2) == fpath)
        elif in_file and not ln.startswith(("---", "+++", "@@")):
            if ln.startswith("-") and ln[1:].strip():
                removed.add(ln[1:].strip())
            elif ln.startswith(" ") and ln[1:].strip():
                context.add(ln[1:].strip())
    return removed, context


def _prefix_window(user_content: str) -> str:
    """The pre-fix source the model was shown (the fenced block under
    `# Vulnerable source (...)`)."""
    m = re.search(r"# Vulnerable source \([^)]*\)\n```[a-zA-Z0-9]*\n(.*?)\n```",
                  user_content, re.S)
    return m.group(1) if m else ""


def _clean_generated(text: str) -> str:
    """Pull the diff out of a model response: prefer a fenced ```diff block, else
    take from the first diff header onward (the prompt asks for the diff only, but
    models still occasionally wrap or preface it)."""
    m = re.search(r"```(?:diff|patch)?\s*\n(.*?)```", text, re.S)
    body = m.group(1) if m else text
    if "diff --git" in body:
        body = body[body.find("diff --git"):]
    elif "\n--- " in body or body.startswith("--- "):
        idx = 0 if body.startswith("--- ") else body.find("\n--- ") + 1
        body = body[idx:]
    return body.strip()


def score_candidate(generated: str, record: dict) -> dict:
    """Tier 0 + Tier 1 structural score for one generated diff against its canary
    record (which carries the curated reference label + the shown pre-fix source).
    Pure + offline."""
    reference = record["messages"][2]["content"]
    user = record["messages"][1]["content"]
    pre_fix = _prefix_window(user)

    gen_parsed = _authoring_label_from_patch(generated)
    ref_parsed = _authoring_label_from_patch(reference)
    ref_files = set(ref_parsed["churn"]) if ref_parsed else set()
    gen_files = set(gen_parsed["churn"]) if gen_parsed else set()

    # ── Tier 0: Format / Safety ───────────────────────────────────────────────
    targeted = _target_files(generated)
    tier0 = {
        "parses": gen_parsed is not None,
        "no_version_bump": not _has_version_bump(generated),
        "no_test_or_doc_files": bool(targeted) and not any(
            bp._NON_SOURCE_RE.search(f) for f in targeted),
    }
    format_pass = all(tier0.values())

    # ── Tier 1: Structural Reference ──────────────────────────────────────────
    # Primary file = the impl both touch (else the generated file, else reference).
    shared = gen_files & ref_files
    primary = (sorted(shared) or sorted(gen_files) or sorted(ref_files) or [""])[0]

    gen_canon = gen_parsed["fix_diff"] if gen_parsed else ""
    ref_canon = ref_parsed["fix_diff"] if ref_parsed else ""

    ref_syms = _fix_symbols(reference)
    # Match against the candidate's CHANGED lines (added AND removed): `_fix_symbols`
    # draws tokens from both sides of the reference, so a fix that REMOVES a line
    # carrying a key symbol must get credit for reproducing it.
    gen_changed = "\n".join(l for l in generated.splitlines()
                            if l[:1] in ("+", "-") and not l.startswith(("+++", "---")))
    syms_hit = sum(1 for s in ref_syms if s in gen_changed)
    sym_frac = (syms_hit / len(ref_syms)) if ref_syms else 1.0

    gen_rm, gen_ctx = _diff_body_lines(gen_canon, primary)
    ref_rm, ref_ctx = _diff_body_lines(ref_canon, primary)
    region_anchors = len((gen_rm | gen_ctx) & (ref_rm | ref_ctx))

    # Hunk coverage across EVERY reference file (not just the primary): a multi-file
    # fix that omits a required file's hunks must fail, even if the file it does
    # touch matches enough symbols (codex 2026-06-25).
    n_ref_hunks = sum(len(_file_diff_starts(ref_canon, f)) for f in ref_files)
    n_gen_hunks = sum(len(_file_diff_starts(gen_canon, f)) for f in ref_files)
    covers_all = bool(ref_files) and all(
        len(_file_diff_starts(gen_canon, f)) >= len(_file_diff_starts(ref_canon, f))
        for f in ref_files)

    tier1 = {
        # Exactly the reference's source files: covers every required file AND adds
        # no unrelated source file (subset-only would pass an incomplete fix).
        "same_impl_file": bool(gen_files) and gen_files == ref_files,
        "grounds_in_prefix": bool(gen_parsed) and bool(pre_fix)
            and _patch_grounded(gen_canon, primary, pre_fix),
        "hits_reference_region": region_anchors >= _MIN_REGION_ANCHORS,
        "fix_symbols_present": sym_frac >= _FIX_SYMBOL_THRESHOLD,
        "covers_all_reference_hunks": covers_all,
    }
    structural_pass = format_pass and all(tier1.values())

    return {
        "cve_id": record["provenance"]["cve_id"],
        "split_family": record["provenance"]["split_family"],
        "tier0": tier0,
        "tier1": tier1,
        "format_pass": format_pass,
        "structural_pass": structural_pass,
        "detail": {
            "gen_files": sorted(gen_files),
            "ref_files": sorted(ref_files),
            "primary_file": primary,
            "fix_symbols_total": len(ref_syms),
            "fix_symbols_hit": syms_hit,
            "fix_symbol_fraction": round(sym_frac, 3),
            "region_anchors": region_anchors,
            "ref_hunks": n_ref_hunks,
            "gen_hunks": n_gen_hunks,
        },
    }


def _generate(records: list[dict], model_id: str) -> dict[str, str]:
    """Live base-model generation for each canary. Costs API spend."""
    from agents.patcher.adapter import AnthropicAdapter
    adapter = AnthropicAdapter(model_id)
    out: dict[str, str] = {}
    for rec in records:
        msgs = rec["messages"]
        system = next(m["content"] for m in msgs if m["role"] == "system")
        user = next(m["content"] for m in msgs if m["role"] == "user")
        resp = adapter.invoke(system_prompt=system, user_content=user,
                              sampling={"temperature": 0.0, "max_tokens": 4096})
        out[rec["provenance"]["cve_id"]] = _clean_generated(resp.text)
    return out


def _aggregate(scored: list[dict], model_id: str | None) -> dict:
    n = len(scored)
    fmt = sum(1 for s in scored if s["format_pass"])
    struct = sum(1 for s in scored if s["structural_pass"])

    def _check_rates(tier: str) -> dict:
        keys = scored[0][tier].keys() if scored else []
        return {k: round(sum(1 for s in scored if s[tier][k]) / n, 3) for k in keys} if n else {}

    return {
        "scope": "authoring-pilot",
        "schema_version": "1.0.0",
        "model_id": model_id,
        "n": n,
        "format_pass_rate": round(fmt / n, 3) if n else 0.0,
        "structural_pass_rate": round(struct / n, 3) if n else 0.0,
        # Tier 2 is deferred behind --behavioral; surface it as unrun, never as 0.
        "behavioral_pass_rate": None,
        "behavioral_attempted_n": 0,
        "tier0_check_rates": _check_rates("tier0"),
        "tier1_check_rates": _check_rates("tier1"),
        "per_candidate": scored,
    }


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--canary", type=Path, required=True,
                    help="held-out canary JSONL (from `trace export authoring --split-manifest`)")
    ap.add_argument("--responses", type=Path, default=None,
                    help="pre-generated responses JSONL: {cve_id, generated} per line")
    ap.add_argument("--generate", action="store_true",
                    help="generate live from --model instead of reading --responses")
    ap.add_argument("--model", default=None, help="model id for --generate")
    ap.add_argument("--out", type=Path, required=True, help="report JSON path")
    ap.add_argument("--save-responses", type=Path, default=None,
                    help="when generating, also write the raw responses here")
    args = ap.parse_args(argv)

    if not args.canary.is_file():
        print(f"error: canary file not found: {args.canary}", file=sys.stderr)
        return 2
    records = [json.loads(l) for l in args.canary.read_text().splitlines() if l.strip()]
    if not records:
        print("error: canary file is empty (no held-out examples to score)", file=sys.stderr)
        return 2

    if args.generate:
        if not args.model:
            print("error: --generate requires --model", file=sys.stderr)
            return 2
        gen = _generate(records, args.model)
        model_id = args.model
        if args.save_responses:
            args.save_responses.write_text(
                "\n".join(json.dumps({"cve_id": k, "generated": v}) for k, v in gen.items()) + "\n")
    elif args.responses:
        gen = {r["cve_id"]: r["generated"]
               for r in (json.loads(l) for l in args.responses.read_text().splitlines() if l.strip())}
        model_id = args.model  # optional label for which model produced the responses
    else:
        print("error: pass --responses or --generate", file=sys.stderr)
        return 2

    scored = []
    for rec in records:
        cve = rec["provenance"]["cve_id"]
        if cve not in gen:
            print(f"warning: no candidate for {cve}; scoring as empty", file=sys.stderr)
        scored.append(score_candidate(gen.get(cve, ""), rec))

    report = _aggregate(scored, model_id)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(report, indent=2) + "\n")
    print(f"format_pass_rate={report['format_pass_rate']} "
          f"structural_pass_rate={report['structural_pass_rate']} "
          f"(n={report['n']}, model={model_id}) -> {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
