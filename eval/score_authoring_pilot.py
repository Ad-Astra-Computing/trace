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
import hashlib
import json
import re
import shutil
import sys
import tempfile
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
from eval.backport_validation import _VERSION_BUMP_RE, validate_backport

# `_VERSION_BUMP_RE` catches nix-style `version =`/`rev =`/`sha256 =`; add the
# Python `__version__ = "x"` / `VERSION = "x"` shape (the pyjwt release-bump tell).
_PY_VERSION_RE = re.compile(
    r"""^\+(?!\+\+).*\b_{0,2}version_{0,2}\s*=\s*['"]""", re.IGNORECASE
)

# Fraction of the reference's distinctive fix-symbols a candidate must reproduce.
# Not 1.0: a semantically-equivalent fix may name things differently; we want
# "carries the load-bearing guard tokens", not "verbatim identifier match".
_FIX_SYMBOL_THRESHOLD = 0.5
# How close (in shared source lines) a generated hunk must sit to the reference
# to count as hitting the same region — content-based, so it is robust to the
# model numbering hunks against the shown window rather than the full file.
_MIN_REGION_ANCHORS = 1


def _has_version_bump(diff: str) -> bool:
    return any(
        _VERSION_BUMP_RE.match(ln) or _PY_VERSION_RE.match(ln)
        for ln in diff.splitlines()
    )


def _target_files(diff: str) -> list[str]:
    """Every file the diff targets (incl. non-source), from `+++`/`---` headers.
    Deletions name the file on the `---` side; everything else on `+++`. Used to
    detect unrelated/test files BEFORE the source-only filter drops them."""
    files: list[str] = []
    lines = diff.splitlines()
    for i, ln in enumerate(lines):
        if ln.startswith("+++ "):
            new = ln[4:].strip()
            old = (
                lines[i - 1][4:].strip()
                if i and lines[i - 1].startswith("--- ")
                else ""
            )
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
    m = re.search(
        r"# Vulnerable source \([^)]*\)\n```[a-zA-Z0-9]*\n(.*?)\n```",
        user_content,
        re.S,
    )
    return m.group(1) if m else ""


def _clean_generated(text: str) -> str:
    """Pull the diff out of a model response: prefer a fenced ```diff block, else
    take from the first diff header onward (the prompt asks for the diff only, but
    models still occasionally wrap or preface it)."""
    m = re.search(r"```(?:diff|patch)?\s*\n(.*?)```", text, re.S)
    body = m.group(1) if m else text
    if "diff --git" in body:
        body = body[body.find("diff --git") :]
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
        "no_test_or_doc_files": bool(targeted)
        and not any(bp._NON_SOURCE_RE.search(f) for f in targeted),
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
    gen_changed = "\n".join(
        l
        for l in generated.splitlines()
        if l[:1] in ("+", "-") and not l.startswith(("+++", "---"))
    )
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
        for f in ref_files
    )

    tier1 = {
        # Exactly the reference's source files: covers every required file AND adds
        # no unrelated source file (subset-only would pass an incomplete fix).
        "same_impl_file": bool(gen_files) and gen_files == ref_files,
        "grounds_in_prefix": bool(gen_parsed)
        and bool(pre_fix)
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


# ── Tier 2: Behavioral (build + reproducer) ───────────────────────────────────
# Behind --behavioral; needs a Linux nix host + nixpkgs checkout (like
# bundle-linux-cert.yml). The candidate is injected by rewriting ONLY the embedded
# source-patch body inside the bundle's patch.diff — preserving the package path,
# the `patches = [ ./CVE.patch ]` wiring, and the reproducer — then run_builder +
# validate_backport's BUILD-derived subset decides. `semantic-match-upstream-fix`
# (reviewer accept on the ORIGINAL bundle) is excluded; `unpatched-reproducer-fires`
# is a PRECONDITION, not a pass/fail (codex 2026-06-25).

# Candidate-specific behavioral success: the authored patch applies AND closes the
# bug. `unpatched-reproducer-fires` is the precondition checked separately.
_BEHAVIORAL_GATE = ("patch-applies", "backported-reproducer-clean")
_PRECONDITION = "unpatched-reproducer-fires"
_EMBEDDED_PATCH_HDR = re.compile(r"^diff --git a/(\S+\.patch) b/\1$")


def _strip_git_path_prefixes(candidate: str) -> str:
    """Strip a/ and b/ path prefixes from --- and +++ lines of a git-format diff.
    Used when the target package applies patches with -p0 (no prefix stripping by
    patch(1)), so the embedded patch body must use bare filenames. Leaves all other
    lines (diff --git headers, hunk headers, context lines) untouched."""
    out = []
    for ln in candidate.split("\n"):
        if ln.startswith("--- a/"):
            ln = "--- " + ln[6:]
        elif ln.startswith("+++ b/"):
            ln = "+++ " + ln[6:]
        out.append(ln)
    return "\n".join(out)


def _bundle_strip_level(bundle_dir: Path) -> int:
    """Infer the patch strip level for the bundle.
    Returns 0 for -p0 packages, 1 (the nixpkgs default) otherwise.

    Checks both reproducer.nix and package.nix so that packages whose
    patchFlags live only in the derivation (not echoed in the reproducer)
    are still detected correctly."""
    _P0_PATTERNS = ("patch -p0", 'patchFlags = [ "-p0"', 'patchFlags = ["-p0"')
    for fname in ("reproducer.nix", "package.nix"):
        f = bundle_dir / fname
        if f.is_file():
            t = f.read_text()
            if any(pat in t for pat in _P0_PATTERNS):
                return 0
    return 1


def _rewrite_embedded_patch(
    patch_diff: str, candidate: str, *, strip_level: int = 1
) -> str | None:
    """Replace the embedded source-patch body (the `+`-prefixed hunk of the
    `new file mode ... CVE-*.patch` section) inside a source-backport `patch.diff`
    with the generated candidate diff. Returns the rewritten tree-diff, or None
    when `patch.diff` does not create EXACTLY ONE `.patch` file (the v1 contract —
    a multi-patch bundle is ambiguous and refused rather than guessed).

    strip_level=0: strip a/b/ prefixes from ---/+++ lines before embedding (for
    packages whose patchFlags include -p0, e.g. bzip2). strip_level=1 (default):
    leave the candidate diff as-is."""
    if strip_level == 0:
        candidate = _strip_git_path_prefixes(candidate)
    lines = patch_diff.splitlines()
    starts = [
        i
        for i, ln in enumerate(lines)
        if _EMBEDDED_PATCH_HDR.match(ln)
        and i + 1 < len(lines)
        and lines[i + 1].startswith("new file")
    ]
    if len(starts) != 1:
        return None
    start = starts[0]
    hh = next(
        (
            j
            for j in range(start, min(start + 8, len(lines)))
            if lines[j].startswith("@@")
        ),
        None,
    )
    if hh is None:
        return None
    body_end = hh + 1
    while body_end < len(lines) and (
        lines[body_end].startswith("+")
        or lines[body_end] == r"\ No newline at end of file"
    ):
        body_end += 1
    cand = candidate.rstrip("\n").split("\n")
    rewritten = (
        lines[:hh]
        + [f"@@ -0,0 +1,{len(cand)} @@"]
        + [f"+{c}" for c in cand]
        + lines[body_end:]
    )
    return "\n".join(rewritten) + "\n"


def _reproducer_kind(bundle_dir: Path) -> str:
    """The bundle's declared reproducer kind from expect.json. `text-inspection-proxy`
    means the reproducer derives its signal by grepping patch/source TEXT for a fix
    token rather than building + executing the package — so it cannot behaviorally
    validate an AUTHORED candidate (a wrong-but-token-matching fix would pass, a
    correct-but-reworded one would fail). Default `behavioral`."""
    e = _load(bundle_dir / "expect.json") or {}
    return e.get("reproducer_kind", "behavioral")


def _detect_proxy_reproducer(bundle_dir: Path) -> bool:
    """Auto-detect a text-inspection-proxy reproducer (helper for verifying the
    explicit expect.json marker, NOT the authority). Tell: a shell loop greps the
    realized patch paths (`for p in $patches` … `grep … "$p"`) for a fix token."""
    rp = bundle_dir / "reproducer.nix"
    if not rp.is_file():
        return False
    t = rp.read_text()
    return bool(
        re.search(r"for\s+p\s+in\s+\$patches", t)
        and re.search(r'grep\s+-q\S*\s+\S.*"\$p"', t)
    )


def _bundle_for(traces_root: Path, record: dict) -> Path | None:
    """The bundle dir for a canary record. Disambiguates by the record's
    provenance `bundle_id` when multiple dirs share a CVE (the corpus has both
    original and `*-backport` bundles for some CVEs) so the candidate is injected
    into the INTENDED bundle, not just the first sorted match (codex 2026-06-25)."""
    cve = record["provenance"]["cve_id"]
    want_id = record["provenance"].get("bundle_id")
    candidates = sorted(traces_root.glob(f"{cve}--*"))
    if want_id:
        for c in candidates:
            b = _load(c / "bundle.json")
            if b and b.get("bundle_id") == want_id:
                return c
    return candidates[0] if candidates else None


def _load(p: Path) -> dict | None:
    try:
        return json.loads(p.read_text())
    except (OSError, json.JSONDecodeError):
        return None


def score_behavioral(
    generated: str, record: dict, *, traces_root: Path, build_fn
) -> dict:
    """Tier 2 behavioral verdict for one candidate. `build_fn(candidate_bundle_dir)`
    returns the build.json dict (production: run_builder + LocalNixBuildRunner;
    tests inject a synthetic build.json). Pure orchestration otherwise."""
    cve = record["provenance"]["cve_id"]
    out = {"cve_id": cve, "behavioral_status": None, "behavioral_pass": False}
    bundle = _bundle_for(traces_root, record)
    if bundle is None:
        out["behavioral_status"] = "bundle_not_found"
        return out
    # Text-inspection-proxy reproducers grep patch/source text for a fix token and
    # cannot behaviorally validate an authored candidate — exempt them (excluded
    # from the behavioral denominator, NOT a cert failure). codex 2026-06-26.
    if _reproducer_kind(bundle) == "text-inspection-proxy":
        out["behavioral_status"] = "exempt_proxy_reproducer"
        return out
    pd = bundle / "patch.diff"
    if not pd.is_file():
        out["behavioral_status"] = "no_patch_diff"
        return out
    strip_level = _bundle_strip_level(bundle)
    rewritten = _rewrite_embedded_patch(
        pd.read_text(), generated, strip_level=strip_level
    )
    if rewritten is None:
        out["behavioral_status"] = "no_unique_embedded_patch"
        return out
    out["candidate_sha256"] = hashlib.sha256(generated.encode()).hexdigest()[:16]
    out["rewritten_patch_sha256"] = hashlib.sha256(rewritten.encode()).hexdigest()[:16]
    with tempfile.TemporaryDirectory(prefix="trace-author-behav-") as td:
        cdir = Path(td) / bundle.name
        shutil.copytree(bundle, cdir)
        (cdir / "patch.diff").write_text(rewritten)
        (cdir / "build.json").unlink(missing_ok=True)  # force a fresh build
        build_json = build_fn(cdir)
        (cdir / "build.json").write_text(json.dumps(build_json))
        bv = validate_backport(cdir)
    asserts = {a.name: a.passed for a in bv.assertions}
    out["assertions"] = asserts
    if not asserts.get(_PRECONDITION, False):
        # The bundle reproducer can't even fire unpatched, so patched-clean is
        # meaningless — invalid/skipped, NOT a candidate failure.
        out["behavioral_status"] = "precondition_failed"
        return out
    out["behavioral_status"] = "ran"
    out["behavioral_pass"] = all(asserts.get(k, False) for k in _BEHAVIORAL_GATE)
    return out


def _make_build_fn(nixpkgs: Path, timeout: int):
    """Production build_fn: run the real Builder against a nixpkgs checkout. Lazy
    imports so the module loads without a Linux nix host.

    `run_builder(apply_patch=True)` applies the candidate patch INTO the checkout,
    so each candidate gets a fresh detached `git worktree` (shares the object store,
    own working tree) — otherwise the second candidate would apply against a tree
    already dirtied by the first, making the pass rate order-dependent (codex P1
    2026-06-25). The shared `--nixpkgs` checkout is never mutated."""
    import subprocess
    from agents.builder import LocalNixBuildRunner, run_builder

    def build_fn(bundle_dir: Path) -> dict:
        with tempfile.TemporaryDirectory(prefix="trace-nixpkgs-wt-") as wt:
            wtree = Path(wt) / "tree"
            add = subprocess.run(
                [
                    "git",
                    "-C",
                    str(nixpkgs),
                    "worktree",
                    "add",
                    "--detach",
                    str(wtree),
                    "HEAD",
                ],
                capture_output=True,
                text=True,
            )
            if add.returncode != 0:
                raise RuntimeError(
                    f"git worktree add failed: {add.stderr.strip()[:200]}"
                )
            try:
                res = run_builder(
                    bundle_dir=bundle_dir,
                    build_runner=LocalNixBuildRunner(),
                    nixpkgs_checkout=wtree,
                    apply_patch=True,
                    timeout_seconds_per_build=timeout,
                )
                return res.build_json
            finally:
                subprocess.run(
                    [
                        "git",
                        "-C",
                        str(nixpkgs),
                        "worktree",
                        "remove",
                        "--force",
                        str(wtree),
                    ],
                    capture_output=True,
                )

    return build_fn


def _generate(records: list[dict], model_id: str) -> dict[str, str]:
    """Live base-model generation for each canary. Costs API spend."""
    from agents.patcher.adapter import AnthropicAdapter

    adapter = AnthropicAdapter(model_id)
    out: dict[str, str] = {}
    for rec in records:
        msgs = rec["messages"]
        system = next(m["content"] for m in msgs if m["role"] == "system")
        user = next(m["content"] for m in msgs if m["role"] == "user")
        resp = adapter.invoke(
            system_prompt=system,
            user_content=user,
            sampling={"temperature": 0.0, "max_tokens": 4096},
        )
        out[rec["provenance"]["cve_id"]] = _clean_generated(resp.text)
    return out


def _aggregate(scored: list[dict], model_id: str | None) -> dict:
    n = len(scored)
    fmt = sum(1 for s in scored if s["format_pass"])
    struct = sum(1 for s in scored if s["structural_pass"])

    def _check_rates(tier: str) -> dict:
        keys = scored[0][tier].keys() if scored else []
        return (
            {k: round(sum(1 for s in scored if s[tier][k]) / n, 3) for k in keys}
            if n
            else {}
        )

    # Tier 2 (if any candidate carries a behavioral block). `attempted` = candidates
    # whose behavioral run actually ran (status=="ran"); precondition_failed and
    # the various skip statuses are NOT in the denominator (codex 2026-06-25).
    behav = [s["behavioral"] for s in scored if s.get("behavioral")]
    ran = [b for b in behav if b.get("behavioral_status") == "ran"]
    behavioral_pass_rate = (
        round(sum(1 for b in ran if b["behavioral_pass"]) / len(ran), 3)
        if ran
        else None
    )
    behavioral_statuses: dict[str, int] = {}
    for b in behav:
        st = b.get("behavioral_status") or "none"
        behavioral_statuses[st] = behavioral_statuses.get(st, 0) + 1
    behavioral_pass_n = sum(1 for b in ran if b["behavioral_pass"])
    proxy_exempt_n = behavioral_statuses.get("exempt_proxy_reproducer", 0)
    precondition_failed_n = behavioral_statuses.get("precondition_failed", 0)

    return {
        "scope": "authoring-pilot",
        "schema_version": "1.0.0",
        "model_id": model_id,
        "n": n,
        "format_pass_rate": round(fmt / n, 3) if n else 0.0,
        "structural_pass_rate": round(struct / n, 3) if n else 0.0,
        # Tier 2: null when --behavioral was not run (never reported as 0).
        "behavioral_pass_rate": behavioral_pass_rate,
        "behavioral_attempted_n": len(ran),
        "behavioral_pass_n": behavioral_pass_n,
        "proxy_exempt_n": proxy_exempt_n,
        "precondition_failed_n": precondition_failed_n,
        "behavioral_statuses": behavioral_statuses or None,
        "tier0_check_rates": _check_rates("tier0"),
        "tier1_check_rates": _check_rates("tier1"),
        "per_candidate": scored,
    }


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    ap.add_argument(
        "--canary",
        type=Path,
        required=True,
        help="held-out canary JSONL (from `trace export authoring --split-manifest`)",
    )
    ap.add_argument(
        "--responses",
        type=Path,
        default=None,
        help="pre-generated responses JSONL: {cve_id, generated} per line",
    )
    ap.add_argument(
        "--generate",
        action="store_true",
        help="generate live from --model instead of reading --responses",
    )
    ap.add_argument("--model", default=None, help="model id for --generate")
    ap.add_argument("--out", type=Path, required=True, help="report JSON path")
    ap.add_argument(
        "--save-responses",
        type=Path,
        default=None,
        help="when generating, also write the raw responses here",
    )
    ap.add_argument(
        "--behavioral",
        action="store_true",
        help="Tier 2: build the authored fix + run the reproducer "
        "(needs a Linux nix host + --nixpkgs). Runs only on "
        "format-passing candidates.",
    )
    ap.add_argument(
        "--nixpkgs",
        type=Path,
        default=None,
        help="nixpkgs checkout at the bundle's rev (required for --behavioral)",
    )
    ap.add_argument(
        "--traces-root",
        type=Path,
        default=Path("traces/example"),
        help="root of CVE-* bundles (for --behavioral patch injection)",
    )
    ap.add_argument(
        "--build-timeout",
        type=int,
        default=1800,
        help="per-build timeout seconds for --behavioral (default 1800)",
    )
    args = ap.parse_args(argv)

    if not args.canary.is_file():
        print(f"error: canary file not found: {args.canary}", file=sys.stderr)
        return 2
    records = [json.loads(l) for l in args.canary.read_text().splitlines() if l.strip()]
    if not records:
        print(
            "error: canary file is empty (no held-out examples to score)",
            file=sys.stderr,
        )
        return 2

    if args.generate:
        if not args.model:
            print("error: --generate requires --model", file=sys.stderr)
            return 2
        gen = _generate(records, args.model)
        model_id = args.model
        if args.save_responses:
            args.save_responses.write_text(
                "\n".join(
                    json.dumps({"cve_id": k, "generated": v}) for k, v in gen.items()
                )
                + "\n"
            )
    elif args.responses:
        gen = {
            r["cve_id"]: r["generated"]
            for r in (
                json.loads(l)
                for l in args.responses.read_text().splitlines()
                if l.strip()
            )
        }
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

    if args.behavioral:
        if args.nixpkgs is None:
            print("error: --behavioral requires --nixpkgs <checkout>", file=sys.stderr)
            return 2
        build_fn = _make_build_fn(args.nixpkgs, args.build_timeout)
        by_cve = {rec["provenance"]["cve_id"]: rec for rec in records}
        for s in scored:
            # Tier 2 gates on Tier 0 (format/apply) ONLY — a structurally-divergent
            # but behaviorally-correct fix must still get a build.
            if not s["format_pass"]:
                s["behavioral"] = {
                    "cve_id": s["cve_id"],
                    "behavioral_status": "skipped_format_fail",
                    "behavioral_pass": False,
                }
                continue
            rec = by_cve[s["cve_id"]]
            s["behavioral"] = score_behavioral(
                gen.get(s["cve_id"], ""),
                rec,
                traces_root=args.traces_root,
                build_fn=build_fn,
            )

    report = _aggregate(scored, model_id)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(report, indent=2) + "\n")
    msg = (
        f"format_pass_rate={report['format_pass_rate']} "
        f"structural_pass_rate={report['structural_pass_rate']}"
    )
    if report["behavioral_pass_rate"] is not None:
        msg += (
            f" behavioral_pass_rate={report['behavioral_pass_rate']} "
            f"(attempted={report['behavioral_attempted_n']})"
        )
    print(f"{msg} (n={report['n']}, model={model_id}) -> {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
