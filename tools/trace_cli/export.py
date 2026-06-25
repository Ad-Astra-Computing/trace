"""`trace export reviewer`: export the corpus into Reviewer-first training data.

Reads every real-CVE bundle under `traces/example/CVE-*/` and emits chat-format
JSONL training examples for a Reviewer fine-tune (the binary accept/reject task
is the easiest starting point; see the fine-tuning plan).

Design (codex peer 2026-06-10):
  * **Reviewer-only** for v1. Patcher export is a separate slice (different
    leakage + target semantics).
  * **Enumerate all** bundles; only mark `eligibility_for_training: true` for
    those that carry a real reviewer target (`review.md` with a parseable
    verdict, or `review-refusal.json`). Metadata-only negatives are NOT turned
    into SFT examples here.
  * **Split by package family** (normalized `affected[0].attr_path`), not by
    bundle_id, so the same package never crosses train/dev/test (prevents
    memorization leakage).
  * **Dedupe** by (cve_id, attr).
  * **Provenance** (bundle_id, cve_id, attr, reviewer invocation_id, prompt_sha,
    cert run, kind) on every example, as metadata (not in the chat messages).
  * **Redaction**: strip API-key-shaped strings and absolute /home/<user> paths.
  * **Deterministic**: stable ordering + hash-based split; no timestamps/random
    in the output. Re-running on the same corpus yields byte-identical JSONL.

Output (default --out exports/reviewer/):
  * `reviewer.jsonl`      — one record per eligible example (chat format)
  * `manifest.json`       — counts, split sizes, label balance, excluded bundles
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
from pathlib import Path
from typing import Any

from agents.reviewer.parser import VALID_VERDICTS

SCHEMA_VERSION = "1.0.0"

# Split thresholds on hash(attr) % 100. Same attr family → same split always.
_TRAIN_MAX = 70  # [0, 70)   -> train
_DEV_MAX = 85    # [70, 85)  -> dev ; [85, 100) -> test

# Redaction patterns: provider API keys and absolute home paths.
# Covers Anthropic (sk-ant-...), OpenAI legacy + project keys (sk-..., sk-proj-...),
# GitHub tokens (ghp_/gho_/ghs_/ghr_/github_pat_), AWS access key ids (AKIA...),
# and Google API keys (AIza...). The sk- branch allows hyphens/underscores so
# hyphenated prefixes like sk-proj- are caught.
_SECRET_RE = re.compile(
    r"\b("
    r"sk-[A-Za-z0-9_-]{16,}"
    r"|gh[posru]_[A-Za-z0-9]{20,}"
    r"|github_pat_[A-Za-z0-9_]{20,}"
    r"|AKIA[A-Z0-9]{12,}"
    r"|AIza[A-Za-z0-9_-]{20,}"
    r")\b"
)
_HOME_PATH_RE = re.compile(r"/home/[A-Za-z0-9_.\-]+")


def add_parser(subs: argparse._SubParsersAction) -> argparse.ArgumentParser:
    p = subs.add_parser(
        "export",
        help="export the corpus into training-data JSONL (reviewer-first)",
        description=(
            "Reads every real-CVE bundle under traces/example/CVE-*/ and emits "
            "chat-format JSONL training examples. v1 supports the reviewer scope "
            "only. Deterministic: same corpus -> byte-identical output."
        ),
    )
    p_subs = p.add_subparsers(dest="export_scope", required=True)
    rv = p_subs.add_parser("reviewer", help="export reviewer accept/reject examples")
    rv.add_argument(
        "--out",
        type=Path,
        default=Path("exports/reviewer"),
        help="output directory (created if missing; default exports/reviewer)",
    )
    rv.add_argument(
        "--traces-root",
        type=Path,
        default=Path("traces/example"),
        help="root directory of CVE-* bundles (default traces/example)",
    )
    rv.add_argument(
        "--negatives-root",
        type=Path,
        default=None,
        help=(
            "root directory of mutation-based negative bundles. Default: the "
            "'negatives' dir sibling to --traces-root (so a custom corpus uses "
            "its own negatives, not the repo's)."
        ),
    )
    rv.add_argument(
        "--reorg-positives-root",
        type=Path,
        default=None,
        help=(
            "root directory of structure-reorganized POSITIVE bundles (carry "
            "reorg.json, accept verdict). Default: the 'positives-reorg' dir "
            "sibling to --traces-root. Teaches CTW-equivalence under reordering."
        ),
    )
    rv.add_argument(
        "--reviewer-prompt",
        type=Path,
        default=Path("prompts/reviewer.v2.md"),
        help="reviewer system prompt to embed (default prompts/reviewer.v2.md)",
    )
    rv.add_argument("--format", choices=["human", "json"], default="human")
    rv.add_argument(
        "--split-manifest",
        type=Path,
        default=None,
        help=(
            "versioned split-override manifest (e.g. data/splits/reviewer-v1.1.json). "
            "family_key overrides in the manifest take precedence over the hash-based "
            "assignment. Overrides are recorded in manifest.json. v1.1+ only."
        ),
    )

    au = p_subs.add_parser(
        "authoring",
        help="export AUTHORING examples: (CVE + pre-fix source) -> the source fix",
    )
    au.add_argument("--out", type=Path, default=Path("exports/authoring"),
                    help="output directory (default exports/authoring)")
    au.add_argument("--traces-root", type=Path, default=Path("traces/example"),
                    help="root of CVE-* bundles (default traces/example)")
    au.add_argument("--format", choices=["human", "json"], default="human")
    return p


def _redact(text: str) -> str:
    text = _SECRET_RE.sub("<REDACTED-SECRET>", text)
    text = _HOME_PATH_RE.sub("/home/<user>", text)
    return text


def _normalize_attr(attr: str) -> str:
    """Family key for splitting: strip version digits from EVERY dot-component so
    versioned variants collapse to one family, whether the version is in the
    leaf (php84 -> php, openssl_3 -> openssl) or in a package-set prefix
    (python312Packages.django / python313Packages.django -> pythonPackages.django,
    python3Packages.django_4 -> pythonPackages.django). Keeps same-family variants
    in the same train/dev/test split (no leakage)."""
    comps = []
    for comp in attr.strip().split("."):
        c = re.sub(r"\d+", "", comp)          # drop version digit runs
        c = re.sub(r"[_-]+$", "", c)          # tidy trailing separators
        c = re.sub(r"[_-]{2,}", "_", c)        # collapse doubled separators
        comps.append(c or comp)
    norm = ".".join(comps)
    return norm or attr


def _split_for(attr: str) -> str:
    family = _normalize_attr(attr)
    bucket = int(hashlib.sha256(family.encode("utf-8")).hexdigest(), 16) % 100
    if bucket < _TRAIN_MAX:
        return "train"
    if bucket < _DEV_MAX:
        return "dev"
    return "test"


def _load_json(path: Path) -> dict[str, Any] | None:
    try:
        return json.loads(path.read_text())
    except (OSError, json.JSONDecodeError):
        return None


def _parse_verdict(review_md: str) -> str | None:
    """Extract the verdict line from review.md ('## Verdict\\n<verdict>')."""
    m = re.search(r"##\s*Verdict\s*\n+\s*([a-zA-Z-]+)", review_md)
    return m.group(1).strip().lower() if m else None


def _model_id_to_family(model_id: str | None) -> str | None:
    """Coarse model_id -> family label. Mirrors the executor's check; kept in
    sync with agents/scorers/reviewer_scorers.py._model_id_to_family."""
    if not model_id:
        return None
    if model_id.startswith("claude-opus"):
        return "anthropic-opus"
    if model_id.startswith("claude-sonnet"):
        return "anthropic-sonnet"
    if model_id.startswith("claude-haiku"):
        return "anthropic-haiku"
    if model_id.startswith("claude-"):
        return "anthropic-other"
    if model_id.startswith("gpt-") or model_id.startswith("o1") or model_id.startswith("o3"):
        return "openai-gpt"
    return None


def _invocation_models(bundle_dir: Path) -> dict[str, str | None]:
    """Pull reviewer + patcher model ids / invocation ids from replay.json."""
    replay = _load_json(bundle_dir / "replay.json") or {}
    out: dict[str, str | None] = {}
    for role in replay.get("roles", []):
        rname = role.get("role")
        if rname in ("reviewer", "patcher"):
            # replay appends invocations on rerun; the latest reflects the
            # review.md/refusal currently on disk (matches scorer logic).
            inv = (role.get("invocations") or [{}])[-1]
            out[f"{rname}_invocation_id"] = inv.get("invocation_id")
            out[f"{rname}_model_id"] = (inv.get("model") or {}).get("model_id")
            if rname == "reviewer":
                out["reviewer_prompt_sha"] = (inv.get("prompt") or {}).get("sha256")
    return out


def _model_attestation_context(models: dict[str, str | None]) -> dict[str, Any] | None:
    """Reconstruct the load-bearing v2 attestation block the executor fed the
    Reviewer, from the recorded reviewer/patcher model ids."""
    rev_mid = models.get("reviewer_model_id")
    pat_mid = models.get("patcher_model_id")
    rev_fam = _model_id_to_family(rev_mid)
    pat_fam = _model_id_to_family(pat_mid)
    if not (rev_mid and pat_mid and rev_fam and pat_fam):
        return None
    return {
        "reviewer_model_id": rev_mid,
        "reviewer_family": rev_fam,
        "patcher_model_id": pat_mid,
        "patcher_family": pat_fam,
        "cross_family_rule_honored_expected": rev_fam != pat_fam,
    }


def _attestation_mismatch(cf: Any, mac: dict[str, Any]) -> str | None:
    """Return a description if the parsed cross-family attestation contradicts
    the reconstructed attestation context (families AND rule_honored), else None."""
    if cf.reviewer_family != mac["reviewer_family"]:
        return f"reviewer_family {cf.reviewer_family!r} != reconstructed {mac['reviewer_family']!r}"
    if cf.patcher_family_observed != mac["patcher_family"]:
        return f"patcher_family_observed {cf.patcher_family_observed!r} != reconstructed {mac['patcher_family']!r}"
    if bool(cf.rule_honored) != bool(mac["cross_family_rule_honored_expected"]):
        return (
            f"rule_honored {cf.rule_honored!r} != reconstructed expected "
            f"{mac['cross_family_rule_honored_expected']!r}"
        )
    return None


def _build_user_turn(bundle_dir: Path) -> str | None:
    """Reproduce the exact Reviewer user-message via the canonical assembler
    (includes the original package.nix + the model attestation block) so the
    exported assistant target is grounded in the exported input."""
    from agents.reviewer.runner import assemble_user_content

    finding = _load_json(bundle_dir / "finding.json")
    upstream = _load_json(bundle_dir / "upstream-ref.json")
    impact = _load_json(bundle_dir / "impact.json")
    maintainers = _load_json(bundle_dir / "maintainers.json")
    pkg = bundle_dir / "package.nix"
    patch = bundle_dir / "patch.diff"
    rationale = bundle_dir / "patch-rationale.md"
    if None in (finding, upstream, impact, maintainers) or not (
        pkg.is_file() and patch.is_file() and rationale.is_file()
    ):
        return None

    models = _invocation_models(bundle_dir)
    inputs: dict[str, Any] = {
        "finding": finding,
        "upstream_ref": upstream,
        "impact": impact,
        "maintainers": maintainers,
        "package_source": pkg.read_text(),
        "package_source_path": "package.nix",
        "patch_diff": patch.read_text(),
        "patch_rationale_md": rationale.read_text(),
    }
    # Source-backport bundles need upstream-fix.patch as ground truth so the
    # exported user message matches what the live Reviewer receives (execute.py
    # adds patch_strategy + upstream_fix_patch when patch_strategy=source-backport).
    # Without this the training data and gate pilot lack the artifact the PC section
    # is supposed to compare against, causing the model to hallucinate both sides.
    patch_strategy = (upstream.get("eligibility") or {}).get("patch_strategy")
    if patch_strategy == "source-backport":
        fix_patch = bundle_dir / "upstream-fix.patch"
        if fix_patch.is_file():
            inputs["patch_strategy"] = "source-backport"
            inputs["upstream_fix_patch"] = fix_patch.read_text()
    mac = _model_attestation_context(models)
    if mac:
        inputs["model_attestation_context"] = mac
    try:
        return assemble_user_content(inputs)
    except ValueError:
        return None


def _example_for_bundle(
    bundle_dir: Path, system_prompt: str,
    split_overrides: dict[str, str] | None = None,
) -> tuple[dict[str, Any] | None, dict[str, Any]]:
    """Return (example_or_None, status). status always carries bundle_id/cve/attr
    + eligibility_for_training + exclusion_reason (when ineligible)."""
    bundle = _load_json(bundle_dir / "bundle.json") or {}
    finding = _load_json(bundle_dir / "finding.json") or {}
    cve_id = bundle.get("cve_id") or finding.get("cve_id") or bundle_dir.name
    bundle_id = bundle.get("bundle_id")
    affected = finding.get("affected") or [{}]
    attr = affected[0].get("attr_path") or ""
    kind = bundle.get("kind")

    status = {
        "bundle_dir": bundle_dir.name,
        "cve_id": cve_id,
        "attr_path": attr,
        "bundle_id": bundle_id,
        "kind": kind,
        "eligibility_for_training": False,
        "exclusion_reason": None,
    }

    review_md = bundle_dir / "review.md"
    refusal = bundle_dir / "review-refusal.json"
    assistant: str | None = None
    label: str | None = None

    # Assistant targets must match the exact output contract the reviewer prompt
    # + agents/reviewer/parser.py enforce, so a model trained on this JSONL emits
    # outputs the runner accepts: review bodies wrapped in BEGIN/END review.md,
    # refusals as BEGIN/END refusal blocks. Verdicts must be in VALID_VERDICTS.
    from agents.reviewer.parser import parse_reviewer_output

    models = _invocation_models(bundle_dir)
    mac = _model_attestation_context(models)

    if review_md.is_file():
        text = review_md.read_text().strip()
        wrapped = f"=== BEGIN review.md ===\n{text}\n=== END review.md ==="
        # Only export targets that fully satisfy the reviewer output contract,
        # so a model trained on this JSONL emits runner-acceptable output.
        try:
            parsed = parse_reviewer_output(wrapped)
        except Exception as exc:  # parser raises a typed error; keep the reason
            status["exclusion_reason"] = f"review.md fails reviewer parser contract: {str(exc)[:120]}"
            return None, status
        verdict = parsed.verdict
        if verdict not in VALID_VERDICTS:
            status["exclusion_reason"] = f"unsupported verdict {verdict!r} (not in {VALID_VERDICTS})"
            return None, status
        # Grounding integrity: if we reconstruct an attestation block into the
        # user turn, the review.md's recorded attestation MUST agree with it
        # (families AND rule_honored), or the example is internally
        # contradictory (e.g. older bundles with legacy family labels).
        if mac is not None and parsed.cross_family is not None:
            mismatch = _attestation_mismatch(parsed.cross_family, mac)
            if mismatch:
                status["exclusion_reason"] = f"attestation mismatch (review.md vs replay): {mismatch}"
                return None, status
        assistant = wrapped
        label = "positive" if verdict == "accept" else "negative"
    elif refusal.is_file():
        ref = _load_json(refusal) or {}
        rule = ref.get("rule")
        reason = ref.get("reason")
        if rule is None or not reason:
            status["exclusion_reason"] = "review-refusal.json missing rule/reason"
            return None, status
        one_line = " ".join(str(reason).split())
        candidate = f"=== BEGIN refusal ===\nrule: {rule}\nreason: {one_line}\n=== END refusal ==="
        # Validate the constructed refusal against the same contract review
        # targets must satisfy (e.g. rule must be in the reviewer's allowed range).
        try:
            parse_reviewer_output(candidate)
        except Exception as exc:
            status["exclusion_reason"] = f"refusal fails reviewer parser contract: {str(exc)[:120]}"
            return None, status
        assistant = candidate
        label = "negative"
    else:
        status["exclusion_reason"] = "no reviewer target (review.md / review-refusal.json)"
        return None, status

    if not attr:
        status["exclusion_reason"] = "no affected attr_path in finding.json"
        return None, status

    user_turn = _build_user_turn(bundle_dir)
    if not user_turn or not user_turn.strip():
        status["exclusion_reason"] = "could not assemble reviewer input (missing artifact)"
        return None, status

    family = _normalize_attr(attr)
    override_split = (split_overrides or {}).get(family)
    split = override_split if override_split else _split_for(attr)
    mutation = _load_json(bundle_dir / "mutation.json")
    reorg = _load_json(bundle_dir / "reorg.json")
    provenance = {
        "bundle_id": bundle_id,
        "cve_id": cve_id,
        "attr_path": attr,
        "split_family": family,
        "split_override": override_split,
        "kind": kind,
        "auto_merge_evidence_path": bundle.get("auto_merge_evidence_path"),
        "has_cert_build": (bundle_dir / "build.json").is_file(),
        "steward_signed": bool((bundle.get("signed_manifest") or {}).get("rekor_log_index")),
        "reviewer_invocation_id": models.get("reviewer_invocation_id"),
        "reviewer_model_id": models.get("reviewer_model_id"),
        "reviewer_prompt_sha": models.get("reviewer_prompt_sha"),
        "patcher_model_id": models.get("patcher_model_id"),
        "negative_source": (mutation or {}).get("negative_source"),
        "mutation_type": (mutation or {}).get("mutation_type"),
        "positive_source": (reorg or {}).get("positive_source"),
        "reorg_type": (reorg or {}).get("reorg_type"),
        "base_bundle_id": (mutation or {}).get("base_bundle_id") or (reorg or {}).get("base_bundle_id"),
    }
    status["mutation_type"] = (mutation or {}).get("mutation_type")
    status["reorg_type"] = (reorg or {}).get("reorg_type")

    example = {
        "schema_version": SCHEMA_VERSION,
        "scope": "reviewer",
        "messages": [
            {"role": "system", "content": _redact(system_prompt.rstrip())},
            {"role": "user", "content": _redact(user_turn)},
            {"role": "assistant", "content": _redact(assistant)},
        ],
        "label": label,
        "split": split,
        "eligibility_for_training": True,
        "provenance": provenance,
    }
    status["eligibility_for_training"] = True
    status["label"] = label
    status["split"] = split
    return example, status


# ── authoring export: (CVE + pre-fix source) -> the source fix ───────────────
#
# Teaches a model to AUTHOR the fix from the vulnerability, NOT transcribe a
# supplied one. The cert-green bundle is the ANSWER KEY: label = the validated
# upstream source fix. Leakage scrubbed per docs/AUTHORING_TRAINING.md.

_AUTHORING_SYSTEM = (
    "You are a security engineer fixing a CVE in C/C++. You are given the "
    "vulnerability (symptom only) and the current vulnerable source. Author the "
    "MINIMAL fix as a unified diff against the shown file. Change as few lines as "
    "possible; do not rewrite. Output only the diff."
)
_REMEDIATION_RE = re.compile(
    r"\b(fixed (in|by|upstream)|the fix|patched? (in|by)|adds? a (bounds|null|length) check|"
    r"resolved by|remediat\w+|commit [0-9a-f]{7,}|backport|shipped in)\b", re.IGNORECASE)
# Anchored hex-only: injection-safe (no option chars) at any abbreviated length.
_SAFE_REV_RE = re.compile(r"[0-9a-f]{7,40}\Z")


def _fix_symbols(fix_diff: str) -> set[str]:
    """Symbols a CVE summary must NOT name, or it leaks where/how the fix lands:

      * distinctive IDENTIFIERS on any changed (+/-) line (e.g. RS_PT_SOCKS5,
        BZ_MAX_HANDLED_BLOCKS, slotat). Distinctive = has '_', is ALL_CAPS,
        mixedCase, or len>=6 (skips generic short words like 'if'/'int'). Union of
        both sides: a removed gate is as much a tell as an added guard.
      * numeric literals that CHANGED between the removed and added lines (a moved
        bound, e.g. `> 10` -> `> 8`). Symmetric difference, not union: a constant
        present on both sides (an unchanged buffer size the vuln legitimately
        names, e.g. proxychains's 255) is a vulnerability fact, not a fix tell."""
    syms: set[str] = set()
    minus_nums: set[str] = set()
    plus_nums: set[str] = set()
    for ln in fix_diff.splitlines():
        side = ln[:1]
        if side not in ("+", "-") or ln.startswith(("+++", "---")):
            continue
        body = ln[1:]
        for tok in re.findall(r"[A-Za-z_][A-Za-z0-9_]{2,}", body):
            if "_" in tok or tok.isupper() or tok != tok.lower() or len(tok) >= 6:
                syms.add(tok)
        # multi-digit only: a bare `1`/`0` (off-by-one delta) is too generic to
        # scrub on and the touched identifier usually already carries the tell.
        nums = {n for n in re.findall(r"\b\d+\b", body) if len(n) >= 2}
        (plus_nums if side == "+" else minus_nums).update(nums)
    syms |= (minus_nums ^ plus_nums)  # only the constants the fix actually moved
    return syms


def _mentions(text: str, sym: str) -> bool:
    """Does `text` name fix-symbol `sym`? Word-boundary for numerics (so `50` does
    not match inside `1.0.8`/`5000`); substring for identifiers (distinctive enough
    that a substring hit is a real mention, never a false positive)."""
    if sym.isdigit():
        return re.search(rf"(?<!\d){re.escape(sym)}(?!\d)", text) is not None
    return sym in text


def _scrub_summary(summary: str, fix_diff: str) -> str:
    """Drop any sentence that (a) names the remediation, or (b) mentions a symbol
    the fix changes — leaving the vulnerability (trigger / what's wrong) only."""
    syms = _fix_symbols(fix_diff)
    out = []
    for s in re.split(r"(?<=[.])\s+", summary):
        if _REMEDIATION_RE.search(s):
            continue
        if any(_mentions(s, sym) for sym in syms):
            continue
        out.append(s)
    return " ".join(out).strip()


def _strip_remediation(summary: str) -> str:  # kept for back-compat / tests
    return " ".join(s for s in re.split(r"(?<=[.])\s+", summary)
                    if not _REMEDIATION_RE.search(s)).strip()


def _pick_authoring_input_file(
    churn: dict[str, int], parent_existing: set[str] | None = None
) -> str | None:
    """Pick the input-window file: the changed SOURCE file with the most churn
    (added+removed lines) — i.e. the vulnerable implementation, not an incidental
    public header or small companion edit. Without this, a multi-file fix commit
    whose first-listed path is a header (e.g. libxml2 CVE-2026-0989 listing
    `include/libxml/relaxng.h` before `relaxng.c`) would window the input on the
    header, so the pair's input lacks the vulnerable code the label patches.

    `parent_existing` (when given) is the set of paths that EXIST in the parent
    commit (everything except newly-Added files — Modified AND Deleted both
    qualify). The input is a PRE-fix parent window, so a newly-added file (which
    can have the highest churn) is not a valid candidate — `git show parent:<new>`
    would fail and skip the whole pair. We pick the max-churn parent-existing file;
    only if none qualify do we fall back to the overall max. Ties break
    alphabetically for deterministic, reproducible caches."""
    pool = {p: c for p, c in churn.items() if parent_existing is None or p in parent_existing}
    if not pool:
        pool = churn
    if not pool:
        return None
    return max(sorted(pool), key=lambda p: pool[p])


def _file_diff_starts(fix_diff: str, fpath: str) -> list[int]:
    """The `@@ -N` old-file line starts for `fpath`'s section of a multi-file
    unified diff, so the input window centres on THIS file's hunks rather than
    another file's line numbers."""
    starts: list[int] = []
    in_file = False
    for ln in fix_diff.splitlines():
        if ln.startswith("diff --git "):
            m = re.match(r"diff --git a/(.+?) b/(.+)$", ln)
            in_file = bool(m) and (m.group(1) == fpath or m.group(2) == fpath)
        elif in_file and ln.startswith("@@"):
            mm = re.match(r"^@@ -(\d+)", ln)
            if mm:
                starts.append(int(mm.group(1)))
    return starts


def _authoring_pair(bundle_dir: Path) -> dict[str, Any] | None:
    """Build (or load cached) the authoring training pair for a source-backport
    bundle: pre-fix source window (input) + the upstream commit's source diff
    (label). Cached to <bundle>/authoring-example.json for deterministic, offline
    re-export (the git blobs are sha-pinned, so the content is reproducible)."""
    cache = bundle_dir / "authoring-example.json"
    if cache.is_file():
        return json.loads(cache.read_text())

    import subprocess, tempfile
    from tools.trace_cli import backport_patch as bp

    ur = _load_json(bundle_dir / "upstream-ref.json") or {}
    finding = _load_json(bundle_dir / "finding.json") or {}
    commits = ur.get("upstream_fix_commits") or []
    if not commits or ur.get("eligibility", {}).get("patch_strategy") != "source-backport":
        return None
    repo_url, sha = commits[0]["repo_url"], commits[0]["commit_sha"]
    try:
        bp._validate_repo_url(repo_url)
    except bp.BackportError:
        return None
    # sha is feed-sourced (upstream-ref.json); it reaches `git fetch origin <sha>`
    # as a bare arg, where a value like `--upload-pack=...` would be option
    # injection. The injection-safety comes from the anchored hex-only charset
    # (no `-`/`=`/space can appear), not the length — so allow git's abbreviated
    # revs (some bundles store 10-12 char shas) while still refusing anything that
    # isn't pure hex. (backport_patch's _SAFE_REV_RE is 40-only because its revs
    # come from a full-sha resolver path; authoring reads hand-authored bundles.)
    if not _SAFE_REV_RE.match(sha):
        return None

    with tempfile.TemporaryDirectory(prefix="trace-author-export-") as td:
        repo = Path(td) / "src"
        repo.mkdir()
        env = {**os.environ, **bp._HARDENED_ENV}

        def git(*a):
            return subprocess.run(["git", "-C", str(repo), *a], capture_output=True, text=True, env=env)
        git("init", "-q")
        git("remote", "add", "origin", repo_url)
        if git("fetch", "--depth", "2", "origin", sha).returncode != 0:
            git("fetch", "origin")
        parent = git("rev-parse", "-q", "--verify", f"{sha}^").stdout.strip()
        if not parent:
            return None
        # label = the upstream commit's SOURCE diff (exclude tests/docs/changelog).
        ns = git("show", "--numstat", "--format=", "--no-color", sha)
        churn: dict[str, int] = {}
        for ln in ns.stdout.splitlines():
            parts = ln.split("\t")
            if len(parts) == 3 and parts[0] != "-" and not bp._NON_SOURCE_RE.search(parts[2]):
                churn[parts[2]] = int(parts[0]) + int(parts[1])
        src_paths = list(churn)
        if not src_paths:
            return None
        fix_diff = git("show", "--no-color", "--format=", sha, "--", *src_paths).stdout
        fix_diff = bp._extract_diff(fix_diff) if "diff --git" in fix_diff else fix_diff
        # input = the highest-churn affected SOURCE file that EXISTS in the parent
        # (the vulnerable impl), windowed around THIS file's hunks. Exclude only
        # NEWLY-ADDED (status A) files — their parent blob doesn't exist, so they
        # can't be windowed and would skip the pair. Modified AND deleted files
        # both exist in the parent (a fix that DELETES the vulnerable file is a
        # valid input), so they stay candidates.
        added = git("show", "--numstat", "--format=", "--no-color", "--diff-filter=A", sha)
        added_paths = {p.split("\t")[2] for p in added.stdout.splitlines() if len(p.split("\t")) == 3}
        parent_existing = {p for p in churn if p not in added_paths}
        fpath = _pick_authoring_input_file(churn, parent_existing) or src_paths[0]
        starts = _file_diff_starts(fix_diff, fpath) or [1]
        blob = subprocess.run(["git", "-C", str(repo), "show", f"{parent}:{fpath}"],
                              capture_output=True, text=True, env=env)
        if blob.returncode != 0:
            return None
        lines = blob.stdout.splitlines()
        lo, hi = max(0, min(starts) - 20), min(len(lines), max(starts) + 20)
        pre_fix = "\n".join(lines[lo:hi])

    pair = {
        "cve_id": finding.get("cve_id"),
        "attr_path": (finding.get("affected") or [{}])[0].get("attr_path"),
        "vuln_raw": finding.get("summary", ""),  # scrubbed against fix_diff at export time
        "file": fpath,
        "pre_fix_source": pre_fix,
        "fix_diff": fix_diff.strip(),
        "fix_commit": {"repo_url": repo_url, "commit_sha": sha},
    }
    cache.write_text(json.dumps(pair, indent=2) + "\n")
    return pair


def _run_authoring(args: argparse.Namespace) -> int:
    traces_root: Path = args.traces_root
    out_dir: Path = args.out
    if not traces_root.is_dir():
        print(f"error: traces root not found: {traces_root}")
        return 2
    out_dir.mkdir(parents=True, exist_ok=True)

    examples, excluded, diagnostics = [], [], []
    for bd in sorted(traces_root.glob("CVE-*")):
        if not (bd / "upstream-ref.json").is_file():
            continue
        pair = _authoring_pair(bd)
        if pair is None:
            continue
        if not (pair["vuln_raw"] and pair["pre_fix_source"] and pair["fix_diff"]):
            excluded.append({"bundle": bd.name, "reason": "incomplete pair"})
            continue
        # Scrub the CVE summary against the ACTUAL fix: drop remediation language AND
        # any sentence naming a symbol the fix changes (else the summary leaks where
        # the fix lands — e.g. proxychains's RS_PT_SOCKS5, graphite2's slotat).
        vuln = _scrub_summary(pair["vuln_raw"], pair["fix_diff"])
        # Leakage guard: nothing the fix touches may survive into the input.
        fix_syms = _fix_symbols(pair["fix_diff"])
        if not vuln:
            excluded.append({"bundle": bd.name, "reason": "summary empty after fix-symbol scrub"})
            continue
        if _REMEDIATION_RE.search(vuln) or any(_mentions(vuln, s) for s in fix_syms):
            excluded.append({"bundle": bd.name, "reason": "fix language survived scrub"})
            continue
        # A fix with 0 extractable symbols (e.g. whitespace-/comment-only, or a
        # leak class the heuristic can't name) passes the gate silently — flag it
        # so "nothing to scrub" is visibly distinct from "scrubbed clean".
        diagnostics.append({"bundle": bd.name, "cve_id": pair["cve_id"],
                            "fix_symbols": len(fix_syms), "low_signal": not fix_syms})
        bundle = _load_json(bd / "bundle.json") or {}
        attr = pair["attr_path"] or bd.name
        user = (f"# CVE\n{pair['cve_id']}: {vuln}\n\n"
                f"# Vulnerable source ({pair['file']})\n```c\n{pair['pre_fix_source']}\n```")
        examples.append({
            "messages": [
                {"role": "system", "content": _redact(_AUTHORING_SYSTEM)},
                {"role": "user", "content": _redact(user)},
                {"role": "assistant", "content": _redact(pair["fix_diff"])},
            ],
            "task": "author-from-vuln",
            "split": _split_for(attr),
            "provenance": {
                "bundle_id": bundle.get("bundle_id"),
                "cve_id": pair["cve_id"], "attr_path": attr,
                "split_family": _normalize_attr(attr),
                "fix_commit": pair["fix_commit"]["commit_sha"],
                "steward_signed": bool((bundle.get("signed_manifest") or {}).get("rekor_log_index")),
                "kind": bundle.get("kind"),
            },
        })

    examples.sort(key=lambda e: (e["split"], e["provenance"]["cve_id"] or ""))
    jsonl = out_dir / "authoring.jsonl"
    with jsonl.open("w") as fh:
        for ex in examples:
            fh.write(json.dumps(ex, sort_keys=True) + "\n")
    splits: dict[str, int] = {}
    for e in examples:
        splits[e["split"]] = splits.get(e["split"], 0) + 1
    manifest = {
        "scope": "authoring", "schema_version": "1.0.0",
        "eligible_examples": len(examples), "splits": splits,
        "families": sorted({e["provenance"]["split_family"] for e in examples}),
        "excluded": excluded,
        "diagnostics": diagnostics,
        "low_signal_bundles": [d["bundle"] for d in diagnostics if d["low_signal"]],
        "note": "label = validated upstream source fix; input = CVE (vuln-only) + pre-fix source. "
                "Leakage-partitioned: these CVEs are the author-from-vuln task; exclude them from "
                "any transcription/backport-package export to avoid answer-key leakage. "
                "low_signal_bundles produced 0 scrub symbols — review their inputs by hand.",
    }
    (out_dir / "manifest.json").write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n")
    if args.format == "json":
        print(json.dumps(manifest, indent=2, sort_keys=True))
    else:
        print(f"authoring export -> {jsonl}")
        print(f"  examples: {len(examples)}  splits: {splits}  excluded: {len(excluded)}")
    return 0


def run(args: argparse.Namespace) -> int:
    if getattr(args, "export_scope", "reviewer") == "authoring":
        return _run_authoring(args)
    traces_root: Path = args.traces_root
    out_dir: Path = args.out
    prompt_path: Path = args.reviewer_prompt

    if not traces_root.is_dir():
        print(f"error: traces root not found: {traces_root}")
        return 2
    if not prompt_path.is_file():
        print(f"error: reviewer prompt not found: {prompt_path}")
        return 2

    system_prompt = prompt_path.read_text()

    # Load optional versioned split-override manifest (e.g. data/splits/reviewer-v1.1.json).
    split_overrides: dict[str, str] = {}
    split_manifest_meta: dict | None = None
    manifest_path = getattr(args, "split_manifest", None)
    if manifest_path is not None:
        if not manifest_path.is_file():
            print(f"error: split manifest not found: {manifest_path}")
            return 2
        sm = json.loads(manifest_path.read_text())
        split_overrides = {k: v["split"] for k, v in sm.get("overrides", {}).items()}
        split_manifest_meta = {"name": sm.get("name"), "path": str(manifest_path),
                               "overrides": list(split_overrides.keys())}

    # Enumerate real-CVE positives (traces/example, skip synthetic CVE-0000-*) +
    # mutation-based negatives (traces/negatives). Deterministic order.
    negatives_root: Path = args.negatives_root
    bundle_dirs = sorted(
        d for d in traces_root.glob("CVE-*")
        if d.is_dir() and not d.name.startswith("CVE-0000")
    )
    negative_dirs: set[Path] = set()
    if negatives_root is None:
        negatives_root = traces_root.parent / "negatives"
    if negatives_root.is_dir():
        nd = sorted(d for d in negatives_root.glob("CVE-*") if d.is_dir())
        negative_dirs = set(nd)
        bundle_dirs += nd

    # Structure-reorganized positives (carry reorg.json, accept verdict).
    reorg_root: Path = args.reorg_positives_root
    reorg_dirs: set[Path] = set()
    if reorg_root is None:
        reorg_root = traces_root.parent / "positives-reorg"
    if reorg_root.is_dir():
        rd = sorted(d for d in reorg_root.glob("CVE-*") if d.is_dir())
        reorg_dirs = set(rd)
        bundle_dirs += rd

    examples: list[dict[str, Any]] = []
    statuses: list[dict[str, Any]] = []
    seen: set[tuple[str, str, str | None]] = set()

    for bd in bundle_dirs:
        ex, status = _example_for_bundle(bd, system_prompt, split_overrides)
        # Negatives-root hygiene: a bundle under traces/negatives MUST carry
        # mutation provenance AND have produced a negative reviewer verdict.
        # Otherwise it would train a deliberately-defective patch as a positive
        # (e.g. a mutation the Reviewer mistakenly accepted, or a stray bundle).
        if ex is not None and bd in negative_dirs:
            if ex["provenance"].get("negative_source") != "mutation" or ex["label"] != "negative":
                status["eligibility_for_training"] = False
                status["exclusion_reason"] = (
                    f"negatives-root bundle is not a kept mutation reject "
                    f"(negative_source={ex['provenance'].get('negative_source')}, label={ex['label']})"
                )
                statuses.append(status)
                continue
        # Reorg-positives-root hygiene: a bundle here MUST carry reorg provenance
        # AND have produced an accept (label positive). A reorg the Reviewer
        # REJECTED is a correct fix wrongly rejected (the very failure we train
        # against) — it must NOT enter the corpus as a negative; exclude entirely.
        if ex is not None and bd in reorg_dirs:
            if ex["provenance"].get("positive_source") != "reorg" or ex["label"] != "positive":
                status["eligibility_for_training"] = False
                status["exclusion_reason"] = (
                    f"reorg-positives-root bundle is not a kept reorg accept "
                    f"(positive_source={ex['provenance'].get('positive_source')}, label={ex['label']})"
                )
                statuses.append(status)
                continue
        # Defensive: a positives-root bundle must NOT carry mutation provenance.
        if ex is not None and bd not in negative_dirs and bd not in reorg_dirs \
                and ex["provenance"].get("negative_source"):
            status["eligibility_for_training"] = False
            status["exclusion_reason"] = "mutation provenance in positives root"
            statuses.append(status)
            continue
        if ex is not None:
            # Canary split: excluded from training entirely (held-out for gate pilot only).
            if ex["split"] == "canary":
                status["eligibility_for_training"] = False
                status["exclusion_reason"] = "canary split (held-out for gate pilot only)"
                statuses.append(status)
                continue
            # Include mutation_type AND reorg_type so a mutated negative or a
            # reorganized positive is NOT deduped against its base positive
            # (same cve+attr, legitimately distinct example).
            dedup_key = (status["cve_id"], status["attr_path"],
                         status.get("mutation_type"), status.get("reorg_type"))
            if dedup_key in seen:
                status["eligibility_for_training"] = False
                status["exclusion_reason"] = "duplicate (cve_id, attr_path, mutation_type)"
                statuses.append(status)
                continue
            seen.add(dedup_key)
            examples.append(ex)
        statuses.append(status)

    # Deterministic order: by split, label, then bundle_id + mutation_type.
    examples.sort(key=lambda e: (
        e["split"], e["label"], e["provenance"]["bundle_id"] or "",
        e["provenance"].get("mutation_type") or "",
        e["provenance"].get("reorg_type") or "",
    ))

    out_dir.mkdir(parents=True, exist_ok=True)
    jsonl_path = out_dir / "reviewer.jsonl"
    with jsonl_path.open("w") as fh:
        for ex in examples:
            fh.write(json.dumps(ex, sort_keys=True) + "\n")

    def _count(pred) -> int:
        return sum(1 for e in examples if pred(e))

    manifest = {
        "schema_version": SCHEMA_VERSION,
        "scope": "reviewer",
        "reviewer_prompt": _redact(str(prompt_path)),
        "split_manifest": split_manifest_meta,
        "total_bundles_enumerated": len(bundle_dirs),
        "eligible_examples": len(examples),
        "excluded": [
            {
                "bundle_dir": s["bundle_dir"],
                "cve_id": s["cve_id"],
                "attr_path": s["attr_path"],
                # exclusion_reason can echo raw artifact text from a parser
                # exception; redact it like every other exported field.
                "exclusion_reason": _redact(s["exclusion_reason"]) if s["exclusion_reason"] else s["exclusion_reason"],
            }
            for s in statuses if not s["eligibility_for_training"]
        ],
        "splits": {
            sp: _count(lambda e, sp=sp: e["split"] == sp)
            for sp in ("train", "dev", "test", "canary")
        },
        "labels": {
            lb: _count(lambda e, lb=lb: e["label"] == lb)
            for lb in ("positive", "negative")
        },
        "families": sorted({e["provenance"]["split_family"] for e in examples}),
        "leakage_check_ok": _leakage_ok(examples),
    }
    (out_dir / "manifest.json").write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n")

    if args.format == "json":
        print(json.dumps(manifest, indent=2, sort_keys=True))
    else:
        print(f"reviewer export complete -> {jsonl_path}")
        print(f"  bundles enumerated: {manifest['total_bundles_enumerated']}")
        print(f"  eligible examples:  {manifest['eligible_examples']}")
        print(f"  splits:  {manifest['splits']}")
        print(f"  labels:  {manifest['labels']}")
        print(f"  families: {len(manifest['families'])}")
        print(f"  excluded: {len(manifest['excluded'])}")
        print(f"  no-family-leakage-across-splits: {manifest['leakage_check_ok']}")
    return 0


def _leakage_ok(examples: list[dict[str, Any]]) -> bool:
    """Verify no split_family appears in more than one split."""
    fam_split: dict[str, str] = {}
    for e in examples:
        fam = e["provenance"]["split_family"]
        if fam in fam_split and fam_split[fam] != e["split"]:
            return False
        fam_split[fam] = e["split"]
    return True
