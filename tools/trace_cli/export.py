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
        "--reviewer-prompt",
        type=Path,
        default=Path("prompts/reviewer.v2.md"),
        help="reviewer system prompt to embed (default prompts/reviewer.v2.md)",
    )
    rv.add_argument("--format", choices=["human", "json"], default="human")
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
    mac = _model_attestation_context(models)
    if mac:
        inputs["model_attestation_context"] = mac
    try:
        return assemble_user_content(inputs)
    except ValueError:
        return None


def _example_for_bundle(
    bundle_dir: Path, system_prompt: str,
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

    split = _split_for(attr)
    provenance = {
        "bundle_id": bundle_id,
        "cve_id": cve_id,
        "attr_path": attr,
        "split_family": _normalize_attr(attr),
        "kind": kind,
        "auto_merge_evidence_path": bundle.get("auto_merge_evidence_path"),
        "has_cert_build": (bundle_dir / "build.json").is_file(),
        "steward_signed": bool((bundle.get("signed_manifest") or {}).get("rekor_log_index")),
        "reviewer_invocation_id": models.get("reviewer_invocation_id"),
        "reviewer_model_id": models.get("reviewer_model_id"),
        "reviewer_prompt_sha": models.get("reviewer_prompt_sha"),
        "patcher_model_id": models.get("patcher_model_id"),
    }

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


def run(args: argparse.Namespace) -> int:
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

    # Enumerate real-CVE bundles deterministically; skip synthetic CVE-0000-*.
    bundle_dirs = sorted(
        d for d in traces_root.glob("CVE-*")
        if d.is_dir() and not d.name.startswith("CVE-0000")
    )

    examples: list[dict[str, Any]] = []
    statuses: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()

    for bd in bundle_dirs:
        ex, status = _example_for_bundle(bd, system_prompt)
        if ex is not None:
            dedup_key = (status["cve_id"], status["attr_path"])
            if dedup_key in seen:
                status["eligibility_for_training"] = False
                status["exclusion_reason"] = "duplicate (cve_id, attr_path)"
                statuses.append(status)
                continue
            seen.add(dedup_key)
            examples.append(ex)
        statuses.append(status)

    # Deterministic order: by split then bundle_id.
    examples.sort(key=lambda e: (e["split"], e["provenance"]["bundle_id"] or ""))

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
            for sp in ("train", "dev", "test")
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
