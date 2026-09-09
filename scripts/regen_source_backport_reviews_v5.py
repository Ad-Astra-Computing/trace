"""Re-run the Reviewer with reviewer.v5.md on source-backport train-split bundles.

This script regenerates review.md files for the 19 train-split source-backport
positive bundles so they contain the required `## Patch comparison` section
introduced in reviewer.v5.md.

Usage:
    set -a && source .env && set +a
    python3 scripts/regen_source_backport_reviews_v5.py [--dry-run] [--bundle CVE-ID]

The script reads the same inputs the CLI executor reads, calls run_reviewer
with reviewer.v5.md, and atomically writes the new review.md.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

REVIEWER_MODEL = "claude-sonnet-4-5-20250929"
PROMPT_PATH = ROOT / "prompts" / "reviewer.v5.md"
TRACES_EXAMPLE = ROOT / "traces" / "example"

TRAIN_MAX = 75
DEV_MAX = 90

SPLIT_OVERRIDES: dict[str, str] = {
    # From reviewer-v1.2.json overrides
    "sqlite": "train",
}


def _family_key(bundle_dir: Path) -> str:
    """Derive family key from upstream-ref.json attr or bundle dir name."""
    uref_path = bundle_dir / "upstream-ref.json"
    try:
        uref = json.loads(uref_path.read_text())
        attr = uref.get("attr", "")
        if attr:
            return attr
    except Exception:
        pass
    name = bundle_dir.name
    return name.rsplit("--", 1)[0] if "--" in name else name


def _split_for_bundle(bundle_dir: Path) -> str:
    family = _family_key(bundle_dir)
    if family in SPLIT_OVERRIDES:
        return SPLIT_OVERRIDES[family]
    bucket = int(hashlib.sha256(family.encode()).hexdigest(), 16) % 100
    if bucket < TRAIN_MAX:
        return "train"
    if bucket < DEV_MAX:
        return "dev"
    return "test"


def _model_id_family(model_id: str) -> str:
    """Return fine-grained family label matching what export.py expects."""
    m = model_id.lower()
    if "claude-opus" in m or "opus" in m:
        return "anthropic-opus"
    if "claude-sonnet" in m or "sonnet" in m:
        return "anthropic-sonnet"
    if "claude-haiku" in m or "haiku" in m:
        return "anthropic-haiku"
    if "claude" in m or "anthropic" in m:
        return "anthropic"
    if "gpt" in m or "openai" in m:
        return "openai"
    return "unknown"


def _read_patcher_role_from_replay(bundle_dir: Path) -> dict | None:
    """Return the last patcher invocation dict from replay.json, or None."""
    replay_path = bundle_dir / "replay.json"
    if not replay_path.is_file():
        return None
    try:
        replay = json.loads(replay_path.read_text())
        for role in replay.get("roles", []):
            if role.get("role") != "patcher":
                continue
            invs = role.get("invocations", [])
            if invs:
                return invs[-1]
    except Exception:
        return None
    return None


def _read_patcher_family_from_replay(bundle_dir: Path) -> str | None:
    inv = _read_patcher_role_from_replay(bundle_dir)
    if inv is None:
        return None
    model = inv.get("model") or {}
    # Always derive fine-grained family from model_id; replay stores coarse "anthropic".
    model_id = model.get("model_id", "")
    if model_id:
        return _model_id_family(model_id)
    family = model.get("family") or ""
    if family and family not in ("", "unknown", "deterministic-no-model"):
        return family
    return None


def _read_patcher_model_id_from_replay(bundle_dir: Path) -> str | None:
    inv = _read_patcher_role_from_replay(bundle_dir)
    if inv is None:
        return None
    return (inv.get("model") or {}).get("model_id") or None


def build_inputs(bundle_dir: Path, model_id: str) -> dict:
    """Build the inputs dict for run_reviewer."""
    finding = json.loads((bundle_dir / "finding.json").read_text())
    upstream_ref = json.loads((bundle_dir / "upstream-ref.json").read_text())
    impact = json.loads((bundle_dir / "impact.json").read_text())
    maintainers = json.loads((bundle_dir / "maintainers.json").read_text())
    package_source = (bundle_dir / "package.nix").read_text()
    patch_diff = (bundle_dir / "patch.diff").read_text()
    patch_rationale_md = (bundle_dir / "patch-rationale.md").read_text()

    patcher_family = _read_patcher_family_from_replay(bundle_dir)
    patcher_model_id = _read_patcher_model_id_from_replay(bundle_dir) or "<unknown>"
    requested_family = _model_id_family(model_id)
    rule_honored_expected = bool(
        patcher_family and requested_family and patcher_family != requested_family
    )

    inputs: dict = {
        "finding": finding,
        "upstream_ref": upstream_ref,
        "impact": impact,
        "maintainers": maintainers,
        "package_source": package_source,
        "package_source_path": "package.nix",
        "patch_diff": patch_diff,
        "patch_rationale_md": patch_rationale_md,
        "model_attestation_context": {
            "reviewer_model_id": model_id,
            "reviewer_family": requested_family,
            "patcher_model_id": patcher_model_id,
            "patcher_family": patcher_family or "<unknown>",
            "cross_family_rule_honored_expected": rule_honored_expected,
        },
    }

    patch_strategy = (upstream_ref.get("eligibility") or {}).get("patch_strategy", "")
    if patch_strategy == "source-backport":
        fix_patch_path = bundle_dir / "upstream-fix.patch"
        if not fix_patch_path.is_file():
            raise FileNotFoundError(f"upstream-fix.patch missing in {bundle_dir}")
        inputs["patch_strategy"] = "source-backport"
        inputs["upstream_fix_patch"] = fix_patch_path.read_text()

    return inputs


def _atomic_write(path: Path, content: bytes) -> None:
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=".tmp-")
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(content)
        os.replace(tmp, path)
    except Exception:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def regen_bundle(
    bundle_dir: Path, model_id: str, dry_run: bool, force: bool = False
) -> bool:
    from agents.patcher import AnthropicAdapter
    from agents.reviewer import ReviewerOutputMalformed, run_reviewer

    # Skip if review.md already has ## Patch comparison (unless --force)
    review_path = bundle_dir / "review.md"
    if not force and review_path.is_file():
        existing = review_path.read_text()
        if "## Patch comparison" in existing:
            print(f"  skip {bundle_dir.name} (already has PC section)")
            return True

    print(f"  processing {bundle_dir.name}...", end="", flush=True)

    try:
        inputs = build_inputs(bundle_dir, model_id)
    except FileNotFoundError as e:
        print(f" SKIP ({e})")
        return False

    if dry_run:
        print(" DRY-RUN (inputs ok)")
        return True

    try:
        adapter = AnthropicAdapter(model_id=model_id)
        result = run_reviewer(
            inputs=inputs,
            adapter=adapter,
            prompt_path=PROMPT_PATH,
        )
    except ReviewerOutputMalformed as e:
        print(f" FAIL (malformed: {e})")
        return False
    except Exception as e:
        print(f" FAIL ({e})")
        return False

    if result.kind == "review":
        review_md = result.parsed.raw_review_md or ""
        review_bytes = review_md.encode("utf-8")
        if review_bytes and not review_bytes.endswith(b"\n"):
            review_bytes += b"\n"

        # Verify the new review has ## Patch comparison
        has_pc = b"## Patch comparison" in review_bytes
        _atomic_write(bundle_dir / "review.md", review_bytes)
        verdict = result.parsed.verdict or "?"
        pc_marker = "has_pc" if has_pc else "NO_PC"
        print(f" OK verdict={verdict} {pc_marker}")
        return True
    else:
        print(f" REFUSAL (rule={result.parsed.refusal_rule})")
        return False


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--dry-run", action="store_true", help="build inputs but don't call API"
    )
    parser.add_argument(
        "--bundle", help="filter to a single bundle name (partial match)"
    )
    parser.add_argument(
        "--split",
        default="train",
        choices=["train", "dev", "test", "all"],
        help="which split to process (default: train)",
    )
    parser.add_argument("--model", default=REVIEWER_MODEL, help="reviewer model id")
    parser.add_argument(
        "--force",
        action="store_true",
        help="re-run even if review.md already has ## Patch comparison",
    )
    args = parser.parse_args()

    if not PROMPT_PATH.is_file():
        print(f"error: prompt not found: {PROMPT_PATH}", file=sys.stderr)
        return 1

    print(f"Reviewer prompt: {PROMPT_PATH.name}")
    print(f"Reviewer model:  {args.model}")
    print(f"Split filter:    {args.split}")
    print()

    bundles = sorted(TRACES_EXAMPLE.iterdir())
    source_backport_train: list[Path] = []

    for bd in bundles:
        if not bd.is_dir():
            continue
        uref_path = bd / "upstream-ref.json"
        if not uref_path.is_file():
            continue
        try:
            uref = json.loads(uref_path.read_text())
        except Exception:
            continue
        strategy = (uref.get("eligibility") or {}).get("patch_strategy", "")
        if strategy != "source-backport":
            continue
        split = _split_for_bundle(bd)
        if args.split != "all" and split != args.split:
            continue
        if args.bundle and args.bundle not in bd.name:
            continue
        source_backport_train.append(bd)

    print(f"Found {len(source_backport_train)} source-backport bundles to process:")
    for bd in source_backport_train:
        print(f"  {bd.name}")
    print()

    ok = 0
    fail = 0
    for bd in source_backport_train:
        success = regen_bundle(bd, args.model, args.dry_run, force=args.force)
        if success:
            ok += 1
        else:
            fail += 1

    print()
    print(f"Done: {ok} ok, {fail} failed/skipped")
    return 0 if fail == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
