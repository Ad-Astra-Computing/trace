"""`trace mutate reviewer-negative`: mint a Reviewer NEGATIVE candidate.

The corpus has plenty of reviewer-positive (accept) examples but zero
negatives; the N=50 Reviewer-LoRA pilot needs ~20-30. Per codex peer
(<redacted-session-id>, 2026-06-10) the training-valid way to get them is *mutation-based*:

  1. copy a known-good bundle,
  2. apply ONE deliberate, realistic defect to the Patcher output,
  3. run the REAL Reviewer (separate `trace replay` step),
  4. keep only cases where the Reviewer genuinely rejects with evidence,
  5. label provenance `negative_source: mutation` + the mutation type.

The target stays a real Reviewer output (not a synthetic rejection), so the
example is training-valid. This module does steps 1-2 + the provenance marker,
deterministically and offline; the live Reviewer run is a normal `trace replay
--execute --role reviewer` against the mutated bundle dir, and the exporter
(`trace export reviewer`) reads `traces/negatives/` and carries the mutation
provenance.

Mutation types (defect injected into patch.diff, all realistic Patcher errors):
  * wrong-src-hash        — the new hash is corrupted (doesn't match upstream-ref)
  * version-without-hash  — version bumped but hash left at the pre-patch value
  * hash-from-other-bundle— the new hash is a real hash lifted from another bundle
  * patch-touches-unrelated-file — the diff edits a file other than the affected pkg
"""

from __future__ import annotations

import argparse
import json
import re
import shutil
from pathlib import Path
from typing import Any

MUTATION_TYPES = (
    "wrong-src-hash",
    "version-without-hash",
    "hash-from-other-bundle",
    "patch-touches-unrelated-file",
)

# A syntactically-valid but deliberately-wrong SRI hash (base64 of 32 zero bytes).
_DECOY_SRI = "sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="

_HASH_LINE_RE = re.compile(r'^([+\-]?\s*(?:hash|sha256|sha512)\s*=\s*")([^"]+)(".*)$')


def add_parser(subs: argparse._SubParsersAction) -> argparse.ArgumentParser:
    p = subs.add_parser(
        "mutate",
        help="mint a Reviewer negative candidate by injecting a defect into a bundle",
        description=(
            "Copies a known-good bundle, injects one realistic Patcher defect, and "
            "writes a mutation.json marker. Run `trace replay --execute --role "
            "reviewer` against the output to get the real reject target."
        ),
    )
    p_subs = p.add_subparsers(dest="mutate_scope", required=True)
    rn = p_subs.add_parser("reviewer-negative", help="inject a defect for a reviewer negative")
    rn.add_argument("--base-dir", type=Path, required=True, help="known-good source bundle dir")
    rn.add_argument("--mutation", choices=MUTATION_TYPES, required=True)
    rn.add_argument("--out-dir", type=Path, required=True, help="destination bundle dir (created)")
    rn.add_argument("--decoy-hash", default=None, help="hash to use for hash-from-other-bundle")
    rn.add_argument("--format", choices=["human", "json"], default="human")
    return p


def _patched_hash_lines(diff: str) -> list[int]:
    """Indices of '+...hash = "..."' lines in patch.diff."""
    out = []
    for i, line in enumerate(diff.splitlines()):
        if line.startswith("+") and _HASH_LINE_RE.match(line):
            out.append(i)
    return out


def _apply_mutation(out_dir: Path, mutation: str, decoy_hash: str | None) -> dict[str, Any]:
    """Mutate the staged bundle in-place; return details for the marker."""
    patch_path = out_dir / "patch.diff"
    diff = patch_path.read_text()
    lines = diff.splitlines()
    details: dict[str, Any] = {}

    if mutation in ("wrong-src-hash", "hash-from-other-bundle"):
        idxs = _patched_hash_lines(diff)
        if not idxs:
            raise ValueError("no '+...hash = \"...\"' line in patch.diff to mutate")
        repl = decoy_hash or _DECOY_SRI
        i = idxs[0]
        m = _HASH_LINE_RE.match(lines[i])
        details["original_patched_hash"] = m.group(2)
        details["injected_hash"] = repl
        lines[i] = f"{m.group(1)}{repl}{m.group(3)}"
        patch_path.write_text("\n".join(lines) + ("\n" if diff.endswith("\n") else ""))

    elif mutation == "version-without-hash":
        # Revert the '+' hash line back to the pre-patch '-' hash value, so the
        # version is bumped but the hash is left stale.
        minus = {}
        for line in lines:
            mm = _HASH_LINE_RE.match(line)
            if line.startswith("-") and mm:
                minus[mm.group(1).lstrip("-").strip()] = mm.group(2)
        idxs = _patched_hash_lines(diff)
        if not idxs or not minus:
            raise ValueError("could not find paired -/+ hash lines for version-without-hash")
        i = idxs[0]
        m = _HASH_LINE_RE.match(lines[i])
        old_val = next(iter(minus.values()))
        details["reverted_to_prepatch_hash"] = old_val
        details["dropped_patched_hash"] = m.group(2)
        lines[i] = f"{m.group(1)}{old_val}{m.group(3)}"
        patch_path.write_text("\n".join(lines) + ("\n" if diff.endswith("\n") else ""))

    elif mutation == "patch-touches-unrelated-file":
        # Re-point the diff headers at an unrelated file.
        new = diff.replace("a/package.nix", "a/pkgs/unrelated/evil.nix").replace(
            "b/package.nix", "b/pkgs/unrelated/evil.nix"
        )
        if new == diff:
            new = diff.replace("package.nix", "pkgs/unrelated/evil.nix")
        details["retargeted_to"] = "pkgs/unrelated/evil.nix"
        patch_path.write_text(new)

    else:  # pragma: no cover - guarded by argparse choices
        raise ValueError(f"unknown mutation {mutation!r}")

    return details


def run(args: argparse.Namespace) -> int:
    base: Path = args.base_dir
    out: Path = args.out_dir
    if not (base / "patch.diff").is_file():
        print(f"error: base bundle has no patch.diff: {base}")
        return 2
    if out.exists():
        print(f"error: out-dir already exists: {out}")
        return 2

    if args.mutation == "hash-from-other-bundle" and not args.decoy_hash:
        print(
            "error: --mutation hash-from-other-bundle requires --decoy-hash "
            "(a real hash lifted from another bundle); without it the result is "
            "indistinguishable from wrong-src-hash and the provenance would be mislabeled"
        )
        return 2

    shutil.copytree(base, out)
    # Drop the prior reviewer verdict + any signing/cert artifacts: the mutated
    # bundle must be re-reviewed from scratch, and it is NOT a signed/cert bundle.
    for stale in ("review.md", "review-scoring-report.json", "review-refusal.json",
                  "reviewer-invocation.json", "bundle.sig", "build.json"):
        sp = out / stale
        if sp.exists():
            sp.unlink()

    # Scrub the copied replay.json's reviewer role: its recorded input hashes
    # are for the pre-mutation patch.diff, so a fresh `replay --execute --role
    # reviewer` would otherwise fail input verification instead of re-reviewing.
    replay_path = out / "replay.json"
    if replay_path.is_file():
        try:
            replay = json.loads(replay_path.read_text())
            roles = replay.get("roles")
            if isinstance(roles, list):
                replay["roles"] = [r for r in roles if r.get("role") != "reviewer"]
                replay_path.write_text(json.dumps(replay, indent=2) + "\n")
        except (json.JSONDecodeError, OSError):
            pass

    # Scrub signing metadata: a mutated bundle must never claim a signature for
    # bytes that were deliberately changed (would misstate steward_signed
    # provenance to the exporter / verifiers).
    # A mutated bundle is NOT finalized: drop signing fields AND the file
    # manifest (its hashes are for the pre-mutation patch.diff and reference
    # now-deleted artifacts like bundle.sig/build.json). The mutation.json marker
    # + the on-disk files are the source of truth; consumers must not trust a
    # stale manifest. (Run `trace bundle finalize` if a real manifest is needed.)
    bundle_path = out / "bundle.json"
    if bundle_path.is_file():
        try:
            bj = json.loads(bundle_path.read_text())
            for k in ("signed_manifest", "auto_merge_evidence_path", "files"):
                bj.pop(k, None)
            bundle_path.write_text(json.dumps(bj, indent=2) + "\n")
        except (json.JSONDecodeError, OSError):
            pass

    try:
        details = _apply_mutation(out, args.mutation, args.decoy_hash)
    except Exception as exc:
        # Roll back the partial copy so a corrected rerun isn't blocked by an
        # 'out-dir already exists' from a half-mutated directory.
        shutil.rmtree(out, ignore_errors=True)
        print(f"error: mutation failed ({args.mutation}): {exc}")
        return 2

    base_bundle = json.loads((base / "bundle.json").read_text()) if (base / "bundle.json").is_file() else {}
    marker = {
        "schema_version": "1.0.0",
        "negative_source": "mutation",
        "mutation_type": args.mutation,
        "base_bundle_dir": base.name,
        "base_bundle_id": base_bundle.get("bundle_id"),
        "base_cve_id": base_bundle.get("cve_id"),
        "mutation_details": details,
        "expected_reviewer_verdict": "reject",
        "note": (
            "Run `trace replay --execute --role reviewer --model <m>` against this "
            "dir, then keep only if the Reviewer genuinely rejects with findings."
        ),
    }
    (out / "mutation.json").write_text(json.dumps(marker, indent=2, sort_keys=True) + "\n")

    if args.format == "json":
        print(json.dumps(marker, indent=2, sort_keys=True))
    else:
        print(f"mutated bundle written -> {out}")
        print(f"  base:     {base.name} ({marker['base_cve_id']})")
        print(f"  mutation: {args.mutation}")
        print(f"  details:  {details}")
        print(f"  next: trace replay --execute --role reviewer --model claude-sonnet-4-6 {out.name}")
    return 0
