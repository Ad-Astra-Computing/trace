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

Mutation types (one realistic Patcher defect per copy):
  hash-grounding:
  * wrong-src-hash        — the new hash is corrupted (doesn't match upstream-ref)
  * version-without-hash  — version bumped but hash left at the pre-patch value
  * hash-from-other-bundle— the new hash is a real hash lifted from another bundle
  version/target:
  * wrong-target-version  — version bumped to one that is NOT the resolver target
  scope/minimality:
  * patch-touches-unrelated-file — the diff edits a file other than the affected pkg
  * extra-unrelated-hunk  — keeps the real change but appends an unrelated edit
  evidence/rationale:
  * rationale-cites-wrong-version — patch-rationale.md claims a version != the diff
  * rationale-cites-wrong-hash    — patch-rationale.md cites a hash != the diff
"""

from __future__ import annotations

import argparse
import json
import re
import shutil
from pathlib import Path
from typing import Any

MUTATION_TYPES = (
    # hash-grounding defects
    "wrong-src-hash",
    "version-without-hash",
    "hash-from-other-bundle",
    # version/target defects
    "wrong-target-version",
    # scope/minimality defects
    "patch-touches-unrelated-file",
    "extra-unrelated-hunk",
    # evidence/rationale defects
    "rationale-cites-wrong-version",
    "rationale-cites-wrong-hash",
)

# Structure-preserving reorganizations for reviewer POSITIVES. These change the
# layout of patch.diff (hunk/section order) without altering the fix content, so
# the bundle stays a valid accept. Teaches CTW-equivalence under reordering (the
# v1.8 zlib false-reject failure mode).
REORG_TYPES = (
    "reorder-hunks",
    "context-reshape",
)

# A syntactically-valid but deliberately-wrong SRI hash (base64 of 32 zero bytes).
_DECOY_SRI = "sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="

_HASH_LINE_RE = re.compile(
    r'^([+\-]?\s*(?:hash|sha256|sha512|vendorHash|vendorSha256|cargoHash|cargoSha256'
    r'|npmDepsHash|npmDepsSha256|pnpmDepsHash|yarnDepsHash|outputHash)\s*=\s*")([^"]+)(".*)$'
)
_VERSION_LINE_RE = re.compile(r'^([+]\s*version\s*=\s*")([^"]+)(".*)$')


def _wrong_version(v: str) -> str:
    """Return a clearly-wrong version derived from v: bump the last numeric
    component by +7 (e.g. 3.9.4 -> 3.9.11, 4.2.1 -> 4.2.8) so it is grounded-
    looking but does NOT match the resolver's target_version."""
    parts = v.split(".")
    for i in range(len(parts) - 1, -1, -1):
        m = re.match(r"^(\d+)(\D*)$", parts[i])
        if m:
            parts[i] = f"{int(m.group(1)) + 7}{m.group(2)}"
            return ".".join(parts)
    return v + "7"


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

    rp = p_subs.add_parser(
        "reviewer-positive-reorg",
        help="reshape a known-good positive's patch.diff layout (still ACCEPT)",
        description=(
            "Copies a known-good positive bundle and reorganizes patch.diff's hunk "
            "layout WITHOUT changing the fix content, so it stays a valid positive. "
            "Teaches the Reviewer CTW-equivalence under reordering. Run `trace replay "
            "--execute --role reviewer` against the output to get the real accept target."
        ),
    )
    rp.add_argument("--base-dir", type=Path, required=True, help="known-good positive bundle dir")
    rp.add_argument("--reorg", choices=REORG_TYPES, required=True)
    rp.add_argument("--out-dir", type=Path, required=True, help="destination bundle dir (created)")
    rp.add_argument("--format", choices=["human", "json"], default="human")
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

    elif mutation == "wrong-target-version":
        # Single coherent defect: the patch targets a release that is NOT the
        # resolver's target_version. A version error intrinsically implies a
        # hash mismatch (the hash is version-specific), so set BOTH the version
        # and the hash to non-target values rather than leaving a stale-but-real
        # hash grounded to the original target (which would read as a separate
        # hash-grounding defect). Root cause: wrong release target.
        vidx = [i for i, ln in enumerate(lines) if _VERSION_LINE_RE.match(ln)]
        if not vidx:
            raise ValueError("no '+version = \"...\"' line in patch.diff to mutate")
        i = vidx[0]
        m = _VERSION_LINE_RE.match(lines[i])
        bad = _wrong_version(m.group(2))
        details["original_target_version"] = m.group(2)
        details["injected_version"] = bad
        lines[i] = f"{m.group(1)}{bad}{m.group(3)}"
        # Neutralize EVERY now-inconsistent patched hash (some diffs carry both
        # `hash` and `vendorHash`) to a decoy, so the only signal is "wrong
        # release", not a stale real hash grounded to the original version.
        neutralized: list[str] = []
        for hi in _patched_hash_lines("\n".join(lines)):
            hm = _HASH_LINE_RE.match(lines[hi])
            neutralized.append(hm.group(2))
            lines[hi] = f"{hm.group(1)}{_DECOY_SRI}{hm.group(3)}"
        details["neutralized_hashes"] = neutralized
        patch_path.write_text("\n".join(lines) + ("\n" if diff.endswith("\n") else ""))
        # Keep patch-rationale.md CONSISTENT with the mutated diff (cite the
        # wrong version + neutralized hashes) so this stays a single 'wrong
        # release' defect, not also a rationale-contradicts-diff defect.
        rat_path = out_dir / "patch-rationale.md"
        if rat_path.is_file():
            rat = rat_path.read_text().replace(m.group(2), bad)
            for oh in neutralized:
                rat = rat.replace(oh, _DECOY_SRI)
            rat_path.write_text(rat)

    elif mutation == "patch-touches-unrelated-file":
        # Re-point the diff headers at an unrelated file.
        new = diff.replace("a/package.nix", "a/pkgs/unrelated/evil.nix").replace(
            "b/package.nix", "b/pkgs/unrelated/evil.nix"
        )
        if new == diff:
            new = diff.replace("package.nix", "pkgs/unrelated/evil.nix")
        details["retargeted_to"] = "pkgs/unrelated/evil.nix"
        patch_path.write_text(new)

    elif mutation == "extra-unrelated-hunk":
        # Keep the real change but APPEND an unrelated second file-diff, so the
        # patch is no longer minimal (a scope violation the Reviewer must catch).
        # The Reviewer READS patch.diff (it does not `git apply` it — that is the
        # Builder's job), so the appended path only needs to signal an unrelated
        # edit; it need not exist in the nixpkgs checkout.
        extra = (
            "diff --git a/pkgs/unrelated/cleanup.nix b/pkgs/unrelated/cleanup.nix\n"
            "--- a/pkgs/unrelated/cleanup.nix\n"
            "+++ b/pkgs/unrelated/cleanup.nix\n"
            "@@ -1,3 +1,3 @@\n"
            " {\n"
            '-  description = "old";\n'
            '+  description = "refactored while we were here";\n'
            " }\n"
        )
        sep = "" if diff.endswith("\n") else "\n"
        patch_path.write_text(diff + sep + extra)
        details["appended_unrelated_hunk"] = "pkgs/unrelated/cleanup.nix"

    elif mutation == "rationale-cites-wrong-version":
        ur = json.loads((out_dir / "upstream-ref.json").read_text())
        tgt = ur.get("target_version")
        rat_path = out_dir / "patch-rationale.md"
        rat = rat_path.read_text()
        if not tgt or tgt not in rat:
            raise ValueError(
                "rationale-cites-wrong-version: target_version not found in patch-rationale.md"
            )
        bad = _wrong_version(tgt)
        rat_path.write_text(rat.replace(tgt, bad))
        details["rationale_version_claimed"] = bad
        details["actual_patch_version"] = tgt

    elif mutation == "rationale-cites-wrong-hash":
        idxs = _patched_hash_lines(diff)
        if not idxs:
            raise ValueError("rationale-cites-wrong-hash: no patched hash in patch.diff")
        real = _HASH_LINE_RE.match(lines[idxs[0]]).group(2)
        rat_path = out_dir / "patch-rationale.md"
        rat = rat_path.read_text()
        if real not in rat:
            raise ValueError(
                "rationale-cites-wrong-hash: patched hash not cited in patch-rationale.md"
            )
        repl = decoy_hash or _DECOY_SRI
        rat_path.write_text(rat.replace(real, repl))
        details["rationale_hash_claimed"] = repl
        details["actual_patch_hash"] = real

    else:  # pragma: no cover - guarded by argparse choices
        raise ValueError(f"unknown mutation {mutation!r}")

    return details


def _split_file_sections(lines: list[str]) -> tuple[list[str], list[list[str]]]:
    """Split a unified diff into (preamble, [file-section, ...]). A section
    starts at a `diff --git ` line, or at a `--- ` line when there are no
    `diff --git` headers."""
    starts = [i for i, l in enumerate(lines) if l.startswith("diff --git ")]
    if not starts:
        starts = [i for i, l in enumerate(lines) if l.startswith("--- ")]
    if not starts:
        return lines, []
    preamble = lines[: starts[0]]
    sections = []
    for j, s in enumerate(starts):
        e = starts[j + 1] if j + 1 < len(starts) else len(lines)
        sections.append(lines[s:e])
    return preamble, sections


def _split_hunks(section: list[str]) -> tuple[list[str], list[list[str]]]:
    """Split one file section into (header, [hunk, ...]). A hunk starts at an
    `@@` line; the header is everything before the first `@@`."""
    hstarts = [i for i, l in enumerate(section) if l.startswith("@@")]
    if not hstarts:
        return section, []
    header = section[: hstarts[0]]
    hunks = []
    for j, s in enumerate(hstarts):
        e = hstarts[j + 1] if j + 1 < len(hstarts) else len(section)
        hunks.append(section[s:e])
    return header, hunks


_HUNK_HDR_RE = re.compile(r"^@@ -(\d+)(?:,\d+)? \+(\d+)(?:,\d+)? @@(.*)$")


def _emb_char(line: str, depth: int) -> str:
    """The diff-type char of `line` at nesting `depth` (0 = outer, 1 = a line
    inside an embedded *.patch that the outer diff adds). Missing -> context."""
    return line[depth] if len(line) > depth else " "


def _recompute_header(old_line: str, body: list[str], depth: int) -> str:
    """Rebuild a `@@ -a,b +c,d @@` header (preserving a, c, heading, and any
    outer prefix) with b/d recomputed from `body` at nesting `depth`."""
    prefix = old_line[:depth]
    m = _HUNK_HDR_RE.match(old_line[depth:])
    if not m:  # pragma: no cover - only called on matched headers
        raise ValueError(f"not a hunk header: {old_line!r}")
    a, c, heading = m.group(1), m.group(2), m.group(3)
    old_count = sum(1 for l in body if _emb_char(l, depth) in " -")
    new_count = sum(1 for l in body if _emb_char(l, depth) in " +")
    return f"{prefix}@@ -{a},{old_count} +{c},{new_count} @@{heading}"


def _reshape_context(out_dir: Path) -> dict[str, Any]:
    """Drop one trailing context line from a hunk and recompute the affected
    header(s), preserving every change line. Narrowing trailing context always
    applies cleanly. Prefers an embedded *.patch hunk (the zlib failure shape);
    falls back to a plain hunk. Raises if no droppable trailing context."""
    patch_path = out_dir / "patch.diff"
    diff = patch_path.read_text()
    lines = diff.splitlines()
    preamble, sections = _split_file_sections(lines)

    def _flush() -> None:
        new_lines = preamble + [l for sec in sections for l in sec]
        patch_path.write_text("\n".join(new_lines) + ("\n" if diff.endswith("\n") else ""))

    # 1) Embedded *.patch hunk: outer `@@ -0,0 +1,N @@` adds a file whose body is
    #    itself a diff with a `+@@` header. Reshape the embedded hunk's context.
    for si, sec in enumerate(sections):
        emb_idxs = [i for i, l in enumerate(sec) if l.startswith("+@@")]
        outer_idxs = [i for i, l in enumerate(sec) if l.startswith("@@")]
        if not emb_idxs or not outer_idxs:
            continue
        emb_idx, outer_idx = emb_idxs[-1], outer_idxs[0]
        body = sec[emb_idx + 1:]
        if not body or _emb_char(body[-1], 1) != " ":
            continue  # last embedded line is a change, not droppable context
        dropped = body.pop()
        new_emb_hdr = _recompute_header(sec[emb_idx], body, depth=1)
        sec = sec[:emb_idx] + [new_emb_hdr] + body
        outer_body = sec[outer_idx + 1:]
        new_outer_hdr = _recompute_header(sec[outer_idx], outer_body, depth=0)
        sections[si] = sec[:outer_idx] + [new_outer_hdr] + outer_body
        _flush()
        return {"target": "embedded", "section_index": si, "dropped_context": dropped}

    # 2) Plain hunk: drop the trailing context line of the last hunk in a section.
    for si, sec in enumerate(sections):
        hidxs = [i for i, l in enumerate(sec) if l.startswith("@@")]
        if not hidxs:
            continue
        hidx = hidxs[-1]
        body = sec[hidx + 1:]
        if not body or _emb_char(body[-1], 0) != " ":
            continue
        dropped = body.pop()
        new_hdr = _recompute_header(sec[hidx], body, depth=0)
        sections[si] = sec[:hidx] + [new_hdr] + body
        _flush()
        return {"target": "plain", "section_index": si, "dropped_context": dropped}

    raise ValueError("no hunk with a droppable trailing context line to reshape")


def _apply_reorg(out_dir: Path, reorg: str) -> dict[str, Any]:
    """Reorganize the staged bundle's patch.diff layout in-place; return marker
    details. Content (the set of +/- change lines) is preserved exactly."""
    if reorg == "context-reshape":
        return _reshape_context(out_dir)
    if reorg != "reorder-hunks":  # pragma: no cover - guarded by argparse choices
        raise ValueError(f"unknown reorg {reorg!r}")

    patch_path = out_dir / "patch.diff"
    diff = patch_path.read_text()
    lines = diff.splitlines()
    preamble, sections = _split_file_sections(lines)
    details: dict[str, Any] = {}

    # Prefer reordering @@ hunks WITHIN the first file section that has >=2 of
    # them; otherwise reverse the order of file sections. Both are content-
    # preserving — the Reviewer reads patch.diff, it does not apply it.
    multi = None
    for idx, sec in enumerate(sections):
        _, hunks = _split_hunks(sec)
        if len(hunks) >= 2:
            multi = (idx, hunks)
            break

    if multi is not None:
        idx, hunks = multi
        header, _ = _split_hunks(sections[idx])
        sections[idx] = header + [ln for hunk in reversed(hunks) for ln in hunk]
        details["granularity"] = "hunks-within-file"
        details["section_index"] = idx
        details["hunk_count"] = len(hunks)
        new_lines = preamble + [ln for sec in sections for ln in sec]
    elif len(sections) >= 2:
        sections.reverse()
        details["granularity"] = "file-sections"
        details["section_count"] = len(sections)
        new_lines = preamble + [ln for sec in sections for ln in sec]
    else:
        raise ValueError(
            "patch.diff has a single hunk in a single file — nothing to reorder; "
            "this base is not a reorg-positive candidate"
        )

    patch_path.write_text("\n".join(new_lines) + ("\n" if diff.endswith("\n") else ""))
    return details


def _stage_copy(base: Path, out: Path) -> None:
    """Copy a known-good bundle to `out`, then scrub the prior reviewer verdict,
    signing artifacts, reviewer replay role, and stale file manifest so the
    result is re-reviewed from scratch. Shared by negative + reorg minting."""
    shutil.copytree(base, out)
    # Drop the prior reviewer verdict + any signing/cert artifacts: the variant
    # bundle must be re-reviewed from scratch, and it is NOT a signed/cert bundle.
    for stale in ("review.md", "review-scoring-report.json", "review-refusal.json",
                  "reviewer-invocation.json", "bundle.sig", "build.json"):
        sp = out / stale
        if sp.exists():
            sp.unlink()

    # Scrub the copied replay.json's reviewer role: its recorded input hashes
    # are for the pre-variant patch.diff, so a fresh `replay --execute --role
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

    # A variant bundle is NOT finalized: drop signing fields AND the file
    # manifest (its hashes are for the pre-variant patch.diff and reference
    # now-deleted artifacts). The marker + on-disk files are the source of truth.
    bundle_path = out / "bundle.json"
    if bundle_path.is_file():
        try:
            bj = json.loads(bundle_path.read_text())
            for k in ("signed_manifest", "auto_merge_evidence_path", "files"):
                bj.pop(k, None)
            bundle_path.write_text(json.dumps(bj, indent=2) + "\n")
        except (json.JSONDecodeError, OSError):
            pass


def _run_reorg(args: argparse.Namespace) -> int:
    base: Path = args.base_dir
    out: Path = args.out_dir
    if not (base / "patch.diff").is_file():
        print(f"error: base bundle has no patch.diff: {base}")
        return 2
    if out.exists():
        print(f"error: out-dir already exists: {out}")
        return 2

    _stage_copy(base, out)
    try:
        details = _apply_reorg(out, args.reorg)
    except Exception as exc:
        shutil.rmtree(out, ignore_errors=True)
        print(f"error: reorg failed ({args.reorg}): {exc}")
        return 2

    base_bundle = json.loads((base / "bundle.json").read_text()) if (base / "bundle.json").is_file() else {}
    marker = {
        "schema_version": "1.0.0",
        "positive_source": "reorg",
        "reorg_type": args.reorg,
        "base_bundle_dir": base.name,
        "base_bundle_id": base_bundle.get("bundle_id"),
        "base_cve_id": base_bundle.get("cve_id"),
        "reorg_details": details,
        "expected_reviewer_verdict": "accept",
        "note": (
            "Run `trace replay --execute --role reviewer --model <m>` against this "
            "dir, then keep only if the Reviewer genuinely accepts (content is "
            "unchanged; only patch.diff layout was reorganized)."
        ),
    }
    (out / "reorg.json").write_text(json.dumps(marker, indent=2, sort_keys=True) + "\n")

    if args.format == "json":
        print(json.dumps(marker, indent=2, sort_keys=True))
    else:
        print(f"reorg-positive bundle written -> {out}")
        print(f"  base:   {base.name} ({marker['base_cve_id']})")
        print(f"  reorg:  {args.reorg} ({details})")
        print(f"  next: trace replay --execute --role reviewer --model claude-sonnet-4-6 {out.name}")
    return 0


def run(args: argparse.Namespace) -> int:
    if getattr(args, "mutate_scope", None) == "reviewer-positive-reorg":
        return _run_reorg(args)

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

    # Copy + scrub prior verdict / signing / reviewer-replay / stale manifest, so
    # the mutated bundle is re-reviewed from scratch (shared with reorg minting).
    _stage_copy(base, out)

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
