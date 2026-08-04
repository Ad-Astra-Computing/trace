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
    # order/placement defects (v9): token present, placement wrong
    "token-preserving-misplacement",
    # compound-condition defects (v1.11 queue): break a multi-subterm guard
    # while keeping it plausible — the zlib-shaped hard-generalization case.
    "condition-operator-mutation",
    "condition-drop-conjunct",
)

# Structure-preserving reorganizations for reviewer POSITIVES. These change the
# layout of patch.diff (hunk/section order) without altering the fix content, so
# the bundle stays a valid accept. Teaches CTW-equivalence under reordering (the
# v1.8 zlib false-reject failure mode).
#
# The `guard-*` family is the HARD half (v1.11 compound-guard balance): the added
# compound guard is rewritten into a semantically EQUIVALENT form whose token
# string no longer matches the upstream fix, so a lexical reader mistakes it for a
# dropped conjunct / flipped operator (i.e. for one of the condition-* negatives).
# Every guard-* mint carries a written equivalence argument + hardness rationale;
# they are NOT machine-derivable, so the minter requires them explicitly.
#   guard-demorgan — De Morgan rewrite (`a && b` -> `!(!a || !b)` and friends).
#                    Short-circuit order is preserved exactly, so it is sound even
#                    when an operand has side effects or can fault.
#   guard-hoist    — a subexpression is hoisted into a named local, so the tokens
#                    leave the guard line. Sound only when the hoisted expression
#                    is side-effect-free AND cannot fault when evaluated on the
#                    path where the original short-circuited past it.
#   guard-split    — one guard split into nested ifs (`if (a && b) S` ->
#                    `if (a) { if (b) S }`). Order-preserving; check for an else
#                    clause that could re-bind, and brace the outer if.
#   guard-reorder  — conjuncts reordered. Sound ONLY when every operand is pure
#                    and non-faulting (never for `p && p->x`).
REORG_TYPES = (
    "reorder-hunks",
    "context-reshape",
    "guard-demorgan",
    "guard-hoist",
    "guard-split",
    "guard-reorder",
)

# The subset of REORG_TYPES that rewrites an added guard in place (needs --guard /
# --rewrite-to / --equivalence / --hardness).
GUARD_REWRITE_TYPES = ("guard-demorgan", "guard-hoist", "guard-split", "guard-reorder")

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
    rn.add_argument(
        "--swap", nargs=2, metavar=("LINE_A", "LINE_B"), default=None,
        help="for token-preserving-misplacement: two ADDED source lines (verbatim, "
             "sans diff prefix) to swap so the fix is mis-ordered but the tokens remain",
    )
    rn.add_argument(
        "--guard", default=None,
        help="for condition-* mutations: the exact ADDED compound-guard source line "
             "(verbatim, sans diff prefix) to mutate",
    )
    rn.add_argument("--op-from", default=None,
                    help="condition-operator-mutation: operator substring in --guard to replace")
    rn.add_argument("--op-to", default=None,
                    help="condition-operator-mutation: replacement operator")
    rn.add_argument("--drop-subterm", default=None,
                    help="condition-drop-conjunct: a conjunct substring (e.g. ' || pl > 255') "
                         "to remove from --guard")
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
    rp.add_argument(
        "--guard", action="append", default=None, metavar="LINE",
        help="guard-* reorgs: an ADDED source line of the compound guard to rewrite "
             "(verbatim, sans diff prefix). Repeat, in order, for a multi-line guard.",
    )
    rp.add_argument(
        "--rewrite-to", action="append", default=None, metavar="LINE",
        help="guard-* reorgs: a replacement source line (verbatim, sans diff prefix). "
             "Repeat, in order; the replacement may have a different line count.",
    )
    rp.add_argument(
        "--equivalence", default=None,
        help="guard-* reorgs: the written proof that the rewrite is semantically "
             "equivalent to the original guard (recorded in reorg.json).",
    )
    rp.add_argument(
        "--hardness", default=None,
        help="guard-* reorgs: why this rewrite sits near the rejection boundary — "
             "what a string-level reader would mistake for a missing conjunct.",
    )
    rp.add_argument("--format", choices=["human", "json"], default="human")
    return p


def _patched_hash_lines(diff: str) -> list[int]:
    """Indices of '+...hash = "..."' lines in patch.diff."""
    out = []
    for i, line in enumerate(diff.splitlines()):
        if line.startswith("+") and _HASH_LINE_RE.match(line):
            out.append(i)
    return out


def _added_line_match(line: str, code: str) -> int | None:
    """If `line` is an ADDED diff line whose source content == `code`, return its
    nesting depth (1 = plain `+<code>`, 2 = embedded `++<code>` inside a *.patch
    that the outer diff adds); else None. `code` is verbatim source text WITHOUT
    any diff prefix (it keeps the source's own indentation)."""
    if line.startswith("++"):
        return 2 if line[2:] == code else None
    if line.startswith("+"):
        return 1 if line[1:] == code else None
    return None


def _hunk_header_of(lines: list[str], idx: int, depth: int) -> int | None:
    """Index of the nearest hunk header at `depth` preceding `lines[idx]` (a
    plain `@@` for depth 1, an embedded `+@@` for depth 2), or None."""
    prefix = "+" * (depth - 1) + "@@"
    for i in range(idx, -1, -1):
        if lines[i].startswith(prefix):
            return i
    return None


def _swap_added_lines(out_dir: Path, code_a: str, code_b: str) -> dict[str, Any]:
    """Swap two ADDED code lines in patch.diff (token-preserving-misplacement).

    Both lines keep their `+`/`++` prefix, so every hunk's +/- line counts are
    invariant and the old-side (context + removed) is untouched — the patch
    still applies, but the added code now sits in the wrong order/position
    (e.g. a declaration after the statement that reads it). The CTW token
    strings are all still present; only their placement is broken."""
    if code_a == code_b:
        raise ValueError("--swap lines must differ (a no-op swap is not a defect)")
    patch_path = out_dir / "patch.diff"
    diff = patch_path.read_text()
    lines = diff.splitlines()
    hits_a = [(i, d) for i, l in enumerate(lines) if (d := _added_line_match(l, code_a)) is not None]
    hits_b = [(i, d) for i, l in enumerate(lines) if (d := _added_line_match(l, code_b)) is not None]
    if len(hits_a) != 1:
        raise ValueError(f"--swap line A matched {len(hits_a)} added line(s), need exactly 1: {code_a!r}")
    if len(hits_b) != 1:
        raise ValueError(f"--swap line B matched {len(hits_b)} added line(s), need exactly 1: {code_b!r}")
    (ia, da), (ib, db) = hits_a[0], hits_b[0]
    if da != db:
        raise ValueError(f"--swap lines are at different diff nesting depths ({da} vs {db}); cannot swap")
    ha, hb = _hunk_header_of(lines, ia, da), _hunk_header_of(lines, ib, db)
    if ha is None or hb is None or ha != hb:
        raise ValueError("--swap lines are not in the same hunk; misplacement must be intra-hunk")
    lines[ia], lines[ib] = lines[ib], lines[ia]
    patch_path.write_text("\n".join(lines) + ("\n" if diff.endswith("\n") else ""))
    return {"swapped_lines": [code_a, code_b], "line_indices": [ia, ib], "depth": da}


def _edit_added_guard_line(out_dir: Path, guard: str, find: str, replace: str) -> dict[str, Any]:
    """Edit a single ADDED guard line in patch.diff in place: within the line
    whose source content == `guard`, replace the first occurrence of `find` with
    `replace`. Count-preserving (one line's content changes, no line added/removed),
    so the embedded patch still applies — but the compound guard is now broken
    (a flipped operator or a dropped conjunct), while the surrounding tokens stay.
    `replace=""` drops a subterm. Used by condition-operator-mutation and
    condition-drop-conjunct."""
    if not guard:
        raise ValueError("condition mutation requires --guard (the exact added source line)")
    if find not in guard:
        raise ValueError(f"edit target {find!r} not found in --guard {guard!r}")
    new_inner = guard.replace(find, replace, 1)
    if new_inner == guard:
        raise ValueError("edit produced no change (find == replace?)")
    patch_path = out_dir / "patch.diff"
    diff = patch_path.read_text()
    lines = diff.splitlines()
    hits = [(i, d) for i, l in enumerate(lines) if (d := _added_line_match(l, guard)) is not None]
    if len(hits) != 1:
        raise ValueError(f"--guard matched {len(hits)} added line(s), need exactly 1: {guard!r}")
    i, depth = hits[0]
    lines[i] = lines[i][:depth] + new_inner
    patch_path.write_text("\n".join(lines) + ("\n" if diff.endswith("\n") else ""))
    return {"guard": guard, "find": find, "replace": replace, "mutated_to": new_inner,
            "line_index": i, "depth": depth}


def _apply_mutation(
    out_dir: Path, mutation: str, decoy_hash: str | None, swap: tuple[str, str] | None = None,
    guard: str | None = None, op_from: str | None = None, op_to: str | None = None,
    drop_subterm: str | None = None,
) -> dict[str, Any]:
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

    elif mutation == "token-preserving-misplacement":
        if not swap:
            raise ValueError("token-preserving-misplacement requires --swap LINE_A LINE_B")
        details.update(_swap_added_lines(out_dir, swap[0], swap[1]))

    elif mutation == "condition-operator-mutation":
        if not (guard and op_from and op_to):
            raise ValueError("condition-operator-mutation requires --guard, --op-from, --op-to")
        details.update(_edit_added_guard_line(out_dir, guard, op_from, op_to))

    elif mutation == "condition-drop-conjunct":
        if not (guard and drop_subterm):
            raise ValueError("condition-drop-conjunct requires --guard and --drop-subterm")
        details.update(_edit_added_guard_line(out_dir, guard, drop_subterm, ""))

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


def _find_added_block(lines: list[str], guard: list[str]) -> list[tuple[int, int]]:
    """All (start_index, depth) where `lines[start:start+len(guard)]` are ADDED
    diff lines whose source content is exactly `guard`, all at the same depth."""
    hits: list[tuple[int, int]] = []
    n = len(guard)
    for i in range(len(lines) - n + 1):
        depths = [_added_line_match(lines[i + j], g) for j, g in enumerate(guard)]
        if all(d is not None for d in depths) and len(set(depths)) == 1:
            hits.append((i, depths[0]))  # type: ignore[arg-type]
    return hits


_HUNK_HDR_COUNTS_RE = re.compile(
    r"^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@(.*)$"
)


def _bump_new_count(header: str, delta: int, depth: int) -> str:
    """Add `delta` to the NEW-side line count of a `@@ -a,b +c,d @@` header at
    nesting `depth`, leaving the old side and the start lines alone.

    Deliberately a delta bump rather than a recount: some corpus patch.diff
    headers carry counts that already differ from a strict recount, and a
    positive variant must not silently rewrite bytes outside the guard it is
    there to vary."""
    prefix = header[:depth]
    m = _HUNK_HDR_COUNTS_RE.match(header[depth:])
    if not m:
        raise ValueError(f"not a hunk header: {header!r}")
    a, b, c, d, heading = m.groups()
    old_side = f"-{a}" + (f",{b}" if b is not None else "")
    new_count = (int(d) if d is not None else 1) + delta
    if new_count < 0:
        raise ValueError(f"bump would make a negative line count: {header!r}")
    return f"{prefix}@@ {old_side} +{c},{new_count} @@{heading}"


def _rewrite_guard(out_dir: Path, guard: list[str], rewrite_to: list[str]) -> dict[str, Any]:
    """Replace an ADDED compound-guard block in patch.diff with an equivalent
    rewrite, recomputing the enclosing hunk header(s) so the diff stays
    well-formed. Only the added side changes; the old side (context + removed
    lines) is untouched, so the patch still applies.

    Semantic equivalence of the rewrite is the CALLER's responsibility — this
    function is a mechanical editor, and the minter demands a written argument."""
    if not guard or not rewrite_to:
        raise ValueError("guard rewrite requires both --guard and --rewrite-to")
    if guard == rewrite_to:
        raise ValueError("--rewrite-to is identical to --guard (a no-op is not a rewrite)")
    patch_path = out_dir / "patch.diff"
    diff = patch_path.read_text()
    lines = diff.splitlines()

    hits = _find_added_block(lines, guard)
    if len(hits) != 1:
        raise ValueError(
            f"--guard matched {len(hits)} added block(s), need exactly 1: {guard!r}"
        )
    idx, depth = hits[0]
    prefix = "+" * depth
    new_block = [prefix + l for l in rewrite_to]
    lines[idx:idx + len(guard)] = new_block
    last = idx + len(new_block) - 1

    # Fix up the enclosing hunk header(s): only the NEW side changed, by exactly
    # `delta` lines. An embedded (depth-2) guard sits inside an added file, so
    # BOTH the embedded `+@@` header and the outer `@@` header count it.
    delta = len(new_block) - len(guard)
    if delta:
        headers: list[int] = []
        for d in range(depth, 0, -1):
            h = _hunk_header_of(lines, last, depth=d)
            if h is None:
                raise ValueError(f"no depth-{d} hunk header precedes the guard")
            headers.append(h)
        for d, h in zip(range(depth, 0, -1), headers):
            lines[h] = _bump_new_count(lines[h], delta, depth=d - 1)

    patch_path.write_text("\n".join(lines) + ("\n" if diff.endswith("\n") else ""))
    return {
        "depth": depth,
        "guard": list(guard),
        "rewritten_to": list(rewrite_to),
        "line_index": idx,
        "line_delta": len(rewrite_to) - len(guard),
    }


def _apply_reorg(
    out_dir: Path,
    reorg: str,
    guard: list[str] | None = None,
    rewrite_to: list[str] | None = None,
) -> dict[str, Any]:
    """Reorganize the staged bundle's patch.diff layout in-place; return marker
    details. Content (the set of +/- change lines) is preserved exactly, except
    for the guard-* types, which replace one guard with an equivalent rewrite."""
    if reorg in GUARD_REWRITE_TYPES:
        return _rewrite_guard(out_dir, guard or [], rewrite_to or [])
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
    # Drop the prior reviewer verdict + ALL signing/cert artifacts: the variant
    # bundle must be re-reviewed from scratch, and it is NOT a signed/cert bundle.
    # cosign-cert.pem + bundle.canonical.json attest to the ORIGINAL bytes; a
    # reshaped/mutated patch.diff would make them a stale signature over changed
    # content (provenance tampering), so they must not survive the copy.
    # authoring-example.json is a DIFFERENT pipeline's cache (read by `trace
    # export authoring` from traces/example only) — it is never an input to a
    # reviewer variant, so it is dead weight here and would needlessly carry the
    # authoring exporter's vuln_raw into the reviewer corpus.
    for stale in ("review.md", "review-scoring-report.json", "review-refusal.json",
                  "reviewer-invocation.json", "bundle.sig", "build.json",
                  "cosign-cert.pem", "bundle.canonical.json", "authoring-example.json"):
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


def _emit_applicability_attestation(out: Path) -> dict[str, Any] | None:
    """Adaptation lane: re-run the canonical compiler on the reorged patch.diff.

    A reorg rewrites patch.diff, so the base bundle's patch-applicability.json
    (if any) can never be carried — its canonical_patch_sha256 would not match
    and the Reviewer's fail-closed gate would (correctly) refuse. The only
    honest attestation is a fresh one: run the SAME canonical compiler the
    Patcher path uses (tools/trace_cli/execute.py) against the bundle's own
    source-context, and emit verdicts that are true by construction because
    canonicalize_backport_patch fail-closes on any ungroundable, ambiguous, or
    overlapping hunk. Raises on failure, which _run_reorg turns into a mint
    refusal + rollback — an unattestable reorg must not be minted.

    Returns None for non-adaptation-lane bundles (no source-context files).
    """
    sc_dir = out / "source-context"
    if not sc_dir.is_dir():
        return None
    relpaths = [
        p.relative_to(sc_dir).as_posix()
        for p in sorted(sc_dir.rglob("*"))
        if p.is_file()
    ]
    if not relpaths:
        return None
    import hashlib

    from tools.trace_cli.hunk_normalizer import (
        CANONICALIZER_VERSION,
        canonicalize_backport_patch,
    )

    source_context = {rel: (sc_dir / rel).read_text() for rel in relpaths}
    patch_path = out / "patch.diff"
    raw_text = patch_path.read_text()
    pre_sha = hashlib.sha256(raw_text.encode("utf-8")).hexdigest()
    canon = canonicalize_backport_patch(raw_text, source_context)
    # Forgery edge: a patch whose sections are ALL out-of-context passes through
    # the compiler verbatim with zero proven hunks — attesting fuzz-0/uniqueness
    # over nothing would be a true-by-vacuity lie. Refuse instead.
    if not canon.files:
        raise ValueError(
            "adaptation-lane reorg grounded zero hunks in source-context; "
            "refusing to emit an attestation over nothing"
        )
    text = canon.text
    # Same trailing-newline guarantee as the Patcher path: strict tools report
    # "corrupt patch" without it.
    if text and not text.endswith("\n"):
        text += "\n"
    diff_bytes = text.encode("utf-8")
    patch_path.write_bytes(diff_bytes)
    attestation = {
        "schema_version": "1.0.0",
        "canonicalizer_version": CANONICALIZER_VERSION,
        "raw_patch_sha256": pre_sha,
        "canonical_patch_sha256": hashlib.sha256(diff_bytes).hexdigest(),
        "canonicalized": canon.changed,
        "unique_source_match": True,
        "applies_at_fuzz0": True,
        "files": canon.files,
    }
    (out / "patch-applicability.json").write_text(
        json.dumps(attestation, indent=2, sort_keys=True) + "\n"
    )
    return attestation


def _run_reorg(args: argparse.Namespace) -> int:
    base: Path = args.base_dir
    out: Path = args.out_dir
    if not (base / "patch.diff").is_file():
        print(f"error: base bundle has no patch.diff: {base}")
        return 2
    if out.exists():
        print(f"error: out-dir already exists: {out}")
        return 2

    guard = getattr(args, "guard", None)
    rewrite_to = getattr(args, "rewrite_to", None)
    equivalence = (getattr(args, "equivalence", None) or "").strip()
    hardness = (getattr(args, "hardness", None) or "").strip()
    if args.reorg in GUARD_REWRITE_TYPES:
        if not guard or not rewrite_to:
            print(
                f"error: --reorg {args.reorg} requires --guard and --rewrite-to "
                "(repeat each for a multi-line guard)"
            )
            return 2
        # A guard rewrite is only a POSITIVE if it is semantically equivalent, and
        # that is not machine-checkable here. Refuse to mint one without the written
        # argument: an unproven 'equivalent' rewrite silently poisons the corpus.
        if not equivalence or not hardness:
            print(
                f"error: --reorg {args.reorg} requires --equivalence and --hardness "
                "(the written equivalence proof and the near-boundary rationale)"
            )
            return 2

    _stage_copy(base, out)
    try:
        details = _apply_reorg(out, args.reorg, guard=guard, rewrite_to=rewrite_to)
        applicability = _emit_applicability_attestation(out)
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
    if applicability is not None:
        marker["patch_applicability_regenerated"] = True
        marker["canonical_patch_sha256"] = applicability["canonical_patch_sha256"]
    if args.reorg in GUARD_REWRITE_TYPES:
        marker["equivalence_argument"] = equivalence
        marker["hardness_rationale"] = hardness
        marker["note"] = (
            "Run `trace replay --execute --role reviewer --model <m>` against this "
            "dir, then keep only if the Reviewer genuinely accepts. The guard was "
            "rewritten into a PROVABLY EQUIVALENT form (see equivalence_argument), "
            "so a reject here is a false reject, not a corpus defect."
        )
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

    if args.mutation == "token-preserving-misplacement" and not getattr(args, "swap", None):
        print(
            "error: --mutation token-preserving-misplacement requires --swap LINE_A LINE_B "
            "(the two added source lines to reorder so the fix is mis-placed while its "
            "tokens stay present)"
        )
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
        details = _apply_mutation(
            out, args.mutation, args.decoy_hash, getattr(args, "swap", None),
            guard=getattr(args, "guard", None), op_from=getattr(args, "op_from", None),
            op_to=getattr(args, "op_to", None), drop_subterm=getattr(args, "drop_subterm", None),
        )
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
