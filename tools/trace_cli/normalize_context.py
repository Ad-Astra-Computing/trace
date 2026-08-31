"""`trace bundle normalize-context`: fix + attest a context-byte defect in the
model's nested source patch by substituting hunks from the ground truth.

`normalize_sourceroot.py` handles the path-strip class of representation-only
defects (headers rewritten, hunk bodies byte-identical). This module handles a
second class observed on perl CVE-2026-8376: the Patcher transcribed the fix
with corrupted CONTEXT bytes (one extra leading space on every context line),
while every ADDED line is byte-identical to the curated `upstream-fix.patch`
ground truth. GNU patch matches context byte-exactly, so the payload fails
outright even though the authored fix content is correct.

The normalization is a pure GROUND-TRUTH SUBSTITUTION, never an edit:

  * Each hunk of the nested source patch is replaced wholesale (header +
    context + change lines) by the corresponding hunk of `upstream-fix.patch`.
  * Eligibility is fail-closed: the raw and ground-truth patches must touch
    the same file set, with the same hunk count per file, and every hunk pair
    must agree byte-for-byte on its ADDED lines and its DELETED lines. The
    tool therefore never authors a single change byte — it only repairs the
    surrounding representation to the bytes the ground truth already carries.
  * The normalized payload must dry-run cleanly (`--fuzz=0`) against the
    pinned source before anything is written.

Like the sourceroot normalizer this is a MODEL-OUTPUT-ALTERING operation:
applying is gated behind `--apply` and always emits a signable
`patch-context-normalization.json` attestation carrying raw/normalized/ground
truth hashes plus added-lines and deleted-lines identity proofs. And like the
krb5 precedent (DECISIONS 2026-07-28), rewriting `patch.diff` breaks the
Reviewer's sha-binding: the Reviewer MUST be re-run live on the normalized
bytes before the bundle is finalized or certified. This tool never invokes
the Reviewer itself; `reviewer_attestation` starts as null.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
import tempfile
from pathlib import Path
from typing import Any

from tools.trace_cli import nested_patch, pinned_source, preflight
from tools.trace_cli.preflight import (
    EXIT_APPLY_FAILED,
    EXIT_EXTRACT_FAILED,
    EXIT_NOT_FOUND,
    EXIT_OK,
    EXIT_UNPACK_FAILED,
)


NORMALIZER_VERSION = "1.0.0"
ATTESTATION_SCHEMA = "trace/patch-context-normalization/1.0"
ATTESTATION_FILENAME = "patch-context-normalization.json"

EXIT_REFUSED = 69


_HUNK_HDR_RE = re.compile(r"^@@ -\d+(?:,(\d+))? \+\d+(?:,(\d+))? @@")


class ContextNormalizationError(ValueError):
    """The payload cannot be deterministically normalized — caller fails closed."""


def sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


# ─── unified-diff parsing (count-driven, fail-closed) ────────────────────────

def _parse_unified_diff(text: str, label: str) -> list[dict[str, Any]]:
    """Parse ``text`` into file entries ``{"path", "header", "hunks"}``.

    ``header`` is the section's lines from ``diff --git`` up to (excluding) the
    first hunk; ``hunks`` is a list of line-lists, each beginning with its
    ``@@`` header. Hunk body extent is driven by the header's old/new counts —
    NOT by line-prefix sniffing — so a git trailer (``-- `` / version line)
    after the last hunk is never misread as a deletion line. A body that does
    not satisfy its declared counts is a header defect this tool does not own
    (run the hunk normalizer first): fail closed.
    """
    lines = text.splitlines()
    starts = [i for i, ln in enumerate(lines) if ln.startswith("diff --git ")]
    if not starts:
        raise ContextNormalizationError(
            f"{label}: no `diff --git` section found; unsupported shape"
        )
    entries: list[dict[str, Any]] = []
    for k, s in enumerate(starts):
        e = starts[k + 1] if k + 1 < len(starts) else len(lines)
        section = lines[s:e]
        path = None
        for ln in section:
            m = re.match(r"^\+\+\+ b/(\S+)", ln)
            if m:
                path = m.group(1)
                break
        if path is None:
            raise ContextNormalizationError(
                f"{label}: section starting `{section[0]}` has no `+++ b/…` header"
            )
        hunk_starts = [i for i, ln in enumerate(section) if _HUNK_HDR_RE.match(ln)]
        if not hunk_starts:
            raise ContextNormalizationError(
                f"{label}: file `{path}` has no hunks"
            )
        header = section[:hunk_starts[0]]
        hunks: list[list[str]] = []
        for i in hunk_starts:
            m = _HUNK_HDR_RE.match(section[i])
            assert m is not None
            old_count = int(m.group(1)) if m.group(1) is not None else 1
            new_count = int(m.group(2)) if m.group(2) is not None else 1
            body: list[str] = [section[i]]
            seen_old = seen_new = 0
            j = i + 1
            while j < len(section) and (seen_old < old_count or seen_new < new_count):
                ln = section[j]
                if ln.startswith("\\"):
                    pass  # `\ No newline at end of file` counts on neither side
                elif ln.startswith("+"):
                    seen_new += 1
                elif ln.startswith("-"):
                    seen_old += 1
                elif ln.startswith(" ") or ln == "":
                    seen_old += 1
                    seen_new += 1
                else:
                    break
                body.append(ln)
                j += 1
            if seen_old != old_count or seen_new != new_count:
                raise ContextNormalizationError(
                    f"{label}: file `{path}` hunk `{section[i]}` body does not "
                    f"satisfy its declared counts (old {seen_old}/{old_count}, "
                    f"new {seen_new}/{new_count}); header defects are out of "
                    f"scope here — run the hunk normalizer first"
                )
            # Absorb a trailing no-newline marker belonging to this hunk.
            if j < len(section) and section[j].startswith("\\"):
                body.append(section[j])
            hunks.append(body)
        entries.append({"path": path, "header": header, "hunks": hunks})
    return entries


def _hunk_added(hunk: list[str]) -> list[str]:
    return [ln[1:] for ln in hunk[1:] if ln.startswith("+")]


def _hunk_deleted(hunk: list[str]) -> list[str]:
    return [ln[1:] for ln in hunk[1:] if ln.startswith("-")]


def _added_lines(text: str) -> list[str]:
    out: list[str] = []
    for f in _parse_unified_diff(text, "patch"):
        for h in f["hunks"]:
            out.extend(_hunk_added(h))
    return out


def _deleted_lines(text: str) -> list[str]:
    out: list[str] = []
    for f in _parse_unified_diff(text, "patch"):
        for h in f["hunks"]:
            out.extend(_hunk_deleted(h))
    return out


# ─── ground-truth substitution ───────────────────────────────────────────────

def substitute_hunks_from_ground_truth(
    raw_inner_text: str, ground_truth_text: str
) -> tuple[str, list[dict[str, Any]]]:
    """Return ``(normalized_inner_text, substitutions)``.

    Every hunk of ``raw_inner_text`` is replaced by its positional counterpart
    from ``ground_truth_text``; the raw file headers and any preamble (e.g. a
    ``From:``/``Subject:`` block) are preserved verbatim. Eligibility is
    enforced per file and per hunk (same file set, same hunk count, added and
    deleted lines byte-identical) — any mismatch raises
    :class:`ContextNormalizationError`. ``substitutions`` records only hunks
    whose bytes actually changed; an empty list means the payload is already
    canonical.
    """
    raw_files = _parse_unified_diff(raw_inner_text, "raw payload")
    gt_files = _parse_unified_diff(ground_truth_text, "ground truth")

    gt_by_path = {f["path"]: f for f in gt_files}
    gt_by_base: dict[str, list[dict[str, Any]]] = {}
    for f in gt_files:
        gt_by_base.setdefault(Path(f["path"]).name, []).append(f)

    matched_gt: set[str] = set()
    substitutions: list[dict[str, Any]] = []
    normalized_files: list[tuple[dict[str, Any], list[list[str]]]] = []

    for rf in raw_files:
        gt = gt_by_path.get(rf["path"])
        if gt is None:
            candidates = gt_by_base.get(Path(rf["path"]).name, [])
            if len(candidates) != 1:
                raise ContextNormalizationError(
                    f"raw payload file `{rf['path']}` has "
                    f"{len(candidates)} ground-truth basename match(es); "
                    f"need exactly one"
                )
            gt = candidates[0]
        if gt["path"] in matched_gt:
            raise ContextNormalizationError(
                f"ground-truth file `{gt['path']}` matched more than once"
            )
        matched_gt.add(gt["path"])
        if len(rf["hunks"]) != len(gt["hunks"]):
            raise ContextNormalizationError(
                f"file `{rf['path']}`: raw payload has {len(rf['hunks'])} "
                f"hunk(s), ground truth has {len(gt['hunks'])}"
            )
        new_hunks: list[list[str]] = []
        for idx, (rh, gh) in enumerate(zip(rf["hunks"], gt["hunks"])):
            if _hunk_added(rh) != _hunk_added(gh):
                raise ContextNormalizationError(
                    f"file `{rf['path']}` hunk {idx}: ADDED lines differ from "
                    f"ground truth — this is a content divergence, not a "
                    f"representation defect; refusing to substitute"
                )
            if _hunk_deleted(rh) != _hunk_deleted(gh):
                raise ContextNormalizationError(
                    f"file `{rf['path']}` hunk {idx}: DELETED lines differ "
                    f"from ground truth — this is a content divergence, not a "
                    f"representation defect; refusing to substitute"
                )
            if rh != gh:
                substitutions.append({
                    "file": rf["path"],
                    "hunk_index": idx,
                    "raw_header": rh[0],
                    "ground_truth_header": gh[0],
                    "raw_hunk_sha256": sha256_text("\n".join(rh)),
                    "ground_truth_hunk_sha256": sha256_text("\n".join(gh)),
                })
            new_hunks.append(list(gh))
        normalized_files.append((rf, new_hunks))

    unmatched = [p for p in gt_by_path if p not in matched_gt]
    if unmatched:
        raise ContextNormalizationError(
            f"ground truth touches file(s) absent from the raw payload: "
            f"{unmatched}; the file sets must match exactly"
        )

    # Rebuild: preserve the raw preamble (before the first `diff --git`) and
    # every raw file header verbatim; only hunk blocks are substituted.
    raw_lines = raw_inner_text.splitlines()
    first_diff = next(
        i for i, ln in enumerate(raw_lines) if ln.startswith("diff --git ")
    )
    out: list[str] = raw_lines[:first_diff]
    for rf, new_hunks in normalized_files:
        out.extend(rf["header"])
        for h in new_hunks:
            out.extend(h)
    normalized = "\n".join(out)
    if raw_inner_text.endswith("\n"):
        normalized += "\n"
    return normalized, substitutions


# ─── patch.diff write-back ───────────────────────────────────────────────────

def rebuild_patch_diff(original_patch_diff_text: str, normalized_inner_text: str) -> str:
    """Return ``patch.diff`` with its single nested ``*.patch`` payload replaced
    by ``normalized_inner_text``; every other section (``package.nix`` wiring,
    …) is copied through byte-identical, and the nested new-file hunk header's
    line count is recomputed from the new payload.
    """
    for line in original_patch_diff_text.splitlines():
        if line.startswith("diff --git "):
            break
        if line.strip():
            raise ContextNormalizationError(
                "patch.diff has content before its first `diff --git` section "
                "(a preamble); rebuild would drop it. Unsupported shape."
            )
    sections = nested_patch._split_diff_sections(original_patch_diff_text)
    nested = [
        s for s in sections
        if s["is_new_file"] and nested_patch._basename(s["path"]).endswith(".patch")
    ]
    if len(nested) != 1:
        raise ContextNormalizationError(
            f"patch.diff has {len(nested)} nested *.patch additions; "
            f"write-back only supports exactly one"
        )
    if not normalized_inner_text.endswith("\n"):
        raise ContextNormalizationError(
            "normalized payload has no trailing newline; re-wrapping would "
            "silently add one. Unsupported shape."
        )
    target = nested[0]
    out_sections: list[list[str]] = []
    for s in sections:
        if s is not target:
            out_sections.append(s["raw_lines"])
            continue
        raw = s["raw_lines"]
        header: list[str] = []
        hunk_idx: int | None = None
        for i, line in enumerate(raw):
            header.append(line)
            if nested_patch._HUNK_HEADER_RE.match(line):
                hunk_idx = i
                break
        if hunk_idx is None:
            raise ContextNormalizationError(
                "nested patch section has no `@@ -0,0 +1,N @@` hunk header"
            )
        new_body = [f"+{line}" for line in normalized_inner_text.splitlines()]
        header[-1] = f"@@ -0,0 +1,{len(new_body)} @@"
        out_sections.append(header + new_body)
    return "\n".join("\n".join(lines) for lines in out_sections) + "\n"


# ─── attestation ─────────────────────────────────────────────────────────────

def build_attestation(
    *,
    bundle_dir: Path,
    raw_patch_diff_text: str,
    normalized_patch_diff_text: str,
    raw_inner_text: str,
    normalized_inner_text: str,
    ground_truth_text: str,
    ground_truth_path: str,
    substitutions: list[dict[str, Any]],
    nixpkgs_rev: str | None,
    source_root: str | None,
    effective_root: Path,
    source_hash: str | None,
    raw_dry_run_applies: bool,
    dry_run_output: str,
    patch_flags: list[str],
    patcher_invocation_sha: str | None,
) -> dict[str, Any]:
    """Build the attestation. Independently recomputes the added-lines and
    deleted-lines identity proofs (raw vs normalized vs ground truth) and
    raises :class:`ContextNormalizationError` if either fails — the tool must
    never attest a context-only change when change lines actually moved.
    """
    raw_added = sha256_text("\n".join(_added_lines(raw_inner_text)))
    norm_added = sha256_text("\n".join(_added_lines(normalized_inner_text)))
    gt_added = sha256_text("\n".join(_added_lines(ground_truth_text)))
    raw_deleted = sha256_text("\n".join(_deleted_lines(raw_inner_text)))
    norm_deleted = sha256_text("\n".join(_deleted_lines(normalized_inner_text)))
    gt_deleted = sha256_text("\n".join(_deleted_lines(ground_truth_text)))
    if not (raw_added == norm_added == gt_added):
        raise ContextNormalizationError(
            "added-lines identity proof FAILED: raw/normalized/ground-truth "
            f"added-line hashes differ ({raw_added} / {norm_added} / "
            f"{gt_added}) — refusing to attest"
        )
    if not (raw_deleted == norm_deleted == gt_deleted):
        raise ContextNormalizationError(
            "deleted-lines identity proof FAILED: raw/normalized/ground-truth "
            f"deleted-line hashes differ ({raw_deleted} / {norm_deleted} / "
            f"{gt_deleted}) — refusing to attest"
        )
    return {
        "schema": ATTESTATION_SCHEMA,
        "tool": {"name": "trace-bundle-normalize-context", "version": NORMALIZER_VERSION},
        "bundle_dir": str(bundle_dir),
        "raw_patch_diff_sha256": sha256_text(raw_patch_diff_text),
        "raw_source_patch_sha256": sha256_text(raw_inner_text),
        "normalized_patch_diff_sha256": sha256_text(normalized_patch_diff_text),
        "normalized_source_patch_sha256": sha256_text(normalized_inner_text),
        "ground_truth_path": ground_truth_path,
        "ground_truth_sha256": sha256_text(ground_truth_text),
        "patcher_invocation_raw_response_sha256": patcher_invocation_sha,
        "hunk_substitutions": substitutions,
        "added_lines_identity_proof": {
            "raw_added_sha256": raw_added,
            "normalized_added_sha256": norm_added,
            "ground_truth_added_sha256": gt_added,
            "identical": True,
        },
        "deleted_lines_identity_proof": {
            "raw_deleted_sha256": raw_deleted,
            "normalized_deleted_sha256": norm_deleted,
            "ground_truth_deleted_sha256": gt_deleted,
            "identical": True,
        },
        "nixpkgs_rev": nixpkgs_rev,
        "effective_source_root": source_root,
        "effective_root_path": str(effective_root),
        "source_hash": source_hash,
        "raw_dry_run": {"applies": raw_dry_run_applies, "fuzz": 0},
        "dry_run": {
            "applies": True, "fuzz": 0,
            "patch_flags": list(patch_flags),
            "output": dry_run_output[:4096],
        },
        # Filled once the Reviewer has re-scored the normalized bytes (a live
        # model call, out of scope for this deterministic local check).
        "reviewer_attestation": None,
    }


# ─── CLI ─────────────────────────────────────────────────────────────────────

def add_parser(subs: argparse._SubParsersAction) -> argparse.ArgumentParser:
    p = subs.add_parser(
        "normalize-context",
        help=(
            "detect + (with --apply) fix corrupted context bytes in the "
            "model's nested source patch by substituting hunks from the "
            "ground-truth upstream-fix.patch"
        ),
        description=(
            "Without --apply: reports/gates only (fail-closed, no write). "
            "With --apply: replaces each nested-payload hunk with its "
            "ground-truth counterpart (only eligible when added and deleted "
            f"lines are byte-identical) and writes {ATTESTATION_FILENAME}. "
            "The Reviewer must be re-run live on the normalized bytes."
        ),
    )
    p.add_argument("bundle_dir", type=Path)
    p.add_argument(
        "--ground-truth", type=Path, default=None,
        help="ground-truth patch to substitute hunks from "
             "(default: <bundle_dir>/upstream-fix.patch)",
    )
    p.add_argument(
        "--source-tree", type=Path, default=None,
        help="pre-unpacked EFFECTIVE source root (the dir patchPhase would "
             "cd into) to dry-run against; skips the nix unpack.",
    )
    p.add_argument(
        "--patch-flags", type=str, default=None, metavar="FLAGS",
        help="(--source-tree mode only) the package's patchFlags to dry-run "
             "with, as one whitespace-separated string; use the `=` form, "
             "e.g. --patch-flags=-p0. Defaults to -p1.",
    )
    p.add_argument("--apply", action="store_true",
                   help="write the normalized patch.diff + attestation")
    p.add_argument("--format", choices=("human", "json"), default="human")
    return p


def _emit(fmt: str, payload: dict[str, Any], human_header: str, is_error: bool = False) -> None:
    if fmt == "json":
        json.dump(payload, sys.stdout, indent=2)
        sys.stdout.write("\n")
    else:
        print(human_header, file=sys.stderr if is_error else sys.stdout)


def _emit_error(fmt: str, exit_code: int, message: str) -> int:
    if fmt == "json":
        json.dump({"ok": False, "error": message}, sys.stdout, indent=2)
        sys.stdout.write("\n")
    else:
        print(f"error: {message}", file=sys.stderr)
    return exit_code


def _dry_run(effective_root: Path, inner_text: str, patch_flags: list[str]) -> tuple[bool, str]:
    with tempfile.TemporaryDirectory(prefix="trace-normalize-ctx-") as tmp:
        tmp_path = Path(tmp)
        work = tmp_path / "work"
        preflight._make_writable_copy(effective_root, work)
        patch_file = tmp_path / "candidate.patch"
        patch_file.write_text(inner_text)
        return preflight.apply_patch(work, patch_file, [*patch_flags, "--fuzz=0"])


def run(args: argparse.Namespace, repo_root: Path) -> int:
    bundle_dir: Path = args.bundle_dir.resolve()
    if not bundle_dir.is_dir():
        return _emit_error(args.format, EXIT_NOT_FOUND, f"bundle dir not found: {bundle_dir}")

    patch_diff_path = bundle_dir / "patch.diff"
    if not patch_diff_path.is_file():
        return _emit_error(args.format, EXIT_NOT_FOUND, f"no patch.diff in {bundle_dir}")
    ground_truth_path: Path = (
        args.ground_truth.resolve() if args.ground_truth is not None
        else bundle_dir / "upstream-fix.patch"
    )
    if not ground_truth_path.is_file():
        return _emit_error(args.format, EXIT_NOT_FOUND,
                           f"ground-truth patch not found: {ground_truth_path}")

    raw_patch_diff_text = patch_diff_path.read_text()
    ground_truth_text = ground_truth_path.read_text()
    try:
        raw_inner_text, nested_names = nested_patch.extract_nested_source_patch(
            raw_patch_diff_text)
    except nested_patch.NestedPatchError as exc:
        return _emit_error(args.format, EXIT_EXTRACT_FAILED, str(exc))

    try:
        normalized_inner_text, substitutions = substitute_hunks_from_ground_truth(
            raw_inner_text, ground_truth_text)
    except ContextNormalizationError as exc:
        _emit(args.format, {"ok": False, "bundle_dir": str(bundle_dir), "error": str(exc)},
              f"NORMALIZE-CONTEXT: INELIGIBLE\n{exc}", is_error=True)
        return EXIT_REFUSED

    if not substitutions:
        _emit(args.format, {
            "ok": True, "bundle_dir": str(bundle_dir),
            "normalization_needed": False,
            "nested_patch_files": nested_names,
        }, "NORMALIZE-CONTEXT: payload already matches ground truth (no change needed)")
        return EXIT_OK

    source_root: str | None = None
    nixpkgs_rev: str | None = None
    source_hash: str | None = None
    tmp_ctx = tempfile.TemporaryDirectory(prefix="trace-normalize-ctx-src-")
    try:
        tmp_root = Path(tmp_ctx.name)
        if args.source_tree is not None:
            effective_root = args.source_tree.resolve()
            if not effective_root.is_dir():
                return _emit_error(args.format, EXIT_NOT_FOUND,
                                   f"--source-tree not a directory: {effective_root}")
            _pf = getattr(args, "patch_flags", None)
            if _pf is None:
                patch_flags = ["-p1"]
            elif isinstance(_pf, str):
                patch_flags = _pf.split()
            else:
                patch_flags = list(_pf)
        else:
            try:
                eff = pinned_source.unpack_pinned_source_with_effective_root(
                    bundle_dir, tmp_root)
            except (RuntimeError, ValueError) as exc:
                return _emit_error(args.format, EXIT_UNPACK_FAILED, str(exc))
            if eff.preceding_patches > 0:
                return _emit_error(
                    args.format, EXIT_UNPACK_FAILED,
                    f"package applies {eff.preceding_patches} preceding "
                    f"patch(es) before the model patch; dry-running against "
                    f"pristine pkg.src could mis-report. Pass --source-tree "
                    f"with a tree already prepared through those patches.")
            effective_root = eff.effective_root
            source_root = eff.source_root
            nixpkgs_rev = eff.nixpkgs_rev
            source_hash = eff.store_path.name
            patch_flags = eff.patch_flags

        raw_applies, _raw_out = _dry_run(effective_root, raw_inner_text, patch_flags)
        norm_applies, norm_out = _dry_run(effective_root, normalized_inner_text, patch_flags)
        if not norm_applies:
            msg = (
                f"normalized payload does NOT apply at fuzz=0 from "
                f"{effective_root} — the ground truth itself does not fit "
                f"this base; nothing to attest. patch output:\n{norm_out[:2000]}"
            )
            _emit(args.format, {"ok": False, "bundle_dir": str(bundle_dir), "error": msg},
                  f"NORMALIZE-CONTEXT: GROUND TRUTH DOES NOT APPLY\n{msg}", is_error=True)
            return EXIT_APPLY_FAILED

        if not args.apply:
            msg = (
                f"payload needs {len(substitutions)} hunk substitution(s) "
                f"from {ground_truth_path.name} to apply from "
                f"{effective_root}; re-run with --apply to fix it and emit "
                f"{ATTESTATION_FILENAME}"
            )
            _emit(args.format, {
                "ok": False, "bundle_dir": str(bundle_dir),
                "normalization_needed": True,
                "hunk_substitutions": substitutions,
                "raw_payload_applies": raw_applies,
                "error": msg,
            }, f"NORMALIZE-CONTEXT: FAIL-CLOSED (no --apply)\n{msg}", is_error=True)
            return EXIT_APPLY_FAILED

        try:
            normalized_patch_diff_text = rebuild_patch_diff(
                raw_patch_diff_text, normalized_inner_text)
            attestation = build_attestation(
                bundle_dir=bundle_dir,
                raw_patch_diff_text=raw_patch_diff_text,
                normalized_patch_diff_text=normalized_patch_diff_text,
                raw_inner_text=raw_inner_text,
                normalized_inner_text=normalized_inner_text,
                ground_truth_text=ground_truth_text,
                ground_truth_path=str(ground_truth_path),
                substitutions=substitutions,
                nixpkgs_rev=nixpkgs_rev,
                source_root=source_root,
                effective_root=effective_root,
                source_hash=source_hash,
                raw_dry_run_applies=raw_applies,
                dry_run_output=norm_out,
                patch_flags=patch_flags,
                patcher_invocation_sha=_read_patcher_invocation_sha(bundle_dir),
            )
        except ContextNormalizationError as exc:
            _emit(args.format, {"ok": False, "bundle_dir": str(bundle_dir), "error": str(exc)},
                  f"NORMALIZE-CONTEXT: REFUSED\n{exc}", is_error=True)
            return EXIT_APPLY_FAILED
    finally:
        tmp_ctx.cleanup()

    patch_diff_path.write_text(normalized_patch_diff_text)
    (bundle_dir / ATTESTATION_FILENAME).write_text(json.dumps(attestation, indent=2) + "\n")
    _emit(args.format, {"ok": True, "bundle_dir": str(bundle_dir), "attestation": attestation},
          f"NORMALIZE-CONTEXT: APPLIED ({len(substitutions)} hunk substitution(s))\n"
          f"  wrote: patch.diff, {ATTESTATION_FILENAME}\n"
          f"  REMINDER: the Reviewer must be re-run live on the normalized bytes")
    return EXIT_OK


def _read_patcher_invocation_sha(bundle_dir: Path) -> str | None:
    p = bundle_dir / "patcher-invocation.json"
    if not p.is_file():
        return None
    try:
        data = json.loads(p.read_text())
    except json.JSONDecodeError:
        return None
    val = data.get("raw_response_sha256")
    return val if isinstance(val, str) else None
