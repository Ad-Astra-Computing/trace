"""`trace bundle normalize-sourceroot`: fix + attest a path-strip mismatch in
the model's `patch.diff`.

`preflight.py`'s `--patch-diff` mode (the GATE) catches a source-backport
bundle whose model-authored nested source patch does not apply `-p1` from the
derivation's effective ``sourceRoot`` — e.g. krb5's
``sourceRoot = "krb5-${version}/src"``, where the Patcher transcribed
tarball-root paths (``src/lib/...``) instead of sourceRoot-relative ones
(``lib/...``). That gate is deliberately conservative: it only says "does not
apply," never "here's the fix."

This module is the fix side. When the mismatch is a pure PATH-PREFIX error —
every file the patch touches would resolve if some fixed number of leading
path components were dropped uniformly, and that number is unique — the
patch is trivially "renormalizable" without touching a single byte of the
actual guard/fix content. `find_unique_normalizing_strip` proves the fix is
unique (deterministic, not a guess): it tries every plausible strip depth
against a FRESH copy of the real source, requires `--fuzz=0` (no fuzzy
line-matching that could paper over an unrelated divergence), and refuses
(fails closed) unless EXACTLY one depth applies cleanly.

Because rewriting patch headers is still a MODEL-OUTPUT-ALTERING operation
(even though it changes only path strings, never hunk bodies), applying it is
gated behind an explicit `--apply` flag and always produces a signable
`patch-normalization.json` attestation: raw/normalized hashes, the exact path
remap, and — the actual safety property — a proof that stripping every
`diff --git`/`---`/`+++`/`index` header line from BOTH the raw and the
normalized patch text leaves byte-IDENTICAL hunk bodies. If that proof ever
fails, the tool refuses to apply: normalization must never be a vector for
silently changing what the patch actually does.
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
ATTESTATION_SCHEMA = "trace/patch-normalization/1.0"
ATTESTATION_FILENAME = "patch-normalization.json"

# How many leading path components (beyond the standard git a/, b/ marker) to
# try stripping before giving up. 6 comfortably covers every real sourceRoot
# override seen so far (usually 1) without letting a pathological patch spin
# through a huge search space.
DEFAULT_MAX_EXTRA_STRIP = 6

EXIT_AMBIGUOUS = 69


_DIFF_GIT_RE = re.compile(r"^diff --git a/(\S+) b/(\S+)$")
_OLD_HDR_RE = re.compile(r"^--- a/(\S+)(\t.*)?$")
_NEW_HDR_RE = re.compile(r"^\+\+\+ b/(\S+)(\t.*)?$")
# Any line beginning a file section's header block — used to isolate hunk
# BODIES (the actual guard/fix bytes) from path metadata for the identity proof.
# ONLY matched OUTSIDE a hunk body (see _iter_line_roles): a hunk content line
# whose source text is itself a diff (`+++ b/…`, `--- a/…`) must never be
# mistaken for a file header, or normalization could rewrite real source bytes
# while the identity proof silently drops the same line from both sides.
_PATH_HEADER_RE = re.compile(r"^(diff --git |--- |\+\+\+ |index )")
_HUNK_HDR_RE = re.compile(r"^@@ -\d+(?:,(\d+))? \+\d+(?:,(\d+))? @@")


class NormalizationError(ValueError):
    """The patch cannot be deterministically normalized — caller fails closed."""


# ─── hunk-aware line classification ──────────────────────────────────────────

def _iter_line_roles(patch_text: str):
    """Yield ``(line, role)`` for each line of a unified diff, tracking hunk
    state so a hunk-body CONTENT line is never confused with a file header.

    ``role`` is one of ``"file_header"`` (``diff --git``/``---``/``+++``/
    ``index`` OUTSIDE a hunk), ``"hunk_header"`` (``@@ … @@``), ``"content"``
    (a line inside a hunk body — even if it textually looks like ``+++ b/…``),
    or ``"other"``. Hunk length is read from the ``@@ -a,b +c,d @@`` counts so
    the body boundary is exact; ``-``/``+``/context lines decrement the
    remaining old/new counts until the hunk closes.
    """
    old_rem = new_rem = 0
    in_hunk = False
    for line in patch_text.splitlines():
        if in_hunk and (old_rem > 0 or new_rem > 0):
            if line.startswith("\\"):            # "\ No newline at end of file"
                pass
            elif line.startswith("-"):
                old_rem -= 1
            elif line.startswith("+"):
                new_rem -= 1
            else:                                # context (" " prefix) or blank
                old_rem -= 1
                new_rem -= 1
            yield line, "content"
            if old_rem <= 0 and new_rem <= 0:
                in_hunk = False
            continue
        m = _HUNK_HDR_RE.match(line)
        if m:
            old_rem = int(m.group(1)) if m.group(1) is not None else 1
            new_rem = int(m.group(2)) if m.group(2) is not None else 1
            in_hunk = old_rem > 0 or new_rem > 0
            yield line, "hunk_header"
            continue
        if _PATH_HEADER_RE.match(line):
            yield line, "file_header"
            continue
        yield line, "other"


# ─── path rewriting ─────────────────────────────────────────────────────────

def _drop_components(path: str, n: int) -> str:
    parts = path.split("/")
    if len(parts) <= n:
        raise NormalizationError(
            f"cannot strip {n} leading path component(s) from {path!r}: "
            f"too shallow"
        )
    return "/".join(parts[n:])


def _rewrite_header_line(line: str, extra_strip: int) -> str:
    """Rewrite one FILE-HEADER line's ``a/``/``b/`` path, dropping
    ``extra_strip`` components right after the marker. Only ever called on a
    line already classified ``file_header``; an ``index ``/``/dev/null`` header
    (no ``a/``/``b/`` path) is returned unchanged."""
    m = _DIFF_GIT_RE.match(line)
    if m:
        a, b = m.group(1), m.group(2)
        return f"diff --git a/{_drop_components(a, extra_strip)} b/{_drop_components(b, extra_strip)}"
    m = _OLD_HDR_RE.match(line)
    if m:
        path, ts = m.group(1), m.group(2) or ""
        return f"--- a/{_drop_components(path, extra_strip)}{ts}"
    m = _NEW_HDR_RE.match(line)
    if m:
        path, ts = m.group(1), m.group(2) or ""
        return f"+++ b/{_drop_components(path, extra_strip)}{ts}"
    return line


def rewrite_patch_paths(patch_text: str, extra_strip: int) -> str:
    """Return ``patch_text`` with every path header's leading ``extra_strip``
    components dropped (right after the git ``a/``/``b/`` marker), so a patch
    that needed ``-p(1+extra_strip)`` now applies cleanly at plain ``-p1``.
    Content lines (even ones that look like ``+++ b/…``), hunk headers, and
    ``/dev/null`` sides are untouched. ``extra_strip=0`` returns ``patch_text``
    unchanged (identity).
    """
    if extra_strip == 0:
        return patch_text
    lines = [
        _rewrite_header_line(line, extra_strip) if role == "file_header" else line
        for line, role in _iter_line_roles(patch_text)
    ]
    return "\n".join(lines) + ("\n" if patch_text.endswith("\n") else "")


# ─── strip-level search ─────────────────────────────────────────────────────

def find_unique_normalizing_strip(
    effective_root: Path,
    source_patch_text: str,
    max_extra: int = DEFAULT_MAX_EXTRA_STRIP,
    patch_flags: list[str] | None = None,
) -> tuple[int | None, dict[int, tuple[bool, str]]]:
    """Search for the UNIQUE extra-strip depth that makes ``source_patch_text``
    apply cleanly (``--fuzz=0``, so no fuzzy line-matching can paper over an
    unrelated divergence) against a fresh copy of ``effective_root``.

    Tries ``extra=0`` (the patch as authored) through ``extra=max_extra``.
    Returns ``(extra_strip, attempts)``: ``extra_strip`` is the sole
    succeeding depth, or ``None`` if zero or more than one depth succeeds —
    a real path-strip mismatch is always resolved by EXACTLY one depth, so
    zero means "not a path-strip problem" (a real base mismatch) and more
    than one means the patch is too shallow/ambiguous to trust a guess.
    ``attempts`` maps every depth tried to ``(applied, output)``, so the
    caller can report full diagnostics either way.

    ``patch_flags`` is the pinned package's evaluated ``patchFlags`` (nixpkgs
    default ``["-p1"]``); each candidate is dry-run with EXACTLY those flags so
    a package whose real ``patchPhase`` uses a non-``-p1`` strip (or other
    flags) is validated against what nixpkgs actually runs, not a hard-coded
    ``-p1`` that would mis-report the result. ``--fuzz=0`` is always appended
    to forbid fuzzy matching regardless of the package's own flags.
    """
    # Only None means "unspecified → nixpkgs default"; an explicitly empty list
    # is a valid patchFlags value (patch runs with no strip flag) and must be
    # honored, not silently replaced with -p1.
    flags = ["-p1"] if patch_flags is None else list(patch_flags)
    successes: list[int] = []
    attempts: dict[int, tuple[bool, str]] = {}
    for extra in range(0, max_extra + 1):
        try:
            candidate = rewrite_patch_paths(source_patch_text, extra)
        except NormalizationError as exc:
            attempts[extra] = (False, f"skipped: {exc}")
            continue
        with tempfile.TemporaryDirectory(prefix="trace-normalize-try-") as tmp:
            tmp_path = Path(tmp)
            work = tmp_path / "work"
            preflight._make_writable_copy(effective_root, work)
            patch_file = tmp_path / "candidate.patch"
            patch_file.write_text(candidate)
            ok, output = preflight.apply_patch(work, patch_file, [*flags, "--fuzz=0"])
            attempts[extra] = (ok, output)
            if ok:
                successes.append(extra)
    if len(successes) == 1:
        return successes[0], attempts
    return None, attempts


# ─── patch.diff write-back ──────────────────────────────────────────────────

def _rewrap_nested_section(section: dict[str, Any], extra_strip: int) -> list[str]:
    raw = section["raw_lines"]
    header: list[str] = []
    hunk_idx: int | None = None
    for i, line in enumerate(raw):
        header.append(line)
        if nested_patch._HUNK_HEADER_RE.match(line):
            hunk_idx = i
            break
    if hunk_idx is None:
        raise NormalizationError(
            "nested patch section has no `@@ -0,0 +1,N @@` hunk header; malformed"
        )
    inner_text = nested_patch._unwrap_added_file_body(raw)
    if inner_text and not inner_text.endswith("\n"):
        # The added file has no trailing newline. Re-wrapping via splitlines()
        # + `+`-prefix would silently re-add one and drop the `\ No newline at
        # end of file` marker, so the written patch.diff would diverge from the
        # attested normalized bytes. Fail closed rather than corrupt it.
        raise NormalizationError(
            "nested *.patch has no trailing newline; --apply rewrapping would "
            "re-add one and drop the `\\ No newline at end of file` marker, "
            "diverging from the attested bytes. Unsupported shape — pass a "
            "pre-normalized patch.diff."
        )
    rewritten_inner = rewrite_patch_paths(inner_text, extra_strip)
    new_body = [f"+{line}" for line in rewritten_inner.splitlines()]
    return header + new_body


def normalize_patch_diff(original_patch_diff_text: str, extra_strip: int) -> str:
    """Return ``patch.diff`` with the model's OWN source-patch path headers
    normalized by dropping ``extra_strip`` leading components. ``package.nix``
    sections (and any other non-source-patch section) are copied through
    BYTE-IDENTICAL — only the source patch's own path headers change, never
    its hunk bodies. Raises :class:`NormalizationError` if the bundle carries
    more than one nested ``*.patch`` addition (write-back only supports the
    single-nested-file shape; the multi-file case is rare and left for a
    follow-up rather than guessed at).
    """
    if extra_strip == 0:
        return original_patch_diff_text
    # `_split_diff_sections` skips any content before the first `diff --git`
    # (e.g. a format-patch / email preamble), so a section-only rebuild would
    # silently drop it while the body-identity proof — computed on the inner
    # source patch — never sees it. Fail closed: the Patcher does not emit a
    # preamble, so this is an unsupported shape, not a rewrite to guess at.
    for line in original_patch_diff_text.splitlines():
        if line.startswith("diff --git "):
            break
        if line.strip():
            raise NormalizationError(
                "patch.diff has content before its first `diff --git` section "
                "(a preamble); --apply rebuilds from parsed sections and would "
                "drop it, so the path-only attestation would not hold. "
                "Unsupported shape — pass a pre-normalized patch.diff."
            )
    sections = nested_patch._split_diff_sections(original_patch_diff_text)
    nested = [
        s for s in sections
        if s["is_new_file"] and nested_patch._basename(s["path"]).endswith(".patch")
    ]
    if len(nested) > 1:
        raise NormalizationError(
            f"patch.diff has {len(nested)} nested *.patch additions; --apply "
            f"normalization only supports a single nested source patch"
        )
    out_sections: list[list[str]] = []
    if nested:
        target = nested[0]
        for s in sections:
            out_sections.append(
                _rewrap_nested_section(s, extra_strip) if s is target else s["raw_lines"]
            )
    else:
        for s in sections:
            if nested_patch._basename(s["path"]) == "package.nix":
                out_sections.append(s["raw_lines"])
            else:
                # Hunk-aware rewrite (via rewrite_patch_paths) so a content line
                # that looks like a `---`/`+++` header is never rewritten.
                rewritten = rewrite_patch_paths("\n".join(s["raw_lines"]), extra_strip)
                out_sections.append(rewritten.splitlines())
    return "\n".join("\n".join(lines) for lines in out_sections) + "\n"


# ─── attestation ─────────────────────────────────────────────────────────────

def strip_path_headers(patch_text: str) -> str:
    """Drop every FILE-HEADER line (``diff --git``/``---``/``+++``/``index``
    outside a hunk), leaving only hunk headers + content. Used to prove a
    normalization changed ONLY path representation — never the guard/fix bytes.
    Hunk-aware (via :func:`_iter_line_roles`) so a content line that looks like
    a header stays in the body and is compared by the identity proof."""
    kept = [line for line, role in _iter_line_roles(patch_text) if role != "file_header"]
    return "\n".join(kept)


def sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _extract_plus_paths(patch_text: str) -> list[str]:
    # Hunk-aware: only count `+++ b/…` FILE headers, never a `+++ b/…` that is
    # actually added hunk content.
    return [m.group(1)
            for line, role in _iter_line_roles(patch_text)
            if role == "file_header" and (m := _NEW_HDR_RE.match(line))]


def compute_path_mappings(raw_inner: str, normalized_inner: str) -> list[dict[str, str]]:
    """Pair each raw ``+++ b/<path>`` header (in order) with its normalized
    counterpart. Raises :class:`NormalizationError` if the file COUNT differs
    (would mean normalization silently added/dropped a file section — refuse
    rather than emit a mapping that could mislead a reviewer)."""
    raw_paths = _extract_plus_paths(raw_inner)
    norm_paths = _extract_plus_paths(normalized_inner)
    if len(raw_paths) != len(norm_paths):
        raise NormalizationError(
            f"raw patch touches {len(raw_paths)} file(s), normalized touches "
            f"{len(norm_paths)}: normalization must never change the file set"
        )
    return [
        {"old_path": o, "new_path": n} for o, n in zip(raw_paths, norm_paths) if o != n
    ]


def build_attestation(
    *,
    bundle_dir: Path,
    raw_patch_diff_text: str,
    normalized_patch_diff_text: str,
    raw_source_patch_text: str,
    normalized_source_patch_text: str,
    extra_strip: int,
    nixpkgs_rev: str | None,
    source_root: str | None,
    effective_root: Path,
    source_hash: str | None,
    dry_run_output: str,
    patch_flags: list[str],
    patcher_invocation_sha: str | None,
) -> dict[str, Any]:
    """Build the `patch-normalization.json` attestation. Raises
    :class:`NormalizationError` if the body-identity proof does NOT hold —
    this is the tool's hard safety gate: it must never emit an attestation
    claiming a path-only change when the hunk bodies actually differ.
    """
    raw_body_hash = sha256_text(strip_path_headers(raw_source_patch_text))
    norm_body_hash = sha256_text(strip_path_headers(normalized_source_patch_text))
    if raw_body_hash != norm_body_hash:
        raise NormalizationError(
            "body-identity proof FAILED: stripping path headers from the raw "
            "and normalized source patch yields DIFFERENT hunk-body hashes "
            f"({raw_body_hash} != {norm_body_hash}) — refusing to attest a "
            "path-only change; this indicates a bug in the rewrite, not just "
            "a path mismatch"
        )
    return {
        "schema": ATTESTATION_SCHEMA,
        "tool": {"name": "trace-bundle-normalize-sourceroot", "version": NORMALIZER_VERSION},
        "bundle_dir": str(bundle_dir),
        "raw_patch_diff_sha256": sha256_text(raw_patch_diff_text),
        "raw_source_patch_sha256": sha256_text(raw_source_patch_text),
        "normalized_patch_diff_sha256": sha256_text(normalized_patch_diff_text),
        "normalized_source_patch_sha256": sha256_text(normalized_source_patch_text),
        "patcher_invocation_raw_response_sha256": patcher_invocation_sha,
        "extra_path_components_stripped": extra_strip,
        "path_mappings": compute_path_mappings(raw_source_patch_text, normalized_source_patch_text),
        "body_identity_proof": {
            "raw_body_sha256": raw_body_hash,
            "normalized_body_sha256": norm_body_hash,
            "identical": True,
        },
        "nixpkgs_rev": nixpkgs_rev,
        "effective_source_root": source_root,
        "effective_root_path": str(effective_root),
        "source_hash": source_hash,
        "dry_run": {
            "applies": True, "fuzz": 0,
            "patch_flags": list(patch_flags),
            "output": dry_run_output[:4096],
        },
        # Filled by the caller once the Reviewer has re-scored the normalized
        # bytes (this tool never invokes the Reviewer itself — that is a live
        # model call and out of scope for a deterministic local check).
        "reviewer_attestation": None,
    }


# ─── CLI ─────────────────────────────────────────────────────────────────────

def add_parser(subs: argparse._SubParsersAction) -> argparse.ArgumentParser:
    p = subs.add_parser(
        "normalize-sourceroot",
        help=(
            "detect + (with --apply) fix a path-strip mismatch between the "
            "model's patch.diff and the derivation's effective sourceRoot"
        ),
        description=(
            "Without --apply: reports/gates only (fail-closed, no write) — "
            "use as a pre-cert check. With --apply: rewrites patch.diff's "
            "source-patch path headers to the unique normalizing depth and "
            f"writes {ATTESTATION_FILENAME} (raw/normalized hashes, path "
            "remap, and a proof that only path headers changed)."
        ),
    )
    p.add_argument("bundle_dir", type=Path)
    p.add_argument(
        "--source-tree", type=Path, default=None,
        help="pre-unpacked EFFECTIVE source root (the dir patchPhase would "
             "cd into) to dry-run against; skips the nix unpack.",
    )
    p.add_argument(
        "--strip-max", type=int, default=DEFAULT_MAX_EXTRA_STRIP,
        help=f"max extra path components to try stripping (default {DEFAULT_MAX_EXTRA_STRIP})",
    )
    p.add_argument(
        "--patch-flags", type=str, default=None, metavar="FLAGS",
        help="(--source-tree mode only) the package's patchFlags to dry-run "
             "with, as one whitespace-separated string. Use the `=` form so "
             "argparse accepts dash-prefixed values, e.g. --patch-flags=-p0 or "
             "--patch-flags='-p0 -d sub'. Ignored when the source is "
             "nix-unpacked (the package's evaluated patchFlags are used). "
             "Defaults to -p1.",
    )
    p.add_argument("--apply", action="store_true",
                    help="write the normalized patch.diff + attestation")
    p.add_argument("--format", choices=("human", "json"), default="human")
    return p


def _emit_error(fmt: str, exit_code: int, message: str) -> int:
    if fmt == "json":
        json.dump({"ok": False, "error": message}, sys.stdout, indent=2)
        sys.stdout.write("\n")
    else:
        print(f"error: {message}", file=sys.stderr)
    return exit_code


def run(args: argparse.Namespace, repo_root: Path) -> int:
    bundle_dir: Path = args.bundle_dir.resolve()
    if not bundle_dir.is_dir():
        return _emit_error(args.format, EXIT_NOT_FOUND, f"bundle dir not found: {bundle_dir}")

    patch_diff_path = bundle_dir / "patch.diff"
    if not patch_diff_path.is_file():
        return _emit_error(args.format, EXIT_NOT_FOUND,
                            f"no patch.diff in {bundle_dir}")
    raw_patch_diff_text = patch_diff_path.read_text()
    try:
        raw_inner_text, nested_names = nested_patch.extract_nested_source_patch(
            raw_patch_diff_text)
    except nested_patch.NestedPatchError as exc:
        return _emit_error(args.format, EXIT_EXTRACT_FAILED, str(exc))

    source_root: str | None = None
    nixpkgs_rev: str | None = None
    source_hash: str | None = None
    tmp_ctx = tempfile.TemporaryDirectory(prefix="trace-normalize-")
    try:
        tmp_root = Path(tmp_ctx.name)
        if args.source_tree is not None:
            effective_root = args.source_tree.resolve()
            if not effective_root.is_dir():
                return _emit_error(args.format, EXIT_NOT_FOUND,
                                    f"--source-tree not a directory: {effective_root}")
            # No nix eval in --source-tree mode: honor an explicit --patch-flags
            # override so a non-`-p1` package can still be validated faithfully;
            # default to the nixpkgs default when unspecified.
            _pf = getattr(args, "patch_flags", None)
            # Accept either a pre-split list (programmatic callers) or the CLI's
            # single whitespace-separated string (parsed with the `=` form so
            # argparse doesn't mistake `-p0` for an option).
            # Only None → nixpkgs default. A CLI string splits (empty string →
            # explicit empty flags); a programmatic list (even empty) is honored.
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
            # patchPhase applies the package's own `patches` list BEFORE the
            # model patch. Searching strip depths against pristine pkg.src could
            # attest a depth that fails the real build (a preceding patch may
            # shift the target context/paths). Mirror the preflight gate: fail
            # closed, require a prepared --source-tree. (0 for krb5 on Linux.)
            if eff.preceding_patches > 0:
                return _emit_error(
                    args.format, EXIT_UNPACK_FAILED,
                    f"package applies {eff.preceding_patches} preceding "
                    f"patch(es) before the model patch; normalizing against "
                    f"pristine pkg.src may attest a strip that fails the real "
                    f"patchPhase. Pass --source-tree with a tree already "
                    f"prepared through those patches.")
            effective_root = eff.effective_root
            source_root = eff.source_root
            nixpkgs_rev = eff.nixpkgs_rev
            source_hash = eff.store_path.name
            patch_flags = eff.patch_flags  # the package's evaluated patchFlags

        extra_strip, attempts = find_unique_normalizing_strip(
            effective_root, raw_inner_text, args.strip_max, patch_flags)

        if extra_strip == 0:
            # Nothing to normalize; record a pass.
            result = {
                "ok": True, "bundle_dir": str(bundle_dir),
                "normalization_needed": False,
                "nested_patch_files": nested_names,
                "effective_root": str(effective_root),
                "source_root": source_root,
                "diagnostics": attempts[0][1][:4096],
            }
            _emit(args.format, result, "NORMALIZE-SOURCEROOT: already applies (no change needed)")
            return EXIT_OK

        if extra_strip is None:
            n_ok = sum(1 for ok, _ in attempts.values() if ok)
            detail = {k: (ok, out[:500]) for k, (ok, out) in attempts.items()}
            msg = (
                f"no unique normalizing strip found ({n_ok} of "
                f"{len(attempts)} depths applied at fuzz=0) — this is either "
                f"a genuine base mismatch (0 succeed) or an ambiguous patch "
                f"(>1 succeed); refusing to guess. attempts={detail!r}"
            )
            _emit(args.format, {"ok": False, "bundle_dir": str(bundle_dir), "error": msg,
                                 "attempts": {str(k): v[0] for k, v in attempts.items()}},
                  f"NORMALIZE-SOURCEROOT: AMBIGUOUS/UNRESOLVED\n{msg}", is_error=True)
            return EXIT_AMBIGUOUS

        # extra_strip is a unique positive depth: normalizable.
        normalized_inner_text = rewrite_patch_paths(raw_inner_text, extra_strip)
        dry_ok, dry_output = attempts[extra_strip]
        assert dry_ok  # find_unique_normalizing_strip only returns a succeeding depth

        if not args.apply:
            msg = (
                f"patch.diff needs {extra_strip} extra leading path "
                f"component(s) stripped to apply from the effective "
                f"sourceRoot ({effective_root}); re-run with --apply to fix "
                f"it and emit {ATTESTATION_FILENAME}"
            )
            _emit(args.format, {
                "ok": False, "bundle_dir": str(bundle_dir),
                "normalization_needed": True,
                "extra_path_components_stripped": extra_strip,
                "effective_root": str(effective_root),
                "source_root": source_root,
                "error": msg,
            }, f"NORMALIZE-SOURCEROOT: FAIL-CLOSED (no --apply)\n{msg}", is_error=True)
            return EXIT_APPLY_FAILED

        try:
            normalized_patch_diff_text = normalize_patch_diff(
                raw_patch_diff_text, extra_strip)
            attestation = build_attestation(
                bundle_dir=bundle_dir,
                raw_patch_diff_text=raw_patch_diff_text,
                normalized_patch_diff_text=normalized_patch_diff_text,
                raw_source_patch_text=raw_inner_text,
                normalized_source_patch_text=normalized_inner_text,
                extra_strip=extra_strip,
                nixpkgs_rev=nixpkgs_rev,
                source_root=source_root,
                effective_root=effective_root,
                source_hash=source_hash,
                dry_run_output=dry_output,
                patch_flags=patch_flags,
                patcher_invocation_sha=_read_patcher_invocation_sha(bundle_dir),
            )
        except NormalizationError as exc:
            _emit(args.format, {"ok": False, "bundle_dir": str(bundle_dir), "error": str(exc)},
                  f"NORMALIZE-SOURCEROOT: REFUSED\n{exc}", is_error=True)
            return EXIT_APPLY_FAILED
    finally:
        tmp_ctx.cleanup()

    patch_diff_path.write_text(normalized_patch_diff_text)
    (bundle_dir / ATTESTATION_FILENAME).write_text(json.dumps(attestation, indent=2) + "\n")
    _emit(args.format, {"ok": True, "bundle_dir": str(bundle_dir), "attestation": attestation},
          f"NORMALIZE-SOURCEROOT: APPLIED (extra_strip={extra_strip})\n"
          f"  wrote: patch.diff, {ATTESTATION_FILENAME}\n"
          f"  path mappings: {attestation['path_mappings']}")
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


def _emit(fmt: str, payload: dict[str, Any], human_header: str, is_error: bool = False) -> None:
    if fmt == "json":
        json.dump(payload, sys.stdout, indent=2)
        sys.stdout.write("\n")
    else:
        print(human_header, file=sys.stderr if is_error else sys.stdout)
