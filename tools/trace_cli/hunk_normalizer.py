"""Deterministic hunk-header normalization for the source-backport adaptation lane.

When the Patcher AUTHORS a semantic adaptation (``applies_verbatim == false``), it
must write a fresh unified-diff hunk header ``@@ -a,b +c,d @@``. The model reliably
produces correct hunk *body* content but miscomputes the header arithmetic
(observed 2026-07-27 on libarchive CVE-2026-15028: it emitted ``@@ -3517,13`` — the
upstream start line plus wrong counts — for a hunk whose body sits at pinned line
3443 with 16/16 lines). The verbatim lane copies the upstream header (always
correct); only the adaptation lane authors one, so this normalizer runs on the
adaptation lane only.

The normalizer is a PURE metadata recompute:

  * It rewrites ONLY the ``@@ -a,b +c,d @@`` numbers, never body lines.
  * It matches each hunk's old-side body (context + deletions) exactly and
    uniquely against the pre-patch source in ``source-context/``. No fuzz, no
    whitespace tolerance, no ambiguity: zero matches or >1 match => FAIL.
  * New-side start lines are derived from prior-hunk deltas; both counts are
    recomputed from the body.
  * A hunk whose target file is NOT in ``source-context`` is left untouched
    (``package.nix``, the new-file ``.patch`` wrapper, etc.).

It fails loudly (``HunkNormalizationError``) rather than silently "fixing" an
inconsistent body: a body line that does not exist in the pinned source is a real
defect the model must own, not something to paper over.

Canonical source-backport shape: the outer nixpkgs-tree diff ADDS a ``.patch``
file whose *content* is the inner unified diff Nix's ``patchPhase`` applies. The
broken header lives inside that embedded content, so the normalizer recurses into
embedded ``.patch`` new-file sections, strips the outer ``+`` prefix, normalizes
the inner diff, and re-embeds — recomputing the outer new-file line count. A flat
source-backport (hunks directly against a tree source file) is handled by the same
inner routine run over the outer lines.
"""

from __future__ import annotations

import difflib
import re
from dataclasses import dataclass, field
from hashlib import sha256


class HunkNormalizationError(Exception):
    """Raised when a hunk body cannot be grounded uniquely in the pinned source.

    This is a fail-don't-fix signal: the model's diff body references source that
    does not exist (or is ambiguous) in ``source-context``, so no honest header
    can be computed. The caller must surface it, not swallow it.
    """


@dataclass
class NormalizationResult:
    """Outcome of a normalization pass."""

    text: str
    rewrites: list[dict] = field(default_factory=list)

    @property
    def changed(self) -> bool:
        return bool(self.rewrites)


_HUNK_HEADER_RE = re.compile(
    r"^@@ -(?P<old_start>\d+)(?:,(?P<old_count>\d+))? "
    r"\+(?P<new_start>\d+)(?:,(?P<new_count>\d+))? @@(?P<trailing>.*)$"
)

# A bare / rangeless hunk header: the model emitted `@@` (or `@@ @@`) with no
# `-l,s +l,s` ranges at all (observed 2026-07-27 on maxima CVE-2024-34490, opus-4-7,
# inside a nested in-tree `.patch`). It is unambiguous — a unified-diff *body* line
# always carries a ` `/`+`/`-`/`\` prefix, so a line whose first two chars are `@@`
# and which is not a full header is a header stub to synthesize from the body. Any
# trailing code-context after the (optional) closing `@@` is preserved.
_BARE_HUNK_RE = re.compile(r"^@@(?:\s*@@)?(?P<trailing>.*)$")


def _match_hunk_header(line: str) -> tuple[bool, str] | None:
    """Classify a possible hunk-header line.

    Returns ``(is_full, trailing)`` for a header line, else ``None``. ``is_full``
    True means the line already carries numeric ranges (which may still be wrong —
    they are recomputed either way); False means a bare/rangeless stub whose ranges
    must be synthesized entirely from the body. A diff body line (prefixed
    ` `/`+`/`-`/`\\`) never starts with ``@@``, so this never misclassifies body
    content as a header.
    """
    m = _HUNK_HEADER_RE.match(line)
    if m is not None:
        return (True, m.group("trailing"))
    if line.startswith("@@"):
        bm = _BARE_HUNK_RE.match(line)
        return (False, bm.group("trailing") if bm is not None else "")
    return None


def _strip_ab_prefix(path: str) -> str:
    """Strip a leading ``a/`` or ``b/`` and any trailing tab-metadata."""
    path = path.split("\t", 1)[0].strip()
    if path.startswith(("a/", "b/")):
        return path[2:]
    return path


def _resolve_source_key(path: str, source_context: dict[str, str]) -> str | None:
    """Resolve a diff path to exactly one ``source-context`` key, or None.

    Matches on full path-component suffix in either direction so that a diff
    path ``libarchive/foo.c`` resolves to a key ``libarchive/foo.c`` (exact) and
    a bare ``foo.c`` resolves to ``libarchive/foo.c`` (suffix). Raises on an
    ambiguous match (>1 candidate) — ambiguity is never silently resolved.
    """
    stripped = _strip_ab_prefix(path)
    candidates = []
    for key in source_context:
        if stripped == key or stripped.endswith("/" + key) or key.endswith("/" + stripped):
            candidates.append(key)
    if len(candidates) > 1:
        raise HunkNormalizationError(
            f"diff path {path!r} matches multiple source-context files: {candidates!r}"
        )
    return candidates[0] if candidates else None


def _fmt_side(start: int, count: int) -> str:
    """Format one side of a hunk header, omitting ``,1`` per GNU-diff convention."""
    return f"{start}" if count == 1 else f"{start},{count}"


def _unique_old_start(source_lines: list[str], old_side: list[str], file_label: str) -> int:
    """Return the 1-based start line where ``old_side`` matches ``source_lines`` exactly once.

    No fuzz, no whitespace tolerance. Zero matches or more than one match is an
    error — the header cannot be grounded.
    """
    n = len(old_side)
    if n == 0:
        raise HunkNormalizationError(
            f"{file_label}: hunk has no old-side (context/deletion) lines to ground against"
        )
    hits = [
        i
        for i in range(0, len(source_lines) - n + 1)
        if source_lines[i : i + n] == old_side
    ]
    if not hits:
        raise HunkNormalizationError(
            f"{file_label}: hunk old-side body does not match the pinned source "
            f"(no exact match for {n} context/deletion lines) — the adaptation is "
            f"not grounded in source-context; refusing to fabricate a header"
        )
    if len(hits) > 1:
        raise HunkNormalizationError(
            f"{file_label}: hunk old-side body matches the pinned source in "
            f"{len(hits)} places (ambiguous) — refusing to guess the header line"
        )
    return hits[0] + 1


def _normalize_unified_diff_lines(
    lines: list[str], source_context: dict[str, str]
) -> tuple[list[str], list[dict]]:
    """Normalize hunk headers of a flat unified diff, line list in / line list out.

    Only hunks whose current target file resolves into ``source_context`` are
    touched; everything else (structural lines, out-of-context files) passes
    through byte-for-byte. New-side starts accumulate per-file prior-hunk deltas.
    """
    out: list[str] = []
    rewrites: list[dict] = []

    cur_source_lines: list[str] | None = None
    cur_label: str | None = None
    running_delta = 0

    i = 0
    while i < len(lines):
        line = lines[i]

        if line.startswith("+++ "):
            path = line[4:]
            key = _resolve_source_key(path, source_context)
            cur_source_lines = source_context[key].split("\n") if key is not None else None
            cur_label = _strip_ab_prefix(path)
            running_delta = 0
            out.append(line)
            i += 1
            continue

        if line.startswith("--- ") or line.startswith("diff --git "):
            # New file section may begin without a fresh +++ yet; reset context so
            # a stale source doesn't leak across files. The +++ line sets it.
            if line.startswith("diff --git "):
                cur_source_lines = None
                cur_label = None
            out.append(line)
            i += 1
            continue

        header_match = _match_hunk_header(line)
        if header_match is not None:
            if cur_source_lines is None:
                # Hunk against a file not in source-context: pass through untouched.
                out.append(line)
                i += 1
                continue
            trailing = header_match[1]
            # Collect the hunk body up to the next hunk / file / diff boundary.
            j = i + 1
            body: list[str] = []
            while j < len(lines):
                bl = lines[j]
                if _match_hunk_header(bl) is not None:
                    break
                if bl.startswith("diff --git "):
                    break
                # `--- ` is ambiguous: it is a file header, but it is ALSO how a
                # deletion of a source line beginning with `-- ` renders. A real
                # file header comes in a `--- ` / `+++ ` pair, so only treat it as
                # a boundary when the next line is `+++ `; otherwise it is a
                # deletion line and belongs to the body. (codex review, slice 4.)
                if (
                    bl.startswith("--- ")
                    and j + 1 < len(lines)
                    and lines[j + 1].startswith("+++ ")
                ):
                    break
                # A conforming unified diff prefixes every body line (context
                # lines, even empty ones, carry a single leading space). A bare
                # empty line is the trailing-newline artifact / section boundary,
                # not hunk content: it terminates the body.
                if bl == "":
                    break
                body.append(bl)
                j += 1

            old_side: list[str] = []
            old_count = 0
            new_count = 0
            for bl in body:
                tag = bl[0]
                if tag == " ":
                    old_side.append(bl[1:])
                    old_count += 1
                    new_count += 1
                elif tag == "-":
                    old_side.append(bl[1:])
                    old_count += 1
                elif tag == "+":
                    new_count += 1
                elif tag == "\\":
                    # "\ No newline at end of file": not a counted line.
                    continue
                else:
                    raise HunkNormalizationError(
                        f"{cur_label}: unexpected hunk body line {bl!r}"
                    )

            old_start = _unique_old_start(cur_source_lines, old_side, cur_label or "?")
            new_start = old_start + running_delta
            new_header = (
                f"@@ -{_fmt_side(old_start, old_count)} "
                f"+{_fmt_side(new_start, new_count)} @@{trailing}"
            )
            if new_header != line:
                rewrites.append({"file": cur_label, "from": line, "to": new_header})
            out.append(new_header)
            out.extend(body)
            running_delta += new_count - old_count
            i = j
            continue

        out.append(line)
        i += 1

    return out, rewrites


def _looks_like_unified_diff(text_lines: list[str]) -> bool:
    """Heuristic: does this line list contain a unified-diff file+hunk header pair?

    A hunk header counts whether it carries numeric ranges or is a bare/rangeless
    stub (`@@`), so an embedded `.patch` whose inner headers the model left bare is
    still recognized as a nested diff to normalize rather than passed through.
    """
    has_file = any(ln.startswith("--- ") for ln in text_lines)
    has_hunk = any(_match_hunk_header(ln) is not None for ln in text_lines)
    return has_file and has_hunk


def _split_outer_sections(lines: list[str]) -> list[tuple[int, int]]:
    """Return (start, end) index spans for each ``diff --git`` section, plus preamble.

    The preamble (anything before the first ``diff --git``) is returned as its own
    leading span with start == 0.
    """
    starts = [i for i, ln in enumerate(lines) if ln.startswith("diff --git ")]
    if not starts:
        return [(0, len(lines))]
    spans: list[tuple[int, int]] = []
    if starts[0] != 0:
        spans.append((0, starts[0]))
    for k, s in enumerate(starts):
        e = starts[k + 1] if k + 1 < len(starts) else len(lines)
        spans.append((s, e))
    return spans


def _is_new_file_section(section: list[str]) -> bool:
    return any(
        ln.startswith("new file mode") or ln == "--- /dev/null" for ln in section
    )


def _embedded_patch_bounds(section: list[str]) -> tuple[int, int] | None:
    """If a section adds a ``.patch`` file whose content is a unified diff, return
    the (start, end) index range of its ``+``-prefixed content lines within the
    section; else None.
    """
    # Find the outer new-file hunk header (@@ -0,0 +1,N @@).
    hunk_idx = None
    for idx, ln in enumerate(section):
        if ln.startswith("@@ ") and _HUNK_HEADER_RE.match(ln):
            hunk_idx = idx
            break
    if hunk_idx is None:
        return None
    content_start = hunk_idx + 1
    # Trailing empty lines are the diff's final-newline artifact / section
    # boundary, not embedded content — exclude them from the content span so the
    # all-`+` check and the re-embed line count are exact.
    end = len(section)
    while end > content_start and section[end - 1] == "":
        end -= 1
    core = section[content_start:end]
    if not core or not all(ln.startswith("+") for ln in core):
        return None
    inner = [ln[1:] for ln in core]
    if not _looks_like_unified_diff(inner):
        return None
    return (content_start, end)


def normalize_backport_patch(
    patch_text: str, source_context: dict[str, str]
) -> NormalizationResult:
    """Normalize the adaptation-lane patch's hunk headers against ``source_context``.

    Recomputes ``@@`` headers deterministically from hunk bodies matched uniquely
    against the pinned pre-patch source. Handles the canonical nested shape (an
    added ``.patch`` file carrying the inner diff) and the flat shape (hunks
    directly against a source-context file). Body lines are never modified.

    Raises HunkNormalizationError on an ungroundable / ambiguous body. Idempotent:
    a byte-correct verbatim patch passes through with zero rewrites.
    """
    if not patch_text:
        return NormalizationResult(text=patch_text, rewrites=[])

    lines = patch_text.split("\n")
    spans = _split_outer_sections(lines)
    rewrites: list[dict] = []
    result_lines: list[str] = []

    for start, end in spans:
        section = lines[start:end]
        if start == end:
            continue
        # Preamble span (before first diff --git) is not a real section.
        if not section or not section[0].startswith("diff --git "):
            result_lines.extend(section)
            continue

        bounds = None
        if _is_new_file_section(section):
            bounds = _embedded_patch_bounds(section)

        if bounds is not None:
            c_start, c_end = bounds
            header = section[:c_start]
            content = section[c_start:c_end]
            tail = section[c_end:]  # trailing empty lines, preserved verbatim
            inner = [ln[1:] for ln in content]
            inner_norm, inner_rewrites = _normalize_unified_diff_lines(inner, source_context)
            rewrites.extend(inner_rewrites)
            re_embedded = ["+" + ln for ln in inner_norm]
            # The .patch file this section adds — used to label an outer rewrite.
            patch_label = None
            for hl in header:
                if hl.startswith("+++ "):
                    patch_label = _strip_ab_prefix(hl[4:])
                    break
            # Recompute the outer new-file hunk header line count. If the model's
            # declared count was wrong (independent of the inner headers), record
            # the rewrite so provenance/`changed` reflect the mutation.
            new_header = list(header)
            for hi, hl in enumerate(new_header):
                if hl.startswith("@@ ") and _HUNK_HEADER_RE.match(hl):
                    m = _HUNK_HEADER_RE.match(hl)
                    assert m is not None
                    recomputed = f"@@ -0,0 +1,{len(re_embedded)} @@{m.group('trailing')}"
                    if recomputed != hl:
                        rewrites.append(
                            {"file": patch_label, "from": hl, "to": recomputed}
                        )
                    new_header[hi] = recomputed
                    break
            result_lines.extend(new_header)
            result_lines.extend(re_embedded)
            result_lines.extend(tail)
        else:
            sec_norm, sec_rewrites = _normalize_unified_diff_lines(section, source_context)
            rewrites.extend(sec_rewrites)
            result_lines.extend(sec_norm)

    return NormalizationResult(text="\n".join(result_lines), rewrites=rewrites)


# ─── canonical compilation (supersedes metadata-only normalization) ───────────
#
# The metadata-only normalizer above recomputes a hunk's ``@@`` header but leaves
# the body verbatim. That is insufficient: the adaptation-lane model also authors
# NON-CANONICAL bodies — it redundantly deletes+re-adds byte-identical lines and
# omits trailing context — which GNU ``patch``/``git apply`` reject at default fuzz
# even when the header is correct and every line matches the pinned source
# (observed 2026-07-27 on maxima CVE-2024-34490: a hunk whose old-side matched
# source exactly still failed ``patch --fuzz=0``; the equivalent difflib-canonical
# form applied). The fix (codex-directed, 2026-07-27) is a *transparent
# compilation step*, not a correction of model intent:
#
#   1. preserve+hash the raw model patch (done by the caller);
#   2. exact, UNIQUE old-side match of each model hunk against signed
#      ``source-context`` (ambiguous/absent => fail, never guess);
#   3. construct the postimage SOLELY from the model's own old/new body — splice
#      each hunk's new-side in place of its matched old-side;
#   4. re-diff the original source against that postimage with ``difflib`` — this
#      is what eliminates redundant del/readd, fixes boundaries, and emits correct
#      headers regardless of what the model wrote (bare ``@@`` included);
#   5. verify the canonical diff re-applies at fuzz 0 and reproduces the postimage
#      (an internal invariant; the caller's ``patch --dry-run`` gate is the
#      load-bearing external check);
#   6. record raw→canonical provenance.
#
# Semantic mistakes the model made stay in the postimage and therefore remain
# visible to the Reviewer and Builder — canonicalization changes representation,
# never meaning.


@dataclass
class CanonicalizationResult:
    """Outcome of a canonical-compilation pass over an adaptation-lane patch.

    ``changed`` means the canonical bytes differ from the raw model bytes (the model
    authored a non-canonical patch we recompiled); ``files`` carries per-file
    provenance (model vs canonical hunk counts + postimage sha256) for every
    source-context file that was compiled, recorded even when the output is already
    canonical.
    """

    text: str
    files: list[dict] = field(default_factory=list)
    changed: bool = False


# Unprefixed git directives that carry file-level semantics beyond content hunks.
# `index …` blob-hash lines are intentionally excluded — they are cosmetic (patch
# ignores them, git apply recomputes) and safe to drop.
_GIT_METADATA_PREFIXES = (
    "old mode ",
    "new mode ",
    "rename from ",
    "rename to ",
    "copy from ",
    "copy to ",
    "deleted file mode ",
    "new file mode ",
)


def _parse_flat_hunks(diff_lines: list[str]) -> list[tuple[str | None, list[str], list[str]]]:
    """Parse a flat unified diff into ``(target_path, old_side, new_side)`` per hunk.

    ``old_side`` = context+deletion content (no prefix); ``new_side`` =
    context+addition content. Bare/rangeless ``@@`` headers are handled via
    ``_match_hunk_header`` — the model's header numbers are irrelevant here because
    the canonical header is re-derived, so only hunk *segmentation* matters.
    """
    hunks: list[tuple[str | None, list[str], list[str]]] = []
    cur_path: str | None = None
    i = 0
    n = len(diff_lines)
    while i < n:
        line = diff_lines[i]
        if line.startswith("+++ "):
            cur_path = _strip_ab_prefix(line[4:])
            i += 1
            continue
        if line.startswith("--- ") or line.startswith("diff --git "):
            i += 1
            continue
        if _match_hunk_header(line) is not None:
            i += 1
            old_side: list[str] = []
            new_side: list[str] = []
            while i < n:
                bl = diff_lines[i]
                if _match_hunk_header(bl) is not None:
                    break
                if bl.startswith("diff --git "):
                    break
                if (
                    bl.startswith("--- ")
                    and i + 1 < n
                    and diff_lines[i + 1].startswith("+++ ")
                ):
                    break
                if bl == "":
                    break
                tag = bl[:1]
                if tag == " ":
                    old_side.append(bl[1:])
                    new_side.append(bl[1:])
                elif tag == "-":
                    old_side.append(bl[1:])
                elif tag == "+":
                    new_side.append(bl[1:])
                elif tag == "\\":
                    # `\ No newline at end of file`. Canonicalization reconstructs
                    # the postimage from LOGICAL lines and cannot faithfully model an
                    # EOF-newline change, so fail closed rather than silently drop the
                    # marker and emit bytes that differ from the recorded postimage.
                    raise HunkNormalizationError(
                        f"{cur_path or '?'}: hunk carries a '\\ No newline at end of "
                        f"file' marker — EOF-newline changes are not supported by "
                        f"canonicalization (fail closed)"
                    )
                else:
                    raise HunkNormalizationError(
                        f"{cur_path or '?'}: unexpected hunk body line {bl!r}"
                    )
                i += 1
            hunks.append((cur_path, old_side, new_side))
            continue
        i += 1
    return hunks


def _split_source_lines(text: str) -> tuple[list[str], bool]:
    """Split file text into LOGICAL lines the way GNU patch counts them.

    A plain ``text.split("\\n")`` appends a phantom empty element for a
    newline-terminated file; ``difflib`` would then treat that phantom as a real
    blank context line and inflate hunk ranges (``old\\n`` -> ``@@ -1,2`` instead of
    ``@@ -1``), which GNU ``patch`` rejects when a change sits within a context
    window of EOF. Drop the phantom, and return whether the file ended with a
    newline so the postimage bytes can be reconstructed faithfully.
    """
    if text == "":
        return [], False
    had_newline = text.endswith("\n")
    lines = text.split("\n")
    if had_newline:
        lines = lines[:-1]
    return lines, had_newline


def _apply_canonical_single_file(source_lines: list[str], ud_lines: list[str]) -> list[str]:
    """Apply a single-file difflib unified diff to ``source_lines`` at fuzz 0.

    A minimal, strict applier used only to VERIFY the canonical diff reproduces the
    intended postimage; any context/deletion that does not match the source exactly
    raises (which would mean a defect in our own compilation, not the model's).
    """
    out: list[str] = []
    src_idx = 0
    i = 0
    n = len(ud_lines)
    while i < n:
        line = ud_lines[i]
        if line.startswith("--- ") or line.startswith("+++ "):
            i += 1
            continue
        m = _HUNK_HEADER_RE.match(line)
        if m is None:
            i += 1
            continue
        old_start = int(m.group("old_start"))
        while src_idx < old_start - 1:
            out.append(source_lines[src_idx])
            src_idx += 1
        i += 1
        while i < n and _HUNK_HEADER_RE.match(ud_lines[i]) is None and not ud_lines[
            i
        ].startswith(("--- ", "+++ ")):
            bl = ud_lines[i]
            tag = bl[:1]
            if tag == " ":
                if src_idx >= len(source_lines) or source_lines[src_idx] != bl[1:]:
                    raise HunkNormalizationError("canonical self-apply: context mismatch")
                out.append(bl[1:])
                src_idx += 1
            elif tag == "-":
                if src_idx >= len(source_lines) or source_lines[src_idx] != bl[1:]:
                    raise HunkNormalizationError("canonical self-apply: deletion mismatch")
                src_idx += 1
            elif tag == "+":
                out.append(bl[1:])
            i += 1
    out.extend(source_lines[src_idx:])
    return out


def _compile_canonical_diff(
    diff_lines: list[str], source_context: dict[str, str]
) -> tuple[list[str], list[dict]]:
    """Compile a flat model diff into a canonical, applying unified diff.

    Every hunk must target a ``source_context`` file (source-backport inner diffs
    only touch pinned source). Returns ``(canonical_lines, provenance_records)``.
    """
    # Fail closed on git metadata directives (mode change / rename / copy / delete /
    # new-file). Canonicalization compiles CONTENT hunks only and reconstructs just
    # `---`/`+++`/`@@` headers, so silently dropping these would change the patch's
    # semantics. Source-backport content edits never carry them; a real one is a
    # signal to stop, not to paper over. (A diff *body* line is prefixed
    # ` `/`+`/`-`, so an unprefixed directive here is unambiguously metadata.)
    for ln in diff_lines:
        for pfx in _GIT_METADATA_PREFIXES:
            if ln.startswith(pfx):
                raise HunkNormalizationError(
                    f"adaptation diff carries a git metadata directive {ln!r} "
                    f"(mode/rename/copy/delete/new-file); canonicalization compiles "
                    f"content hunks only — fail closed"
                )

    hunks = _parse_flat_hunks(diff_lines)
    if not hunks:
        return list(diff_lines), []

    # Group hunks by resolved source-context key, preserving first-seen order.
    grouped: dict[str, list[tuple[list[str], list[str]]]] = {}
    order: list[str] = []
    for path, old_side, new_side in hunks:
        key = _resolve_source_key(path, source_context) if path is not None else None
        if key is None:
            raise HunkNormalizationError(
                f"adaptation diff targets {path!r}, which is not in source-context; "
                f"cannot canonicalize an ungrounded hunk"
            )
        if key not in grouped:
            grouped[key] = []
            order.append(key)
        grouped[key].append((old_side, new_side))

    canonical: list[str] = []
    records: list[dict] = []
    for key in order:
        source_lines, had_newline = _split_source_lines(source_context[key])
        if not had_newline:
            # A non-newline-terminated pinned source needs `\ No newline` markers to
            # canonicalize losslessly; source-backport source files are always
            # newline-terminated, so fail closed rather than risk postimage drift.
            raise HunkNormalizationError(
                f"{key}: pinned source is not newline-terminated — canonicalization "
                f"cannot preserve EOF-newline state (fail closed)"
            )
        placed: list[tuple[int, int, list[str]]] = []
        for old_side, new_side in grouped[key]:
            if not old_side:
                raise HunkNormalizationError(
                    f"{key}: hunk has no old-side lines to ground against"
                )
            start = _unique_old_start(source_lines, old_side, key) - 1
            # Reduce the hunk to its minimal CORE edit by stripping the common
            # leading/trailing context (lines identical on the old and new sides).
            # Two hunks that overlap only through shared surrounding context then
            # have DISJOINT cores; only genuinely conflicting edits (both changing
            # the same source line) overlap. The postimage is identical either way —
            # the stripped context is byte-equal source that is simply copied.
            p = 0
            while p < len(old_side) and p < len(new_side) and old_side[p] == new_side[p]:
                p += 1
            s = 0
            while (
                s < len(old_side) - p
                and s < len(new_side) - p
                and old_side[len(old_side) - 1 - s] == new_side[len(new_side) - 1 - s]
            ):
                s += 1
            core_old = old_side[p : len(old_side) - s]
            core_new = new_side[p : len(new_side) - s]
            placed.append((start + p, len(core_old), core_new))
        # Sort by (start, core-length): a zero-length insertion at a boundary orders
        # BEFORE a replacement that consumes the line at the same start, so the two
        # compose deterministically regardless of the model's hunk order (an
        # insertion at `start` places its lines before the replaced region). Two
        # real replacements at the same start still overlap and are rejected below.
        placed.sort(key=lambda t: (t[0], t[1]))

        postimage: list[str] = []
        cursor = 0
        for start, old_len, new_side in placed:
            if start < cursor:
                raise HunkNormalizationError(
                    f"{key}: conflicting adaptation edits overlap at source line "
                    f"{start + 1} (two hunks change the same line)"
                )
            postimage.extend(source_lines[cursor:start])
            postimage.extend(new_side)
            cursor = start + old_len
        postimage.extend(source_lines[cursor:])

        ud = list(
            difflib.unified_diff(
                source_lines, postimage, f"a/{key}", f"b/{key}", n=3, lineterm=""
            )
        )
        # Internal invariant: the canonical diff must reproduce the postimage.
        if _apply_canonical_single_file(source_lines, ud) != postimage:
            raise HunkNormalizationError(
                f"{key}: canonical diff does not reproduce the postimage (compiler bug)"
            )
        canonical.extend(ud)
        # Postimage bytes = logical lines rejoined + the file's original trailing
        # newline (source-backports don't change EOF), so the hash matches what
        # Nix's patchPhase produces on disk.
        postimage_text = "\n".join(postimage) + ("\n" if had_newline else "")
        records.append(
            {
                "file": key,
                "model_hunks": len(grouped[key]),
                "canonical_hunks": sum(1 for ln in ud if _HUNK_HEADER_RE.match(ln)),
                "postimage_sha256": sha256(postimage_text.encode("utf-8")).hexdigest(),
            }
        )
    return canonical, records


def _rewrite_outer_new_file_count(header: list[str], count: int) -> list[str]:
    """Return ``header`` with the outer new-file hunk line's count set to ``count``."""
    out = list(header)
    for hi, hl in enumerate(out):
        if hl.startswith("@@ ") and _HUNK_HEADER_RE.match(hl):
            m = _HUNK_HEADER_RE.match(hl)
            assert m is not None
            out[hi] = f"@@ -0,0 +1,{count} @@{m.group('trailing')}"
            break
    return out


def _section_targets_source(section: list[str], source_context: dict[str, str]) -> bool:
    """True if the section's ``diff --git`` target resolves into source-context.

    The target is read from the unambiguous ``diff --git a/X b/X`` header, NOT by
    scanning for ``+++`` — a diff *body* addition whose content begins with ``++``
    renders as ``+++ …`` and would otherwise be mistaken for a file header. Body
    lines are prefixed ` `/`+`/`-`, so they can never start with ``diff --git ``.
    ``_split_outer_sections`` gives one ``diff --git`` per section.
    """
    if not section or not section[0].startswith("diff --git "):
        return False
    parts = section[0][len("diff --git ") :].split(" ", 1)
    return bool(parts) and _resolve_source_key(parts[0], source_context) is not None


def _prepend_git_headers(ud_lines: list[str]) -> list[str]:
    """Insert a ``diff --git a/f b/f`` line before each file's ``--- a/f`` header.

    ``difflib`` emits only ``--- ``/``+++ `` headers; a leading ``diff --git`` keeps
    the flat outer patch git-compatible without changing what ``patch -p1`` applies.
    """
    out: list[str] = []
    for ln in ud_lines:
        if ln.startswith("--- "):
            path = _strip_ab_prefix(ln[4:])
            out.append(f"diff --git a/{path} b/{path}")
        out.append(ln)
    return out


def canonicalize_backport_patch(
    patch_text: str, source_context: dict[str, str]
) -> CanonicalizationResult:
    """Compile an adaptation-lane patch into a canonical, applying unified diff.

    Handles the canonical nested shape (an added ``.patch`` file whose content is
    the inner diff Nix's ``patchPhase`` applies) and the flat shape (hunks directly
    against a source-context file). Out-of-context sections (``package.nix``) pass
    through byte-for-byte. Raises ``HunkNormalizationError`` on an ungroundable,
    ambiguous, or overlapping hunk. Idempotent: a byte-canonical patch recompiles
    to itself.
    """
    if not patch_text:
        return CanonicalizationResult(text=patch_text, files=[])

    lines = patch_text.split("\n")
    spans = _split_outer_sections(lines)
    # Blocks emitted in order; flat-source sections are DEFERRED (collected across
    # the whole patch) so multiple `diff --git` sections targeting one file are
    # compiled against a single postimage — otherwise a later same-file section
    # would still expect the original preimage and conflict after the first applies.
    blocks: list[list[str]] = []
    records: list[dict] = []
    flat_diff_lines: list[str] = []
    flat_block_index: int | None = None

    for start, end in spans:
        section = lines[start:end]
        if not section:
            continue
        if not section[0].startswith("diff --git "):
            blocks.append(list(section))  # preamble
            continue

        bounds = _embedded_patch_bounds(section) if _is_new_file_section(section) else None
        if bounds is not None:
            c_start, c_end = bounds
            header = section[:c_start]
            content = section[c_start:c_end]
            tail = section[c_end:]  # trailing empties, verbatim
            inner = [ln[1:] for ln in content]
            first_diff = next(
                (k for k, l in enumerate(inner) if l.startswith(("--- ", "diff --git "))),
                len(inner),
            )
            preamble = inner[:first_diff]  # model prose header, inert to patch
            canonical_inner, recs = _compile_canonical_diff(inner[first_diff:], source_context)
            records.extend(recs)
            new_inner = preamble + canonical_inner
            re_embedded = ["+" + ln for ln in new_inner]
            block = _rewrite_outer_new_file_count(header, len(re_embedded))
            block.extend(re_embedded)
            block.extend(tail)
            blocks.append(block)
        elif _section_targets_source(section, source_context):
            # Defer: accumulate the section's diff content (drop its `diff --git`
            # wrapper; the canonical output re-emits per-file headers) and reserve a
            # single block slot for the combined canonical.
            flat_diff_lines.extend(section)
            if flat_block_index is None:
                flat_block_index = len(blocks)
                blocks.append([])  # placeholder, filled after the loop
        else:
            blocks.append(list(section))  # out-of-context (package.nix), verbatim

    if flat_block_index is not None:
        canonical, recs = _compile_canonical_diff(flat_diff_lines, source_context)
        records.extend(recs)
        blocks[flat_block_index] = _prepend_git_headers(canonical)

    out_lines: list[str] = []
    for block in blocks:
        out_lines.extend(block)

    text = "\n".join(out_lines)
    return CanonicalizationResult(text=text, files=records, changed=text != patch_text)
