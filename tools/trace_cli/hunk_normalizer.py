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

import re
from dataclasses import dataclass, field


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

        if line.startswith("@@ ") and _HUNK_HEADER_RE.match(line):
            if cur_source_lines is None:
                # Hunk against a file not in source-context: pass through untouched.
                out.append(line)
                i += 1
                continue
            m = _HUNK_HEADER_RE.match(line)
            assert m is not None
            trailing = m.group("trailing")
            # Collect the hunk body up to the next hunk / file / diff boundary.
            j = i + 1
            body: list[str] = []
            while j < len(lines):
                bl = lines[j]
                if bl.startswith("@@ ") and _HUNK_HEADER_RE.match(bl):
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
    """Heuristic: does this line list contain a unified-diff file+hunk header pair?"""
    has_file = any(ln.startswith("--- ") for ln in text_lines)
    has_hunk = any(_HUNK_HEADER_RE.match(ln) for ln in text_lines)
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
