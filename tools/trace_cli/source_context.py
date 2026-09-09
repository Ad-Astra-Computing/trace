"""Extract the pre-patch source an upstream fix touches, into ``source-context/``.

Slice 2 of the semantic-backport-adaptation arc. On the source-backport lane the
upstream fix normally applies verbatim to the pinned nixpkgs source, and the
Patcher (v3) transcribes it byte-for-byte. When the pinned base has diverged —
the libarchive CVE-2026-15028 shape, where the upstream fix used ``archive_ckd_*``
helpers absent from the pinned 3.8.7 — a verbatim transcription cannot apply, and
a correct fix requires a *semantic adaptation* authored against the pinned base's
own code. ``patcher.v5`` performs that adaptation, but only if it can see the
affected source of the pinned base.

This module parses the exact file set out of ``upstream-fix.patch`` and copies
those pre-patch files from the pinned ``pkg.src`` into ``<bundle>/source-context/``,
preserving normalized upstream-relative paths. The copy is hardened against path
traversal (trace threat model item #4): feed-sourced diff paths are validated to
be relative, ``..``-free, symlink-free, and confined to both the source tree and
the destination before any byte is written.

The written files become a new replay-critical Patcher input (per-file sha256 in
the signed bundle manifest); see ``bundle.py`` finalize + ``policy/bundle-schema.json``
1.1.0 branch.
"""

from __future__ import annotations

import re
import shutil
from pathlib import Path

SOURCE_CONTEXT_DIRNAME = "source-context"

# `@@ -oldstart,oldlen +newstart,newlen @@` — the len fields default to 1 when
# omitted. Used to count hunk-body lines so a removed source line that happens to
# render as `--- ...` (e.g. deleting a `-- comment`) is never mistaken for a
# file header.
_HUNK_RE = re.compile(r"^@@ -\d+(?:,(\d+))? \+\d+(?:,(\d+))? @@")


class SourceContextError(ValueError):
    """A diff path is unsafe, or an affected file is missing from the pinned source."""


def _strip_diff_prefix(raw: str) -> str:
    """Strip a single leading ``a/`` or ``b/`` component from a unified-diff path.

    Upstream fixes are ``-p1`` diffs (``--- a/foo.c`` / ``+++ b/foo.c``). The
    normalized upstream-relative path is the path with that one leading component
    removed. A path without the prefix is returned unchanged.
    """
    if raw.startswith(("a/", "b/")):
        return raw[2:]
    return raw


def parse_touched_paths(patch_text: str) -> list[str]:
    """Return the sorted, unique set of pre-patch files an upstream fix touches.

    Reads the ``--- `` (old-file) side of each file section of a unified diff.
    ``/dev/null`` old-sides (files the fix ADDS) have no pre-patch source and are
    skipped: there is nothing in the pinned base to copy. A trailing tab-delimited
    timestamp (``--- a/foo.c\\t2026-...``) is trimmed.

    Raises SourceContextError on a path that escapes the tree (absolute, ``..``,
    empty component) — validated here, before it can reach a filesystem copy.

    Structure-aware: only ``--- `` lines that sit in a file header (outside any
    hunk body, immediately followed by a ``+++ `` line) are read as paths. Hunk
    bodies are skipped by counting the line budget declared in each ``@@`` header,
    so a removed line whose content begins with ``-- `` (rendering as ``--- ``) is
    never misread as a header.
    """
    paths: set[str] = set()
    lines = patch_text.splitlines()
    old_budget = new_budget = 0  # >0 means we are inside a hunk body
    i = 0
    n = len(lines)
    while i < n:
        line = lines[i]
        if old_budget > 0 or new_budget > 0:
            # Inside a hunk body: consume one line against the budget and move on.
            if line.startswith("-"):
                old_budget -= 1
            elif line.startswith("+"):
                new_budget -= 1
            elif line.startswith("\\"):
                pass  # "\ No newline at end of file" — not counted
            else:  # context line (leading space) or a blank line
                old_budget -= 1
                new_budget -= 1
            i += 1
            continue
        m = _HUNK_RE.match(line)
        if m:
            old_budget = int(m.group(1)) if m.group(1) is not None else 1
            new_budget = int(m.group(2)) if m.group(2) is not None else 1
            i += 1
            continue
        # Header region: a real old-file path is a `--- ` line immediately
        # followed by a `+++ ` line.
        if line.startswith("--- ") and i + 1 < n and lines[i + 1].startswith("+++ "):
            raw = line[4:].split("\t", 1)[0].strip()
            if raw and raw != "/dev/null":
                rel = _strip_diff_prefix(raw)
                _assert_safe_relpath(rel)
                paths.add(rel)
        i += 1
    return sorted(paths)


def _assert_safe_relpath(rel: str) -> None:
    """Reject any path that is absolute, ``..``-bearing, or has empty components."""
    if not rel:
        raise SourceContextError("empty diff path")
    p = Path(rel)
    if p.is_absolute():
        raise SourceContextError(f"absolute diff path rejected: {rel!r}")
    parts = p.parts
    if any(part in ("", "..") for part in parts):
        raise SourceContextError(f"unsafe diff path (traversal): {rel!r}")


def write_source_context(
    patch_text: str, source_tree: Path, dest_dir: Path
) -> list[str]:
    """Copy the pre-patch files an upstream fix touches into ``dest_dir``.

    ``dest_dir`` is ``<bundle>/source-context`` (created if absent). Each touched
    path (from :func:`parse_touched_paths`) is resolved *within* ``source_tree``
    and copied to the same relative path under ``dest_dir``. Returns the sorted
    list of relative paths actually written.

    Hardening (trace threat model #4): the resolved source path must stay inside
    ``source_tree`` and the resolved destination inside ``dest_dir`` (no symlink or
    traversal escape); a symlink anywhere on the source path is rejected rather
    than followed. A touched file absent from the pinned source raises
    SourceContextError — a base mismatch the caller must surface, not paper over.
    """
    # Reject a symlinked source-context root BEFORE resolving it: resolve() would
    # follow the link and make an external target the trusted dst_root, defeating
    # every confinement check below. assemble may run on a pre-existing,
    # feed-influenced output dir, so this is a real out-of-bundle-write vector.
    if dest_dir.is_symlink():
        raise SourceContextError(
            f"source-context root is a symlink ({dest_dir}); refusing to write "
            "through it (out-of-bundle write vector)."
        )
    src_root = source_tree.resolve()
    dst_root = dest_dir.resolve()
    dst_root.mkdir(parents=True, exist_ok=True)

    written: list[str] = []
    for rel in parse_touched_paths(patch_text):
        src = src_root / rel
        # Reject a symlink at any component of the source path (no following).
        _assert_no_symlink_within(src, src_root)
        resolved_src = src.resolve()
        if not _is_within(resolved_src, src_root):
            raise SourceContextError(
                f"source path escapes the pinned source tree: {rel!r}"
            )
        if not resolved_src.is_file():
            raise SourceContextError(
                f"affected file not present in pinned source: {rel!r} "
                f"(base mismatch — the upstream fix touches a file absent from the "
                f"pinned base; retire/reharvest rather than adapt)"
            )
        dst = dst_root / rel
        resolved_parent = dst.parent.resolve()
        # dst.parent may not exist yet; resolve() still normalizes it. Confirm the
        # normalized destination stays under dst_root before creating anything.
        if not _is_within(resolved_parent, dst_root) and resolved_parent != dst_root:
            raise SourceContextError(
                f"destination path escapes source-context: {rel!r}"
            )
        dst.parent.mkdir(parents=True, exist_ok=True)
        # The leaf itself may already be a symlink (pre-existing / feed-influenced
        # output dir) even though its parent resolves inside dst_root; copyfile
        # would follow it and overwrite an external target. Refuse rather than
        # follow — this runs before the finalize-time guard can reject the bundle.
        if dst.is_symlink():
            raise SourceContextError(
                f"destination is a symlink, refusing to write through it: {rel!r}"
            )
        shutil.copyfile(resolved_src, dst)
        written.append(rel)
    return sorted(written)


def _assert_no_symlink_within(target: Path, root: Path) -> None:
    """Raise if any component from ``root`` down to ``target`` is a symlink."""
    try:
        rel = target.relative_to(root)
    except ValueError:
        raise SourceContextError(f"path {target} is not under {root}")
    cur = root
    for part in rel.parts:
        cur = cur / part
        if cur.is_symlink():
            raise SourceContextError(f"symlink in source path rejected: {cur}")


def _is_within(path: Path, root: Path) -> bool:
    """True if ``path`` is ``root`` or a descendant (both already resolved)."""
    return path == root or root in path.parents
