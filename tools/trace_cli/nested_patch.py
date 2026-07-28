"""Extract the model's SOURCE patch out of a bundle's `patch.diff`.

For a source-backport bundle the Patcher's `patch.diff` normally does two
things in one git-style diff: (1) *adds* a new file — `CVE-XXXX.patch` — whose
body is itself a unified diff against the upstream source, and (2) edits
`package.nix` to wire that new file into `patches = [...]`. Only (1) is a
source patch that nixpkgs' `patchPhase` will ever run through `patch`; (2) is
metadata about the nixpkgs recipe, never applied with `patch`. Some Patcher
outputs skip the nesting and edit source files directly in the same
`patch.diff` (the "flat" shape) — that shape is supported too.

This module is shared by `preflight.py` (`--patch-diff`: the fail-closed
apply gate) and `normalize_sourceroot.py` (the strip-normalizer +
attestation), so both parse `patch.diff` through one code path.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any


_DIFF_GIT_PREFIX = "diff --git "
_NEW_FILE_MARK = "new file mode"
_PLUS_PLUS_PLUS_RE = re.compile(r"^\+\+\+ (.+)$")
# The OUTER diff's own hunk header (e.g. `@@ -0,0 +1,25 @@`), never `+`-prefixed
# — a nested patch's hunk headers live *inside* the added-file body and are
# always `+`-prefixed there, so this never matches one of those by accident.
_HUNK_HEADER_RE = re.compile(r"^@@ -\d+(?:,\d+)? \+\d+(?:,\d+)? @@")


class NestedPatchError(ValueError):
    """`patch.diff` has no extractable source patch (malformed / empty)."""


def _split_diff_sections(patch_text: str) -> list[dict[str, Any]]:
    """Split a unified/git diff into per-file sections.

    Each section is ``{"raw_lines": [...], "is_new_file": bool, "path": str|None}``.
    Splits on lines starting literally with ``diff --git `` at column 0 — a
    nested patch's OWN ``diff --git`` header (inside an added-file hunk body)
    is always ``+``-prefixed there, so it never triggers a false section
    boundary.
    """
    sections: list[dict[str, Any]] = []
    cur: dict[str, Any] | None = None
    for line in patch_text.splitlines():
        if line.startswith(_DIFF_GIT_PREFIX):
            if cur is not None:
                sections.append(cur)
            cur = {"raw_lines": [line], "is_new_file": False, "path": None}
            continue
        if cur is None:
            continue  # preamble before the first file section (rare)
        cur["raw_lines"].append(line)
        if line.startswith(_NEW_FILE_MARK):
            cur["is_new_file"] = True
        m = _PLUS_PLUS_PLUS_RE.match(line)
        if m and cur["path"] is None:
            raw = m.group(1).split("\t", 1)[0].strip()
            cur["path"] = raw[2:] if raw.startswith(("a/", "b/")) else raw
    if cur is not None:
        sections.append(cur)
    return sections


def _unwrap_added_file_body(raw_lines: list[str]) -> str:
    """Reconstruct an added file's literal content from its outer diff hunk.

    Every content line of a ``new file`` addition is the real file content
    prefixed with exactly one outer ``+`` (git always emits a whole-file
    addition as a single hunk, since the old side has zero lines); strip that
    one prefix to recover the byte-exact inner text.

    A ``\\ No newline at end of file`` marker (emitted when the added file has
    no trailing newline) is NOT content — it is dropped, and its presence means
    the recovered body must NOT get a synthetic trailing newline (otherwise the
    nested patch handed to ``patch`` differs byte-for-byte from what the build
    applies).
    """
    out: list[str] = []
    started = False
    trailing_newline = True
    for line in raw_lines:
        if not started:
            if _HUNK_HEADER_RE.match(line):
                started = True
            continue
        if line.startswith("\\"):        # "\ No newline at end of file"
            trailing_newline = False
            continue
        out.append(line[1:] if line.startswith("+") else line)
    if not out:
        return ""
    body = "\n".join(out)
    return body + "\n" if trailing_newline else body


def _basename(path: str | None) -> str:
    return Path(path).name if path else ""


def extract_nested_source_patch(patch_diff_text: str) -> tuple[str, list[str]]:
    """Return ``(source_patch_text, nested_patch_filenames)`` from `patch.diff`.

    Prefers the nested-file shape: every section that ``new file``-adds a
    ``*.patch`` is unwrapped and concatenated (in `patch.diff` order) into one
    combined unified diff — the text nixpkgs' `patchPhase` will actually feed
    to `patch`. ``nested_patch_filenames`` names the file(s) found this way.

    Falls back to the flat shape (no nested ``*.patch`` addition found): every
    section EXCEPT ``package.nix`` is treated as a direct source edit and
    concatenated verbatim; ``nested_patch_filenames`` is empty in this case —
    the caller can tell the two shapes apart from that.

    Raises :class:`NestedPatchError` if neither shape yields anything to
    dry-run (e.g. `patch.diff` touches only `package.nix`).
    """
    sections = _split_diff_sections(patch_diff_text)
    nested = [
        s for s in sections
        if s["is_new_file"] and _basename(s["path"]).endswith(".patch")
    ]
    # A section that MODIFIES an existing `*.patch` (not a new-file addition)
    # is itself a nested source patch whose *applied* content we cannot
    # reconstruct without its pre-image base (not available here). Fail closed
    # whenever one is present — even alongside a new-file `*.patch` addition:
    # returning only the added bodies would silently omit a modified patch that
    # still affects the build, so the gate could pass without validating the
    # complete source-patch change. Left to the flat fallback it would instead
    # be fed verbatim to `patch`, which tries to patch the `*.patch` path in the
    # source tree — a misleading false-failure. Both cases: fail closed.
    modified_nested = [
        s for s in sections
        if not s["is_new_file"] and _basename(s["path"]).endswith(".patch")
    ]
    if modified_nested:
        names = [s["path"] for s in modified_nested]
        raise NestedPatchError(
            f"patch.diff modifies existing nested patch file(s) {names!r} "
            f"rather than only adding them; reconstructing the applied source "
            f"patch needs the pre-image base, which is unavailable here. "
            f"Unsupported source-backport shape."
        )
    if len(nested) > 1:
        # The order these apply in is the package's `patches = [...]` wiring
        # order, which is NOT recoverable from `patch.diff` section order —
        # concatenating in emission order could reject a series cert applies
        # (or pass one it rejects) when the patches depend on each other. Fail
        # closed; no current corpus bundle adds more than one nested patch.
        names = [s["path"] for s in nested]
        raise NestedPatchError(
            f"patch.diff adds multiple nested patch files {names!r}; their "
            f"application order is set by the package's patches=[] wiring, "
            f"which is not recoverable from patch.diff alone. Unsupported "
            f"source-backport shape."
        )
    if nested:
        bodies = [_unwrap_added_file_body(s["raw_lines"]) for s in nested]
        names = [s["path"] for s in nested]
        combined = "\n".join(b for b in bodies if b)
        if not combined.strip():
            raise NestedPatchError(
                f"nested patch file(s) {names!r} in patch.diff are empty "
                f"after unwrapping"
            )
        return combined, names

    flat = [s for s in sections if _basename(s["path"]) != "package.nix"]
    if not flat:
        raise NestedPatchError(
            "patch.diff has no nested *.patch addition and no non-package.nix "
            "file section; nothing to preflight"
        )
    combined = "\n".join("\n".join(s["raw_lines"]) for s in flat) + "\n"
    return combined, []
