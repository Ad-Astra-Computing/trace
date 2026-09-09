"""Discover adaptation-oracle candidates in an upstream nixpkgs source tree.

**Why.** The Reviewer's adaptation lane (reviewer.v10, see
``agents/scorers/adaptation_oracle.py``) judges whether a model-authored
security backport is *semantically equivalent* to the upstream fix once
adapted to a pinned (older) base. Scoring that verdict needs ground-truth
oracles: trusted HUMAN backports whose equivalence to the upstream fix a
person has already adjudicated. Today exactly one oracle is registered
(CVE-2024-34490 / maxima). nixpkgs itself carries ~49 hand-maintained
``*CVE-<id>*.patch`` files scattered under ``pkgs/**`` — some of those are
verbatim ``git format-patch`` cherry-picks of the upstream fix commit
(nothing to adjudicate: a verbatim copy has no adaptation to compare
against), and some are genuinely hand-adapted to the package version nixpkgs
pins (exactly the shape an oracle needs). This script scans nixpkgs offline,
extracts cheap structural signals from each patch, and emits a RANKED
manifest so a human can pick the next oracle candidates to hand-adjudicate.

**This script does discovery only.** It never registers an oracle, never
imports or modifies ``adaptation_oracle.py``, and never reads a bundle's
Patcher/Reviewer context — see that module's docstring for why the oracle
patch must stay outside model context (the isolation property). This script
runs entirely offline against a local nixpkgs checkout; no network, no model
calls, no ``nix`` subprocess (the ``<nixpkgs>`` store path is resolved by
parsing ``$NIX_PATH`` directly).

**Classification rule** (kept deliberately simple — see module docstring
for the tradeoff this accepts):

  * ``is_format_patch``: the patch's first line matches the canonical
    ``git format-patch`` header ``From <40-hex-sha> Mon Sep 17 00:00:00
    2001``. This is the strongest positive signal that a patch is a
    mechanical, unedited cherry-pick of an exact upstream commit.
  * ``adaptation_signals``: substrings/patterns found in the patch's header
    region (everything before the first diff line) that a human maintainer
    writes when they hand-adjust a fix — e.g. "backport", "adapted",
    "modified", "rebased", or a version-targeting phrase like "for 1.2",
    "against 1.2", or "adjusted to apply to 1.2".
  * classification:
      - ``unknown``           — the patch has no parseable diff hunks at
        all (``n_hunks == 0``); there is nothing to judge either way.
      - ``likely-verbatim``   — clean format-patch header AND no
        adaptation signals. The strong case for "nothing to adjudicate".
      - ``likely-adaptation`` — otherwise (adaptation signals present, OR
        the patch does not open with a clean format-patch header). A
        missing format-patch header is itself weak evidence of
        hand-editing: nixpkgs' own convention for a pure cherry-pick is to
        carry the untouched ``git format-patch`` output, so a patch that
        deviates from that (DEP-3 headers, bare ``diff -up``/``diff -ur``
        output, hand-written prose headers, ``git show``-style ``commit
        <sha>`` blocks) has already lost its claim to being a byte-exact
        copy even if we can't point to an explicit "I adapted this" phrase.

  This intentionally over-includes: some ``likely-adaptation`` results are
  really just verbatim diffs that were hand-extracted without the git
  wrapper (mcrypt, openslp, lua-5's older CVEs). ``rank_score`` (below) is
  what separates the genuinely useful hand-adapted fixes from that noise —
  the classification alone is a coarse first cut.

**rank_score formula** (higher = better oracle candidate; deterministic,
no wall-clock, no randomness):

    rank_score = classification_bonus
               + signal_bonus
               + single_file_bonus
               - size_penalty
               - unwired_penalty

    classification_bonus = 100 if likely-adaptation
                             40 if unknown
                              0 if likely-verbatim
    signal_bonus          = 40 * min(len(adaptation_signals), 3)
    single_file_bonus    = 10 if n_files == 1 else 0
    size_penalty          = 1.0 * n_hunks
                          + 1.5 * max(n_files - 1, 0)
                          + 0.03 * (added_lines + removed_lines)
    unwired_penalty       = 1000 if not wired else 0

  ``wired`` is whether any ``.nix`` at/below the patch's anchor dir
  references the patch basename — i.e. some derivation actually applies it.
  An unwired patch is an orphaned/stale ``.patch`` file with no pinned base
  to adjudicate against, so it cannot be an oracle; ``unwired_penalty`` (a
  flat 1000, larger than the entire positive range) sinks every unwired
  candidate below every wired one while preserving wired ordering. Unwired
  candidates are still listed (with ``"wired": false``) rather than dropped,
  so a stale patch remains visible as a diagnostic.

  The classification gap (100 vs 0) dominates: any adaptation-classified
  candidate outranks every verbatim-classified one regardless of size.
  Within the adaptation bucket, `signal_bonus` is deliberately the
  largest swing factor (up to 120, versus a `single_file_bonus` of only
  10): explicit textual evidence that a maintainer hand-edited the fix
  (an actual "backport"/"adapted"/version-target phrase) is stronger
  evidence of oracle-worthiness than "this patch merely lacks a git
  format-patch header", which is the weaker, catch-all half of the
  likely-adaptation rule and just as often a straight upstream diff that
  was hand-extracted without the git wrapper. `size_penalty` uses
  deliberately soft per-unit weights so a real multi-file hand adaptation
  (like the registered maxima oracle) is not crowded out by trivial
  1-file/1-hunk diffs that happen to carry no header at all. Ties break
  on (n_hunks asc, cve_ids[0]) at the caller.

Usage::

    python3 scripts/harvest_oracle_candidates.py \\
        [--nixpkgs DIR] [--out DIR] [--limit N]

Writes ``<out>/oracle-candidates.jsonl`` and ``<out>/oracle-candidates.md``,
both ranked best-first. The manifest's first jsonl line is a header object
(``"kind": "harvest-header"``); every subsequent line is a candidate
(``"kind": "oracle-candidate"``).
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
from pathlib import Path
from typing import Any

SCHEMA_VERSION = "1.0.0"

CVE_ID_RE = re.compile(r"CVE-\d{4}-\d{4,}", re.IGNORECASE)

# Canonical `git format-patch` first line, e.g.
# "From e47e56d226519635768e6aab2f38f0ab037c09e5 Mon Sep 17 00:00:00 2001"
FORMAT_PATCH_RE = re.compile(r"^From ([0-9a-fA-F]{40}) Mon Sep 17 00:00:00 2001\s*$")

# `version = "..."` as written in a package.nix / default.nix.
VERSION_RE = re.compile(r'\bversion\s*=\s*"([^"]+)"')

# Literal adaptation-language words (case-insensitive, whole-word matched —
# NOT a bare substring check: "context" as a bare substring would false-hit
# inside identifiers like "gss_accept_sec_context", so every word below is
# compiled with \b boundaries in _ADAPTATION_WORD_RES).
ADAPTATION_WORDS: tuple[str, ...] = (
    "backported",  # check before "backport" so the longer match wins first
    "backport",
    "adapted",
    "adapt for",
    "modified",
    "rebased",
)

# "context" was previously a bare word in ADAPTATION_WORDS. It fired on
# skypilot CVE-2026-13482 -- a clean `git format-patch` cherry-pick -- because
# the commit message carried a `Co-Authored-By: Claude Opus 4.8 (1M context)`
# trailer. Word boundaries are not enough: the collision is with ordinary prose,
# not with an identifier. The maintainer sense we actually want is "I refreshed
# the context lines to make this apply", so require the phrase.
CONTEXT_PHRASE_RE = re.compile(
    r"\b(context (?:lines? )?(?:adjust|refresh|fix|updat)\w*"
    r"|(?:adjust|refresh|updat)\w* (?:the )?context(?: lines?)?"
    r"|context lines?)\b",
    re.IGNORECASE,
)

# Commit trailers are metadata appended by tooling/reviewers, not a
# maintainer's statement about adapting the fix. Strip them before signal
# matching so trailer prose cannot manufacture an adaptation signal.
TRAILER_RE = re.compile(
    r"^\s*(?:Co-Authored-By|Signed-off-by|Reviewed-by|Acked-by|Tested-by"
    r"|Reported-by|Suggested-by|Cc|Fixes|Link|Change-Id)\s*:",
    re.IGNORECASE,
)

_ADAPTATION_WORD_RES: dict[str, re.Pattern[str]] = {
    word: re.compile(r"\b" + re.escape(word) + r"\b", re.IGNORECASE)
    for word in ADAPTATION_WORDS
}

# "for 1.2" / "against 1.2" / "adjusted to apply to 1.2" style version
# targeting phrases — the other common way a maintainer signals "I moved
# this fix onto a specific pinned version".
VERSION_TARGET_RE = re.compile(
    r"\b(for|against|adjusted to apply to|adjusted for|apply(?:ing)? to)"
    r"\s+v?\d+(?:\.\d+){1,3}\b",
    re.IGNORECASE,
)


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


# ─── nixpkgs resolution ────────────────────────────────────────────────────


def resolve_nixpkgs_dir(explicit: Path | None) -> Path:
    """Resolve the nixpkgs source tree to scan.

    If `explicit` is given, use it verbatim (must be a directory). Otherwise
    parse `$NIX_PATH` for a `nixpkgs=<path>` entry — the conventional way a
    Nix dev shell exposes `<nixpkgs>` — without shelling out to `nix`.
    """
    if explicit is not None:
        if not explicit.is_dir():
            raise SystemExit(f"error: --nixpkgs is not a directory: {explicit}")
        return explicit

    nix_path = os.environ.get("NIX_PATH", "")
    for entry in nix_path.split(":"):
        entry = entry.strip()
        if not entry or "=" not in entry:
            continue
        key, _, value = entry.partition("=")
        if key.strip() == "nixpkgs":
            resolved = Path(value.strip())
            if not resolved.is_dir():
                raise SystemExit(
                    f"error: NIX_PATH nixpkgs entry does not exist: {resolved}"
                )
            return resolved

    raise SystemExit(
        "error: could not resolve nixpkgs. Pass --nixpkgs DIR explicitly, or "
        "ensure $NIX_PATH contains a 'nixpkgs=<dir>' entry "
        f"(got NIX_PATH={nix_path!r})."
    )


def find_cve_patches(nixpkgs_dir: Path) -> list[Path]:
    """All `pkgs/**/*CVE-<id>*.patch` files, case-insensitive, sorted for
    determinism."""
    pkgs_root = nixpkgs_dir / "pkgs"
    if not pkgs_root.is_dir():
        raise SystemExit(f"error: no pkgs/ dir under nixpkgs root: {pkgs_root}")
    matches = [p for p in pkgs_root.rglob("*.patch") if CVE_ID_RE.search(p.name)]
    return sorted(matches)


# ─── per-patch parsing ─────────────────────────────────────────────────────


def parse_cve_ids(filename: str) -> list[str]:
    """CVE ids embedded in a filename, deduped and sorted, ids upper-cased."""
    ids = {m.group(0).upper() for m in CVE_ID_RE.finditer(filename)}
    return sorted(ids)


def find_anchor_dir(patch_path: Path, pkgs_root: Path) -> Path | None:
    """Nearest directory, walking from `patch_path`'s parent up to (and
    including) `pkgs_root`, that directly contains a `package.nix` or
    `default.nix`. None if no such ancestor exists."""
    cur = patch_path.parent
    while True:
        if (cur / "package.nix").is_file() or (cur / "default.nix").is_file():
            return cur
        if cur == pkgs_root:
            return None
        cur = cur.parent


def derive_package_name(patch_path: Path, nixpkgs_dir: Path, pkgs_root: Path) -> str:
    """Best-effort package name for a CVE patch.

    `pkgs/by-name/XX/<pkg>/...` uses the flake-parts by-name convention
    directly: the third path segment is authoritative. Otherwise fall back
    to the nearest ancestor directory carrying a package.nix/default.nix
    (see `find_anchor_dir`), and if even that fails, the patch's own
    parent directory name.
    """
    rel_parts = patch_path.relative_to(nixpkgs_dir).parts
    if len(rel_parts) >= 4 and rel_parts[0] == "pkgs" and rel_parts[1] == "by-name":
        return rel_parts[3]

    anchor = find_anchor_dir(patch_path, pkgs_root)
    if anchor is not None:
        return anchor.name
    return patch_path.parent.name


def patch_is_wired(patch_path: Path, anchor_dir: Path | None) -> bool:
    """True if the patch's basename is referenced by any `.nix` file at or
    below its anchor dir.

    A CVE patch that no derivation applies (an orphaned/stale `.patch` file
    left in the tree, e.g. after a version bump dropped it from the
    ``patches`` list) has no defined *pinned base*: the base an oracle
    adjudicates against is exactly the version of the derivation that
    applies the patch. So an unwired patch cannot be an oracle, and
    ``downstream_patch_applies`` is undefined for it. Pure offline file
    read; never raises (unreadable .nix files are skipped)."""
    if anchor_dir is None:
        return False
    needle = patch_path.name
    for nix_file in anchor_dir.rglob("*.nix"):
        try:
            if needle in nix_file.read_text(encoding="utf-8", errors="replace"):
                return True
        except OSError:
            continue
    return False


def parse_pinned_version(anchor_dir: Path | None) -> str | None:
    """Best-effort `version = "..."` parse from the anchor dir's
    package.nix (preferred) or default.nix. None if there's no anchor dir
    or no `version = "..."` line — never raises."""
    if anchor_dir is None:
        return None
    for name in ("package.nix", "default.nix"):
        candidate = anchor_dir / name
        if not candidate.is_file():
            continue
        try:
            text = candidate.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        m = VERSION_RE.search(text)
        if m:
            return m.group(1)
    return None


def _strip_trailers(header_text: str) -> str:
    """Drop commit-trailer lines from a header region.

    A trailer is tooling/reviewer metadata, so its prose says nothing about
    whether the maintainer adapted the fix. Leaving trailers in let a
    `Co-Authored-By: ... (1M context)` line masquerade as an adaptation
    signal on an otherwise verbatim cherry-pick.
    """
    return "\n".join(
        line for line in header_text.splitlines() if not TRAILER_RE.match(line)
    )


def _find_adaptation_signals(header_text: str) -> list[str]:
    header_text = _strip_trailers(header_text)
    signals: list[str] = []
    for word in ADAPTATION_WORDS:
        if not _ADAPTATION_WORD_RES[word].search(header_text):
            continue
        # "backport" is a whole-word substring of "backported"; report only
        # the more specific match once "backported" has already fired.
        if word == "backport" and "backported" in signals:
            continue
        signals.append(word)
    m = CONTEXT_PHRASE_RE.search(header_text)
    if m:
        signals.append(f"context-phrase:{m.group(0).strip().lower()}")
    m = VERSION_TARGET_RE.search(header_text)
    if m:
        signals.append(f"version-target:{m.group(0).strip()}")
    return signals


def parse_patch(raw: bytes) -> dict[str, Any]:
    """Parse a raw patch file's bytes into structural fields.

    Pure text/regex parsing; never raises on malformed input — worst case
    every count comes back 0 / None.
    """
    text = raw.decode("utf-8", errors="replace")
    lines = text.splitlines()

    m = FORMAT_PATCH_RE.match(lines[0]) if lines else None
    is_format_patch = bool(m)
    upstream_commit = m.group(1).lower() if m else None

    # Header/comment region: everything before the first line that opens a
    # unified diff (git-style "diff --git ..." or a bare "--- a/file"
    # style header). A lone "---" separator line (no trailing content) is
    # the git format-patch commit-message/diffstat divider, not a diff
    # header, so it must NOT stop the scan.
    diff_start = len(lines)
    for i, line in enumerate(lines):
        if line.startswith("diff --git ") or (
            line.startswith("--- ") and len(line) > len("--- ")
        ):
            diff_start = i
            break
    header_text = "\n".join(lines[:diff_start])
    body_lines = lines[diff_start:]

    n_files = sum(1 for l in body_lines if l.startswith("+++ "))
    n_hunks = sum(1 for l in body_lines if l.startswith("@@ "))
    added_lines = sum(
        1 for l in body_lines if l.startswith("+") and not l.startswith("+++ ")
    )
    removed_lines = sum(
        1 for l in body_lines if l.startswith("-") and not l.startswith("--- ")
    )

    adaptation_signals = _find_adaptation_signals(header_text)

    return {
        "n_files": n_files,
        "n_hunks": n_hunks,
        "added_lines": added_lines,
        "removed_lines": removed_lines,
        "is_format_patch": is_format_patch,
        "upstream_commit": upstream_commit,
        "adaptation_signals": adaptation_signals,
    }


def classify(is_format_patch: bool, adaptation_signals: list[str], n_hunks: int) -> str:
    """See the module docstring "Classification rule" section."""
    if n_hunks == 0:
        return "unknown"
    if is_format_patch and not adaptation_signals:
        return "likely-verbatim"
    return "likely-adaptation"


# ─── payload verification against upstream ─────────────────────────────────
#
# The classifier above reads a patch's HEADER. The 2026-08-09 verification pass
# proved header wording is not admissible: 7 of 20 candidates whose headers
# claimed adaptation ("rebased", "modified ... to apply without <commit>") were
# byte-identical to the named upstream commit once headers/paths/offsets were
# normalised away. Whether a maintainer patch is a GENUINE content adaptation
# or a verbatim copy is only decidable by comparing PAYLOAD lines — the `+`/`-`
# content — against the real upstream diff. This is the reusable core of that
# pass: pure text, no network, no execution. The fetch layer that supplies the
# upstream text is a separate concern (host allowlist / sha256 / no-exec), kept
# out of this function deliberately so the comparison stays trivially testable.

# Lines that are diff STRUCTURE, not payload: file headers, hunk headers, index
# lines, format-patch metadata, and the format-patch signature separator.
_NONPAYLOAD_PREFIXES = (
    "+++",
    "---",
    "diff ",
    "index ",
    "@@",
    "Index:",
    "# ",
    "From ",
    "Date:",
    "Subject:",
    "From:",
)


def payload_lines(text: str) -> list[str]:
    """Normalised `+`/`-` PAYLOAD lines of a unified diff.

    Ignores file headers, hunk headers/offsets, index lines, format-patch
    metadata and its `--` signature separator, and collapses internal
    whitespace — so two diffs that differ only in where they apply, how their
    hunks are numbered, or their indentation compare EQUAL. Context lines (no
    `+`/`-`) are excluded entirely: a change to surrounding context is not a
    content adaptation, so it must not register as a payload difference.
    """
    out: list[str] = []
    for line in text.splitlines():
        if line.startswith(_NONPAYLOAD_PREFIXES):
            continue
        stripped = line.rstrip()
        if stripped == "--" or stripped.startswith("-- "):
            continue  # git format-patch signature, not a removed payload line
        if line[:1] in "+-":
            collapsed = " ".join(line[1:].split())
            if collapsed:
                out.append(line[0] + collapsed)
    return out


# Above this Jaccard overlap, a non-identical maintainer patch is close enough
# to upstream that the difference may be a WRONG-REFERENCE artifact (the
# maintainer cherry-picked from a release branch whose fix differs from master,
# or squashed several commits) rather than a real adaptation. Flag for the
# provenance check fable raised (2026-08-09) rather than silently trusting it.
PROVENANCE_REVIEW_OVERLAP = 0.85


def verify_against_upstream(
    maintainer_patch: str, upstream_patch: str
) -> dict[str, Any]:
    """Decide whether a maintainer patch genuinely ADAPTS the upstream fix or
    merely COPIES it, by comparing normalised payload lines.

    Returns a verdict dict; never raises. Verdicts:
      - ``verbatim-copy``       — payload identical to upstream ⇒ nothing to
        adjudicate; reject as an oracle regardless of header wording.
      - ``genuine-adaptation``  — payload differs materially from upstream.
      - ``provenance-ambiguous``— payload differs, but overlap is so high the
        reference commit may be wrong (branch variant / squash). Needs a human
        provenance check before it counts as an adaptation.
      - ``empty``               — one side has no payload (unfetchable /
        unparsable); cannot decide here.
    """
    a = payload_lines(maintainer_patch)
    b = payload_lines(upstream_patch)
    if not a or not b:
        return {
            "verdict": "empty",
            "overlap": 0.0,
            "maintainer_payload_lines": len(a),
            "upstream_payload_lines": len(b),
            "identical": False,
        }
    sa, sb = set(a), set(b)
    overlap = len(sa & sb) / len(sa | sb)
    identical = a == b
    if identical:
        verdict = "verbatim-copy"
    elif overlap >= PROVENANCE_REVIEW_OVERLAP:
        verdict = "provenance-ambiguous"
    else:
        verdict = "genuine-adaptation"
    return {
        "verdict": verdict,
        "overlap": round(overlap, 3),
        "maintainer_payload_lines": len(a),
        "upstream_payload_lines": len(b),
        "maintainer_only_lines": len(sa - sb),
        "upstream_only_lines": len(sb - sa),
        "identical": identical,
    }


def rank_score(
    classification: str,
    *,
    n_files: int,
    n_hunks: int,
    added_lines: int,
    removed_lines: int,
    adaptation_signals: list[str],
    wired: bool,
) -> float:
    """See the module docstring "rank_score formula" section."""
    classification_bonus = {
        "likely-adaptation": 100.0,
        "unknown": 40.0,
        "likely-verbatim": 0.0,
    }[classification]
    signal_bonus = 40.0 * min(len(adaptation_signals), 3)
    single_file_bonus = 10.0 if n_files == 1 else 0.0
    size_penalty = (
        1.0 * n_hunks + 1.5 * max(n_files - 1, 0) + 0.03 * (added_lines + removed_lines)
    )
    # An unwired (orphaned) patch has no derivation applying it, so no
    # pinned base to adjudicate against — it cannot be an oracle. Sink it
    # below every wired candidate with a flat penalty larger than the whole
    # positive range, so wired ordering is preserved within each bucket.
    unwired_penalty = 0.0 if wired else 1000.0
    return (
        classification_bonus
        + signal_bonus
        + single_file_bonus
        - size_penalty
        - unwired_penalty
    )


# ─── harvest ────────────────────────────────────────────────────────────────


def build_candidate(
    patch_path: Path, nixpkgs_dir: Path, pkgs_root: Path
) -> dict[str, Any]:
    raw = patch_path.read_bytes()
    parsed = parse_patch(raw)
    classification = classify(
        parsed["is_format_patch"], parsed["adaptation_signals"], parsed["n_hunks"]
    )
    anchor_dir = find_anchor_dir(patch_path, pkgs_root)
    wired = patch_is_wired(patch_path, anchor_dir)
    score = rank_score(
        classification,
        n_files=parsed["n_files"],
        n_hunks=parsed["n_hunks"],
        added_lines=parsed["added_lines"],
        removed_lines=parsed["removed_lines"],
        adaptation_signals=parsed["adaptation_signals"],
        wired=wired,
    )
    cve_ids = parse_cve_ids(patch_path.name)

    return {
        "kind": "oracle-candidate",
        "cve_ids": cve_ids,
        "package": derive_package_name(patch_path, nixpkgs_dir, pkgs_root),
        "patch_path": patch_path.relative_to(nixpkgs_dir).as_posix(),
        "patch_sha256": sha256_hex(raw),
        "pinned_version": parse_pinned_version(anchor_dir),
        "n_files": parsed["n_files"],
        "n_hunks": parsed["n_hunks"],
        "added_lines": parsed["added_lines"],
        "removed_lines": parsed["removed_lines"],
        "is_format_patch": parsed["is_format_patch"],
        "upstream_commit": parsed["upstream_commit"],
        "adaptation_signals": parsed["adaptation_signals"],
        "wired": wired,
        "classification": classification,
        "rank_score": score,
    }


# ─── history mode ──────────────────────────────────────────────────────────
#
# The tree scan above sees only patches that are LIVE at one ref. nixpkgs
# DELETES a `*CVE-*.patch` file once the package is bumped past the fix, so a
# tree scan systematically misses every backport whose package later moved on
# — measured 2026-08-07 at 46 live vs 263 ever-added on upstream/master, a
# ~5.7x undercount. A deleted patch is not a worse oracle: it is still a human
# maintainer's adaptation, and the version it was pinned against is recoverable
# from the commit that added it. History mode recovers those.


def _git(repo: Path, *args: str) -> bytes:
    """Run git in `repo`, returning raw stdout. Returns b"" on failure rather
    than raising: a missing blob or an unparseable path must skip one
    candidate, never abort a 263-patch scan."""
    try:
        proc = subprocess.run(
            ["git", "-C", str(repo), *args],
            capture_output=True,
            check=False,
        )
    except OSError:
        return b""
    return proc.stdout if proc.returncode == 0 else b""


def find_cve_patches_history(repo: Path, ref: str) -> list[dict[str, str]]:
    """Every `*CVE-*.patch` path ever ADDED on `ref`, with the commit that
    first added it.

    `git log` walks newest-first, so for a path added, deleted and re-added we
    keep overwriting until the OLDEST add wins — that is the commit whose tree
    carries the version the patch was originally written against.
    """
    out = _git(
        repo,
        "log",
        "--diff-filter=A",
        "--name-only",
        "--pretty=format:%x00%H %cI",
        ref,
        "--",
        "*CVE-*.patch",
        "*cve-*.patch",
    )
    first: dict[str, tuple[str, str]] = {}
    commit = date = ""
    for chunk in out.decode("utf-8", errors="replace").split("\x00"):
        if not chunk.strip():
            continue
        lines = chunk.splitlines()
        head = lines[0].strip().split(" ", 1)
        if len(head) != 2:
            continue
        commit, date = head[0], head[1]
        for path in lines[1:]:
            path = path.strip()
            if path and CVE_ID_RE.search(Path(path).name):
                first[path] = (commit, date)  # oldest add wins (newest-first walk)
    return [{"path": p, "commit": c, "date": d} for p, (c, d) in sorted(first.items())]


def _pinned_version_at(repo: Path, commit: str, pkg_dir: str) -> str | None:
    for fname in ("package.nix", "default.nix"):
        blob = _git(repo, "show", f"{commit}:{pkg_dir}/{fname}")
        if not blob:
            continue
        m = VERSION_RE.search(blob.decode("utf-8", errors="replace"))
        if m:
            return m.group(1)
    return None


def _wired_at(repo: Path, commit: str, pkg_dir: str, patch_name: str) -> bool:
    for fname in ("package.nix", "default.nix"):
        blob = _git(repo, "show", f"{commit}:{pkg_dir}/{fname}")
        if blob and patch_name in blob.decode("utf-8", errors="replace"):
            return True
    return False


def build_candidate_from_history(
    repo: Path, entry: dict[str, str], live_paths: set[str]
) -> dict[str, Any] | None:
    rel = entry["path"]
    commit = entry["commit"]
    raw = _git(repo, "show", f"{commit}:{rel}")
    if not raw:
        return None
    parsed = parse_patch(raw)
    classification = classify(
        parsed["is_format_patch"], parsed["adaptation_signals"], parsed["n_hunks"]
    )
    pkg_dir = str(Path(rel).parent)
    patch_name = Path(rel).name
    wired = _wired_at(repo, commit, pkg_dir, patch_name)
    score = rank_score(
        classification,
        n_files=parsed["n_files"],
        n_hunks=parsed["n_hunks"],
        added_lines=parsed["added_lines"],
        removed_lines=parsed["removed_lines"],
        adaptation_signals=parsed["adaptation_signals"],
        wired=wired,
    )
    return {
        "kind": "oracle-candidate",
        "source": "history",
        "cve_ids": parse_cve_ids(patch_name),
        "package": Path(pkg_dir).name,
        "patch_path": rel,
        "patch_sha256": sha256_hex(raw),
        "pinned_version": _pinned_version_at(repo, commit, pkg_dir),
        "first_added_commit": commit,
        "first_added_at": entry["date"],
        "live_at_ref": Path(rel).name in live_paths,
        "n_files": parsed["n_files"],
        "n_hunks": parsed["n_hunks"],
        "added_lines": parsed["added_lines"],
        "removed_lines": parsed["removed_lines"],
        "is_format_patch": parsed["is_format_patch"],
        "upstream_commit": parsed["upstream_commit"],
        "adaptation_signals": parsed["adaptation_signals"],
        "wired": wired,
        "classification": classification,
        "rank_score": score,
    }


def harvest_history(
    repo: Path, ref: str, limit: int | None = None
) -> list[dict[str, Any]]:
    # Match on BASENAME, not full path. A history entry records the path at
    # FIRST ADD, and nixpkgs relocates packages constantly (the by-name
    # migration moved thousands), so full-path equality reports live=False for
    # every package that ever moved — it wrongly marked the registered maxima
    # oracle as deleted, since it was added under
    # pkgs/applications/science/math/ and now lives under pkgs/by-name/ma/.
    # Basenames carry a CVE id and usually a version prefix, so they are
    # specific enough; a cross-package basename collision would at worst call
    # a deleted patch live, which is the harmless direction.
    live = {
        Path(line.strip()).name
        for line in _git(repo, "ls-tree", "-r", "--name-only", ref)
        .decode("utf-8", errors="replace")
        .splitlines()
        if line.strip() and CVE_ID_RE.search(Path(line.strip()).name)
    }
    entries = find_cve_patches_history(repo, ref)
    candidates = [
        c
        for c in (build_candidate_from_history(repo, e, live) for e in entries)
        if c is not None
    ]
    candidates.sort(key=_sort_key)
    return candidates[:limit] if limit is not None else candidates


def _sort_key(c: dict[str, Any]) -> tuple[float, int, str]:
    first_cve = c["cve_ids"][0] if c["cve_ids"] else ""
    return (-c["rank_score"], c["n_hunks"], first_cve)


def harvest(nixpkgs_dir: Path, limit: int | None = None) -> list[dict[str, Any]]:
    """Scan `nixpkgs_dir` for CVE backport patches and return a ranked list
    of candidate dicts (best-first). `limit`, if given, truncates the
    returned list but does not affect ranking."""
    pkgs_root = nixpkgs_dir / "pkgs"
    patch_paths = find_cve_patches(nixpkgs_dir)
    candidates = [build_candidate(p, nixpkgs_dir, pkgs_root) for p in patch_paths]
    candidates.sort(key=_sort_key)
    if limit is not None:
        candidates = candidates[:limit]
    return candidates


def build_header(
    nixpkgs_dir: Path, all_candidates: list[dict[str, Any]]
) -> dict[str, Any]:
    counts: dict[str, int] = {}
    for c in all_candidates:
        counts[c["classification"]] = counts.get(c["classification"], 0) + 1
    wired_count = sum(1 for c in all_candidates if c["wired"])
    hist = [c for c in all_candidates if c.get("source") == "history"]
    history_fields: dict[str, Any] = {}
    if hist:
        live = sum(1 for c in hist if c.get("live_at_ref"))
        history_fields = {
            "scan_mode": "history",
            "live_at_ref_count": live,
            # The whole point of history mode: these are invisible to a tree scan.
            "deleted_since_count": len(hist) - live,
        }
    else:
        history_fields = {"scan_mode": "tree"}
    return {
        **history_fields,
        "kind": "harvest-header",
        "schema_version": SCHEMA_VERSION,
        "nixpkgs_dir": str(nixpkgs_dir),
        "nixpkgs_ref": nixpkgs_dir.name,
        "total_patches_scanned": len(all_candidates),
        "classification_counts": counts,
        "wired_count": wired_count,
        "unwired_count": len(all_candidates) - wired_count,
    }


# ─── rendering / writing ────────────────────────────────────────────────────


def render_markdown(header: dict[str, Any], candidates: list[dict[str, Any]]) -> str:
    lines: list[str] = []
    lines.append("# Adaptation-oracle candidates")
    lines.append("")
    lines.append(f"nixpkgs: `{header['nixpkgs_dir']}`")
    lines.append(f"nixpkgs_ref: `{header['nixpkgs_ref']}`")
    lines.append(f"total patches scanned: {header['total_patches_scanned']}")
    lines.append(
        f"wired: {header['wired_count']} / unwired: {header['unwired_count']} "
        "(unwired = orphaned patch, no derivation applies it → not oracle-viable)"
    )
    lines.append("")
    counts = header["classification_counts"]
    lines.append("| classification | count |")
    lines.append("|---|---|")
    for key in ("likely-adaptation", "likely-verbatim", "unknown"):
        lines.append(f"| {key} | {counts.get(key, 0)} |")
    lines.append("")
    lines.append("## Ranked candidates (best-first)")
    lines.append("")
    lines.append(
        "| rank | score | cve_ids | package | wired | classification | files "
        "| hunks | +/- | signals | patch_path |"
    )
    lines.append("|---|---|---|---|---|---|---|---|---|---|---|")
    for i, c in enumerate(candidates, start=1):
        signals = ", ".join(c["adaptation_signals"]) or "-"
        wired = "yes" if c["wired"] else "**no**"
        lines.append(
            f"| {i} | {c['rank_score']:.2f} | {', '.join(c['cve_ids']) or '-'} "
            f"| {c['package']} | {wired} | {c['classification']} | {c['n_files']} "
            f"| {c['n_hunks']} | +{c['added_lines']}/-{c['removed_lines']} "
            f"| {signals} | `{c['patch_path']}` |"
        )
    lines.append("")
    return "\n".join(lines)


def write_manifest(
    out_dir: Path, header: dict[str, Any], candidates: list[dict[str, Any]]
) -> tuple[Path, Path]:
    out_dir.mkdir(parents=True, exist_ok=True)
    jsonl_path = out_dir / "oracle-candidates.jsonl"
    md_path = out_dir / "oracle-candidates.md"

    with jsonl_path.open("w", encoding="utf-8") as f:
        f.write(json.dumps(header, sort_keys=True) + "\n")
        for c in candidates:
            f.write(json.dumps(c, sort_keys=True) + "\n")

    md_path.write_text(render_markdown(header, candidates), encoding="utf-8")
    return jsonl_path, md_path


# ─── CLI ────────────────────────────────────────────────────────────────────


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Discover adaptation-oracle candidates (CVE backport patches) "
            "in an upstream nixpkgs source tree. Offline, no model spend."
        )
    )
    parser.add_argument(
        "--nixpkgs",
        type=Path,
        default=None,
        help="nixpkgs source dir (default: resolve <nixpkgs> from $NIX_PATH)",
    )
    parser.add_argument(
        "--out",
        type=Path,
        default=Path("data/reports"),
        help="output directory (default: data/reports/)",
    )
    parser.add_argument(
        "--history",
        action="store_true",
        help=(
            "scan git HISTORY for every CVE patch ever added, not just those "
            "live at one ref (nixpkgs deletes a patch once the package is "
            "bumped past the fix; a tree scan misses ~5.7x the population). "
            "Requires --nixpkgs to point at a git checkout."
        ),
    )
    parser.add_argument(
        "--ref",
        default="HEAD",
        help="(--history) git ref to walk (default: HEAD)",
    )
    parser.add_argument(
        "--limit",
        type=int,
        default=None,
        help="cap the number of candidates written (ranking still computed over all)",
    )
    parser.add_argument(
        "--verify-pair",
        nargs=2,
        metavar=("MAINTAINER_PATCH", "UPSTREAM_PATCH"),
        help=(
            "offline: compare a maintainer patch against the upstream fix it "
            "claims to adapt, by normalised payload lines, and print the "
            "verdict (verbatim-copy / genuine-adaptation / provenance-ambiguous). "
            "Header wording is not trusted. No network; the two patch files must "
            "already be on disk."
        ),
    )
    return parser


def main(argv: list[str]) -> int:
    parser = build_arg_parser()
    args = parser.parse_args(argv[1:])

    # Offline verify mode: needs no nixpkgs tree, so short-circuit before
    # resolving one.
    if args.verify_pair:
        maint_path, up_path = (Path(p) for p in args.verify_pair)
        result = verify_against_upstream(
            maint_path.read_text(errors="replace"),
            up_path.read_text(errors="replace"),
        )
        result["maintainer_patch"] = str(maint_path)
        result["upstream_patch"] = str(up_path)
        print(json.dumps(result, indent=2))
        return 0 if result["verdict"] != "empty" else 3

    nixpkgs_dir = resolve_nixpkgs_dir(args.nixpkgs)
    if args.history:
        if not (nixpkgs_dir / ".git").exists():
            raise SystemExit(
                f"error: --history needs a git checkout; {nixpkgs_dir} has no .git"
            )
        all_candidates = harvest_history(nixpkgs_dir, args.ref)
    else:
        pkgs_root = nixpkgs_dir / "pkgs"
        patch_paths = find_cve_patches(nixpkgs_dir)
        all_candidates = [
            build_candidate(p, nixpkgs_dir, pkgs_root) for p in patch_paths
        ]
        all_candidates.sort(key=_sort_key)

    header = build_header(nixpkgs_dir, all_candidates)
    candidates = (
        all_candidates[: args.limit] if args.limit is not None else all_candidates
    )

    jsonl_path, md_path = write_manifest(args.out, header, candidates)

    print(f"nixpkgs: {nixpkgs_dir}")
    print(f"nixpkgs_ref: {header['nixpkgs_ref']}")
    print(f"total patches scanned: {header['total_patches_scanned']}")
    print(f"  wired: {header['wired_count']}  unwired: {header['unwired_count']}")
    counts = header["classification_counts"]
    for key in ("likely-adaptation", "likely-verbatim", "unknown"):
        print(f"  {key}: {counts.get(key, 0)}")
    print(f"wrote: {jsonl_path}")
    print(f"wrote: {md_path}")
    print()
    print(f"top {min(10, len(candidates))} candidates:")
    print(
        f"{'rank':>4}  {'score':>7}  {'cve_ids':<28}  {'pkg':<16}  {'class':<17}  {'f/h':<5}  {'+/-':<10}  path"
    )
    for i, c in enumerate(candidates[:10], start=1):
        fh = f"{c['n_files']}/{c['n_hunks']}"
        pm = f"+{c['added_lines']}/-{c['removed_lines']}"
        print(
            f"{i:>4}  {c['rank_score']:>7.2f}  {', '.join(c['cve_ids'])[:28]:<28}  "
            f"{c['package'][:16]:<16}  {c['classification']:<17}  {fh:<5}  {pm:<10}  "
            f"{c['patch_path']}"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
