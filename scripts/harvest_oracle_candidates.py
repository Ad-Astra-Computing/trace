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

    classification_bonus = 100 if likely-adaptation
                             40 if unknown
                              0 if likely-verbatim
    signal_bonus          = 40 * min(len(adaptation_signals), 3)
    single_file_bonus    = 10 if n_files == 1 else 0
    size_penalty          = 1.0 * n_hunks
                          + 1.5 * max(n_files - 1, 0)
                          + 0.03 * (added_lines + removed_lines)

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
import sys
from pathlib import Path
from typing import Any

SCHEMA_VERSION = "1.0.0"

CVE_ID_RE = re.compile(r"CVE-\d{4}-\d{4,}", re.IGNORECASE)

# Canonical `git format-patch` first line, e.g.
# "From e47e56d226519635768e6aab2f38f0ab037c09e5 Mon Sep 17 00:00:00 2001"
FORMAT_PATCH_RE = re.compile(
    r"^From ([0-9a-fA-F]{40}) Mon Sep 17 00:00:00 2001\s*$"
)

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
    "context",
    "rebased",
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
    matches = [
        p
        for p in pkgs_root.rglob("*.patch")
        if CVE_ID_RE.search(p.name)
    ]
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
    if (
        len(rel_parts) >= 4
        and rel_parts[0] == "pkgs"
        and rel_parts[1] == "by-name"
    ):
        return rel_parts[3]

    anchor = find_anchor_dir(patch_path, pkgs_root)
    if anchor is not None:
        return anchor.name
    return patch_path.parent.name


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


def _find_adaptation_signals(header_text: str) -> list[str]:
    signals: list[str] = []
    for word in ADAPTATION_WORDS:
        if not _ADAPTATION_WORD_RES[word].search(header_text):
            continue
        # "backport" is a whole-word substring of "backported"; report only
        # the more specific match once "backported" has already fired.
        if word == "backport" and "backported" in signals:
            continue
        signals.append(word)
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


def rank_score(
    classification: str,
    *,
    n_files: int,
    n_hunks: int,
    added_lines: int,
    removed_lines: int,
    adaptation_signals: list[str],
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
        1.0 * n_hunks
        + 1.5 * max(n_files - 1, 0)
        + 0.03 * (added_lines + removed_lines)
    )
    return classification_bonus + signal_bonus + single_file_bonus - size_penalty


# ─── harvest ────────────────────────────────────────────────────────────────


def build_candidate(patch_path: Path, nixpkgs_dir: Path, pkgs_root: Path) -> dict[str, Any]:
    raw = patch_path.read_bytes()
    parsed = parse_patch(raw)
    classification = classify(
        parsed["is_format_patch"], parsed["adaptation_signals"], parsed["n_hunks"]
    )
    score = rank_score(
        classification,
        n_files=parsed["n_files"],
        n_hunks=parsed["n_hunks"],
        added_lines=parsed["added_lines"],
        removed_lines=parsed["removed_lines"],
        adaptation_signals=parsed["adaptation_signals"],
    )
    anchor_dir = find_anchor_dir(patch_path, pkgs_root)
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
        "classification": classification,
        "rank_score": score,
    }


def _sort_key(c: dict[str, Any]) -> tuple[float, int, str]:
    first_cve = c["cve_ids"][0] if c["cve_ids"] else ""
    return (-c["rank_score"], c["n_hunks"], first_cve)


def harvest(nixpkgs_dir: Path, limit: int | None = None) -> list[dict[str, Any]]:
    """Scan `nixpkgs_dir` for CVE backport patches and return a ranked list
    of candidate dicts (best-first). `limit`, if given, truncates the
    returned list but does not affect ranking."""
    pkgs_root = nixpkgs_dir / "pkgs"
    patch_paths = find_cve_patches(nixpkgs_dir)
    candidates = [
        build_candidate(p, nixpkgs_dir, pkgs_root) for p in patch_paths
    ]
    candidates.sort(key=_sort_key)
    if limit is not None:
        candidates = candidates[:limit]
    return candidates


def build_header(nixpkgs_dir: Path, all_candidates: list[dict[str, Any]]) -> dict[str, Any]:
    counts: dict[str, int] = {}
    for c in all_candidates:
        counts[c["classification"]] = counts.get(c["classification"], 0) + 1
    return {
        "kind": "harvest-header",
        "schema_version": SCHEMA_VERSION,
        "nixpkgs_dir": str(nixpkgs_dir),
        "nixpkgs_ref": nixpkgs_dir.name,
        "total_patches_scanned": len(all_candidates),
        "classification_counts": counts,
    }


# ─── rendering / writing ────────────────────────────────────────────────────


def render_markdown(header: dict[str, Any], candidates: list[dict[str, Any]]) -> str:
    lines: list[str] = []
    lines.append("# Adaptation-oracle candidates")
    lines.append("")
    lines.append(f"nixpkgs: `{header['nixpkgs_dir']}`")
    lines.append(f"nixpkgs_ref: `{header['nixpkgs_ref']}`")
    lines.append(f"total patches scanned: {header['total_patches_scanned']}")
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
        "| rank | score | cve_ids | package | classification | files | hunks "
        "| +/- | signals | patch_path |"
    )
    lines.append("|---|---|---|---|---|---|---|---|---|---|")
    for i, c in enumerate(candidates, start=1):
        signals = ", ".join(c["adaptation_signals"]) or "-"
        lines.append(
            f"| {i} | {c['rank_score']:.2f} | {', '.join(c['cve_ids']) or '-'} "
            f"| {c['package']} | {c['classification']} | {c['n_files']} "
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
        "--limit",
        type=int,
        default=None,
        help="cap the number of candidates written (ranking still computed over all)",
    )
    return parser


def main(argv: list[str]) -> int:
    parser = build_arg_parser()
    args = parser.parse_args(argv[1:])

    nixpkgs_dir = resolve_nixpkgs_dir(args.nixpkgs)
    pkgs_root = nixpkgs_dir / "pkgs"
    patch_paths = find_cve_patches(nixpkgs_dir)
    all_candidates = [
        build_candidate(p, nixpkgs_dir, pkgs_root) for p in patch_paths
    ]
    all_candidates.sort(key=_sort_key)

    header = build_header(nixpkgs_dir, all_candidates)
    candidates = all_candidates[: args.limit] if args.limit is not None else all_candidates

    jsonl_path, md_path = write_manifest(args.out, header, candidates)

    print(f"nixpkgs: {nixpkgs_dir}")
    print(f"nixpkgs_ref: {header['nixpkgs_ref']}")
    print(f"total patches scanned: {header['total_patches_scanned']}")
    counts = header["classification_counts"]
    for key in ("likely-adaptation", "likely-verbatim", "unknown"):
        print(f"  {key}: {counts.get(key, 0)}")
    print(f"wrote: {jsonl_path}")
    print(f"wrote: {md_path}")
    print()
    print(f"top {min(10, len(candidates))} candidates:")
    print(f"{'rank':>4}  {'score':>7}  {'cve_ids':<28}  {'pkg':<16}  {'class':<17}  {'f/h':<5}  {'+/-':<10}  path")
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
