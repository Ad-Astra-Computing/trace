#!/usr/bin/env python3
"""Regenerate REUSE.toml and traces/THIRD_PARTY_NOTICES.md from `git
ls-files`: declares every file that carries third-party text (an upstream
patch, a co-landed source excerpt, a verbatim package.nix) under its own
license, separate from trace's own Apache-2.0 content. A synthetic bundle
(upstream-ref.json points at example.invalid, or CVE-0000-* with none at
all) is excluded regardless of how patch-shaped its files look.

Run after the corpus changes: python3 scripts/gen_third_party_notices.py
"""

from __future__ import annotations

import json
import re
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

NIX_TO_SPDX = {
    "agpl3Only": "AGPL-3.0-only",
    "agpl3Plus": "AGPL-3.0-or-later",
    "artistic1": "Artistic-1.0",
    "asl20": "Apache-2.0",
    "bsd2": "BSD-2-Clause",
    "bsd3": "BSD-3-Clause",
    "bsdOriginal": "BSD-4-Clause",
    "curl": "curl",
    "gpl2Only": "GPL-2.0-only",
    "gpl2": "GPL-2.0-only",
    "gpl2Plus": "GPL-2.0-or-later",
    "gpl3Plus": "GPL-3.0-or-later",
    "gpl3": "GPL-3.0-only",
    "isc": "ISC",
    "lgpl21": "LGPL-2.1-only",
    "lgpl21Plus": "LGPL-2.1-or-later",
    "lgpl2Plus": "LGPL-2.0-or-later",
    "mit": "MIT",
    "mpl20": "MPL-2.0",
    "openssl": "OpenSSL",
    "libpng2": "libpng-2.0",
    "libtiff": "libtiff",
    "psfl": "PSF-2.0",
    "publicDomain": "LicenseRef-public-domain",
    "xfig": "LicenseRef-xfig",
    "zlib": "Zlib",
}

NIXPKGS_MIT = "MIT"
NIXPKGS_COPYRIGHT = "NixOS/nixpkgs contributors (package.nix is a verbatim nixpkgs file)"

THIRD_PARTY_FALLBACK = "LicenseRef-third-party-varies"
UNKNOWN_CELL = "unknown, see upstream"
NO_UPSTREAM_CELL = "n/a"


def tracked_files() -> list[Path]:
    out = subprocess.run(
        ["git", "ls-files"], cwd=ROOT, capture_output=True, text=True, check=True
    ).stdout
    return [ROOT / line for line in out.splitlines() if line]


def bundle_root_for(path: Path) -> Path | None:
    """Walk up from a corpus file to the bundle directory that holds its
    upstream-ref.json / package.nix / finding.json, however deep the file
    sits (e.g. source-context/libarchive/archive_read_support_format_tar.c)."""
    for parent in path.parents:
        if parent == ROOT:
            return None
        if (parent / "upstream-ref.json").is_file() or (parent / "finding.json").is_file():
            return parent
    return None


def is_synthetic(bundle: Path) -> bool:
    """A hand-authored fixture, not a real CVE against a real project.
    Checked against the whole upstream-ref.json text rather than specific
    fields: an advisory-only fixture (CVE-0000-9001, say) can carry
    example.invalid only in advisory_urls with no upstream_fix_commits at
    all, and a field-by-field check misses exactly that shape."""
    ref = bundle / "upstream-ref.json"
    if not ref.is_file():
        return bundle.name.startswith("CVE-0000-")
    return "example.invalid" in ref.read_text(errors="ignore")


LICENSE_LIST_RE = re.compile(
    r"license\s*=\s*(?:with\s+(?:lib\.)?licenses;\s*)?"
    r"(?:\[\s*(?P<list>[\w\s.]+?)\s*\]|(?:lib\.)?(?:licenses\.)?(?P<single>\w+))"
)


def package_license(bundle: Path) -> str | None:
    """A single resolvable SPDX id from package.nix's meta.license, or None
    when it's absent, unparsed, or (deliberately) a multi-entry list: a list
    needs either an SPDX OR-expression or human judgment, not a guess at
    which entry actually covers the patched file, so it falls through to
    the LicenseRef-third-party-varies marker instead of a specific wrong
    answer."""
    pn = bundle / "package.nix"
    if not pn.is_file():
        return None
    text = pn.read_text(errors="ignore")
    m = LICENSE_LIST_RE.search(text)
    if not m:
        return None
    if m.group("list"):
        keys = m.group("list").split()
        if len(keys) != 1:
            return None
        key = keys[0]
    else:
        key = m.group("single")
    return NIX_TO_SPDX.get(key)


def upstream_project(bundle: Path) -> str | None:
    ref = bundle / "upstream-ref.json"
    if not ref.is_file():
        return None
    try:
        doc = json.loads(ref.read_text())
    except Exception:
        return None
    commits = doc.get("upstream_fix_commits") or []
    if commits and isinstance(commits, list):
        repo = commits[0].get("repo_url")
        if repo:
            return str(repo)
    return None


def is_source_backport_patch_diff(text: str) -> bool:
    added_or_modified_patch_file = any(
        line.startswith("+++ b/") and line.strip().endswith(".patch")
        for line in text.splitlines()
    )
    return added_or_modified_patch_file or text.startswith("From ") or "\nFrom " in text


def authoring_example_sizeable(path: Path) -> bool:
    try:
        doc = json.loads(path.read_text(errors="ignore"))
    except Exception:
        return False
    src = doc.get("pre_fix_source") or ""
    diff = doc.get("fix_diff") or ""
    return len(src) > 40 or len(diff) > 40


Entry = tuple[str, str, str | None, str | None]  # (path, label, license, upstream)


def main() -> None:
    entries: list[Entry] = []
    seen_paths: set[str] = set()
    bundle_cache: dict[Path, tuple[str | None, str | None, bool]] = {}

    def bundle_info(bundle: Path) -> tuple[str | None, str | None, bool]:
        if bundle not in bundle_cache:
            bundle_cache[bundle] = (
                package_license(bundle),
                upstream_project(bundle),
                is_synthetic(bundle),
            )
        return bundle_cache[bundle]

    def declare(path: Path, bundle: Path, label: str, override_license: str | None = None) -> None:
        rel = path.relative_to(ROOT).as_posix()
        if rel in seen_paths:
            return
        lic, upstream, synthetic = bundle_info(bundle)
        if synthetic:
            return
        seen_paths.add(rel)
        entries.append((rel, label, override_license or lic, upstream))

    all_tracked = [f for f in tracked_files() if f.is_file()]

    for f in all_tracked:
        name = f.name

        if name.endswith(".patch"):
            bundle = bundle_root_for(f)
            if not bundle:
                continue
            if name == "upstream-fix.patch" and "negatives" in f.relative_to(ROOT).parts:
                # traces/negatives/: this file is a deliberately mutated
                # corruption of the real upstream fix (see the sibling
                # upstream-fix.original.patch), not the fix itself. Still
                # third-party-derived text, worth a label that says so.
                declare(f, bundle, "mutated negative fixture (derived from the upstream fix)")
            else:
                declare(f, bundle, "upstream fix patch")
            continue

        if name == "patch.diff":
            bundle = bundle_root_for(f)
            if bundle is None:
                continue
            text = f.read_text(errors="ignore")
            if is_source_backport_patch_diff(text):
                declare(f, bundle, "source-backport patch")
            continue

        if name == "package.nix":
            bundle = bundle_root_for(f)
            if bundle:
                declare(f, bundle, "nixpkgs package expression", override_license=NIXPKGS_MIT)
            continue

        if name == "authoring-example.json":
            bundle = bundle_root_for(f)
            if bundle and authoring_example_sizeable(f):
                declare(f, bundle, "embedded upstream source/diff (pre_fix_source, fix_diff)")
            continue

    for f in all_tracked:
        parts = f.relative_to(ROOT).parts
        if "source-context" in parts:
            bundle = bundle_root_for(f)
            if bundle:
                declare(f, bundle, "staged upstream source")
        elif "reproducer-fixtures" in parts and f.name.count(".") >= 2 and ".prefix." in f.name:
            bundle = bundle_root_for(f)
            if bundle:
                declare(f, bundle, "upstream source excerpt (reproducer fixture)")

    # reproducer.nix documenting a fixture as co-landed with the upstream
    # fix means every file under reproducer-fixtures/ is upstream's, not
    # trace's; a hand-authored harness carries no such comment and is left alone.
    CO_LANDED_MARKERS = ("co-landed", "CO-LANDED", "backport-fixtures")
    for f in all_tracked:
        if f.name != "reproducer.nix":
            continue
        bundle = bundle_root_for(f) or f.parent
        rf = bundle / "reproducer-fixtures"
        if not rf.is_dir():
            continue
        text = f.read_text(errors="ignore")
        if not any(marker in text for marker in CO_LANDED_MARKERS):
            continue
        for fixture in sorted(rf.rglob("*")):
            if fixture.is_file():
                declare(fixture, bundle, "upstream regression-test asset (co-landed with the fix)")

    # Any tracked *.jsonl that embeds a real unified-diff hunk: LoRA export
    # files aggregating many bundles, no single upstream to resolve against,
    # so these get the safe fallback license rather than a specific guess.
    for f in all_tracked:
        if f.suffix != ".jsonl":
            continue
        rel = f.relative_to(ROOT).as_posix()
        if rel in seen_paths:
            continue
        text = f.read_text(errors="ignore")
        if "@@ -" in text and "+++" in text:
            seen_paths.add(rel)
            entries.append((rel, "LoRA export aggregating multiple upstream diffs/sources", None, None))

    entries.sort()

    def copyright_text(label: str, upstream: str | None) -> str:
        if label == "nixpkgs package expression":
            return NIXPKGS_COPYRIGHT
        if label.startswith("LoRA export"):
            return "multiple upstream projects; one row per CVE, see the corresponding traces/ bundle for each"
        if upstream:
            return f"the upstream project at {upstream}"
        return "the upstream project this bundle's CVE was filed against (see traces/THIRD_PARTY_NOTICES.md)"

    lines = [
        "# Generated by scripts/gen_third_party_notices.py; do not hand-edit.",
        "# Declares the files that carry third-party text, not trace's own.",
        "",
        "version = 1",
        "",
    ]
    for rel, label, lic, upstream in entries:
        spdx = lic or THIRD_PARTY_FALLBACK
        lines.append("[[annotations]]")
        lines.append(f'path = "{rel}"')
        lines.append(f'SPDX-FileCopyrightText = "{copyright_text(label, upstream)}"')
        lines.append(f'SPDX-License-Identifier = "{spdx}"')
        lines.append("")

    (ROOT / "REUSE.toml").write_text("\n".join(lines).rstrip() + "\n")

    by_bundle: dict[str, list[Entry]] = {}
    for rel, label, lic, upstream in entries:
        # The bundle directory is the file's parent for a top-level file
        # (upstream-fix.patch, patch.diff, package.nix, authoring-example.json)
        # and the nearest ancestor holding one of those for a nested file
        # (source-context/**, reproducer-fixtures/*.prefix.*).
        p = ROOT / rel
        bundle = bundle_root_for(p) or p.parent
        bname = bundle.relative_to(ROOT).as_posix()
        by_bundle.setdefault(bname, []).append((rel, label, lic, upstream))

    md = [
        "# Third-party notices",
        "",
        "trace's own content is Apache-2.0 (see [`LICENSE`](../LICENSE)). The files",
        "listed here are different: each one is a verbatim upstream security patch or",
        "source excerpt, or the nixpkgs package expression itself, reproduced here as",
        "the evidentiary record a bundle's claim rests on. They remain under",
        "whatever license the originating project (or nixpkgs) uses, not trace's.",
        "",
        "This file is generated by [`scripts/gen_third_party_notices.py`]"
        "(../scripts/gen_third_party_notices.py) from `git ls-files`, machine-readable",
        "as [`REUSE.toml`](../REUSE.toml). A bundle whose `package.nix` does not carry a",
        f"single resolvable `meta.license` is marked `{UNKNOWN_CELL}` below; check the",
        "upstream project directly before reusing that file. Synthetic test fixtures",
        "(no real CVE, no real upstream project) are excluded entirely.",
        "",
        "| Bundle | File | What it is | License | Upstream |",
        "|---|---|---|---|---|",
    ]
    for bname in sorted(by_bundle):
        for rel, label, lic, upstream in by_bundle[bname]:
            fname = rel.split("/")[-1]
            lic_cell = lic or UNKNOWN_CELL
            up_cell = upstream or NO_UPSTREAM_CELL
            md.append(f"| {bname} | `{fname}` | {label} | {lic_cell} | {up_cell} |")

    (ROOT / "traces" / "THIRD_PARTY_NOTICES.md").write_text("\n".join(md) + "\n")

    print(f"{len(entries)} third-party files declared across {len(by_bundle)} bundles")
    resolved = sum(1 for _, _, lic, _ in entries if lic)
    print(f"{resolved} with a known single SPDX license, {len(entries) - resolved} marked unknown")

    # Every resolved id needs a license text on disk, or reuse lint would
    # flag it the day a bundle first resolves to it, however cleanly the
    # corpus lints today. Checked against every id the NIX_TO_SPDX mapping
    # can produce, not just the ones currently in use, so this catches a
    # gap before a future run hits it rather than after.
    missing_texts = sorted(
        {spdx for spdx in NIX_TO_SPDX.values() if not spdx.startswith("LicenseRef")}
        - {p.stem for p in (ROOT / "LICENSES").glob("*.txt")}
    )
    if missing_texts:
        print(f"WARNING: no LICENSES/ text for: {', '.join(missing_texts)}")


if __name__ == "__main__":
    main()
