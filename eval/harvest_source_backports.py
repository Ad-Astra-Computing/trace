"""Source-backport candidate harvester — the abundant supply vein.

Strategy (codex peer <redacted-session-id>, 2026-06-15): do NOT start from the CVE feed. Scan
*nixpkgs history* for commits that fix a CVE by CARRYING A PATCH rather than
bumping the version. Every such commit is a ready-made source-backport candidate:
it gives a real CVE, a real pre-fix nixpkgs tree, the affected package, and a
historical adapted patch to compare against. This is the opposite of the
version-bump scarcity — nixpkgs carries hundreds of these.

A candidate is a commit that ADDS a `*.patch` file under `pkgs/` and references a
CVE, where the package VERSION is unchanged (a pure patch-add, not a bump that
also happens to ship a patch). For each we extract:

  * nixpkgs_fix_commit      the commit SHA that added the patch
  * nixpkgs_pre_fix_rev     its parent (the vulnerable tree the agent patches)
  * package                 the attr/dir inferred from the patch path
  * cve_ids                 CVE ids from the subject + patch filename
  * patch_files             the added .patch path(s)  (the nixpkgs reference patch)
  * version_changed         True ⇒ skip (bump+patch combo, not a clean backport)

The output JSONL feeds the bundle-bootstrap pipeline (CLAUDE.md § Bundle
bootstrap): each row is a lead to hand-author resolver-side files against the
pre-fix rev, set `patch_strategy: source-backport`, and let the Patcher AUTHOR
the fix. Behavioral validation then runs via eval/backport_validation.py.

This module shells out to a local `nixpkgs` clone (read-only `git log`/`git
show`); the parsing is factored into pure functions so it is unit-testable
without a repo.
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path

_CVE_RE = re.compile(r"CVE-\d{4}-\d{3,7}")
# An added line that changes the package version (the bump signal we exclude).
_VERSION_CHANGE_RE = re.compile(r"^\+(?!\+\+).*\bversion\s*=\s*[\"']")


@dataclass(frozen=True)
class BackportCandidate:
    cve_ids: list[str]
    package: str
    nixpkgs_fix_commit: str
    nixpkgs_pre_fix_rev: str
    patch_files: list[str]
    subject: str
    version_changed: bool
    keywords: list[str] = field(default_factory=list)
    build_class: str = "unknown"
    craftability: str = "unknown"
    upstream_fix_url: str | None = None

    def to_dict(self) -> dict:
        return {
            "cve_ids": self.cve_ids,
            "package": self.package,
            "nixpkgs_fix_commit": self.nixpkgs_fix_commit,
            "nixpkgs_pre_fix_rev": self.nixpkgs_pre_fix_rev,
            "patch_files": self.patch_files,
            "subject": self.subject,
            "version_changed": self.version_changed,
            "keywords": self.keywords,
            "build_class": self.build_class,
            "craftability": self.craftability,
            "upstream_fix_url": self.upstream_fix_url,
            "patch_strategy": "source-backport",
        }


# Memory-safety classes that are silent without ASAN — flagged so the bootstrap
# can scope v1 to behaviorally-testable-WITHOUT-ASAN candidates first (codex).
_ASAN_HINTS = ("heap buffer overflow", "heap-buffer-overflow", "buffer overflow",
               "use-after-free", "use after free", "out-of-bounds", "out of bounds",
               "oob", "double free", "double-free", "uninitialized")
_TESTABLE_HINTS = ("command injection", "shell injection", "path traversal",
                   "null", "host key", "credential", "verification", "auth",
                   "ssrf", "xxe", "denial", "infinite loop", "integer overflow")


def package_from_patch_path(patch_path: str) -> str:
    """Infer the package attr/dir from a patch path. by-name packages live at
    pkgs/by-name/<2>/<pkg>/...; legacy ones at pkgs/.../<pkg>/<file>.patch."""
    parts = patch_path.split("/")
    if len(parts) >= 4 and parts[1] == "by-name":
        return parts[3]
    # legacy: the directory holding the patch is usually the package dir
    if len(parts) >= 2:
        return parts[-2]
    return patch_path


def packages_from_patches(patch_files: list[str]) -> list[str]:
    """The distinct packages a commit's added patches touch. Strict mode requires
    exactly one — a commit adding patches across several package dirs (a treewide
    security sweep) is not a single source-backport lead and was the source of the
    espeak-style noise (one package label, every CVE in the sweep)."""
    return sorted({package_from_patch_path(p) for p in patch_files})


def cves_tied_to_patches(
    patch_files: list[str], full_diff_added_lines: list[str]
) -> list[str]:
    """CVE ids that are actually attributable to the patch, i.e. present in a patch
    FILENAME or in the patch BODY. A CVE that appears only in the commit subject is
    NOT tied — it is usually one entry in a multi-CVE changelog and does not mean
    the added patch fixes it. This is the precision fix for the espeak failure:
    a subject listing 30 CVEs no longer taints a commit that ships one patch."""
    blob = " ".join(patch_files) + "\n" + "\n".join(full_diff_added_lines)
    return sorted(set(_CVE_RE.findall(blob)), key=str.upper)


def resolve_strict_cves(
    patch_files: list[str], full_diff_added_lines: list[str], subject: str
) -> list[str]:
    """The CVE ids a strict candidate may claim. Patch-tied CVEs (filename/body) are
    authoritative. With none tied, a subject that names exactly ONE CVE is still
    trusted: a focused commit like `putty: fix CVE-2026-4115` is the maintainer's
    own attribution, even when the patch file keeps a descriptive name. A subject
    naming several CVEs with none tied to the patch is a changelog/batch (the espeak
    failure) and yields no claimable CVE."""
    tied = cves_tied_to_patches(patch_files, full_diff_added_lines)
    if tied:
        return tied
    subject_cves = sorted(set(_CVE_RE.findall(subject)), key=str.upper)
    if len(subject_cves) == 1:
        return subject_cves
    return []


# Upstream-reference tells inside a backport `.patch` body. Patches carried in
# nixpkgs almost always cite their origin: a project commit URL, a git
# format-patch `From <40hex>` header, or an `Origin:`/`Upstream-commit:` line.
_UPSTREAM_URL_RE = re.compile(
    r"https?://[^\s'\"<>]+/(?:commit|commits|pull|cgit[^\s'\"<>]*/commit)/[^\s'\"<>)]+")
_GIT_FROM_RE = re.compile(r"^From ([0-9a-f]{40})\b")
_ORIGIN_SHA_RE = re.compile(
    r"(?:Upstream-commit|Git-commit|Origin|Upstream-Status)\s*:.*?\b([0-9a-f]{40})\b",
    re.IGNORECASE)


def extract_upstream_fix_url(full_diff_added_lines: list[str]) -> str | None:
    """Recover the upstream fix reference (a commit URL, or a bare 40-hex commit
    sha) from the backport `.patch` body embedded in the commit's added lines.
    Returns None when no reference is present — in strict mode that is a soft
    signal, not a hard reject, since some legitimate patches carry only a
    description."""
    inner = [ln[1:] for ln in full_diff_added_lines if ln.startswith("+")]
    for pl in inner:
        m = _UPSTREAM_URL_RE.search(pl)
        if m:
            return m.group(0)
    for pl in inner:
        m = _GIT_FROM_RE.search(pl) or _ORIGIN_SHA_RE.search(pl)
        if m:
            return m.group(1)
    return None


def strict_reject_reason(
    *, packages: list[str], patch_cves: list[str], version_changed: bool,
    patch_files: list[str], max_patches: int = 4, max_cves: int = 3,
) -> str | None:
    """Return why a candidate fails the strict precision gate, or None if it passes.

    The gate (codex 2026-06-18): a strict source-backport lead touches exactly one
    package, ships a patch tied to its CVE, leaves the version unchanged, and is not
    a mass import. Each rejected shape is a documented false-positive class."""
    if len(packages) != 1:
        return f"multi-package ({len(packages)} packages: {','.join(packages)})"
    if not patch_cves:
        return "no CVE tied to the patch (subject-only match)"
    if version_changed:
        return "version changed (bump+patch combo, not a clean backport)"
    if len(patch_files) > max_patches:
        return f"too many patches ({len(patch_files)} > {max_patches}; likely a sweep)"
    if len(patch_cves) > max_cves:
        return f"too many CVEs ({len(patch_cves)} > {max_cves}; likely a batch)"
    return None


def classify_keywords(subject: str, patch_files: list[str]) -> list[str]:
    """Tag a candidate with hints used to scope the bootstrap order. 'asan-class'
    = likely silent memory bug (parallel ASAN track); 'testable' = behaviorally
    testable without ASAN (the v1 priority)."""
    hay = (subject + " " + " ".join(patch_files)).lower()
    tags = []
    if any(h in hay for h in _ASAN_HINTS):
        tags.append("asan-class")
    if any(h in hay for h in _TESTABLE_HINTS):
        tags.append("testable")
    return tags


_NATIVE_SRC_RE = re.compile(r"[ab]/.*\.(xs|c|cc|cpp|cxx|h|hpp|rs|go)\b")


def classify_build_class(
    patch_files: list[str], keywords: list[str], inner_native: bool = False,
) -> str:
    """Coarse build-class tag used to scope the bootstrap to the fast cert lane
    (codex 2026-06-16):
      - 'asan-required'    : memory-class bug (separate ASAN track), takes priority
      - 'light-interpreter': pure-script library (perl/python/ruby module) patching
        only interpreted source — builds fast on a CACHED interpreter, so the cert
        is minutes regardless of how old the pinned pre-fix rev is (the fast lane)
      - 'compiled'         : C/C++/Rust/Go or a NATIVE extension (.xs/.c/...) inside
        a script-module dir — needs the toolchain; cert time depends on
        cache-availability of the pinned rev's stdenv (an OLD rev can be 'cold' =
        multi-hour from-source rebuild). Run a substitute-availability preflight
        before any live spend on these.
    `inner_native` is True when the authored patch edits native source (a .xs/.c/...
    file) even though it lives under perl-modules/python-modules — those are NOT
    light (e.g. JSON::XS, onnx). Cache-warmth ('compiled-cached' vs 'compiled-cold')
    is a preflight refinement, not knowable from the patch path alone."""
    if "asan-class" in keywords:
        return "asan-required"
    if inner_native:
        return "compiled"
    joined = " ".join(patch_files)
    if "/perl-modules/" in joined or "/python-modules/" in joined or "/ruby-modules/" in joined:
        return "light-interpreter"
    return "compiled"


# The inner backport `.patch` file is itself committed as added lines, so the
# commit's `+` lines (full_diff_added_lines, populated under --check-version /
# --craftable-only) contain the patch's own header/`+`/`-`/context lines. We mine
# them for the "tell" that decides whether a candidate's discriminating
# reproducer is CRAFTABLE from the fix alone (the lesson of 2026-06-16: giflib/
# jq/coreutils/zlib were craftable; fig2dev/lua/mpack were PoC-gated and burned
# bootstrap cycles).
#
# An inner patch line `+++ b/tests/foo` arrives here as a commit-added line
# `++++ b/tests/foo` (commit `+` then the patch's own `+`); a header `--- a/x`
# arrives as `+--- a/x`. We strip the single leading commit `+` to recover the
# patch's own line, then inspect.
_INNER_TEST_PATH_RE = re.compile(
    r"^[-+]{3}\s+[ab]/.*("
    r"tests?/|/test|[._-]test\b|testdata|testsuite|/t/|fixtures?/|samples?/|"
    r"fuzz|corpus|regress)", re.IGNORECASE)
# A bound/comparison/NULL token introduced by the fix. When a backport ADDS such
# a check, its out-of-range trigger is usually DERIVABLE directly from the fix
# (make the new condition false). `<`/`>` require a trailing space so member
# access (`->`) and includes (`<config.h>`) don't match.
_ADDED_BOUND_RE = re.compile(
    r"(>=|<=|==|!=|[<>](?=\s|$)|\bNULL\b|\bnullptr\b|_max\b|_MAX\b|_len\b|"
    r"\b(count|length|size|bound|limit|extra_max|extra_len|ColorCount|maxdepth)\b)")


def classify_craftability(full_diff_added_lines: list[str]) -> str:
    """Rank a candidate by whether its discriminating reproducer is craftable
    from the fix alone. Operates on the commit's added lines (which embed the
    backport `.patch` body); returns "unknown" when those aren't available
    (no --check-version / --craftable-only content fetch).

      - 'embeds-test'    : the inner patch touches a test/fixture/fuzz path, so
        the upstream regression input IS the PoC (e.g. jq's tests/jq.test,
        coreutils' tests/sort/*). The most reliable tell.
      - 'derivable-guard': the inner patch ADDS a bound/NULL/length comparison, so
        the trigger is "make the new check fail" (giflib `>= ColorCount`, zlib
        `< extra_max`, coreutils field-offset bound). Heuristic: a bound that
        merely re-validates a field whose vulnerable downstream use is opaque
        (e.g. fig2dev `style_val > MAX`) is a known false-positive — the local
        probe in the bootstrap is still the real viability gate.
      - 'poc-gated'      : a bare code fix with neither — the trigger needs an
        external PoC artifact (lua's `luaK_exp2anyregup`, mpack's perms change).
        Deprioritize: bootstrapping these burns cycles (2026-06-16 lesson).
    """
    if not full_diff_added_lines:
        return "unknown"
    # recover the inner patch's own lines (strip the single leading commit '+')
    inner = [ln[1:] for ln in full_diff_added_lines if ln.startswith("+")]
    if any(_INNER_TEST_PATH_RE.match(pl) for pl in inner):
        return "embeds-test"
    # the patch's own ADDED code lines appear here as inner lines starting '+'
    if any(_ADDED_BOUND_RE.search(pl[1:]) for pl in inner if pl.startswith("+")):
        return "derivable-guard"
    return "poc-gated"


def parse_commit_record(
    *, commit: str, parent: str, subject: str,
    added_patch_files: list[str], full_diff_added_lines: list[str],
    patch_filenames_for_cve: bool = True, strict: bool = False,
) -> BackportCandidate | None:
    """Pure parser: build a candidate from already-extracted git facts. Returns
    None if the commit added no `*.patch` under pkgs/ (not a source-backport).

    `strict` applies the precision gate (codex 2026-06-18): CVE ids are restricted
    to those tied to the patch (filename/body, not the subject changelog), the
    candidate must touch exactly one package, leave the version unchanged and not be
    a mass sweep, and the upstream fix reference is extracted. Commits that fail the
    gate return None. Non-strict behaviour is unchanged (the bulk-scan default)."""
    patches = [f for f in added_patch_files
               if f.endswith(".patch") and f.startswith("pkgs/")]
    if not patches:
        return None
    version_changed = any(_VERSION_CHANGE_RE.match(ln) for ln in full_diff_added_lines)

    if strict:
        cves = resolve_strict_cves(patches, full_diff_added_lines, subject)
        packages = packages_from_patches(patches)
        if strict_reject_reason(
            packages=packages, patch_cves=cves,
            version_changed=version_changed, patch_files=patches,
        ) is not None:
            return None
        package = packages[0]
        upstream_fix_url = extract_upstream_fix_url(full_diff_added_lines)
    else:
        cve_blob = subject + (" " + " ".join(patches) if patch_filenames_for_cve else "")
        cves = sorted(set(_CVE_RE.findall(cve_blob)), key=str.upper)
        package = package_from_patch_path(patches[0])
        upstream_fix_url = extract_upstream_fix_url(full_diff_added_lines)

    return BackportCandidate(
        cve_ids=cves,
        package=package,
        nixpkgs_fix_commit=commit,
        nixpkgs_pre_fix_rev=parent,
        patch_files=patches,
        subject=subject,
        version_changed=version_changed,
        keywords=classify_keywords(subject, patches),
        build_class=classify_build_class(
            patches, classify_keywords(subject, patches),
            inner_native=any(_NATIVE_SRC_RE.search(ln) for ln in full_diff_added_lines),
        ),
        craftability=classify_craftability(full_diff_added_lines),
        upstream_fix_url=upstream_fix_url,
    )


def _git(repo: Path, *args: str, timeout: int = 120) -> str:
    # errors="replace": some upstream *.patch payloads carry non-UTF8 bytes (binary
    # test fixtures, latin-1 author names); decode tolerantly so a `git show` over
    # patch bodies (build-class native detection) never crashes the scan.
    out = subprocess.run(
        ["git", "-C", str(repo), *args],
        capture_output=True, text=True, timeout=timeout, errors="replace",
    )
    if out.returncode != 0:
        raise RuntimeError(f"git {' '.join(args)} failed: {out.stderr[-300:]}")
    return out.stdout


def _is_shallow_ref(repo: Path, ref: str) -> bool:
    """A shallow commit (e.g. FETCH_HEAD from `fetch --depth=1`) has no recorded
    parent, so `--diff-filter=A` would mark EVERY file as added in that one
    pseudo-commit — useless for history scanning. Detect and refuse it."""
    try:
        parents = _git(repo, "rev-list", "--parents", "-1", ref).split()
    except RuntimeError:
        return False
    return len(parents) <= 1  # only the commit's own sha, no parent


def harvest(repo: Path, *, limit: int, require_cve: bool = True,
            ref: str = "HEAD", check_version: bool = False,
            craftable: bool = False, strict: bool = False) -> list[BackportCandidate]:
    """Scan the last `limit` commits of `repo` for source-backport candidates.

    `check_version` (off by default) runs a `git show` per candidate to flag
    bump+patch combos via `version_changed`; it adds one subprocess per candidate,
    so the fast bulk scan leaves `version_changed=False` (unprobed) and the
    bootstrap step re-checks the handful it actually pursues.

    `strict` applies the precision gate per candidate and forces the patch-body
    read (so version-change and upstream-url extraction are reliable). It is the
    mode to use before spending model calls — it drops multi-package sweeps,
    subject-only CVE matches and bump+patch combos."""
    if strict:
        check_version = True
    # commits that ADD a *.patch under pkgs/, newest first
    log = _git(
        repo, "log", f"-{limit}", ref, "--diff-filter=A",
        "--name-only", "--pretty=format:\x01%H\x02%P\x02%s", "--", "pkgs/**/*.patch",
        timeout=600,
    )
    candidates: list[BackportCandidate] = []
    blocks = log.split("\x01")
    for blk in blocks:
        if not blk.strip():
            continue
        header, _, rest = blk.partition("\n")
        try:
            commit, parents, subject = header.split("\x02", 2)
        except ValueError:
            continue
        parent = parents.split()[0] if parents.strip() else ""
        added = [ln.strip() for ln in rest.splitlines()
                 if ln.strip().endswith(".patch") and ln.strip().startswith("pkgs/")]
        if not added:
            continue
        # version-change probe + craftability classification (opt-in): read the
        # commit's added package.nix / patch-body lines. Both reuse the same
        # `git show` (the `.patch` bodies carry the embedded backport diff used by
        # craftability; the package.nix lines carry the version-bump signal).
        added_lines: list[str] = []
        if check_version or craftable:
            try:
                show = _git(repo, "show", "--format=", "--unified=0", commit,
                            "--", "pkgs/**/package.nix", "pkgs/**/default.nix",
                            "pkgs/top-level/perl-packages.nix", "pkgs/**/*.patch")
                added_lines = [ln for ln in show.splitlines() if ln.startswith("+")]
            except RuntimeError:
                pass
        cand = parse_commit_record(
            commit=commit, parent=parent, subject=subject,
            added_patch_files=added, full_diff_added_lines=added_lines,
            strict=strict,
        )
        if cand is None:
            continue
        if require_cve and not cand.cve_ids:
            continue
        candidates.append(cand)
    return candidates


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description="Harvest source-backport candidates from nixpkgs history")
    ap.add_argument("--repo", type=Path, default=Path.home() / "code" / "nixpkgs")
    ap.add_argument("--limit", type=int, default=3000, help="commits to scan")
    ap.add_argument("--ref", default="HEAD",
                    help="git ref to scan from. Must have full history — a shallow "
                         "FETCH_HEAD (fetch --depth=1) is refused (default HEAD).")
    ap.add_argument("--all", action="store_true", help="include commits with no CVE id in subject/patch")
    ap.add_argument("--testable-only", action="store_true",
                    help="only emit candidates tagged 'testable' (no-ASAN v1 priority)")
    ap.add_argument("--light-only", action="store_true",
                    help="only emit build_class=light-interpreter candidates (pure-script "
                         "libs on a cached interpreter — the fast cert lane)")
    ap.add_argument("--strict", action="store_true",
                    help="apply the precision gate: exactly one package, CVE tied to "
                         "the patch (not subject-only), version unchanged, not a mass "
                         "sweep; extracts upstream_fix_url. Forces --check-version. Use "
                         "before any model spend.")
    ap.add_argument("--check-version", action="store_true",
                    help="probe each candidate for a version change (slower; flags bump+patch combos)")
    ap.add_argument("--craftable-only", action="store_true",
                    help="classify reproducer craftability (embeds-test / derivable-guard / "
                         "poc-gated) and emit only embeds-test + derivable-guard candidates — the "
                         "ones whose discriminating reproducer is craftable from the fix alone "
                         "(reads patch bodies, slower)")
    ap.add_argument("--out", type=Path, help="write JSONL here (default stdout)")
    args = ap.parse_args(argv)

    ref = args.ref
    if _is_shallow_ref(args.repo, ref):
        print(f"error: {ref} is shallow (no parent) — history scanning needs full "
              f"history. Use --ref HEAD against a non-shallow clone, or "
              f"`git -C {args.repo} fetch --unshallow`.", file=sys.stderr)
        return 2
    try:
        cands = harvest(args.repo, limit=args.limit, require_cve=not args.all, ref=ref,
                        check_version=args.check_version, craftable=args.craftable_only,
                        strict=args.strict)
    except RuntimeError as exc:
        if "unknown revision" in str(exc) or "bad revision" in str(exc):
            ref = "HEAD"
            cands = harvest(args.repo, limit=args.limit, require_cve=not args.all, ref=ref,
                            check_version=args.check_version, craftable=args.craftable_only,
                            strict=args.strict)
        else:
            print(f"error: {exc}", file=sys.stderr)
            return 2

    if args.testable_only:
        cands = [c for c in cands if "testable" in c.keywords]
    if args.light_only:
        cands = [c for c in cands if c.build_class == "light-interpreter"]
    if args.craftable_only:
        cands = [c for c in cands if c.craftability in ("embeds-test", "derivable-guard")]

    lines = [json.dumps(c.to_dict()) for c in cands]
    text = "\n".join(lines) + ("\n" if lines else "")
    if args.out:
        args.out.write_text(text)
    else:
        sys.stdout.write(text)
    n_test = sum(1 for c in cands if "testable" in c.keywords)
    n_asan = sum(1 for c in cands if "asan-class" in c.keywords)
    n_light = sum(1 for c in cands if c.build_class == "light-interpreter")
    n_compiled = sum(1 for c in cands if c.build_class == "compiled")
    craft = ""
    if args.check_version or args.craftable_only:
        n_embed = sum(1 for c in cands if c.craftability == "embeds-test")
        n_guard = sum(1 for c in cands if c.craftability == "derivable-guard")
        n_poc = sum(1 for c in cands if c.craftability == "poc-gated")
        craft = f"; craftability {n_embed} embeds-test, {n_guard} derivable-guard, {n_poc} poc-gated"
    print(f"# {len(cands)} candidates ({n_light} light-interpreter, "
          f"{n_compiled} compiled, {n_asan} asan-class; {n_test} testable{craft}) "
          f"from {ref}[-{args.limit}]", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
