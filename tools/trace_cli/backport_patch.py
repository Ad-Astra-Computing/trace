"""`trace backport-patch` — deterministically produce a version-adapted
`upstream-fix.patch` for a source-backport bundle.

Replaces the hand-authoring step: given an upstream fix commit and the package's
CURRENT nixpkgs version, this fetches the fix, re-targets it onto the current
version's source via a 3-way `git apply`, and emits a plain unified diff that is
PROVEN to apply verbatim under the package's exact `patchFlags`.

Design (peer-reviewed 2026-06-11). The four hand-authoring lessons are encoded:

  1. CONTEXT DRIFT — the upstream fix diff's context/line-numbers come from
     dev-HEAD; the current release (e.g. bzip2 1.0.8) has the same code at
     different lines/whitespace. We check out the CURRENT version tag and 3-way
     `git apply` the fix onto it, then `git diff` — git's content-based merge
     re-targets the fix and produces correct context + counts. A 3-way CONFLICT
     means the fix is not cleanly backportable → REJECT (don't emit).
  2. TRAILING-BLANK DROP — the Patcher drops trailing whitespace-only context
     lines when transcribing, desyncing the hunk count. We deterministically
     trim trailing blank context and re-stamp the hunk header so the patch ends
     on a content line.
  3. PATCHFLAGS — match the package's strip level. `patchFlags` is derivation-
     wide; we are a TAKER (match it, never set it). Read it via `nix eval`
     (never grep). `-pN` does not encode path format on its own (sourceRoot
     matters too), so we derive a CANDIDATE format and PROVE it with the
     dry-run, falling back to the other format if needed.
  4. BOOTSTRAP STDENV — bootstrap-critical packages use a stricter `patch` that
     chokes on git-extended headers. Whether a package is bootstrap-critical is
     not a readable field, so we ALWAYS emit plain unified diffs (strip
     `diff --git`/`index`/mode/rename headers). Zero downside.

The tool owns "applies" (the in-tool `patch --dry-run` against the unpacked src
is the deterministic gate — non-applying ⇒ fail, don't emit). The cert owns
"correct" (compile + CVE-reproducer). A clean exit means: this patch will apply
verbatim, exactly as the Patcher invokes it.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Sequence

EXIT_OK = 0
EXIT_USAGE = 2
EXIT_REJECT = 3  # candidate not cleanly backportable / patch does not apply


class BackportError(Exception):
    """Fatal, non-reject error (bad inputs, tooling missing)."""


class BackportReject(Exception):
    """The candidate is not cleanly backportable (3-way conflict, or the
    re-targeted patch does not apply to the real package src). Distinct from a
    tooling error: this is a real signal that the bundle should not proceed."""


# ── subprocess seams (injectable for unit tests) ─────────────────────────────

Runner = Callable[[Sequence[str], Path | None], subprocess.CompletedProcess]


# Hardened environment for every subprocess. Restricts git to safe transports
# (kills the `ext::`/`fd::`/`file://` transport-helper RCE class from a
# feed-sourced repo_url) and ignores operator/attacker git config so neither can
# inject hooks/filters/helpers into the run. Harmless for nix/patch/tar.
_HARDENED_ENV = {
    "GIT_ALLOW_PROTOCOL": "https:git:ssh",
    "GIT_PROTOCOL_FROM_USER": "0",
    "GIT_CONFIG_GLOBAL": "/dev/null",
    "GIT_CONFIG_SYSTEM": "/dev/null",
    "GIT_TERMINAL_PROMPT": "0",
}


def _default_runner(
    cmd: Sequence[str], cwd: Path | None = None
) -> subprocess.CompletedProcess:
    env = dict(os.environ)
    env.update(_HARDENED_ENV)
    return subprocess.run(
        list(cmd),
        cwd=str(cwd) if cwd else None,
        env=env,
        capture_output=True,
        text=True,
        check=False,
        timeout=600,
    )


# Feed-sourced inputs reach git as arguments. Validate them before use: a
# malicious repo_url (`ext::sh -c ...`), refspec-injecting nixpkgs_rev
# (`+refs/heads/*:...`), or option-injecting version_tag (`--upload-pack=...`)
# would otherwise be interpreted by git even with no shell.
# Anchored with \Z (not $) so a trailing newline can't smuggle a second line
# past the validator ($ matches before a final \n; \Z matches only true EOS).
_SAFE_REPO_URL_RE = re.compile(r"(?:https?|git|ssh)://[^\s]+\Z|git@[^\s:]+:[^\s]+\Z")
_SAFE_REV_RE = re.compile(r"[0-9a-f]{40}\Z")
# Fetch-time revs may be git-abbreviated (a feed sometimes records a short sha),
# so the fetch path accepts 7-40 hex — still strictly hex, so it can never
# option-inject as a bare `git fetch ... origin <sha>` argument.
_SAFE_FETCH_REV_RE = re.compile(r"[0-9a-f]{7,40}\Z")
_SAFE_TAG_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._+~/-]*\Z")

# Minimum git that refuses path-traversal/symlink writes during `git apply`
# (CVE-2023-23946, fixed in the 2.39.2 / 2.38.4 line). We apply an attacker-
# controlled diff onto an attacker-checked-out tree, so this floor is load-bearing.
_MIN_GIT = (2, 39, 2)


def _validate_repo_url(repo_url: str) -> str:
    if not isinstance(repo_url, str) or not _SAFE_REPO_URL_RE.match(repo_url):
        raise BackportError(
            f"refusing unsafe repo_url {repo_url!r}: only https/git/ssh URLs are "
            "allowed (blocks ext::/fd::/file:// transport-helper execution)."
        )
    return repo_url


def _validate_tag(version_tag: str) -> str:
    if (
        not isinstance(version_tag, str)
        or not _SAFE_TAG_RE.match(version_tag)
        or ".." in version_tag
    ):
        raise BackportError(f"refusing unsafe version tag {version_tag!r}")
    return version_tag


# cgit/gitweb "browse" URLs are not smart-http git endpoints, so cloning/fetching
# them 404s (savannah serves the repo at /git/<x>.git, not the /cgit/<x>.git
# browse path). Map the known browse form of our feed sources to the clone
# endpoint. Host-pinned + anchored so normalization can never widen the trust
# boundary: _validate_repo_url runs FIRST (rejects ext::/fd:: transport helpers),
# and we rewrite ONLY this exact single-host pattern.
_CGIT_BROWSE_RE = re.compile(
    r"\A(https://git\.savannah\.gnu\.org)/cgit/([^?#\s]+?\.git)\Z"
)


def clone_url(repo_url: str) -> str:
    """Validate `repo_url`, then map a known cgit browse URL to its clone
    endpoint. Returns the validated (possibly rewritten) URL."""
    safe = _validate_repo_url(repo_url)
    m = _CGIT_BROWSE_RE.match(safe)
    return f"{m.group(1)}/git/{m.group(2)}" if m else safe


def blobless_fetch_commit(
    git: Callable[..., subprocess.CompletedProcess], sha: str
) -> bool:
    """Make commit `sha` (full or git-abbreviated) resolvable in the repo behind
    the bound `git(*args)` callable, fetching as little as possible:

      1. a shallow blobless want for the sha (fast on servers that allow it);
      2. else a blobless fetch of ALL branches + tags. This is COMPLETE: it
         resolves abbreviated shas and shas the server refuses as a direct want
         (`not our ref` on GitHub, `unadvertised object` on cgit), because the
         object lands via a reachable ref and git resolves it locally afterward.

    `--filter=blob:none` keeps the transfer to the commit/tree graph; the single
    file blob the caller needs is pulled lazily by a later `git show
    <parent>:<file>`. Returns True iff `sha^{commit}` resolves afterward.

    `sha` is validated hex-only here (the choke point), so a feed-sourced value
    like `--upload-pack=...` / `--exec=...` can never option-inject as a bare
    `git fetch ... origin <sha>` argument: a non-hex sha returns False before any
    fetch runs. Callers may validate too, but this guard is authoritative.
    """
    if not isinstance(sha, str) or not _SAFE_FETCH_REV_RE.match(sha):
        return False

    def _present() -> bool:
        return git("rev-parse", "-q", "--verify", f"{sha}^{{commit}}").returncode == 0

    if (
        git("fetch", "--filter=blob:none", "--depth", "2", "origin", sha).returncode
        == 0
        and _present()
    ):
        return True
    # Fall back to a complete (but still blobless) fetch of every branch + tag.
    git("fetch", "--filter=blob:none", "origin")
    git("fetch", "--filter=blob:none", "--tags", "origin")
    return _present()


def _assert_git_version(runner: Runner) -> None:
    proc = runner(["git", "--version"], None)
    m = re.search(r"(\d+)\.(\d+)\.(\d+)", proc.stdout or "")
    if not m:
        raise BackportError(f"could not parse git version from {proc.stdout!r}")
    ver = tuple(int(x) for x in m.groups())
    if ver < _MIN_GIT:
        raise BackportError(
            f"git {'.'.join(map(str, ver))} is below the required floor "
            f"{'.'.join(map(str, _MIN_GIT))} (CVE-2023-23946 apply-path-traversal); "
            "the tool applies an attacker-controlled diff onto an attacker tree."
        )


# ── git: fetch + 3-way re-target onto the current version tag ─────────────────


def _git(runner: Runner, repo: Path | None, *args: str) -> subprocess.CompletedProcess:
    return runner(["git", *args], repo)


def retarget_fix(
    *,
    repo_url: str,
    commit_sha: str,
    version_tag: str,
    paths: list[str] | None,
    workdir: Path,
    runner: Runner = _default_runner,
) -> str:
    """Fetch `commit_sha` and `version_tag` from `repo_url`, 3-way `git apply`
    the fix (file-scoped to `paths` if given) onto the version tag, and return
    the resulting `git diff` (still git-extended; reformat happens later).

    Raises BackportReject on a 3-way conflict (not cleanly backportable).
    Raises BackportError on fetch/tooling failure.
    """
    _validate_repo_url(repo_url)
    _validate_tag(version_tag)
    _assert_git_version(runner)
    repo = workdir / "upstream"
    repo.mkdir(parents=True, exist_ok=True)
    _git(runner, repo, "init", "-q")
    _git(runner, repo, "config", "core.autocrlf", "false")
    add = _git(runner, repo, "remote", "add", "origin", repo_url)
    if add.returncode != 0 and "already exists" not in (add.stderr or ""):
        raise BackportError(f"git remote add failed: {add.stderr.strip()}")
    # Full (non-shallow) fetch of branches + tags. The current-version tag can be
    # YEARS older than the fix commit (e.g. bzip2-1.0.8 from 2019 vs a 2026 fix),
    # so a shallow fetch would leave the old tag's tree incomplete and the 3-way
    # apply would silently no-op. Git tag names also vary per project (bzip2
    # 'bzip2-1.0.8', libxmp 'libxmp-4.6.2', proxychains 'v4.17'), so we fetch
    # broadly and resolve the tag by candidate spelling below.
    branches = _git(runner, repo, "fetch", "origin")
    tags = _git(runner, repo, "fetch", "--tags", "origin")
    if branches.returncode != 0 and tags.returncode != 0:
        raise BackportError(
            f"git fetch failed for {repo_url}: {(branches.stderr or tags.stderr).strip()[:300]}"
        )
    # Ensure the fix commit itself is present (it may live only on a branch tip).
    have = _git(runner, repo, "rev-parse", "--verify", "-q", f"{commit_sha}^{{commit}}")
    if have.returncode != 0:
        raise BackportError(
            f"fix commit {commit_sha} not found in {repo_url} after fetch "
            "(wrong sha, or it lives on an unfetched ref)"
        )

    resolved_tag = _resolve_tag(runner, repo, version_tag, repo_url)
    if resolved_tag is None:
        raise BackportError(
            f"could not resolve a git tag for version {version_tag!r} in {repo_url} "
            f"(tried common naming variants)"
        )
    co = _git(runner, repo, "checkout", "-q", resolved_tag)
    if co.returncode != 0:
        raise BackportError(f"git checkout {resolved_tag} failed: {co.stderr.strip()}")

    # Determine which files to backport. A real fix commit usually also touches
    # tests, changelogs, and binary fixtures that have diverged wildly from the
    # current release (or can't 3-way apply at all) — including them turns a
    # clean source backport into a spurious conflict. So when the caller did not
    # pin --paths, auto-scope to the commit's SOURCE text files (excluding
    # test/doc/changelog/binary).
    if not paths:
        paths = _auto_scope_source_paths(runner, repo, commit_sha)
        if not paths:
            raise BackportReject(
                f"commit {commit_sha} touches no backportable source files after "
                "excluding tests/docs/changelog/binary; pin --paths to override."
            )

    # The fix commit's diff, file-scoped.
    show_args = ["show", "--no-color", f"{commit_sha}", "--", *paths]
    show = _git(runner, repo, *show_args)
    if show.returncode != 0:
        raise BackportError(f"git show {commit_sha} failed: {show.stderr.strip()}")
    fix_diff = _extract_diff(show.stdout)
    if not fix_diff.strip():
        raise BackportError(
            f"commit {commit_sha} has no diff for the requested paths {paths!r}"
        )

    # 3-way apply onto the current version tree. --3way uses the diff's `index`
    # blobs as the merge base (content-based; immune to whitespace/line drift).
    patch_file = workdir / "fix.diff"
    patch_file.write_text(fix_diff)
    applied = _git(
        runner, repo, "apply", "--3way", "--whitespace=nowarn", str(patch_file)
    )
    if applied.returncode != 0:
        raise BackportReject(
            "fix does not cleanly 3-way apply onto the current version "
            f"({version_tag}); not backportable without manual work. "
            f"git apply: {applied.stderr.strip()[:400]}"
        )

    # The re-targeted diff against the pristine version tag. `git apply --3way`
    # STAGES its result (updates the index), so we diff against HEAD (not the
    # index) to capture the change.
    diff_args = ["diff", "HEAD", "--no-color", "--unified=3"]
    if paths:
        diff_args += ["--", *paths]
    diff = _git(runner, repo, *diff_args)
    if diff.returncode != 0:
        raise BackportError(f"git diff failed: {diff.stderr.strip()}")
    if not diff.stdout.strip():
        raise BackportReject(
            "after 3-way apply the working tree is unchanged — the fix is "
            "already present at this version (nothing to backport)."
        )
    return diff.stdout


# Paths a security source-backport should NOT carry: test suites, docs,
# changelogs, generated/data fixtures. Matched against the full repo-relative
# path (case-insensitive).
_NON_SOURCE_RE = re.compile(
    r"(^|/)(tests?|testsuite|test-dev|t/|doc|docs|examples?|samples?|"
    r"fixtures?|data|benchmarks?|\.github)(/|$)"
    r"|(^|/)(changelog|changes|news|authors|readme|copying|license|"
    r"notice|todo|\.gitignore)(\.[a-z]+)?$"
    # Test-harness FILES at any directory level (not just under a tests/ dir):
    # libxml2-style run_test, and the test_*.c / *_test.c separator conventions.
    # Deliberately NARROW (separator-based) so real source whose name merely
    # starts with 'test' (testing.c, testament.c, testapi.c) is NOT dropped — a
    # false exclusion would omit a real security fix, which is worse than keeping
    # an occasional harness file.
    r"|(^|/)(run_?tests?|test[_-][\w-]*|[\w-]+[_-]tests?)\.[a-z0-9]+$",
    re.IGNORECASE,
)


def _auto_scope_source_paths(runner: Runner, repo: Path, commit_sha: str) -> list[str]:
    """The commit's changed TEXT source files, excluding tests/docs/changelog and
    binary files. Binary files show as '-\\t-\\t<path>' in --numstat."""
    ns = _git(runner, repo, "show", "--numstat", "--format=", "--no-color", commit_sha)
    if ns.returncode != 0:
        raise BackportError(f"git show --numstat failed: {ns.stderr.strip()[:200]}")
    out: list[str] = []
    for line in ns.stdout.splitlines():
        parts = line.split("\t")
        if len(parts) != 3:
            continue
        added, removed, path = parts
        if added == "-" and removed == "-":
            continue  # binary
        if _NON_SOURCE_RE.search(path):
            continue  # test / doc / changelog / data
        out.append(path)
    return out


# Reproducer-oracle extraction: a crash-class fix commit frequently co-lands the
# REGRESSION TEST — the crashing input fixture (binary/data/font) and a harness
# that exercises the bug. backport-patch EXCLUDES these from the source patch;
# this is the inverse selection — they are the reproducer's oracle. A file is an
# oracle candidate if it lives under a test/data/fixture dir AND is not a
# changelog/doc or a build-system file (CMakeLists/Makefile/meson — wiring, not
# oracle).
_FIXTURE_DIR_RE = re.compile(
    r"(^|/)(tests?|testsuite|test-dev|data|fixtures?|fonts?|samples?|"
    r"standards|corpus|seeds?|regress(ion)?|poc|crash(es)?)(/|$)",
    re.IGNORECASE,
)
_NOT_FIXTURE_RE = re.compile(
    r"(^|/)(changelog|changes|news|authors|readme|copying|license|notice|todo)"
    r"(\.[a-z]+)?$"
    r"|(^|/)(CMakeLists\.txt|Makefile(\.am|\.in)?|meson\.build|configure(\.ac)?|"
    r"[^/]+\.cmake|\.gitignore|\.gitattributes)$",
    re.IGNORECASE,
)


def _is_oracle_fixture(path: str) -> bool:
    return bool(_FIXTURE_DIR_RE.search(path)) and not _NOT_FIXTURE_RE.search(path)


def _safe_fixture_name(path: str) -> bool:
    """Reject names that are unsafe as on-disk paths OR as downstream ASAN-harness
    inputs: no control chars/NUL, no empty/'.'/'..' components, no leading-dash
    component (argument injection if interpolated into a command later)."""
    if not path or "\x00" in path or any(ord(ch) < 32 for ch in path):
        return False
    parts = Path(path).parts
    for p in parts:
        if p in ("", ".", "..") or p.startswith("-") or p.startswith("/"):
            return False
    return True


def _blob_mode(runner: Runner, repo: Path, commit_sha: str, path: str) -> str | None:
    """The git object mode for `path` at `commit_sha`, or None. Used to extract
    ONLY regular blobs (100644/100755) and reject symlinks (120000) and gitlinks
    (160000) — `core.symlinks=false` governs checkout, not our manual blob write."""
    ls = _git(runner, repo, "ls-tree", commit_sha, "--", path)
    line = (ls.stdout or "").strip()
    if not line:
        return None
    # "<mode> <type> <sha>\t<path>"
    return line.split(" ", 1)[0] if " " in line else None


# A focused crash-class regression test adds a handful of oracle files; more than
# this signals "not a focused regression test" (or a parentless-diff bug).
_MAX_FIXTURES = 25
# A crash oracle is small (KB–MB). A huge blob is a memory/disk-DoS attempt (the
# whole blob is captured by `git show`) — skip it rather than materialise it.
_MAX_FIXTURE_BYTES = 25 * 1024 * 1024


def extract_fix_fixtures(
    *,
    repo_url: str,
    commit_sha: str,
    out_dir: Path,
    workdir: Path,
    runner: Runner = _default_runner,
) -> list[str]:
    """Fetch `commit_sha` and extract its co-landed regression-test fixtures (the
    reproducer oracle: crash inputs + harness) into `out_dir`, preserving the
    repo-relative layout. Returns the list of extracted repo-relative paths.
    Binary-safe. Reuses the same hardened transport as the patch path."""
    _validate_repo_url(repo_url)
    _assert_git_version(runner)
    repo = workdir / "fixsrc"
    repo.mkdir(parents=True, exist_ok=True)
    _git(runner, repo, "init", "-q")
    _git(runner, repo, "config", "core.autocrlf", "false")
    _git(runner, repo, "config", "core.symlinks", "false")  # neutralize symlink-in-tree
    add = _git(runner, repo, "remote", "add", "origin", repo_url)
    if add.returncode != 0 and "already exists" not in (add.stderr or ""):
        raise BackportError(f"git remote add failed: {add.stderr.strip()}")
    # --depth 2 (commit + its PARENT): `git show` must diff against the parent.
    # A --depth 1 fetch leaves the commit parentless, so git show treats the
    # ENTIRE tree as added and lists the whole test corpus.
    fetched = _git(runner, repo, "fetch", "--depth", "2", "origin", commit_sha)
    if fetched.returncode != 0:
        _git(runner, repo, "fetch", "origin")
    have = _git(runner, repo, "rev-parse", "--verify", "-q", f"{commit_sha}^{{commit}}")
    if have.returncode != 0:
        raise BackportError(
            f"fix commit {commit_sha} not found in {repo_url} after fetch"
        )

    ns = _git(runner, repo, "show", "--numstat", "--format=", "--no-color", commit_sha)
    if ns.returncode != 0:
        raise BackportError(f"git show --numstat failed: {ns.stderr.strip()[:200]}")
    fixtures = []
    for line in ns.stdout.splitlines():
        parts = line.split("\t")
        if len(parts) != 3:
            continue
        path = parts[2]
        if _is_oracle_fixture(path):
            fixtures.append(path)
    # Safety cap: a clean crash-class regression test adds a handful of oracle
    # files. A huge set means the commit isn't a focused regression test (or the
    # diff is still parentless) — refuse rather than copy a whole test corpus.
    if len(fixtures) > _MAX_FIXTURES:
        raise BackportReject(
            f"fix commit {commit_sha} touches {len(fixtures)} oracle-dir files "
            f"(> {_MAX_FIXTURES}); not a focused regression test. Pin the oracle "
            "by hand."
        )
    out_root = out_dir.resolve()
    out_dir.mkdir(parents=True, exist_ok=True)
    kept: list[str] = []
    for path in fixtures:
        # Filename hygiene (on-disk path AND downstream ASAN-harness input).
        if not _safe_fixture_name(path):
            print(f"  (skipped {path!r}: unsafe fixture name)", flush=True)
            continue
        # Object-mode filter: extract ONLY regular blobs. A 120000 (symlink) blob's
        # content is a target path — materialising it is an escape primitive;
        # 160000 is a submodule gitlink. core.symlinks=false governs checkout, not
        # this manual blob write, so filter on mode explicitly.
        mode = _blob_mode(runner, repo, commit_sha, path)
        if mode not in ("100644", "100755"):
            print(f"  (skipped {path}: non-regular git mode {mode})", flush=True)
            continue
        dest = out_dir / path
        # Containment AFTER creating parents as real dirs (no symlink got written —
        # they're mode-filtered — so no TOCTOU redirect). Use is_relative_to, not a
        # string prefix.
        dest.parent.mkdir(parents=True, exist_ok=True)
        if not dest.parent.resolve().is_relative_to(out_root):
            raise BackportReject(f"fixture path escapes output dir: {path!r}")
        # Size guard before materialising: a crash oracle is small.
        size = _git(runner, repo, "cat-file", "-s", f"{commit_sha}:{path}")
        try:
            nbytes = int((size.stdout or "0").strip())
        except ValueError:
            nbytes = 0
        if nbytes > _MAX_FIXTURE_BYTES:
            print(
                f"  (skipped {path}: {nbytes} bytes > {_MAX_FIXTURE_BYTES} cap)",
                flush=True,
            )
            continue
        _extract_blob(repo, commit_sha, path, dest)
        kept.append(path)
    return kept


def _extract_blob(repo: Path, commit_sha: str, path: str, dest: Path) -> None:
    """Binary-safe extraction of a blob at a commit to `dest` (the text Runner
    would corrupt binary fixtures, so this uses a bytes subprocess directly)."""
    env = dict(os.environ)
    env.update(_HARDENED_ENV)
    proc = subprocess.run(
        ["git", "-C", str(repo), "show", f"{commit_sha}:{path}"],
        capture_output=True,
        check=False,
        timeout=180,
        env=env,
    )
    if proc.returncode != 0:
        raise BackportError(
            f"git show {commit_sha}:{path} failed: "
            f"{proc.stderr.decode('utf-8', 'replace').strip()[:200]}"
        )
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_bytes(proc.stdout)


def _tag_candidates(version_tag: str, repo_url: str) -> list[str]:
    """Common git-tag spellings for a version. The bundle's `tag`/version field
    may be the nixpkgs version ('1.0.8') while the git tag is project-prefixed
    ('bzip2-1.0.8') or v-prefixed ('v4.17')."""
    reponame = re.sub(r"\.git$", "", repo_url.rstrip("/").rsplit("/", 1)[-1])
    bare = re.sub(r"^v", "", version_tag)
    cands = [
        version_tag,
        f"v{bare}",
        f"{reponame}-{bare}",
        f"{reponame}_{bare}",
        bare,
    ]
    seen: set[str] = set()
    return [c for c in cands if not (c in seen or seen.add(c))]


def _resolve_tag(
    runner: Runner, repo: Path, version_tag: str, repo_url: str
) -> str | None:
    for cand in _tag_candidates(version_tag, repo_url):
        for ref in (cand, f"tags/{cand}", f"refs/tags/{cand}"):
            rp = _git(runner, repo, "rev-parse", "--verify", "-q", f"{ref}^{{commit}}")
            if rp.returncode == 0 and rp.stdout.strip():
                return ref
    return None


def _extract_diff(show_output: str) -> str:
    """Strip the commit message preamble from `git show`, keeping from the first
    `diff --git` onward."""
    idx = show_output.find("diff --git")
    return show_output[idx:] if idx != -1 else ""


# ── reformat: plain unified diff, path format, ends-on-content ────────────────

_HUNK_RE = re.compile(r"^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@")


def to_plain_unified(diff_text: str, *, strip_level: int) -> str:
    """Convert a git diff into a plain unified diff with the requested path
    strip level baked into the ---/+++ headers, dropping ALL git-extended
    headers (diff --git, index, new/deleted file mode, rename/copy/similarity).

    strip_level=1 keeps `a/`/`b/` prefixes (applied with -p1).
    strip_level=0 emits bare paths (applied with -p0).
    """
    out: list[str] = []
    lines = diff_text.splitlines()
    i = 0
    while i < len(lines):
        line = lines[i]
        if line.startswith("diff --git"):
            # parse the b/ path, gather this file's hunks, emit clean headers
            m = re.match(r"diff --git a/(.+) b/(.+)$", line)
            i += 1
            # skip extended-header lines until --- / +++
            while i < len(lines) and not lines[i].startswith("--- "):
                if lines[i].startswith("@@") or lines[i].startswith("diff --git"):
                    break
                i += 1
            # capture ---/+++ if present (use them for the path; else fall back to m)
            old_path = new_path = None
            if i < len(lines) and lines[i].startswith("--- "):
                old_path = lines[i][4:].strip()
                i += 1
            if i < len(lines) and lines[i].startswith("+++ "):
                new_path = lines[i][4:].strip()
                i += 1
            path = _norm_path(new_path or old_path or (m.group(2) if m else ""))
            if strip_level <= 0:
                out.append(f"--- {path}")  # bare, applied with -p0
                out.append(f"+++ {path}")
            else:
                out.append(f"--- a/{path}")  # applied with -p1 (strips a/ b/)
                out.append(f"+++ b/{path}")
            continue
        out.append(line)
        i += 1
    text = "\n".join(out)
    if not text.endswith("\n"):
        text += "\n"
    return text


def _norm_path(p: str) -> str:
    # drop a leading a/ or b/ and any trailing tab-metadata
    p = p.split("\t", 1)[0].strip()
    if p.startswith("a/") or p.startswith("b/"):
        p = p[2:]
    return p


def ensure_ends_on_content(diff_text: str) -> str:
    """Trim trailing whitespace-only CONTEXT lines from each hunk and re-stamp
    the hunk header counts, so the patch ends on a content line (lesson 2: the
    Patcher drops trailing blank context lines)."""
    lines = diff_text.splitlines()
    out: list[str] = []
    i = 0
    while i < len(lines):
        line = lines[i]
        m = _HUNK_RE.match(line)
        if not m:
            out.append(line)
            i += 1
            continue
        # gather the hunk body (until next @@ / ---/diff or EOF)
        body: list[str] = []
        j = i + 1
        while j < len(lines) and not (
            lines[j].startswith("@@")
            or lines[j].startswith("--- ")
            or lines[j].startswith("diff --git")
        ):
            body.append(lines[j])
            j += 1
        # trim trailing context lines that are whitespace-only (a leading space
        # then nothing/space). Never trim +/- lines or non-blank context.
        while body and body[-1][:1] == " " and body[-1].strip() == "":
            body.pop()
        old_c = sum(1 for b in body if b[:1] in (" ", "-"))
        new_c = sum(1 for b in body if b[:1] in (" ", "+"))
        os_, ns = m.group(1), m.group(3)
        tail = line[m.end() :]
        out.append(f"@@ -{os_},{old_c} +{ns},{new_c} @@{tail}")
        out.extend(body)
        i = j
    text = "\n".join(out)
    if not text.endswith("\n"):
        text += "\n"
    return text


# ── patchFlags via nix eval (never grep) ─────────────────────────────────────


def eval_patch_flags(
    attr: str, nixpkgs: Path, runner: Runner = _default_runner
) -> list[str]:
    """Resolve `pkgs.<attr>.patchFlags` via nix eval (overlay-proof). Returns
    [] when the attr has no patchFlags (nixpkgs default = ["-p1"])."""
    if not re.match(r"^[A-Za-z_][A-Za-z0-9_.\-]*$", attr):
        raise BackportError(f"unsafe attr for nix eval: {attr!r}")
    expr = (
        f"let p = (import {json.dumps(str(nixpkgs.resolve()))} {{}}).{attr}; "
        f'in p.patchFlags or [ "-p1" ]'
    )
    proc = runner(
        ["nix-instantiate", "--eval", "--strict", "--json", "--expr", expr], None
    )
    if proc.returncode != 0:
        raise BackportError(
            f"nix eval patchFlags failed for {attr}: {proc.stderr.strip()[:300]}"
        )
    try:
        flags = json.loads(proc.stdout.strip())
    except json.JSONDecodeError:
        raise BackportError(
            f"nix eval patchFlags returned non-JSON: {proc.stdout[:120]!r}"
        )
    return [str(f) for f in flags] if isinstance(flags, list) else ["-p1"]


def strip_level_from_flags(patch_flags: list[str]) -> int:
    """Candidate strip level from patchFlags (proven later by the dry-run)."""
    for f in patch_flags:
        m = re.fullmatch(r"-p(\d+)", f)
        if m:
            return int(m.group(1))
        if f.startswith("--strip="):
            return int(f.split("=", 1)[1])
    return 1  # nixpkgs default


# ── verify-apply against the unpacked src (the deterministic gate) ───────────


@dataclass
class VerifyResult:
    applied: bool
    detail: str


def verify_apply(
    *,
    patch_text: str,
    attr: str,
    nixpkgs: Path,
    patch_flags: list[str],
    workdir: Path,
    runner: Runner = _default_runner,
) -> VerifyResult:
    """Build + unpack `pkgs.<attr>.src` and `patch --dry-run` the candidate with
    the package's EXACT patchFlags. This re-creates the Patcher's apply
    environment — the only thing that catches tag≠tarball drift."""
    if not shutil.which("nix-build"):
        return VerifyResult(False, "nix-build not on PATH; cannot verify-apply")
    src = runner(
        ["nix-build", str(nixpkgs.resolve()), "-A", f"{attr}.src", "--no-out-link"],
        None,
    )
    if src.returncode != 0:
        return VerifyResult(
            False, f"nix-build {attr}.src failed: {src.stderr.strip()[:200]}"
        )
    src_path = src.stdout.strip().splitlines()[-1]
    unpack = workdir / "src"
    if unpack.exists():
        shutil.rmtree(unpack, ignore_errors=True)
    unpack.mkdir(parents=True, exist_ok=True)
    # src may be a tarball or a directory (fetchFromGitHub). Handle both. The
    # nix store is read-only with symlinks, so copy via `cp -rL` (dereference
    # symlinks) + chmod (drop read-only) rather than shutil.copytree, which
    # chokes on mode preservation / dangling symlinks.
    p = Path(src_path)
    if p.is_dir():
        tree = unpack / "tree"
        tree.mkdir()
        cp = runner(["cp", "-rL", f"{src_path}/.", str(tree)], None)
        if cp.returncode != 0:
            return VerifyResult(
                False, f"copy src dir failed: {cp.stderr.strip()[:200]}"
            )
        runner(["chmod", "-R", "u+w", str(tree)], None)
        root = tree
    else:
        ex = runner(["tar", "xf", src_path, "-C", str(unpack)], None)
        if ex.returncode != 0:
            return VerifyResult(False, f"unpack failed: {ex.stderr.strip()[:200]}")
        subdirs = [d for d in unpack.iterdir() if d.is_dir()]
        root = subdirs[0] if len(subdirs) == 1 else unpack
    patch_file = workdir / "candidate.patch"
    patch_file.write_text(patch_text)
    dry = runner(["patch", *patch_flags, "--dry-run", "-i", str(patch_file)], root)
    ok = dry.returncode == 0
    return VerifyResult(ok, (dry.stdout + dry.stderr).strip()[:300])


# ── orchestration ────────────────────────────────────────────────────────────


def produce_backport_patch(
    *,
    bundle_dir: Path,
    nixpkgs: Path,
    paths: list[str] | None = None,
    runner: Runner = _default_runner,
    skip_verify: bool = False,
) -> str:
    """Full pipeline. Returns the version-adapted, verified plain-unified-diff
    text for upstream-fix.patch. Raises BackportReject / BackportError."""
    ur = json.loads((bundle_dir / "upstream-ref.json").read_text())
    finding = json.loads((bundle_dir / "finding.json").read_text())
    commits = ur.get("upstream_fix_commits") or []
    if not commits:
        raise BackportError("upstream-ref.json has no upstream_fix_commits to backport")
    repo_url = commits[0]["repo_url"]
    commit_sha = commits[0]["commit_sha"]
    version_tag = ur.get("tag") or ur.get("current_version")
    attr = (finding.get("affected") or [{}])[0].get("attr_path")
    if not version_tag or not attr:
        raise BackportError("could not resolve version tag / attr from the bundle")
    # The verify gate must run against the bundle's PINNED nixpkgs_rev — where the
    # package is still at the vulnerable version. Against arbitrary HEAD the
    # package may already carry the fix (a later release / an applied patch), and
    # the gate would wrongly read the backport as "already applied".
    nixpkgs_rev = None
    bj = bundle_dir / "bundle.json"
    if bj.is_file():
        nixpkgs_rev = json.loads(bj.read_text()).get("nixpkgs_rev")

    with tempfile.TemporaryDirectory(prefix="trace-backport-") as td:
        workdir = Path(td)
        raw = retarget_fix(
            repo_url=repo_url,
            commit_sha=commit_sha,
            version_tag=version_tag,
            paths=paths,
            workdir=workdir,
            runner=runner,
        )

        eval_nixpkgs, wt = _nixpkgs_at_rev(nixpkgs, nixpkgs_rev, workdir, runner)
        try:
            flags = eval_patch_flags(attr, eval_nixpkgs, runner=runner)
            level = strip_level_from_flags(flags)
            candidate = ensure_ends_on_content(to_plain_unified(raw, strip_level=level))
            if skip_verify:
                return candidate
            # Deterministic gate: prove the candidate applies under the exact
            # patchFlags. Try the derived strip level first, then the other
            # format (trap c3: -pN doesn't fully encode path format).
            res = verify_apply(
                patch_text=candidate,
                attr=attr,
                nixpkgs=eval_nixpkgs,
                patch_flags=flags,
                workdir=workdir,
                runner=runner,
            )
            if res.applied:
                return candidate
            alt_level = 0 if level == 1 else 1
            alt = ensure_ends_on_content(to_plain_unified(raw, strip_level=alt_level))
            res2 = verify_apply(
                patch_text=alt,
                attr=attr,
                nixpkgs=eval_nixpkgs,
                patch_flags=flags,
                workdir=workdir,
                runner=runner,
            )
            if res2.applied:
                return alt
            raise BackportReject(
                "re-targeted patch does not apply to the unpacked src under "
                f"patchFlags={flags} (tried -p{level} and -p{alt_level}). "
                f"tag≠tarball drift, the fix touches generated files, or the "
                f"package already carries the fix at this rev. detail: {res.detail}"
            )
        finally:
            if wt is not None:
                runner(
                    [
                        "git",
                        "-C",
                        str(nixpkgs),
                        "worktree",
                        "remove",
                        "--force",
                        str(wt),
                    ],
                    None,
                )


def _nixpkgs_at_rev(
    nixpkgs: Path,
    rev: str | None,
    workdir: Path,
    runner: Runner,
) -> tuple[Path, Path | None]:
    """Return (path-to-use, worktree-or-None). If `rev` is set and differs from
    the checkout HEAD, add a detached git worktree at `rev` (fetching it if
    needed) so eval + verify run against the pinned source. Falls back to the
    given checkout (with the worktree=None) when no rev / not a git checkout /
    rev unobtainable — the caller's gate still runs, just against HEAD."""
    if not rev:
        return nixpkgs, None
    # nixpkgs_rev is feed-sourced and reaches `git fetch origin <rev>` against the
    # operator's REAL checkout — a refspec/option-injecting value (`+refs/*:...`,
    # `--upload-pack=...`) could mutate it. A pinned rev is always a 40-hex SHA;
    # anything else is refused (verify falls back to HEAD).
    if not _SAFE_REV_RE.match(rev):
        return nixpkgs, None
    head = runner(["git", "-C", str(nixpkgs), "rev-parse", "HEAD"], None)
    if head.returncode == 0 and head.stdout.strip() == rev:
        return nixpkgs, None
    have = runner(
        ["git", "-C", str(nixpkgs), "cat-file", "-e", f"{rev}^{{commit}}"], None
    )
    if have.returncode != 0:
        runner(
            ["git", "-C", str(nixpkgs), "fetch", "--depth", "1", "origin", rev], None
        )
        have = runner(
            ["git", "-C", str(nixpkgs), "cat-file", "-e", f"{rev}^{{commit}}"], None
        )
        if have.returncode != 0:
            return nixpkgs, None  # can't obtain the rev; verify against HEAD
    runner(
        ["git", "-C", str(nixpkgs), "worktree", "prune"], None
    )  # clear stale temp worktrees
    wt = workdir / "nixpkgs-wt"
    add = runner(
        ["git", "-C", str(nixpkgs), "worktree", "add", "--detach", str(wt), rev], None
    )
    if add.returncode != 0:
        return nixpkgs, None
    return wt, wt


def add_parser(subs: argparse._SubParsersAction) -> argparse.ArgumentParser:
    p = subs.add_parser(
        "backport-patch",
        help="produce a version-adapted upstream-fix.patch for a source-backport bundle",
    )
    p.add_argument(
        "--bundle-dir",
        required=True,
        type=Path,
        help="bundle dir with upstream-ref.json (fix commit + version tag) + finding.json",
    )
    p.add_argument(
        "--nixpkgs",
        type=Path,
        default=Path("."),
        help="nixpkgs checkout for patchFlags eval + src unpack (default: .)",
    )
    p.add_argument(
        "--paths",
        default=None,
        help="comma-separated source paths to scope the fix to (default: all commit files)",
    )
    p.add_argument(
        "--write",
        action="store_true",
        help="write upstream-fix.patch into the bundle dir (default: stdout)",
    )
    p.add_argument(
        "--skip-verify",
        action="store_true",
        help="skip the patch --dry-run gate (NOT recommended; loses the 'applies' guarantee)",
    )
    return p


def add_fixtures_parser(subs: argparse._SubParsersAction) -> argparse.ArgumentParser:
    p = subs.add_parser(
        "backport-fixtures",
        help="extract a fix commit's co-landed regression-test fixtures (reproducer oracle)",
    )
    p.add_argument(
        "--bundle-dir",
        required=True,
        type=Path,
        help="bundle dir with upstream-ref.json (the fix commit)",
    )
    p.add_argument(
        "--out",
        type=Path,
        default=None,
        help="output dir for fixtures (default: <bundle-dir>/reproducer-fixtures)",
    )
    return p


def run_fixtures(args: argparse.Namespace) -> int:
    bundle_dir: Path = args.bundle_dir
    urf = bundle_dir / "upstream-ref.json"
    if not urf.is_file():
        print(f"error: {urf} not found", flush=True)
        return EXIT_USAGE
    ur = json.loads(urf.read_text())
    commits = ur.get("upstream_fix_commits") or []
    if not commits:
        print("error: upstream-ref.json has no upstream_fix_commits", flush=True)
        return EXIT_USAGE
    out_dir = args.out or (bundle_dir / "reproducer-fixtures")
    with tempfile.TemporaryDirectory(prefix="trace-fixtures-") as td:
        try:
            fixtures = extract_fix_fixtures(
                repo_url=commits[0]["repo_url"],
                commit_sha=commits[0]["commit_sha"],
                out_dir=out_dir,
                workdir=Path(td),
            )
        except BackportError as exc:
            print(f"error: {exc}", flush=True)
            return EXIT_USAGE
    if not fixtures:
        print(
            "no co-landed regression-test fixtures in the fix commit "
            "(reproducer oracle must be constructed by hand)",
            flush=True,
        )
        return EXIT_REJECT
    print(f"extracted {len(fixtures)} oracle fixture(s) to {out_dir}:", flush=True)
    for f in fixtures:
        print(f"  {f}", flush=True)
    return EXIT_OK


def run(args: argparse.Namespace) -> int:
    bundle_dir: Path = args.bundle_dir
    if not (bundle_dir / "upstream-ref.json").is_file():
        print(f"error: {bundle_dir}/upstream-ref.json not found", flush=True)
        return EXIT_USAGE
    paths = [s.strip() for s in args.paths.split(",")] if args.paths else None
    try:
        patch = produce_backport_patch(
            bundle_dir=bundle_dir,
            nixpkgs=args.nixpkgs,
            paths=paths,
            skip_verify=args.skip_verify,
        )
    except BackportReject as exc:
        print(f"REJECT: {exc}", flush=True)
        return EXIT_REJECT
    except BackportError as exc:
        print(f"error: {exc}", flush=True)
        return EXIT_USAGE
    if args.write:
        (bundle_dir / "upstream-fix.patch").write_text(patch)
        print(
            f"wrote {bundle_dir}/upstream-fix.patch ({len(patch.splitlines())} lines)",
            flush=True,
        )
    else:
        print(patch, end="", flush=True)
    return EXIT_OK
