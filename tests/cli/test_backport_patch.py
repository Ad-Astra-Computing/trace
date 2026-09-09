"""Tests for `trace backport-patch` (tools/trace_cli/backport_patch.py).

Pure-logic + mocked-runner unit tests run offline. The end-to-end integration
test is gated behind TRACE_REAL_BACKPORT=1 (needs network + nix).
"""

from __future__ import annotations

import os
import subprocess
from pathlib import Path

import pytest

from tools.trace_cli import backport_patch as bp


# ── reformat: plain unified diff + path format ───────────────────────────────

_GIT_DIFF = """diff --git a/src/x.c b/src/x.c
index a8131e0..4b1c219 100644
--- a/src/x.c
+++ b/src/x.c
@@ -10,7 +10,7 @@ int main(void)
   a;
   b;
   c;
-  if (old)
+  if (new)
   d;
   e;

"""


def test_to_plain_unified_strips_git_headers_p0():
    out = bp.to_plain_unified(_GIT_DIFF, strip_level=0)
    assert "diff --git" not in out
    assert "index a8131e0" not in out
    assert out.startswith("--- src/x.c\n+++ src/x.c\n")  # bare paths for -p0


def test_to_plain_unified_p1_keeps_ab_prefix():
    out = bp.to_plain_unified(_GIT_DIFF, strip_level=1)
    assert "--- a/src/x.c" in out and "+++ b/src/x.c" in out
    assert "diff --git" not in out


def test_ensure_ends_on_content_trims_trailing_blank_and_restamps():
    plain = bp.to_plain_unified(_GIT_DIFF, strip_level=1)
    out = bp.ensure_ends_on_content(plain)
    body = out.rstrip("\n").splitlines()
    assert body[-1].strip() != ""  # ends on a content line
    # original U3 had 3+change+3 ctx incl. a trailing blank; after trim the
    # hunk header count must match the body (no desync).
    hunk = next(l for l in body if l.startswith("@@"))
    import re

    m = re.match(r"@@ -\d+,(\d+) \+\d+,(\d+) @@", hunk)
    old_c = sum(1 for l in body if l[:1] in (" ", "-") and not l.startswith("---"))
    new_c = sum(1 for l in body if l[:1] in (" ", "+") and not l.startswith("+++"))
    assert int(m.group(1)) == old_c and int(m.group(2)) == new_c


def test_ends_on_content_never_trims_change_lines():
    # a hunk whose last body line is a +/- change must be preserved verbatim
    diff = "--- a/x\n+++ b/x\n@@ -1,2 +1,2 @@\n ctx\n-old\n+new\n"
    out = bp.ensure_ends_on_content(diff)
    assert "+new" in out and "-old" in out


# ── strip level from patchFlags ──────────────────────────────────────────────


@pytest.mark.parametrize(
    "flags,expected",
    [
        (["-p0"], 0),
        (["-p1"], 1),
        ([], 1),
        (["-p2"], 2),
        (["--strip=0"], 0),
        (["-l", "-p0"], 0),
    ],
)
def test_strip_level_from_flags(flags, expected):
    assert bp.strip_level_from_flags(flags) == expected


# ── commit-message preamble stripping ────────────────────────────────────────


def test_extract_diff_strips_commit_message():
    show = "commit abc\nAuthor: x\n\n    msg body\n\ndiff --git a/x b/x\n--- a/x\n+++ b/x\n"
    assert bp._extract_diff(show).startswith("diff --git a/x b/x")
    assert "commit abc" not in bp._extract_diff(show)


# ── tag candidates ───────────────────────────────────────────────────────────


def test_tag_candidates_covers_project_prefix_and_v():
    cands = bp._tag_candidates("1.0.8", "https://sourceware.org/git/bzip2.git")
    assert "bzip2-1.0.8" in cands and "v1.0.8" in cands and "1.0.8" in cands


def test_tag_candidates_dedup_for_v_prefixed():
    cands = bp._tag_candidates("v4.17", "https://github.com/rofl0r/proxychains-ng")
    assert cands.count("v4.17") == 1
    assert "proxychains-ng-4.17" in cands


# ── non-source exclusion ─────────────────────────────────────────────────────


@pytest.mark.parametrize(
    "path,excluded",
    [
        ("src/loaders/prowizard/pha.c", False),
        ("src/libproxychains.c", False),
        ("bzip2recover.c", False),
        ("docs/Changelog", True),
        ("test-dev/data/f/fixture", True),
        ("tests/test_foo.c", True),
        ("ChangeLog", True),
        ("README.md", True),
        ("data/sample.bin", True),
        (".github/workflows/ci.yml", True),
        # top-level test-harness files (libxml2 CVE-2026-0989 shape)
        ("runtest.c", True),
        ("runtests.c", True),
        ("run_test.c", True),
        ("test_relaxng.c", True),  # test_ separator
        ("HTMLparser_test.c", True),  # _test separator
        # ...but real source whose name merely starts with/contains "test" stays
        # source (a false exclusion would drop a real security fix).
        ("latest.c", False),
        ("contest.c", False),
        ("testing.c", False),
        ("testament.c", False),
        ("testapi.c", False),  # no separator: kept as source (safe bias)
        ("relaxng.c", False),
        ("include/libxml/relaxng.h", False),
    ],
)
def test_non_source_exclusion(path, excluded):
    assert bool(bp._NON_SOURCE_RE.search(path)) == excluded


# ── auto-scope with a mocked runner (numstat) ────────────────────────────────


def _completed(stdout="", returncode=0, stderr=""):
    return subprocess.CompletedProcess(
        args=[], returncode=returncode, stdout=stdout, stderr=stderr
    )


def test_auto_scope_excludes_binary_test_and_doc():
    numstat = "\n".join(
        [
            "5\t0\tsrc/loaders/prowizard/pha.c",  # source: keep
            "10\t2\tdocs/Changelog",  # doc: drop
            "-\t-\ttest-dev/data/f/fixture",  # binary + test: drop
            "3\t1\ttests/test_pha.c",  # test: drop
        ]
    )

    def runner(cmd, cwd=None):
        return _completed(stdout=numstat)

    paths = bp._auto_scope_source_paths(runner, Path("/tmp/repo"), "deadbeef")
    assert paths == ["src/loaders/prowizard/pha.c"]


# ── retarget_fix: conflict → reject; clean → diff (mocked git) ────────────────


def _mock_git_runner(
    *,
    apply_rc=0,
    diff_out="--- x\n+++ x\n",
    show_out="diff --git a/x b/x\n@@ -1 +1 @@\n-a\n+b\n",
):
    """Simulate the git command sequence retarget_fix issues."""

    def runner(cmd, cwd=None):
        c = cmd[1] if len(cmd) > 1 and cmd[0] == "git" else ""
        if c == "--version":
            return _completed(stdout="git version 2.43.0\n")
        if c in ("init", "config", "remote", "fetch", "checkout"):
            return _completed()
        if c == "rev-parse":
            return _completed(stdout="abc123\n")
        if c == "show":
            if "--numstat" in cmd:
                return _completed(stdout="5\t0\tx\n")
            return _completed(stdout=show_out)
        if c == "apply":
            return _completed(
                returncode=apply_rc, stderr="conflict" if apply_rc else ""
            )
        if c == "diff":
            return _completed(stdout=diff_out)
        return _completed()

    return runner


def test_retarget_fix_conflict_rejects(tmp_path):
    with pytest.raises(bp.BackportReject):
        bp.retarget_fix(
            repo_url="https://example.invalid/x",
            commit_sha="abc",
            version_tag="1.0",
            paths=["x"],
            workdir=tmp_path,
            runner=_mock_git_runner(apply_rc=1),
        )


def test_retarget_fix_clean_returns_diff(tmp_path):
    out = bp.retarget_fix(
        repo_url="https://example.invalid/x",
        commit_sha="abc",
        version_tag="1.0",
        paths=["x"],
        workdir=tmp_path,
        runner=_mock_git_runner(),
    )
    assert out.startswith("--- x")


def test_retarget_fix_empty_diff_rejects(tmp_path):
    # fix already present at this version -> empty diff -> reject
    with pytest.raises(bp.BackportReject):
        bp.retarget_fix(
            repo_url="https://example.invalid/x",
            commit_sha="abc",
            version_tag="1.0",
            paths=["x"],
            workdir=tmp_path,
            runner=_mock_git_runner(diff_out="\n"),
        )


# ── integration (network + nix) ──────────────────────────────────────────────


@pytest.mark.skipif(
    os.environ.get("TRACE_REAL_BACKPORT") != "1",
    reason="real-network/nix test; set TRACE_REAL_BACKPORT=1 to enable",
)
def test_integration_bzip2_skip_verify():
    repo_root = Path(__file__).resolve().parents[2]
    bundle = repo_root / "traces/example/CVE-2026-42250--bzip2-backport"
    patch = bp.produce_backport_patch(
        bundle_dir=bundle,
        nixpkgs=repo_root.parent / "nixpkgs",
        skip_verify=True,
    )
    assert "BZ_MAX_HANDLED_BLOCKS - 1" in patch
    assert "diff --git" not in patch  # plain unified
    assert patch.startswith("--- bzip2recover.c")  # bare paths for -p0
    assert patch.rstrip().splitlines()[-1].strip() != ""  # ends on content


@pytest.mark.skipif(
    os.environ.get("TRACE_REAL_BACKPORT") != "1",
    reason="real-network/nix test; set TRACE_REAL_BACKPORT=1 to enable",
)
def test_integration_graphite2_generalization(tmp_path):
    """Generalization check: the tool was built/tuned against bzip2, libxmp,
    proxychains. graphite2 (CVE-2026-50593) is a FRESH 4th package the tool was
    never tuned for — a fetchurl tarball, a GitHub upstream (silnrsi/graphite),
    a header-macro fix in src/inc/opcodes.h, -p1 + a/ b/. From a minimal 3-file
    bundle the tool must fetch, re-target onto the 1.3.14 tag, and emit a plain
    unified diff carrying the upstream bounds-check. WITH verify it must also
    apply to the 1.3.14 tarball (tag≈tarball)."""
    nixpkgs = Path(__file__).resolve().parents[2].parent / "nixpkgs"
    rev = subprocess.run(
        ["git", "-C", str(nixpkgs), "rev-parse", "HEAD"], capture_output=True, text=True
    ).stdout.strip()
    (tmp_path / "finding.json").write_text(
        '{"affected":[{"attr_path":"graphite2","version":"1.3.14","pname":"graphite2"}]}'
    )
    (tmp_path / "bundle.json").write_text('{"nixpkgs_rev":"%s"}' % rev)
    (tmp_path / "upstream-ref.json").write_text(
        '{"cve_id":"CVE-2026-50593","current_version":"1.3.14","target_version":"1.3.14",'
        '"tag":"1.3.14","upstream_fix_commits":[{"repo_url":"https://github.com/silnrsi/graphite",'
        '"commit_sha":"ad78c6b7319909e1540c1b134e115ced03417866"}],'
        '"eligibility":{"verdict":"eligible-requires-human-review","verdict_reason":"backport",'
        '"human_review_trigger":"source-backport-experimental","patch_strategy":"source-backport"}}'
    )
    patch = bp.produce_backport_patch(
        bundle_dir=tmp_path, nixpkgs=nixpkgs
    )  # WITH verify gate
    assert "slot_offset_out_bounds" in patch  # the upstream bounds-check
    assert "diff --git" not in patch  # plain unified
    assert "--- a/src/inc/opcodes.h" in patch  # -p1 + a/ b/ (default patchFlags)
    assert patch.rstrip().splitlines()[-1].strip() != ""


# ── security: feed-sourced arg validation ────────────────────────────────────


@pytest.mark.parametrize(
    "url,ok",
    [
        ("https://github.com/a/b.git", True),
        ("http://example.com/x", True),
        ("git://sourceware.org/git/bzip2.git", True),
        ("ssh://git@host/repo", True),
        ("git@github.com:a/b.git", True),
        ("ext::sh -c 'id'", False),  # transport-helper RCE
        ("fd::17", False),
        ("file:///etc/passwd", False),
        ("-oProxyCommand=evil", False),
        ("transport::x", False),
        ("", False),
    ],
)
def test_validate_repo_url(url, ok):
    if ok:
        assert bp._validate_repo_url(url) == url
    else:
        with pytest.raises(bp.BackportError):
            bp._validate_repo_url(url)


@pytest.mark.parametrize(
    "tag,ok",
    [
        ("1.0.8", True),
        ("v4.17", True),
        ("libxmp-4.6.2", True),
        ("REL_1_2", True),
        ("--upload-pack=evil", False),
        ("-x", False),
        ("a b", False),
        ("$(id)", False),
    ],
)
def test_validate_tag(tag, ok):
    if ok:
        assert bp._validate_tag(tag) == tag
    else:
        with pytest.raises(bp.BackportError):
            bp._validate_tag(tag)


def test_safe_rev_regex_is_40_hex():
    assert bp._SAFE_REV_RE.match("0" * 40)
    assert not bp._SAFE_REV_RE.match("+refs/heads/*:refs/heads/*")
    assert not bp._SAFE_REV_RE.match("HEAD")
    assert not bp._SAFE_REV_RE.match("a" * 39)


def test_retarget_fix_refuses_ext_transport(tmp_path):
    with pytest.raises(bp.BackportError):
        bp.retarget_fix(
            repo_url="ext::sh -c id",
            commit_sha="abc",
            version_tag="1.0",
            paths=["x"],
            workdir=tmp_path,
            runner=_mock_git_runner(),
        )


def test_hardened_env_restricts_git_protocol():
    assert bp._HARDENED_ENV["GIT_ALLOW_PROTOCOL"] == "https:git:ssh"
    assert bp._HARDENED_ENV["GIT_CONFIG_GLOBAL"] == "/dev/null"


def test_repo_url_regex_rejects_trailing_newline_smuggle():
    # \Z (not $) must reject a smuggled second line
    assert not bp._SAFE_REPO_URL_RE.match("https://x\nevil")
    assert not bp._SAFE_REV_RE.match("a" * 40 + "\nevil")
    assert not bp._SAFE_TAG_RE.match("1.0\n--evil")


def test_validate_tag_rejects_dotdot_traversal():
    with pytest.raises(bp.BackportError):
        bp._validate_tag("v1/../../etc")


# ── clone_url: cgit browse URL -> clone endpoint, validate-first ──────────────


@pytest.mark.parametrize(
    "browse,clone",
    [
        (
            "https://git.savannah.gnu.org/cgit/coreutils.git",
            "https://git.savannah.gnu.org/git/coreutils.git",
        ),
        (
            "https://git.savannah.gnu.org/cgit/gnulib.git",
            "https://git.savannah.gnu.org/git/gnulib.git",
        ),
    ],
)
def test_clone_url_maps_savannah_cgit_browse(browse, clone):
    assert bp.clone_url(browse) == clone


@pytest.mark.parametrize(
    "url",
    [
        "https://github.com/jqlang/jq",  # github untouched
        "https://git.busybox.net/busybox",  # cgit but already a clone endpoint
        "https://git.savannah.gnu.org/git/coreutils.git",  # already normalized
    ],
)
def test_clone_url_passthrough(url):
    assert bp.clone_url(url) == url


def test_clone_url_validates_first():
    # normalization must never rescue an unsafe transport
    with pytest.raises(bp.BackportError):
        bp.clone_url("ext::sh -c id")


# ── blobless_fetch_commit: tiered fetch with an injected git callable ─────────


class _FakeGit:
    """Records git invocations and resolves `present_after` set of fetch verbs."""

    def __init__(self, want_ok: bool, present_after: set[str]):
        self.want_ok = want_ok  # does the shallow sha-want succeed?
        self.present_after = present_after  # which fetch makes sha resolvable
        self.fetched: set[str] = set()
        self.calls: list[tuple[str, ...]] = []

    def __call__(self, *args):
        self.calls.append(args)
        rc = 0
        if args[0] == "fetch":
            if "--depth" in args:
                rc = 0 if self.want_ok else 1
                if self.want_ok:
                    self.fetched.add("want")
            elif "--tags" in args:
                self.fetched.add("tags")
            else:
                self.fetched.add("branches")
        elif args[0] == "rev-parse":
            rc = 0 if (self.present_after & self.fetched) else 1
        return subprocess.CompletedProcess(args, rc, stdout="", stderr="")


def test_blobless_fetch_fast_path_skips_allbranches():
    g = _FakeGit(want_ok=True, present_after={"want"})
    assert bp.blobless_fetch_commit(g, "a" * 40) is True
    # the shallow want resolved it; no all-branches/tags fetch needed
    assert g.fetched == {"want"}
    assert all("--filter=blob:none" in c for c in g.calls if c[0] == "fetch")


def test_blobless_fetch_falls_back_to_allbranches_and_tags():
    # server refuses the sha-want (cgit/abbrev); the complete fetch resolves it
    g = _FakeGit(want_ok=False, present_after={"branches", "tags"})
    assert bp.blobless_fetch_commit(g, "deadbeef") is True
    assert "branches" in g.fetched and "tags" in g.fetched


def test_blobless_fetch_returns_false_when_unreachable():
    g = _FakeGit(want_ok=False, present_after=set())  # sha on no ref (fossil/bad sha)
    assert bp.blobless_fetch_commit(g, "c" * 40) is False


def test_blobless_fetch_always_blobless():
    g = _FakeGit(want_ok=False, present_after={"branches"})
    bp.blobless_fetch_commit(g, "b" * 40)
    assert all("--filter=blob:none" in c for c in g.calls if c[0] == "fetch")


def test_blobless_fetch_rejects_option_injection_sha():
    # a feed-sourced sha that is git option syntax must never reach `git fetch`:
    # the hex-only guard returns False before any fetch runs (option-injection,
    # e.g. --upload-pack=<cmd> / --exec=<cmd>, can't smuggle through a bare arg).
    for bad in (
        "--upload-pack=touch /tmp/x",
        "--exec=sh",
        "-deadbeef",
        "HEAD",
        "a" * 6,
        "g" * 40,
        "abc def",
    ):
        g = _FakeGit(want_ok=True, present_after={"want"})
        assert bp.blobless_fetch_commit(g, bad) is False
        assert not any(c[0] == "fetch" for c in g.calls)


def test_assert_git_version_floor():
    bp._assert_git_version(
        lambda cmd, cwd=None: _completed(stdout="git version 2.43.0")
    )
    with pytest.raises(bp.BackportError):
        bp._assert_git_version(
            lambda cmd, cwd=None: _completed(stdout="git version 2.30.0")
        )
    with pytest.raises(bp.BackportError):
        bp._assert_git_version(lambda cmd, cwd=None: _completed(stdout="garbage"))


# ── reproducer-oracle fixture extraction ─────────────────────────────────────


@pytest.mark.parametrize(
    "path,is_oracle",
    [
        ("tests/fonts/underflow.ttf", True),
        ("test-dev/data/f/prowizard_pha_invalid_ocpt", True),
        ("tests/standards/underflow.json", True),
        ("tests/fuzz-tests/crash/Bad cmap.fuzz", True),
        ("regression/poc/crash.bin", True),
        ("test_fuzzer_x.c", False),  # not under a fixture dir
        ("src/loaders/pha.c", False),  # source, not oracle
        ("tests/CMakeLists.txt", False),  # build wiring, not oracle
        ("docs/Changelog", False),  # doc
        ("tests/Makefile.am", False),  # build
        ("tests/fonts/LICENSE", False),  # license, not oracle
    ],
)
def test_is_oracle_fixture(path, is_oracle):
    assert bp._is_oracle_fixture(path) == is_oracle


def test_extract_fixtures_caps_runaway(tmp_path):
    """A parentless/huge diff must be refused, not copied wholesale."""
    many = "\n".join(f"5\t0\ttests/fonts/f{i}.ttf" for i in range(bp._MAX_FIXTURES + 5))

    def runner(cmd, cwd=None):
        c = cmd[1] if len(cmd) > 1 and cmd[0] == "git" else ""
        if c == "--version":
            return _completed(stdout="git version 2.43.0")
        if c == "show" and "--numstat" in cmd:
            return _completed(stdout=many)
        if c == "rev-parse":
            return _completed(stdout="abc\n")
        return _completed()

    with pytest.raises(bp.BackportReject):
        bp.extract_fix_fixtures(
            repo_url="https://example.invalid/x",
            commit_sha="abc",
            out_dir=tmp_path / "out",
            workdir=tmp_path,
            runner=runner,
        )


@pytest.mark.skipif(
    os.environ.get("TRACE_REAL_BACKPORT") != "1",
    reason="real-network test; set TRACE_REAL_BACKPORT=1 to enable",
)
def test_integration_extract_oracle_fixtures(tmp_path):
    """The crash oracle co-lands in the fix commit. libxmp's commit carries the
    exact binary fixture used in its cert; graphite2's carries the malicious
    underflow.ttf. The tool must extract precisely those (a focused handful)."""
    lx = bp.extract_fix_fixtures(
        repo_url="https://github.com/libxmp/libxmp",
        commit_sha="004a102c5a",
        out_dir=tmp_path / "lx",
        workdir=tmp_path / "lxwork",
    )
    assert any("prowizard_pha_invalid_ocpt" in f for f in lx)
    assert len(lx) <= bp._MAX_FIXTURES
    # the extracted binary fixture is non-empty bytes
    assert (
        tmp_path / "lx" / "test-dev/data/f/prowizard_pha_invalid_ocpt"
    ).stat().st_size > 0

    g2 = bp.extract_fix_fixtures(
        repo_url="https://github.com/silnrsi/graphite",
        commit_sha="ad78c6b7319909e1540c1b134e115ced03417866",
        out_dir=tmp_path / "g2",
        workdir=tmp_path / "g2work",
    )
    assert any(f.endswith("underflow.ttf") for f in g2)
    assert (tmp_path / "g2" / "tests/fonts/underflow.ttf").stat().st_size > 1000


@pytest.mark.parametrize(
    "evil",
    [
        "tests/../../../etc/cron.d/x",  # traversal
        "tests/-rf",  # leading-dash component (arg injection)
        "tests/a\x00b",  # NUL
        "tests/a\nb.ttf",  # control char
    ],
)
def test_safe_fixture_name_rejects_dangerous(evil):
    assert bp._safe_fixture_name(evil) is False


def test_safe_fixture_name_accepts_normal():
    assert bp._safe_fixture_name("tests/fonts/underflow.ttf") is True
    assert bp._safe_fixture_name("test-dev/data/f/prowizard_pha_invalid_ocpt") is True


def _fixtures_runner(*, numstat, mode="100644 blob abc\tp", catsize="100"):
    def runner(cmd, cwd=None):
        c = cmd[1] if len(cmd) > 1 and cmd[0] == "git" else ""
        if c == "--version":
            return _completed(stdout="git version 2.43.0")
        if c == "rev-parse":
            return _completed(stdout="abc\n")
        if c == "show" and "--numstat" in cmd:
            return _completed(stdout=numstat)
        if c == "ls-tree":
            return _completed(stdout=mode)
        if c == "cat-file":
            return _completed(stdout=catsize)
        return _completed()

    return runner


def test_extract_skips_symlink_mode(tmp_path, capsys):
    """A 120000 (symlink) blob must NOT be materialised — its content is a target
    path (escape primitive). Mode-filtered out (core.symlinks=false governs only
    checkout, not our manual blob write)."""
    r = _fixtures_runner(
        numstat="5\t0\ttests/fonts/evil", mode="120000 blob deadbeef\ttests/fonts/evil"
    )
    kept = bp.extract_fix_fixtures(
        repo_url="https://example.invalid/x",
        commit_sha="abc",
        out_dir=tmp_path / "out",
        workdir=tmp_path / "wk",
        runner=r,
    )
    assert kept == []
    assert "non-regular git mode 120000" in capsys.readouterr().out


def test_extract_skips_traversal_and_unsafe_names(tmp_path):
    """`..`/unsafe fixture paths are skipped (never written outside out_dir)."""
    r = _fixtures_runner(numstat="5\t0\ttests/../../escape")
    kept = bp.extract_fix_fixtures(
        repo_url="https://example.invalid/x",
        commit_sha="abc",
        out_dir=tmp_path / "out",
        workdir=tmp_path / "wk",
        runner=r,
    )
    assert kept == []
    assert not (tmp_path / "escape").exists()


def test_extract_regular_blob_is_written(tmp_path):
    r = _fixtures_runner(
        numstat="5\t0\ttests/fonts/ok.ttf", mode="100644 blob abc\ttests/fonts/ok.ttf"
    )
    # patch _extract_blob to avoid a real binary git call in the unit path
    import tools.trace_cli.backport_patch as _bp

    orig = _bp._extract_blob
    _bp._extract_blob = lambda repo, sha, path, dest: (
        dest.parent.mkdir(parents=True, exist_ok=True),
        dest.write_bytes(b"x"),
    )
    try:
        kept = bp.extract_fix_fixtures(
            repo_url="https://example.invalid/x",
            commit_sha="abc",
            out_dir=tmp_path / "out",
            workdir=tmp_path / "wk",
            runner=r,
        )
    finally:
        _bp._extract_blob = orig
    assert kept == ["tests/fonts/ok.ttf"]
    assert (tmp_path / "out/tests/fonts/ok.ttf").read_bytes() == b"x"
