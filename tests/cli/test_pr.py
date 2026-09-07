"""Tests for `trace pr`.

Covers the validation / parse layer and dry-run path. Git + gh subprocess
calls are mocked; this is a unit-level suite — the integration path (real
clone + real PR) is exercised manually or in a dedicated e2e test.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from unittest import mock

import pytest

from tools.trace_cli import pr as pr_mod


# ─── fixture helpers ─────────────────────────────────────────────────────────


def _bundle_dir(
    tmp_path: Path,
    *,
    kind: str = "auto-merge",
    rekor_log_index: int | None = 9999999,
    signer: str = "https://github.com/Ad-Astra-Computing/trace/.github/workflows/steward.yml@refs/heads/main",
    with_patch_diff: bool = True,
) -> Path:
    d = tmp_path / "bundle"
    d.mkdir()
    bundle: dict = {
        "schema_version": "1.0.0",
        "bundle_id": "abcd1234ef567890",
        "cve_id": "CVE-2025-8176",
        "nixpkgs_rev": "d07af9b07a5fb0d212372f4d796f11d6267476ee",
        "kind": kind,
        "signed_manifest": {
            "algorithm": "sigstore-cosign-v1",
            "signer": signer,
            "identity_subject": signer,
            "identity_issuer": "https://token.actions.githubusercontent.com",
            "rekor_log_index": rekor_log_index,
            "rekor_uuid": "aabbcc",
        },
    }
    import hashlib
    patch_text = ("--- a/package.nix\n+++ b/package.nix\n@@ -1 +1 @@\n"
                  "-version = \"4.7.0\";\n+version = \"4.7.1\";\n")
    if with_patch_diff:
        # a finalized bundle lists patch.diff in the signed manifest (trace pr verifies it)
        bundle["files"] = {"patch.diff": {"sha256": hashlib.sha256(patch_text.encode()).hexdigest()}}
    (d / "bundle.json").write_text(json.dumps(bundle))
    (d / "resolver-input.json").write_text(
        json.dumps({"cve_id": "CVE-2025-8176", "attr_path": "libtiff", "current_version": "4.7.0", "candidate_refs": []})
    )
    (d / "upstream-ref.json").write_text(
        json.dumps({"schema_version": "1.0.0", "cve_id": "CVE-2025-8176", "current_version": "4.7.0", "target_version": "4.7.1", "delta": {}, "tag": None, "release_url": None, "advisory_urls": [], "upstream_fix_commits": [], "eligibility": {}, "prefetch_hashes": [], "fix_tier": "patch", "replay_critical": True})
    )
    if with_patch_diff:
        (d / "patch.diff").write_text(patch_text)
    return d


def _policy_dir(tmp_path: Path) -> Path:
    pd = tmp_path / "policy"
    pd.mkdir()
    policy = {
        "schema_version": "1.0.0",
        "fork": {
            "owner": "Ad-Astra-Computing",
            "repo": "nixpkgs",
            "url": "https://github.com/Ad-Astra-Computing/nixpkgs",
            "ssh_url": "git@github.com:Ad-Astra-Computing/nixpkgs.git",
            "upstream": {"owner": "NixOS", "repo": "nixpkgs", "url": "https://github.com/NixOS/nixpkgs"},
            "default_branch": "master",
            "tracked_channels": ["nixos-unstable"],
        },
        "patch_branch_convention": {
            "format": "trace/{cve_id}--{attr_path}--{bundle_id_short}",
            "examples": [],
            "notes": "",
        },
        "pr_convention": {
            "title_format": "{cve_id}: {attr_path} -> {target_version}",
            "title_examples": [],
            "base_branch": "master",
            "labels": ["trace-bundle"],
            "body_includes": [],
        },
        "trust_boundary": {
            "trace_writes_to": "Ad-Astra-Computing/nixpkgs only",
            "never_writes_to": "NixOS/nixpkgs",
            "notes": "",
        },
    }
    (pd / "nixpkgs-fork.json").write_text(json.dumps(policy))
    return pd / "nixpkgs-fork.json"


def _args(
    bundle_dir: Path,
    policy_path: Path,
    *,
    dry_run: bool = False,
    nixpkgs_checkout: Path | None = None,
    fork: str | None = None,
    base: str | None = None,
    cert_run_url: str | None = None,
    push_url: str | None = None,
    review: bool = False,
    execute: bool = False,
) -> argparse.Namespace:
    return argparse.Namespace(
        cmd="pr",
        bundle_dir=bundle_dir,
        nixpkgs_checkout=nixpkgs_checkout,
        fork=fork,
        base=base,
        cert_run_url=cert_run_url,
        push_url=push_url,
        dry_run=dry_run,
        policy=policy_path,
        review=review,
        execute=execute,
    )


# ─── validation tests ─────────────────────────────────────────────────────────


def test_rejects_non_auto_merge(tmp_path: Path, capsys) -> None:
    bd = _bundle_dir(tmp_path, kind="advisory-only")
    pp = _policy_dir(tmp_path)
    rc = pr_mod.run(_args(bd, pp))
    assert rc != 0
    err = capsys.readouterr().err
    assert "auto-merge" in err


def test_rejects_human_review_required(tmp_path: Path, capsys) -> None:
    bd = _bundle_dir(tmp_path, kind="human-review-required")
    pp = _policy_dir(tmp_path)
    rc = pr_mod.run(_args(bd, pp))
    assert rc != 0
    err = capsys.readouterr().err
    assert "auto-merge" in err


def test_rejects_unsigned_bundle(tmp_path: Path, capsys) -> None:
    bd = _bundle_dir(tmp_path, signer="ci-pending", rekor_log_index=None)
    pp = _policy_dir(tmp_path)
    rc = pr_mod.run(_args(bd, pp))
    assert rc != 0
    err = capsys.readouterr().err
    assert "signed" in err.lower() or "rekor" in err.lower()


def test_rejects_missing_rekor_index(tmp_path: Path, capsys) -> None:
    bd = _bundle_dir(tmp_path, rekor_log_index=None)
    pp = _policy_dir(tmp_path)
    rc = pr_mod.run(_args(bd, pp))
    assert rc != 0


def test_rejects_missing_patch_diff(tmp_path: Path, capsys) -> None:
    bd = _bundle_dir(tmp_path, with_patch_diff=False)
    pp = _policy_dir(tmp_path)
    rc = pr_mod.run(_args(bd, pp))
    assert rc != 0
    err = capsys.readouterr().err
    assert "patch.diff" in err


def test_rejects_missing_bundle_json(tmp_path: Path, capsys) -> None:
    empty = tmp_path / "empty"
    empty.mkdir()
    pp = _policy_dir(tmp_path)
    rc = pr_mod.run(_args(empty, pp))
    assert rc != 0
    err = capsys.readouterr().err
    assert "bundle.json" in err


def test_rejects_invalid_fork_format(tmp_path: Path, capsys) -> None:
    bd = _bundle_dir(tmp_path)
    pp = _policy_dir(tmp_path)
    rc = pr_mod.run(_args(bd, pp, fork="not-a-valid-fork-format"))
    assert rc != 0
    err = capsys.readouterr().err
    assert "owner/repo" in err


def test_rejects_upstream_as_fork_override(tmp_path: Path, capsys) -> None:
    """Trust boundary: --fork / TRACE_NIXPKGS_FORK must never target the
    policy's declared upstream (NixOS/nixpkgs). trace opens PRs against the
    fork only; upstream submission is a separate human-driven step."""
    bd = _bundle_dir(tmp_path)
    pp = _policy_dir(tmp_path)
    rc = pr_mod.run(_args(bd, pp, fork="NixOS/nixpkgs"))
    assert rc != 0
    err = capsys.readouterr().err
    assert "trust boundary" in err.lower()
    assert "NixOS/nixpkgs" in err


def test_rejects_upstream_override_case_insensitive(tmp_path: Path, capsys) -> None:
    """The upstream-deny guard must be case-insensitive so a casing trick
    (nixos/NixPkgs) cannot slip past it."""
    bd = _bundle_dir(tmp_path)
    pp = _policy_dir(tmp_path)
    rc = pr_mod.run(_args(bd, pp, fork="nixos/NixPkgs"))
    assert rc != 0
    err = capsys.readouterr().err
    assert "trust boundary" in err.lower()


# ─── dry-run tests ────────────────────────────────────────────────────────────


def test_dry_run_prints_plan_on_valid_bundle(tmp_path: Path, capsys) -> None:
    """dry-run should reach the checkout+check stage. We mock subprocess
    so no real git calls happen."""
    bd = _bundle_dir(tmp_path)
    pp = _policy_dir(tmp_path)

    # Provide a fake nixpkgs checkout that has the expected package.nix
    nixpkgs_dir = tmp_path / "nixpkgs"
    pkg_dir = nixpkgs_dir / "pkgs" / "by-name" / "li" / "libtiff"
    pkg_dir.mkdir(parents=True)
    (pkg_dir / "package.nix").write_text('{ version = "4.7.0"; }')

    with mock.patch("subprocess.run") as mock_run:
        mock_run.return_value = mock.MagicMock(returncode=0, stdout="", stderr="")

        rc = pr_mod.run(_args(bd, pp, dry_run=True, nixpkgs_checkout=nixpkgs_dir))

    assert rc == 0
    out = capsys.readouterr().out
    assert "[dry-run]" in out
    assert "CVE-2025-8176" in out
    assert "Ad-Astra-Computing" in out


def test_dry_run_aborts_if_apply_check_fails(tmp_path: Path, capsys) -> None:
    bd = _bundle_dir(tmp_path)
    pp = _policy_dir(tmp_path)

    nixpkgs_dir = tmp_path / "nixpkgs"
    pkg_dir = nixpkgs_dir / "pkgs" / "by-name" / "li" / "libtiff"
    pkg_dir.mkdir(parents=True)
    (pkg_dir / "package.nix").write_text('{ version = "4.7.0"; }')

    with mock.patch("subprocess.run") as mock_run:
        mock_run.return_value = mock.MagicMock(returncode=1, stdout="", stderr="hunk failed")

        rc = pr_mod.run(_args(bd, pp, dry_run=True, nixpkgs_checkout=nixpkgs_dir))

    assert rc != 0
    err = capsys.readouterr().err
    assert "check" in err.lower() or "apply" in err.lower()


def test_push_uses_ssh_url_from_policy(tmp_path: Path) -> None:
    """The branch push must go over SSH (policy fork.ssh_url), not https:
    a branch based on the frozen nixpkgs_rev carries nixpkgs's own
    .github/workflows/ files, which a PAT can't push without `workflow`
    scope. SSH avoids that. Clone stays https."""
    bd = _bundle_dir(tmp_path)
    pp = _policy_dir(tmp_path)
    nixpkgs_dir = tmp_path / "nixpkgs"
    pkg_dir = nixpkgs_dir / "pkgs" / "by-name" / "li" / "libtiff"
    pkg_dir.mkdir(parents=True)
    (pkg_dir / "package.nix").write_text('{ version = "4.7.0"; }')

    with mock.patch("tools.trace_cli.pr._commit_is_only_the_patch", return_value=(True, "mocked")), \
         mock.patch("tools.trace_cli.pr._resolve_base", return_value="master"), \
         mock.patch("subprocess.run") as mock_run:
        # git ops + gh return 0; gh pr create returns a PR url on stdout.
        def _fake(cmd, *a, **k):
            stdout = "https://github.com/Ad-Astra-Computing/nixpkgs/pull/1" if cmd[:2] == ["gh", "pr"] else ""
            return mock.MagicMock(returncode=0, stdout=stdout, stderr="")
        mock_run.side_effect = _fake
        rc = pr_mod.run(_args(bd, pp, nixpkgs_checkout=nixpkgs_dir))

    assert rc == 0
    push_calls = [c.args[0] for c in mock_run.call_args_list
                  if c.args and c.args[0][:2] == ["git", "push"]]
    assert push_calls, "expected a git push"
    # the push target must be the SSH url, never the https fork url
    assert any("git@github.com:Ad-Astra-Computing/nixpkgs.git" in arg
               for arg in push_calls[0]), push_calls[0]
    assert not any("https://github.com" in arg for arg in push_calls[0])


def _mk_nixpkgs(tmp_path: Path) -> Path:
    """A minimal checkout with the libtiff package dir the bundle targets."""
    nixpkgs_dir = tmp_path / "nixpkgs"
    pkg_dir = nixpkgs_dir / "pkgs" / "by-name" / "li" / "libtiff"
    pkg_dir.mkdir(parents=True)
    (pkg_dir / "package.nix").write_text('{ version = "4.7.0"; }')
    return nixpkgs_dir


def test_push_url_flag_overrides_ssh_default(tmp_path: Path) -> None:
    """--push-url swaps the default ssh transport for https against the SAME
    configured fork (the workflow-scope-token use case)."""
    bd = _bundle_dir(tmp_path)
    pp = _policy_dir(tmp_path)
    nixpkgs_dir = _mk_nixpkgs(tmp_path)
    custom = "https://github.com/Ad-Astra-Computing/nixpkgs.git"

    with mock.patch("tools.trace_cli.pr._commit_is_only_the_patch", return_value=(True, "mocked")), \
         mock.patch("tools.trace_cli.pr._resolve_base", return_value="master"), \
         mock.patch("subprocess.run") as mock_run:
        def _fake(cmd, *a, **k):
            stdout = "https://github.com/x/y/pull/2" if cmd[:2] == ["gh", "pr"] else ""
            return mock.MagicMock(returncode=0, stdout=stdout, stderr="")
        mock_run.side_effect = _fake
        rc = pr_mod.run(_args(bd, pp, nixpkgs_checkout=nixpkgs_dir, push_url=custom))

    assert rc == 0
    push_calls = [c.args[0] for c in mock_run.call_args_list
                  if c.args and c.args[0][:2] == ["git", "push"]]
    assert push_calls and any(custom in arg for arg in push_calls[0])
    # the override beat the ssh default
    assert not any("git@github.com" in arg for arg in push_calls[0])


@pytest.mark.parametrize(
    "bad",
    [
        # --- upstream, every spelling git would accept ---
        "git@github.com:NixOS/nixpkgs.git",            # scp-form ssh
        "https://github.com/nixos/NixPkgs.git",        # https, case-folded
        "ssh://git@github.com:22/NixOS/nixpkgs.git",   # explicit port
        "https://github.com/NixOS/nixpkgs.git#x",      # client-side fragment
        "https://github.com/NixOS/nixpkgs?foo=1",      # query string
        "https://github.com/Ad-Astra-Computing/nixpkgs;foo",    # path params
        # --- other destinations the fork-only boundary forbids ---
        "origin",                                       # bare remote alias
        "https://git.example.com/group/nixpkgs",       # non-GitHub mirror
        "https://git.example.com/g/sub/nixpkgs.git",   # nested-path mirror
        "https://x:tok@github.com/Ad-Astra-Computing/nixpkgs",  # creds in URL
        "https://github.com/Other-Owner/nixpkgs",      # wrong owner
        "https://github.com:443/Ad-Astra-Computing/nixpkgs",    # explicit port
    ],
)
def test_push_url_rejects_non_fork_targets(
    tmp_path: Path, capsys, bad: str
) -> None:
    """--push-url is a transport override for the configured fork, not a
    destination override. Anything that doesn't normalize to a plain
    https://github.com/<fork> is rejected fail-closed, and nothing is pushed."""
    bd = _bundle_dir(tmp_path)
    pp = _policy_dir(tmp_path)
    nixpkgs_dir = _mk_nixpkgs(tmp_path)

    with mock.patch("subprocess.run") as mock_run:
        rc = pr_mod.run(_args(bd, pp, nixpkgs_checkout=nixpkgs_dir, push_url=bad))

    assert rc != 0, f"{bad!r} should be rejected"
    assert "trust boundary" in capsys.readouterr().err.lower()
    assert not [c for c in mock_run.call_args_list
                if c.args and c.args[0][:2] == ["git", "push"]]


# ─── helper unit tests ────────────────────────────────────────────────────────


def test_resolve_attr_package_dir_finds_pkgs_by_name(tmp_path: Path) -> None:
    attr = "libtiff"
    pkg_dir = tmp_path / "pkgs" / "by-name" / "li" / "libtiff"
    pkg_dir.mkdir(parents=True)
    (pkg_dir / "package.nix").write_text("{ }")
    result = pr_mod._resolve_attr_package_dir(tmp_path, attr)
    assert result == "pkgs/by-name/li/libtiff"


def test_resolve_attr_package_dir_returns_none_when_missing(tmp_path: Path) -> None:
    result = pr_mod._resolve_attr_package_dir(tmp_path, "nonexistent")
    assert result is None


def test_resolve_attr_package_dir_rejects_unsafe_attr(tmp_path: Path) -> None:
    """Attrs that fail _ATTR_SAFE_RE return None without invoking nix eval."""
    for bad in ["ruby}; builtins.readFile /etc/passwd; ({", "a b", "1start", ".leading", "a..b", ""]:
        assert pr_mod._resolve_attr_package_dir(tmp_path, bad) is None, f"expected None for {bad!r}"


def test_build_pr_body_includes_cve_and_rekor(tmp_path: Path) -> None:
    bundle = {
        "cve_id": "CVE-2025-8176",
        "kind": "auto-merge",
        "bundle_id": "abcd1234ef567890",
        "nixpkgs_rev": "d07af9b07a5fb0d212372f4d796f11d6267476ee",
        "signed_manifest": {
            "rekor_log_index": 9999999,
            "identity_subject": "https://github.com/Ad-Astra-Computing/trace/.github/workflows/steward.yml@refs/heads/main",
            "identity_issuer": "https://token.actions.githubusercontent.com",
        },
    }
    bd = tmp_path / "b"
    bd.mkdir()
    body = pr_mod._build_pr_body(bundle, bd, cert_run_url=None)
    assert "CVE-2025-8176" in body
    assert "auto-merge" in body
    assert "abcd1234ef567890" in body
    assert "rekor.sigstore.dev" in body


def test_build_pr_body_includes_cert_run_url(tmp_path: Path) -> None:
    bundle = {
        "cve_id": "CVE-2025-8176",
        "kind": "auto-merge",
        "bundle_id": "abcd1234ef567890",
        "nixpkgs_rev": "d07af9b07a5fb0d212372f4d796f11d6267476ee",
        "signed_manifest": {
            "rekor_log_index": 9999999,
            "identity_subject": "",
            "identity_issuer": "",
        },
    }
    bd = tmp_path / "b"
    bd.mkdir()
    url = "https://github.com/Ad-Astra-Computing/trace/actions/runs/26647927663"
    body = pr_mod._build_pr_body(bundle, bd, cert_run_url=url)
    assert url in body


def test_load_attr_returns_attr_path(tmp_path: Path) -> None:
    ri = tmp_path / "resolver-input.json"
    ri.write_text(json.dumps({"attr_path": "mruby", "cve_id": "CVE-2025-7207", "current_version": "3.3.0", "candidate_refs": []}))
    attr, err = pr_mod._load_attr(tmp_path)
    assert attr == "mruby"
    assert err is None


def test_load_attr_fails_when_missing(tmp_path: Path) -> None:
    attr, err = pr_mod._load_attr(tmp_path)
    assert attr == ""
    assert err is not None
    assert "resolver-input.json" in err


# ─── review-PR mode ───────────────────────────────────────────────────────────

def _backport_bundle(tmp_path: Path, *, rekor_log_index=9999999, with_build=True) -> Path:
    d = _bundle_dir(tmp_path, kind="human-review-required", rekor_log_index=rekor_log_index)
    b = json.loads((d / "bundle.json").read_text())
    b["kind_reason"] = "source-backport-experimental"
    if with_build:
        b.setdefault("files", {})["build.json"] = {"sha256": "0" * 64, "bytes": 1,
                                                   "producer_role": "builder", "replay_critical": False}
    (d / "bundle.json").write_text(json.dumps(b))
    (d / "upstream-ref.json").write_text(json.dumps({
        "cve_id": "CVE-2025-8176", "current_version": "4.7.0", "target_version": "4.7.0",
        "upstream_fix_commits": [{"repo_url": "https://github.com/x/y", "commit_sha": "deadbeef"}],
        "eligibility": {"patch_strategy": "source-backport"},
    }))
    return d


def test_review_refuses_non_source_backport(tmp_path, capsys):
    # an auto-merge bundle with --review is refused (review is for backports only)
    bd = _bundle_dir(tmp_path, kind="auto-merge")
    rc = pr_mod.run(_args(bd, _policy_dir(tmp_path), review=True, dry_run=True))
    assert rc == pr_mod.EXIT_INVALID
    assert "source-backport-experimental" in capsys.readouterr().err


def test_review_keeps_signature_gate(tmp_path, capsys):
    # the no-downgrade principle: an UNSIGNED source-backport is refused in review mode
    bd = _backport_bundle(tmp_path, rekor_log_index=None)
    rc = pr_mod.run(_args(bd, _policy_dir(tmp_path), review=True, dry_run=True))
    assert rc == pr_mod.EXIT_INVALID
    assert "not cosign-signed" in capsys.readouterr().err


def test_review_requires_cert_evidence(tmp_path, capsys):
    # a signed source-backport with no build.json (not cert-green) is refused
    bd = _backport_bundle(tmp_path, with_build=False)
    rc = pr_mod.run(_args(bd, _policy_dir(tmp_path), review=True, dry_run=True))
    assert rc == pr_mod.EXIT_INVALID
    assert "build.json" in capsys.readouterr().err


def test_auto_merge_mode_still_refuses_human_review(tmp_path, capsys):
    # without --review, a human-review bundle is refused as before
    bd = _backport_bundle(tmp_path)
    rc = pr_mod.run(_args(bd, _policy_dir(tmp_path), dry_run=True))
    assert rc == pr_mod.EXIT_INVALID
    assert "auto-merge" in capsys.readouterr().err


def test_review_body_has_blocking_sufficiency_checklist(tmp_path):
    bd = _backport_bundle(tmp_path)
    bundle = json.loads((bd / "bundle.json").read_text())
    body = pr_mod._build_pr_body(bundle, bd, None, review=True)
    assert "EXPERIMENTAL source-backport" in body
    assert "COMPLETE" in body                       # necessary-but-not-sufficient warning
    assert "- [ ]" in body                          # blocking checklist
    assert "github.com/x/y/commit/deadbeef" in body  # upstream fix commit linked
    assert "draft" in body.lower()
    # the auto-merge body has none of this
    assert "EXPERIMENTAL source-backport" not in pr_mod._build_pr_body(bundle, bd, None, review=False)


def test_git_add_includes_new_files_then_commit(tmp_path):
    """Regression: source-backports add a NEW <CVE>.patch file. The commit must
    include it (the old `git commit -a` dropped untracked new files, shipping a
    package.nix referencing a file absent from the PR)."""
    import subprocess
    repo = tmp_path / "repo"
    repo.mkdir()
    pkgdir = repo / "pkgs" / "by-name" / "xx" / "foo"
    pkgdir.mkdir(parents=True)
    (pkgdir / "package.nix").write_text("{ }: { patches = []; }\n")
    for c in (["git", "init", "-q"], ["git", "add", "-A"],
              ["git", "-c", "user.email=t@t", "-c", "user.name=t", "commit", "-qm", "init"]):
        subprocess.run(c, cwd=repo, check=True, capture_output=True)
    # simulate `git apply`: a NEW patch file + a modified tracked file
    (pkgdir / "CVE-2026-0001.patch").write_text("--- a/x\n+++ b/x\n")
    (pkgdir / "package.nix").write_text("{ }: { patches = [ ./CVE-2026-0001.patch ]; }\n")
    assert pr_mod._git_add(repo, "pkgs/by-name/xx/foo") == 0
    assert pr_mod._git_commit(repo, "foo: fix") == 0
    files = subprocess.run(["git", "show", "--name-only", "--format=", "HEAD"],
                           cwd=repo, capture_output=True, text=True).stdout.split()
    assert "pkgs/by-name/xx/foo/CVE-2026-0001.patch" in files   # the new file IS in the commit
    assert "pkgs/by-name/xx/foo/package.nix" in files


def test_nixfmt_modified_targets_nix_not_patch(tmp_path, monkeypatch):
    """nixfmt runs on the modified .nix file, never the authored <CVE>.patch."""
    import subprocess as sp
    pkgdir = tmp_path / "pkgs" / "by-name" / "xx" / "foo"
    pkgdir.mkdir(parents=True)
    (pkgdir / "package.nix").write_text("{ }: { }\n")
    (pkgdir / "CVE-2026-0001.patch").write_text("--- a/x\n+++ b/x\n")
    patch = ("diff --git a/CVE-2026-0001.patch b/CVE-2026-0001.patch\n--- /dev/null\n"
             "+++ b/CVE-2026-0001.patch\n@@ -0,0 +1 @@\n+x\n"
             "diff --git a/package.nix b/package.nix\n--- a/package.nix\n+++ b/package.nix\n@@\n+ patches=[];\n")
    monkeypatch.setattr(pr_mod, "_find_nixfmt", lambda: ["true"])  # no-op formatter
    calls = []
    real_run = sp.run
    def spy(cmd, *a, **k):
        calls.append(cmd)
        return real_run(["true"], *a, **k)
    monkeypatch.setattr(pr_mod.subprocess, "run", spy)
    pr_mod._nixfmt_modified(tmp_path, "pkgs/by-name/xx/foo", patch)
    formatted = [c[-1] for c in calls]
    assert any(p.endswith("package.nix") for p in formatted)
    assert not any(p.endswith(".patch") for p in formatted)  # never the patch


def test_nixfmt_missing_warns_not_fails(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(pr_mod, "_find_nixfmt", lambda: None)
    assert pr_mod._nixfmt_modified(tmp_path, "p", "+++ b/x.nix\n") == 0
    assert "nixfmt not found" in capsys.readouterr().err


# ── apply-plan from the signed build.json (by-name / remap / repo-root) ──────

def _bundle_with_build(tmp_path: Path, build_json: dict) -> tuple[Path, dict]:
    import hashlib
    bd = tmp_path / "bundle"
    bd.mkdir()
    bj_bytes = json.dumps(build_json).encode()
    (bd / "build.json").write_bytes(bj_bytes)
    manifest = {"files": {"build.json": {"sha256": hashlib.sha256(bj_bytes).hexdigest()}}}
    return bd, manifest


def test_verify_build_json_rejects_tampered(tmp_path: Path) -> None:
    bd, manifest = _bundle_with_build(tmp_path, {"patch_apply": {"files_changed": ["pkgs/x/package.nix"]}})
    (bd / "build.json").write_text('{"patch_apply": {"files_changed": ["pkgs/EVIL/package.nix"]}}')
    bj, err = pr_mod._verify_build_json(bd, manifest)
    assert bj is None and "does not match the signed manifest" in err


def test_derive_plan_canonical_remap(tmp_path: Path) -> None:
    bj = {"patch_apply": {"files_changed": ["pkgs/applications/x/putty/default.nix"],
                          "package_file_remap": "package.nix -> .../default.nix (content-match)"}}
    patch = tmp_path / "p.diff"
    patch.write_text("diff --git a/package.nix b/package.nix\n--- a/package.nix\n+++ b/package.nix\n@@ -1 +1 @@\n-a\n+b\n")
    plan, err = pr_mod._derive_apply_plan(bj, patch, tmp_path)
    assert err is None and plan["mode"] == "canonical-package-remap"
    assert plan["package_dir"] == "pkgs/applications/x/putty"
    remapped = plan["patch_path"].read_text()
    assert "b/default.nix" in remapped and "package.nix" not in remapped
    assert "-a\n+b" in remapped  # hunk body untouched


def test_derive_plan_by_name(tmp_path: Path) -> None:
    bj = {"patch_apply": {"files_changed": ["pkgs/by-name/ex/example/package.nix"]}}
    patch = tmp_path / "p.diff"; patch.write_text("x")
    plan, err = pr_mod._derive_apply_plan(bj, patch, tmp_path)
    assert err is None and plan["mode"] == "by-name"
    assert plan["package_dir"] == "pkgs/by-name/ex/example"
    assert plan["patch_path"] == patch  # not remapped


_MULTIFILE_DIFF = (
    "--- a/pkgs/a/default.nix\n+++ b/pkgs/a/default.nix\n@@ -1 +1 @@\n-a\n+b\n"
    "--- /dev/null\n+++ b/pkgs/b/thing.patch\n@@ -0,0 +1 @@\n+x\n"
)


def test_derive_plan_repo_root_multifile(tmp_path: Path) -> None:
    bj = {"patch_apply": {"files_changed": ["pkgs/a/default.nix", "pkgs/b/thing.patch"]}}
    patch = tmp_path / "p.diff"; patch.write_text(_MULTIFILE_DIFF)
    plan, err = pr_mod._derive_apply_plan(bj, patch, tmp_path)
    assert err is None and plan["mode"] == "repo-root" and plan["package_dir"] == ""
    # the verified file list rides along so staging is exact, not `git add -- pkgs`
    assert plan["files_changed"] == ["pkgs/a/default.nix", "pkgs/b/thing.patch"]


_BY_NAME_BACKPORT_DIFF = (
    "--- /dev/null\n+++ b/CVE-2025-0001.patch\n@@ -0,0 +1 @@\n+x\n"
    "--- a/package.nix\n+++ b/package.nix\n@@ -1 +1 @@\n-a\n+b\n"
)


def test_derive_plan_by_name_package_nix_backport(tmp_path: Path) -> None:
    """A by-name source-backport: bundle-relative diff (package.nix + authored
    <CVE>.patch) applied with --directory into one package dir. The record carries
    repo paths; the plan replays the Builder's --directory apply."""
    bj = {"patch_apply": {"apply_mode": "by-name-package-nix", "files_changed": [
        "pkgs/by-name/ex/example/CVE-2025-0001.patch", "pkgs/by-name/ex/example/package.nix"]}}
    patch = tmp_path / "p.diff"; patch.write_text(_BY_NAME_BACKPORT_DIFF)
    plan, err = pr_mod._derive_apply_plan(bj, patch, tmp_path)
    assert err is None and plan["mode"] == "by-name-package-nix"
    assert plan["package_dir"] == "pkgs/by-name/ex/example"
    assert plan["patch_path"] == patch
    assert plan["files_changed"] == bj["patch_apply"]["files_changed"]


def test_derive_plan_by_name_package_nix_rejects_unlisted_basename(tmp_path: Path) -> None:
    """The record lists a different authored patch than the one patch.diff adds:
    staging the recorded set would drop the real file, so refuse."""
    bj = {"patch_apply": {"apply_mode": "by-name-package-nix", "files_changed": [
        "pkgs/by-name/ex/example/other.patch", "pkgs/by-name/ex/example/package.nix"]}}
    patch = tmp_path / "p.diff"; patch.write_text(_BY_NAME_BACKPORT_DIFF)
    plan, err = pr_mod._derive_apply_plan(bj, patch, tmp_path)
    assert plan is None and "CVE-2025-0001.patch" in err and "inconsistent" in err


def test_derive_plan_by_name_package_nix_rejects_nested_patch_paths(tmp_path: Path) -> None:
    """The record says --directory apply, but the patch names repo paths: the
    coordinate systems disagree, so refuse rather than guess."""
    bj = {"patch_apply": {"apply_mode": "by-name-package-nix", "files_changed": [
        "pkgs/a/default.nix", "pkgs/a/thing.patch"]}}
    patch = tmp_path / "p.diff"; patch.write_text(
        "--- a/pkgs/a/default.nix\n+++ b/pkgs/a/default.nix\n@@ -1 +1 @@\n-a\n+b\n")
    plan, err = pr_mod._derive_apply_plan(bj, patch, tmp_path)
    assert plan is None and "nested paths" in err


def test_derive_plan_multifile_without_by_name_mode_stays_repo_root(tmp_path: Path) -> None:
    """Without the by-name apply_mode marker a same-dir multi-file record keeps the
    repo-root rule (patch paths must be the recorded repo paths)."""
    bj = {"patch_apply": {"files_changed": [
        "pkgs/by-name/ex/example/CVE-2025-0001.patch", "pkgs/by-name/ex/example/package.nix"]}}
    patch = tmp_path / "p.diff"; patch.write_text(_BY_NAME_BACKPORT_DIFF)
    plan, err = pr_mod._derive_apply_plan(bj, patch, tmp_path)
    assert plan is None and "inconsistent" in err


def test_derive_plan_repo_root_rejects_record_missing_patched_file(tmp_path: Path) -> None:
    """Fail closed when files_changed omits a path the patch actually modifies —
    staging only the listed subset would silently ship an incomplete PR (audit
    2026-07-20). files_changed here lacks pkgs/b/thing.patch."""
    bj = {"patch_apply": {"files_changed": ["pkgs/a/default.nix"]}}
    patch = tmp_path / "p.diff"; patch.write_text(_MULTIFILE_DIFF)
    plan, err = pr_mod._derive_apply_plan(bj, patch, tmp_path)
    assert plan is None
    assert err is not None and "pkgs/b/thing.patch" in err and "inconsistent" in err


def test_derive_plan_repo_root_allows_superset_record(tmp_path: Path) -> None:
    """A files_changed superset (a listed path the patch doesn't touch) is fine —
    staging an unchanged path is a no-op, not a dropped change."""
    bj = {"patch_apply": {"files_changed":
                          ["pkgs/a/default.nix", "pkgs/b/thing.patch", "pkgs/c/extra.nix"]}}
    patch = tmp_path / "p.diff"; patch.write_text(_MULTIFILE_DIFF)
    plan, err = pr_mod._derive_apply_plan(bj, patch, tmp_path)
    assert err is None and plan["mode"] == "repo-root"


def test_git_add_repo_root_stages_only_verified_files(tmp_path):
    """Repo-root apply must stage exactly the verified files_changed, never a whole
    subtree — a dirty --nixpkgs-checkout with unrelated WIP under pkgs/ must not leak
    that WIP into the PR (M2 / audit 2026-07-20)."""
    import subprocess
    repo = tmp_path / "repo"
    (repo / "pkgs" / "a").mkdir(parents=True)
    (repo / "pkgs" / "wip").mkdir(parents=True)
    (repo / "pkgs" / "a" / "default.nix").write_text("{ }: { }\n")
    for c in (["git", "init", "-q"], ["git", "add", "-A"],
              ["git", "-c", "user.email=t@t", "-c", "user.name=t", "commit", "-qm", "init"]):
        subprocess.run(c, cwd=repo, check=True, capture_output=True)
    # the patch touched pkgs/a/default.nix; an unrelated dirty file sits under pkgs/wip
    (repo / "pkgs" / "a" / "default.nix").write_text("{ }: { patched = true; }\n")
    (repo / "pkgs" / "wip" / "SECRET.nix").write_text("operator WIP, must not ship\n")
    assert pr_mod._git_add(repo, "", ["pkgs/a/default.nix"]) == 0
    assert pr_mod._git_commit(repo, "a: fix") == 0
    files = subprocess.run(["git", "show", "--name-only", "--format=", "HEAD"],
                           cwd=repo, capture_output=True, text=True).stdout.split()
    assert files == ["pkgs/a/default.nix"]           # ONLY the verified file
    assert "pkgs/wip/SECRET.nix" not in files          # WIP stayed out of the PR


def test_derive_plan_rejects_traversal(tmp_path: Path) -> None:
    for bad in ["../etc/passwd.nix", "/abs/package.nix", "pkgs/../x.nix", "notpkgs/x.nix", "pkgs/a/..\\b.nix"]:
        bj = {"patch_apply": {"files_changed": [bad]}}
        patch = tmp_path / "p.diff"; patch.write_text("x")
        plan, err = pr_mod._derive_apply_plan(bj, patch, tmp_path)
        assert plan is None and err is not None, bad


def test_derive_plan_no_record_falls_back(tmp_path: Path) -> None:
    plan, err = pr_mod._derive_apply_plan({}, tmp_path / "p.diff", tmp_path)
    assert plan is None and err is None  # → caller uses attr resolution


def test_verify_manifest_missing_on_disk_is_error(tmp_path: Path) -> None:
    # M1: a file listed in the signed manifest but absent on disk must ERROR,
    # never silently fall back (that would re-enable attr-steering by deletion).
    bd = tmp_path / "b"; bd.mkdir()
    manifest = {"files": {"build.json": {"sha256": "a" * 64}}}  # listed, but no file written
    bj, err = pr_mod._verify_build_json(bd, manifest)
    assert bj is None and "missing on disk" in err


def test_verify_manifest_absent_and_unlisted_falls_back(tmp_path: Path) -> None:
    bd = tmp_path / "b"; bd.mkdir()
    bj, err = pr_mod._verify_build_json(bd, {"files": {}})  # legacy: not listed, not present
    assert bj is None and err is None


def test_verify_manifest_hashes_and_parses_same_bytes(tmp_path: Path) -> None:
    # M3: no TOCTOU — verified bytes are the parsed bytes.
    import hashlib
    bd = tmp_path / "b"; bd.mkdir()
    raw = b'{"patch_apply": {"files_changed": ["pkgs/x/package.nix"]}}'
    (bd / "build.json").write_bytes(raw)
    manifest = {"files": {"build.json": {"sha256": hashlib.sha256(raw).hexdigest()}}}
    bj, err = pr_mod._verify_build_json(bd, manifest)
    assert err is None and bj["patch_apply"]["files_changed"] == ["pkgs/x/package.nix"]


def test_review_title_is_not_bump_shaped():
    """A review-mode (source-backport) PR keeps the package at its current version;
    its title must say so rather than reading `attr -> version` like a bump."""
    policy = {"pr_convention": {"title_format": "{cve_id}: {attr_path} -> {target_version}"}}
    bump = pr_mod._pr_title(policy, False, "CVE-2026-1", "foo", "1.2.3")
    review = pr_mod._pr_title(policy, True, "CVE-2026-1", "foo", "1.2.3")
    assert bump == "CVE-2026-1: foo -> 1.2.3"
    assert review == "CVE-2026-1: foo, backport upstream fix (no version bump)"
    assert "->" not in review and "1.2.3" not in review
    # policy may override the review format
    policy["pr_convention"]["review_title_format"] = "{cve_id}: {attr_path} [backport]"
    assert pr_mod._pr_title(policy, True, "CVE-2026-1", "foo", None) == "CVE-2026-1: foo [backport]"


def test_derive_plan_canonical_source_backport_remap(tmp_path: Path) -> None:
    """A non-by-name source-backport: the Builder remapped the bundle's package.nix
    onto default.nix by content match and applied the two-file diff with
    --directory. The plan rewrites the package.nix basename in a temp copy and
    replays the --directory apply, staging exactly the recorded files."""
    bj = {"patch_apply": {"apply_mode": "canonical-source-backport-remap",
          "package_file_remap": "package.nix -> pkgs/tools/misc/tmux/default.nix (content-match)",
          "files_changed": ["pkgs/tools/misc/tmux/default.nix",
                            "pkgs/tools/misc/tmux/CVE-2025-0001.patch"]}}
    patch = tmp_path / "p.diff"; patch.write_text(_BY_NAME_BACKPORT_DIFF)
    plan, err = pr_mod._derive_apply_plan(bj, patch, tmp_path)
    assert err is None and plan["mode"] == "canonical-source-backport-remap"
    assert plan["package_dir"] == "pkgs/tools/misc/tmux"
    assert plan["files_changed"] == bj["patch_apply"]["files_changed"]
    text = Path(plan["patch_path"]).read_text()
    assert "+++ b/default.nix" in text and "package.nix" not in text
    assert "+++ b/CVE-2025-0001.patch" in text


def test_derive_plan_canonical_source_backport_remap_rejects_unlisted(tmp_path: Path) -> None:
    bj = {"patch_apply": {"apply_mode": "canonical-source-backport-remap",
          "package_file_remap": "package.nix -> pkgs/tools/misc/tmux/default.nix (content-match)",
          "files_changed": ["pkgs/tools/misc/tmux/default.nix",
                            "pkgs/tools/misc/tmux/other.patch"]}}
    patch = tmp_path / "p.diff"; patch.write_text(_BY_NAME_BACKPORT_DIFF)
    plan, err = pr_mod._derive_apply_plan(bj, patch, tmp_path)
    assert plan is None and "CVE-2025-0001.patch" in err and "inconsistent" in err


def test_derive_plan_canonical_source_backport_remap_rejects_nested_paths(tmp_path: Path) -> None:
    bj = {"patch_apply": {"apply_mode": "canonical-source-backport-remap",
          "package_file_remap": "package.nix -> pkgs/a/default.nix (content-match)",
          "files_changed": ["pkgs/a/default.nix", "pkgs/a/thing.patch"]}}
    patch = tmp_path / "p.diff"; patch.write_text(
        "--- a/pkgs/a/default.nix\n+++ b/pkgs/a/default.nix\n@@ -1 +1 @@\n-a\n+b\n")
    plan, err = pr_mod._derive_apply_plan(bj, patch, tmp_path)
    assert plan is None and "nested paths" in err


def test_derive_plan_canonical_source_backport_remap_requires_single_dir(tmp_path: Path) -> None:
    bj = {"patch_apply": {"apply_mode": "canonical-source-backport-remap",
          "package_file_remap": "package.nix -> pkgs/a/default.nix (content-match)",
          "files_changed": ["pkgs/a/default.nix", "pkgs/b/CVE-2025-0001.patch"]}}
    patch = tmp_path / "p.diff"; patch.write_text(_BY_NAME_BACKPORT_DIFF)
    plan, err = pr_mod._derive_apply_plan(bj, patch, tmp_path)
    assert plan is None and "one pkgs/ dir" in err


# ─── the PR carries exactly the patch, against the bundle's pinned revision ───
#
# PR #47 on the fork showed 7975 files and 100 commits: the branch was cut from
# the bundle's pinned nixpkgs_rev but opened against the fork's master, which sat
# at an older revision, so every upstream commit in between rode along.


def test_resolve_base_keeps_master_when_it_contains_the_rev():
    from tools.trace_cli.pr import _resolve_base
    pushed = []
    base = _resolve_base(
        "Ad-Astra-Computing", "nixpkgs", "master", "c" * 40, Path("/x"), "git@github.com:o/r.git",
        compare=lambda owner, repo, base, rev: "behind",
        push=lambda nixpkgs, url, refspec: pushed.append(refspec) or 0,
    )
    assert base == "master"
    assert pushed == []


def test_resolve_base_pushes_the_pinned_rev_when_master_does_not_contain_it():
    from tools.trace_cli.pr import _resolve_base
    pushed = []
    rev = "17de0b976395537756f30a3e78f2f06e5cec89ed"
    base = _resolve_base(
        "Ad-Astra-Computing", "nixpkgs", "master", rev, Path("/x"), "git@github.com:o/r.git",
        compare=lambda owner, repo, base, rev: "diverged",
        push=lambda nixpkgs, url, refspec: pushed.append(refspec) or 0,
    )
    assert base == f"trace/base/{rev}"
    assert pushed == [f"{rev}:refs/heads/trace/base/{rev}"]


def test_resolve_base_refuses_when_the_comparison_cannot_run():
    from tools.trace_cli.pr import _resolve_base
    with pytest.raises(RuntimeError, match="cannot decide the PR base"):
        _resolve_base("o", "r", "master", "c" * 40, Path("/x"), "u",
                      compare=lambda *a: None, push=lambda *a: 0)


def _git_repo_with_base(tmp_path: Path) -> tuple[Path, str]:
    import subprocess
    repo = tmp_path / "nixpkgs"
    (repo / "pkgs/by-name/ma/mailpit").mkdir(parents=True)
    (repo / "pkgs/by-name/ma/mailpit/package.nix").write_text("{ }\n")
    (repo / "pkgs/other.nix").write_text("x\n")
    g = lambda *a: subprocess.run(["git", "-C", str(repo), "-c", "user.email=t@t", "-c", "user.name=t", *a],
                                  check=True, capture_output=True, text=True).stdout.strip()
    g("init", "-q"); g("add", "."); g("commit", "-qm", "base")
    return repo, g("rev-parse", "HEAD")


def test_commit_guard_accepts_one_commit_inside_the_package_dir(tmp_path: Path):
    import subprocess
    from tools.trace_cli.pr import _commit_is_only_the_patch
    repo, rev = _git_repo_with_base(tmp_path)
    (repo / "pkgs/by-name/ma/mailpit/CVE-1.patch").write_text("p\n")
    (repo / "pkgs/by-name/ma/mailpit/package.nix").write_text("{ patches = [ ./CVE-1.patch ]; }\n")
    subprocess.run(["git", "-C", str(repo), "-c", "user.email=t@t", "-c", "user.name=t", "add", "."], check=True)
    subprocess.run(["git", "-C", str(repo), "-c", "user.email=t@t", "-c", "user.name=t", "commit", "-qm", "fix"], check=True)
    ok, why = _commit_is_only_the_patch(repo, rev, "pkgs/by-name/ma/mailpit")
    assert ok, why


def test_commit_guard_refuses_files_outside_the_package_dir(tmp_path: Path):
    import subprocess
    from tools.trace_cli.pr import _commit_is_only_the_patch
    repo, rev = _git_repo_with_base(tmp_path)
    (repo / "pkgs/other.nix").write_text("changed\n")
    subprocess.run(["git", "-C", str(repo), "-c", "user.email=t@t", "-c", "user.name=t", "commit", "-qam", "oops"], check=True)
    ok, why = _commit_is_only_the_patch(repo, rev, "pkgs/by-name/ma/mailpit")
    assert not ok and "pkgs/other.nix" in why


def test_commit_guard_refuses_a_branch_not_cut_from_the_pinned_rev(tmp_path: Path):
    import subprocess
    from tools.trace_cli.pr import _commit_is_only_the_patch
    repo, rev = _git_repo_with_base(tmp_path)
    g = lambda *a: subprocess.run(["git", "-C", str(repo), "-c", "user.email=t@t", "-c", "user.name=t", *a], check=True, capture_output=True)
    (repo / "pkgs/by-name/ma/mailpit/a").write_text("a\n"); g("add", "."); g("commit", "-qm", "one")
    (repo / "pkgs/by-name/ma/mailpit/b").write_text("b\n"); g("add", "."); g("commit", "-qm", "two")
    ok, why = _commit_is_only_the_patch(repo, rev, "pkgs/by-name/ma/mailpit")
    assert not ok and "pinned" in why


def test_shallow_clone_adds_no_anchor_commit():
    """Every fork PR used to show two commits: an empty anchor the clone step
    added, then the patch. The guard requires the patch's parent to be the
    pinned revision, so the clone must leave HEAD exactly there."""
    from tools.trace_cli.pr import _shallow_clone
    seen = []
    with mock.patch("subprocess.run", side_effect=lambda cmd, **kw: (seen.append(cmd), mock.Mock(returncode=0, stdout="", stderr=""))[1]):
        assert _shallow_clone("https://x/y.git", "c" * 40, Path("/tmp/dest")) == 0
    assert not any("commit" in cmd for cmd in seen)
    assert any("FETCH_HEAD" in cmd for cmd in seen)


def test_commit_guard_uses_the_plan_files_in_repo_root_mode(tmp_path: Path):
    """A remap plan applies at the repository root with an empty package dir. The
    guard then compares against the plan's own file list instead of a prefix."""
    import subprocess
    from tools.trace_cli.pr import _commit_is_only_the_patch
    repo, rev = _git_repo_with_base(tmp_path)
    (repo / "pkgs/by-name/ma/mailpit/package.nix").write_text("{ changed = true; }\n")
    subprocess.run(["git", "-C", str(repo), "-c", "user.email=t@t", "-c", "user.name=t", "commit", "-qam", "fix"], check=True)
    ok, why = _commit_is_only_the_patch(repo, rev, "", allowed_files=["pkgs/by-name/ma/mailpit/package.nix"])
    assert ok, why
    ok, why = _commit_is_only_the_patch(repo, rev, "", allowed_files=["pkgs/by-name/ma/mailpit/other.nix"])
    assert not ok


def test_commit_guard_requires_exact_revision_equality(tmp_path: Path):
    """A prefix match let an empty or truncated nixpkgs_rev pass; the pin is a
    full 40-character revision or the guard refuses."""
    import subprocess
    from tools.trace_cli.pr import _commit_is_only_the_patch
    repo, rev = _git_repo_with_base(tmp_path)
    (repo / "pkgs/by-name/ma/mailpit/package.nix").write_text("{ changed = true; }\n")
    subprocess.run(["git", "-C", str(repo), "-c", "user.email=t@t", "-c", "user.name=t", "commit", "-qam", "fix"], check=True)
    assert _commit_is_only_the_patch(repo, rev, "pkgs/by-name/ma/mailpit")[0]
    assert not _commit_is_only_the_patch(repo, rev[:12], "pkgs/by-name/ma/mailpit")[0]
    assert not _commit_is_only_the_patch(repo, "", "pkgs/by-name/ma/mailpit")[0]


def test_run_rejects_a_malformed_nixpkgs_rev(tmp_path: Path, capsys) -> None:
    from tools.trace_cli.pr import _validate_nixpkgs_rev
    assert _validate_nixpkgs_rev("c" * 40) is None
    assert "40" in _validate_nixpkgs_rev("c" * 12)
    assert "40" in _validate_nixpkgs_rev("")
    assert "40" in _validate_nixpkgs_rev("Z" * 40)
