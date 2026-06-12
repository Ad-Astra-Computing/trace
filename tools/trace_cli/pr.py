"""`trace pr`: apply a cert-green bundle's patch.diff to the nixpkgs fork
and open a pull request with embedded OPA cert evidence.

Reads `policy/nixpkgs-fork.json` for the fork target, branch convention,
and PR title format. Never writes to upstream NixOS/nixpkgs — that is a
deliberate trust-boundary policy (see the policy file's `trust_boundary`
block and docs/DECISIONS.md 2026-05-29).

MVP scope:
  * auto-merge bundles only (kind=auto-merge, signed_manifest.rekor_log_index
    present)
  * patch applied via `git apply --check` (dry-run gate) then `git apply`
  * nixpkgs clone via `git fetch --depth=1` at nixpkgs_rev, or a pre-cloned
    checkout supplied via --nixpkgs-checkout
  * PR body built from `pr_snippet` Markdown block + cert summary
  * GitHub auth via `gh` CLI ambient token (no custom env var)

Phase 4 hardening (deferred):
  * sandboxed patch apply (nix shell / container isolation)
  * direct upstream NixOS/nixpkgs PR (separate trust-policy amendment needed)
  * automatic PR labels via GitHub API
"""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any
from urllib.parse import urlparse


POLICY_PATH_DEFAULT = "policy/nixpkgs-fork.json"

EXIT_OK = 0
EXIT_USAGE = 2
EXIT_INVALID = 4
EXIT_GIT_FAIL = 6
EXIT_GH_FAIL = 7


def add_parser(subs: argparse._SubParsersAction) -> argparse.ArgumentParser:
    p = subs.add_parser(
        "pr",
        help=(
            "apply a cert-green bundle's patch.diff to the nixpkgs fork "
            "and open a GitHub PR with embedded OPA cert evidence"
        ),
        description=(
            "Validates the bundle (auto-merge + cosign-signed), applies "
            "patch.diff to the fork's nixpkgs_rev via `git apply --check` "
            "then a real apply, pushes the branch, and creates a GitHub PR "
            "via `gh pr create`. "
            "Never writes to upstream NixOS/nixpkgs."
        ),
    )
    p.add_argument(
        "bundle_dir",
        type=Path,
        help="path to the cert-green auto-merge bundle directory",
    )
    p.add_argument(
        "--nixpkgs-checkout",
        type=Path,
        default=None,
        help=(
            "path to a pre-cloned nixpkgs fork checkout. When omitted, a "
            "shallow clone of the fork is fetched into a temporary directory "
            "at the bundle's pinned nixpkgs_rev."
        ),
    )
    p.add_argument(
        "--fork",
        default=None,
        help=(
            "fork to push the branch to, in owner/repo form "
            "(e.g. Ad-Astra-Computing/nixpkgs). Defaults to the value in "
            "policy/nixpkgs-fork.json. TRACE_NIXPKGS_FORK env var also accepted."
        ),
    )
    p.add_argument(
        "--base",
        default=None,
        help=(
            "base branch of the fork to target (default: policy's "
            "fork.default_branch, typically master)."
        ),
    )
    p.add_argument(
        "--push-url",
        default=None,
        help=(
            "explicit git remote URL for the push (e.g. an https URL when "
            "your token has `workflow` scope). Defaults to the policy fork's "
            "ssh_url — SSH avoids the PAT workflow-scope restriction that "
            "blocks pushing a branch carrying nixpkgs's own workflow files."
        ),
    )
    p.add_argument(
        "--cert-run-url",
        default=None,
        help=(
            "GitHub Actions cert-run URL to embed in the PR body as evidence "
            "(e.g. https://github.com/…/actions/runs/123). Optional."
        ),
    )
    p.add_argument(
        "--dry-run",
        action="store_true",
        help=(
            "validate the patch with git apply --check, print the plan, "
            "then exit without creating a branch or PR."
        ),
    )
    p.add_argument(
        "--policy",
        type=Path,
        default=None,
        help="override path to nixpkgs-fork.json (default: policy/nixpkgs-fork.json)",
    )
    p.add_argument(
        "--review",
        action="store_true",
        help=(
            "REVIEW-PR mode for cert-green source-backport bundles "
            "(kind=human-review-required, kind_reason=source-backport-experimental). "
            "Opens a DRAFT PR for a maintainer to review + merge — never auto-merges. "
            "Keeps the full provenance gate (cosign+rekor signature required, same as "
            "auto-merge: the PR cites the bundle as evidence, so it must be "
            "independently verifiable). Defaults to dry-run; pass --execute to open. "
            "Fork-target only."
        ),
    )
    p.add_argument(
        "--execute",
        action="store_true",
        help=(
            "in --review mode, actually push the branch + open the draft PR "
            "(outward-facing). Without it, --review prints the PR it WOULD open and "
            "exits. Ignored outside --review mode."
        ),
    )
    return p


def run(args: argparse.Namespace) -> int:
    bundle_dir: Path = args.bundle_dir.resolve()

    # ── 1. load + validate bundle ──────────────────────────────────────────
    bundle, err = _load_bundle(bundle_dir)
    if err:
        print(f"error: {err}", file=sys.stderr)
        return EXIT_INVALID

    cve_id = bundle["cve_id"]
    bundle_id = bundle["bundle_id"]
    nixpkgs_rev = bundle["nixpkgs_rev"]
    kind = bundle["kind"]
    kind_reason = bundle.get("kind_reason")
    sm = bundle.get("signed_manifest", {})
    review_mode = bool(getattr(args, "review", False))

    if review_mode:
        # Review-PR mode: cert-green SOURCE-BACKPORT bundles only. The PR is the
        # human-review surface — a maintainer reviews + merges; trace never
        # auto-merges these. The ONLY thing relaxed vs auto-merge is who has merge
        # authority; the provenance gate (signature + cert evidence) is kept in
        # full (peer review 2026-06-12: the PR cites the bundle as evidence, so an
        # unsigned bundle would be a forgeable, independently-unverifiable claim).
        if kind != "human-review-required" or kind_reason != "source-backport-experimental":
            print(
                f"error: --review operates only on human-review-required "
                f"source-backport-experimental bundles; got kind={kind!r}, "
                f"kind_reason={kind_reason!r}.",
                file=sys.stderr,
            )
            return EXIT_INVALID
        if "build.json" not in bundle.get("files", {}):
            print(
                "error: --review requires a cert-green bundle (build.json absent); "
                "the draft PR vouches for the reproducer red→green.",
                file=sys.stderr,
            )
            return EXIT_INVALID
    elif kind != "auto-merge":
        print(
            f"error: bundle kind is {kind!r}; `trace pr` only operates on "
            f"auto-merge bundles. For source-backports use `--review` (opens a "
            f"draft PR for a maintainer); other kinds need a human reviewer first.",
            file=sys.stderr,
        )
        return EXIT_INVALID

    # Provenance gate — KEPT for both modes (no-downgrade): the public PR anchors
    # on the Rekor transparency entry for independent verification.
    if sm.get("signer") == "ci-pending" or sm.get("rekor_log_index") is None:
        print(
            "error: bundle is not cosign-signed (signer=ci-pending or "
            "rekor_log_index absent). Run the bundle through steward.yml "
            "first; trace pr anchors on the Rekor transparency entry.",
            file=sys.stderr,
        )
        return EXIT_INVALID

    patch_diff_path = bundle_dir / "patch.diff"
    if not patch_diff_path.is_file():
        print(
            f"error: patch.diff not found in {bundle_dir}",
            file=sys.stderr,
        )
        return EXIT_INVALID

    # ── 2. load resolver-input.json for attr_path ──────────────────────────
    attr_path, err = _load_attr(bundle_dir)
    if err:
        print(f"error: {err}", file=sys.stderr)
        return EXIT_INVALID

    # ── 3. load upstream-ref.json for target_version ───────────────────────
    target_version = _load_target_version(bundle_dir)

    # ── 4. resolve fork policy ─────────────────────────────────────────────
    policy, err = _load_policy(args)
    if err:
        print(f"error: {err}", file=sys.stderr)
        return EXIT_INVALID

    fork_owner = policy["fork"]["owner"]
    fork_repo = policy["fork"]["repo"]
    fork_url = policy["fork"]["url"]
    # Push over SSH by default: a branch based on the bundle's frozen
    # nixpkgs_rev carries nixpkgs's own .github/workflows/ files, and a
    # GitHub PAT can't push those without `workflow` scope. SSH keys carry
    # no such restriction and are the project's established auth path.
    # Clone stays https (read-only); gh handles PR creation by owner/repo.
    push_url = policy["fork"].get("ssh_url") or fork_url
    base_branch = args.base or policy["pr_convention"]["base_branch"]

    # --fork CLI flag / TRACE_NIXPKGS_FORK env override
    fork_override = args.fork or os.environ.get("TRACE_NIXPKGS_FORK")
    if fork_override:
        parts = fork_override.split("/", 1)
        if len(parts) != 2 or not all(parts):
            print(
                f"error: --fork must be in owner/repo form, got {fork_override!r}",
                file=sys.stderr,
            )
            return EXIT_USAGE
        override_owner, override_repo = parts
        # Trust boundary (policy/nixpkgs-fork.json trust_boundary.never_writes_to):
        # trace must NEVER push a branch or open a PR against the upstream repo.
        # The override is a testing convenience, not an escape hatch around the
        # fork-only contract. Reject the policy's declared upstream explicitly.
        upstream = policy["fork"].get("upstream", {})
        upstream_owner = upstream.get("owner", "")
        upstream_repo = upstream.get("repo", "")
        if (
            override_owner.lower() == upstream_owner.lower()
            and override_repo.lower() == upstream_repo.lower()
        ):
            print(
                f"error: --fork / TRACE_NIXPKGS_FORK={fork_override!r} targets the "
                f"upstream repo {upstream_owner}/{upstream_repo}, which violates the "
                f"fork-only trust boundary (policy/nixpkgs-fork.json "
                f"trust_boundary.never_writes_to). trace opens PRs against the fork "
                f"only; upstream submission is a separate human-driven step.",
                file=sys.stderr,
            )
            return EXIT_INVALID
        fork_owner, fork_repo = override_owner, override_repo
        fork_url = f"https://github.com/{fork_owner}/{fork_repo}"
        push_url = f"git@github.com:{fork_owner}/{fork_repo}.git"

    # Explicit --push-url wins over the derived SSH form (e.g. an https push
    # in an environment whose token carries `workflow` scope).
    if getattr(args, "push_url", None):
        # Trust boundary: --push-url is an alternate-transport handle for the
        # configured fork, never a destination override. Fail-closed allowlist
        # (see _validate_push_url_override): only https://github.com/<fork>
        # passes, so upstream, mirrors, and bare aliases like `origin` are all
        # rejected without a URL-canonicalization arms race.
        # Validate and push the byte-identical string (strip surrounding
        # whitespace once here) so the allowlist can't accept one string while
        # git pushes another.
        candidate = args.push_url.strip()
        reason = _validate_push_url_override(candidate, fork_owner, fork_repo)
        if reason:
            print(
                f"error: --push-url={args.push_url!r} {reason}. It only swaps "
                f"transport/auth for the configured fork — the fork-only trust "
                f"boundary (policy/nixpkgs-fork.json trust_boundary) forbids "
                f"pushing anywhere else.",
                file=sys.stderr,
            )
            return EXIT_INVALID
        push_url = candidate

    # ── 5. derive branch + PR title ────────────────────────────────────────
    branch_fmt = policy["patch_branch_convention"]["format"]
    attr_safe = attr_path.replace("/", "_")
    branch = branch_fmt.format(
        cve_id=cve_id,
        attr_path=attr_safe,
        bundle_id_short=bundle_id,
    )

    title_fmt = policy["pr_convention"]["title_format"]
    pr_title = title_fmt.format(
        cve_id=cve_id,
        attr_path=attr_path,
        target_version=target_version or "unknown",
    )

    # ── 6. set up nixpkgs checkout ─────────────────────────────────────────
    if args.nixpkgs_checkout:
        nixpkgs_dir = args.nixpkgs_checkout.resolve()
        if not nixpkgs_dir.is_dir():
            print(
                f"error: --nixpkgs-checkout {nixpkgs_dir} does not exist",
                file=sys.stderr,
            )
            return EXIT_INVALID
        owned_tmp = None
    else:
        owned_tmp = tempfile.mkdtemp(prefix="trace-pr-nixpkgs-")
        nixpkgs_dir = Path(owned_tmp)
        rc = _shallow_clone(fork_url, nixpkgs_rev, nixpkgs_dir)
        if rc != 0:
            print(
                f"error: failed to clone {fork_url} at rev {nixpkgs_rev[:12]}",
                file=sys.stderr,
            )
            _cleanup(owned_tmp)
            return EXIT_GIT_FAIL

    # ── 7. resolve attr package directory ──────────────────────────────────
    package_dir_rel = _resolve_attr_package_dir(nixpkgs_dir, attr_path)
    if package_dir_rel is None:
        print(
            f"error: could not resolve package directory for attr={attr_path!r} "
            f"inside nixpkgs checkout {nixpkgs_dir}. Expected "
            f"pkgs/by-name/{attr_path[:2].lower()}/{attr_path}/package.nix",
            file=sys.stderr,
        )
        _cleanup(owned_tmp)
        return EXIT_INVALID

    # ── 8. validate patch (git apply --check) ──────────────────────────────
    check_rc = _git_apply_check(nixpkgs_dir, package_dir_rel, patch_diff_path)
    if check_rc != 0:
        print(
            f"error: git apply --check failed (exit {check_rc}). "
            f"The patch.diff may not apply cleanly to nixpkgs_rev {nixpkgs_rev[:12]}. "
            f"Check that the nixpkgs checkout is at the correct revision.",
            file=sys.stderr,
        )
        _cleanup(owned_tmp)
        return EXIT_GIT_FAIL

    # Review mode is dry-run BY DEFAULT (outward-facing draft PR for an
    # experimental backport): require an explicit --execute to actually open it.
    effective_dry_run = args.dry_run or (review_mode and not getattr(args, "execute", False))
    if effective_dry_run:
        why = "--dry-run" if args.dry_run else "--review default (pass --execute to open)"
        print(f"[dry-run] mode:          {'review (draft PR)' if review_mode else 'auto-merge'}")
        print(f"[dry-run] bundle:        {cve_id} ({bundle_id})")
        print(f"[dry-run] fork:          {fork_owner}/{fork_repo}")
        print(f"[dry-run] base branch:   {base_branch}")
        print(f"[dry-run] branch:        {branch}")
        print(f"[dry-run] PR title:      {pr_title}")
        print(f"[dry-run] nixpkgs_rev:   {nixpkgs_rev}")
        print(f"[dry-run] package_dir:   {package_dir_rel}")
        print(f"[dry-run] patch check:   ok (git apply --check passed)")
        if review_mode:
            print(f"[dry-run] draft:         yes (maintainer reviews + merges)")
            print(f"[dry-run] --- PR body ---")
            print(_build_pr_body(bundle, bundle_dir, args.cert_run_url, review=True))
        print(f"[dry-run] stopping here ({why})")
        _cleanup(owned_tmp)
        return EXIT_OK

    # ── 9. create branch, apply, commit, push ──────────────────────────────
    commit_msg = f"{attr_path}: {target_version or 'update'} (fix {cve_id})"

    rc = _create_branch(nixpkgs_dir, branch)
    if rc != 0:
        print(f"error: failed to create branch {branch!r}", file=sys.stderr)
        _cleanup(owned_tmp)
        return EXIT_GIT_FAIL

    rc = _git_apply(nixpkgs_dir, package_dir_rel, patch_diff_path)
    if rc != 0:
        print(f"error: git apply failed after --check passed", file=sys.stderr)
        _cleanup(owned_tmp)
        return EXIT_GIT_FAIL

    # Format the modified .nix file(s) — nixpkgs runs nixfmt (treefmt) in CI, so an
    # unformatted edit gets bounced. The base files are nixfmt-clean, so this only
    # touches our edit's region (a clean, minimal diff). Best-effort: warns + proceeds
    # if nixfmt is unavailable (the PR would then fail treefmt CI, surfacing it).
    _nixfmt_modified(nixpkgs_dir, package_dir_rel, patch_diff_path.read_text())

    # Stage ALL changes in the package dir — INCLUDING new untracked files.
    # Source-backports add a new <CVE>.patch file (git apply leaves it untracked);
    # `git commit -a` would silently drop it, shipping a package.nix that
    # references a file not in the PR. Scope to the package dir so nothing else
    # in the tree is swept in.
    rc = _git_add(nixpkgs_dir, package_dir_rel)
    if rc != 0:
        print(f"error: git add failed", file=sys.stderr)
        _cleanup(owned_tmp)
        return EXIT_GIT_FAIL

    rc = _git_commit(nixpkgs_dir, commit_msg)
    if rc != 0:
        print(f"error: git commit failed", file=sys.stderr)
        _cleanup(owned_tmp)
        return EXIT_GIT_FAIL

    rc = _git_push(nixpkgs_dir, push_url, branch)
    if rc != 0:
        print(f"error: git push to {push_url} failed", file=sys.stderr)
        _cleanup(owned_tmp)
        return EXIT_GIT_FAIL

    # ── 10. create PR ──────────────────────────────────────────────────────
    pr_body = _build_pr_body(bundle, bundle_dir, args.cert_run_url, review=review_mode)
    pr_url, rc = _gh_pr_create(
        nixpkgs_dir=nixpkgs_dir,
        fork_owner=fork_owner,
        fork_repo=fork_repo,
        base_branch=base_branch,
        branch=branch,
        title=pr_title,
        body=pr_body,
        draft=review_mode,
    )
    _cleanup(owned_tmp)
    if rc != 0:
        print(f"error: gh pr create failed (exit {rc})", file=sys.stderr)
        return EXIT_GH_FAIL

    print(pr_url)
    return EXIT_OK


# ─── helpers ─────────────────────────────────────────────────────────────────


def _load_bundle(bundle_dir: Path) -> tuple[dict[str, Any] | None, str | None]:
    path = bundle_dir / "bundle.json"
    if not path.is_file():
        return None, f"bundle.json not found under {bundle_dir}"
    try:
        return json.loads(path.read_text()), None
    except json.JSONDecodeError as exc:
        return None, f"bundle.json is not valid JSON: {exc}"


def _load_attr(bundle_dir: Path) -> tuple[str, str | None]:
    path = bundle_dir / "resolver-input.json"
    if not path.is_file():
        return "", f"resolver-input.json not found under {bundle_dir}"
    try:
        data = json.loads(path.read_text())
    except json.JSONDecodeError as exc:
        return "", f"resolver-input.json is not valid JSON: {exc}"
    attr = data.get("attr_path") or ""
    if not attr:
        return "", "resolver-input.json missing attr_path"
    return attr, None


def _load_target_version(bundle_dir: Path) -> str | None:
    path = bundle_dir / "upstream-ref.json"
    if not path.is_file():
        return None
    try:
        data = json.loads(path.read_text())
        return data.get("target_version") or None
    except (json.JSONDecodeError, OSError):
        return None


def _load_policy(args: argparse.Namespace) -> tuple[dict[str, Any] | None, str | None]:
    if args.policy:
        policy_path = args.policy
    else:
        # resolve relative to repo root (two parents up from this file)
        repo_root = Path(__file__).resolve().parents[2]
        policy_path = repo_root / POLICY_PATH_DEFAULT
    if not policy_path.is_file():
        return None, f"nixpkgs-fork policy not found at {policy_path}"
    try:
        return json.loads(policy_path.read_text()), None
    except json.JSONDecodeError as exc:
        return None, f"nixpkgs-fork.json is not valid JSON: {exc}"


_ATTR_SAFE_RE = re.compile(r"^[a-zA-Z][a-zA-Z0-9_]*(\.[a-zA-Z][a-zA-Z0-9_]*)*$")


def _resolve_attr_package_dir(nixpkgs: Path, attr: str) -> str | None:
    """Return the path of the package directory for `attr` relative to
    `nixpkgs`.

    Tries in order:
      1. pkgs/by-name/<aa>/<attr>/package.nix  (modern convention)
      2. pkgs/by-name/<a>/<attr>/package.nix   (single-char dir)
      3. nix eval --raw --impure --expr ...     (nested sets: rubyPackages.*, etc.)

    The nix-eval fallback resolves meta.position for package sets that are
    not top-level nixpkgs flake outputs (e.g. rubyPackages.sinatra lives in
    pkgs/top-level/ruby-packages.nix, not in pkgs/by-name).
    """
    aa = attr[:2].lower()
    candidates = [
        Path("pkgs") / "by-name" / aa / attr,
        Path("pkgs") / "by-name" / attr[:1].lower() / attr,
    ]
    for rel in candidates:
        if (nixpkgs / rel / "package.nix").is_file():
            return str(rel).replace("\\", "/")

    # attr is the UNTRUSTED field (from the bundle / CVE feed). The regex
    # guards against nix-expression injection via a malformed attr_path.
    if not _ATTR_SAFE_RE.match(attr):
        return None

    nixpkgs_abs = str(nixpkgs.resolve())
    # nixpkgs_abs is TRUSTED operator/CI input (the checkout path), never
    # bundle-controlled — a bare path literal is acceptable below. Reject
    # newline/NUL defensively (keeps logs clean; NUL can't appear in a path).
    if "\n" in nixpkgs_abs or "\x00" in nixpkgs_abs:
        return None

    def _position_from_proc(proc: "subprocess.CompletedProcess[str]") -> str | None:
        if proc.returncode != 0:
            return None
        position = (proc.stdout or "").strip()
        file_path_str = position.rsplit(":", 1)[0]
        if not file_path_str:
            return None
        file_path = Path(file_path_str)
        try:
            rel = file_path.parent.relative_to(nixpkgs.resolve())
        except ValueError:
            return None
        return str(rel).replace("\\", "/")

    bare_expr = f"(import {nixpkgs_abs} {{}}).{attr}.meta.position"
    nixpkgs_json = json.dumps(nixpkgs_abs)
    quoted_expr = (
        f"(import (builtins.path {{ path = {nixpkgs_json}; name = \"nixpkgs\"; }}) "
        f"{{}}).{attr}.meta.position"
    )

    # nix-instantiate: classic interface (no nix-command feature flag needed).
    # Uses bare path literal — faster than builtins.path and works in both
    # local and CI environments.
    try:
        proc = subprocess.run(
            ["nix-instantiate", "--eval", "--raw", "--expr", bare_expr],
            check=False, capture_output=True, text=True, timeout=60,
        )
        result = _position_from_proc(proc)
        if result is not None:
            return result
    except (OSError, subprocess.SubprocessError):
        pass

    # nix eval --impure --expr: requires nix-command feature flag. Uses
    # builtins.path for correct quoting.
    try:
        proc = subprocess.run(
            ["nix", "eval", "--raw", "--impure", "--expr", quoted_expr],
            check=False, capture_output=True, text=True, timeout=60,
        )
        return _position_from_proc(proc)
    except (OSError, subprocess.SubprocessError):
        return None


def _shallow_clone(fork_url: str, rev: str, dest: Path) -> int:
    """Shallow-clone the fork at the exact nixpkgs_rev into dest."""
    cmds = [
        ["git", "init", "-q", str(dest)],
        ["git", "-C", str(dest), "remote", "add", "origin", fork_url],
        ["git", "-C", str(dest), "fetch", "--depth=1", "origin", rev],
        ["git", "-C", str(dest), "checkout", "-q", "FETCH_HEAD"],
        [
            "git", "-C", str(dest),
            "-c", "user.email=trace@adastracomputing.com",
            "-c", "user.name=trace",
            "commit", "--allow-empty", "-q", "-m", "trace-pr anchor",
        ],
    ]
    for cmd in cmds:
        r = subprocess.run(cmd, check=False, capture_output=True, text=True)
        if r.returncode != 0:
            print(
                f"  git step failed: {' '.join(cmd)}\n"
                f"  stderr: {r.stderr[:500]}",
                file=sys.stderr,
            )
            return r.returncode
    return 0


def _git_apply_check(nixpkgs: Path, package_dir: str, patch: Path) -> int:
    # --recount: same as the Builder (agents/builder/runner.py). Model-authored
    # patches — especially source-backports, whose new-file hunk embeds an
    # upstream diff — can carry an off-by-one `@@` line count while the +/-
    # content + context are correct. The Builder certs the patch with --recount,
    # so trace pr MUST apply it the same way or a cert-green bundle fails here.
    r = subprocess.run(
        ["git", "apply", "--recount", f"--directory={package_dir}", "--check", str(patch)],
        cwd=str(nixpkgs), check=False, capture_output=True, text=True,
    )
    if r.returncode != 0:
        print(
            f"  git apply --check stderr:\n  {r.stderr[:800]}",
            file=sys.stderr,
        )
    return r.returncode


def _create_branch(nixpkgs: Path, branch: str) -> int:
    r = subprocess.run(
        ["git", "checkout", "-b", branch],
        cwd=str(nixpkgs), check=False, capture_output=True, text=True,
    )
    return r.returncode


def _git_apply(nixpkgs: Path, package_dir: str, patch: Path) -> int:
    r = subprocess.run(
        ["git", "apply", "--recount", f"--directory={package_dir}", str(patch)],
        cwd=str(nixpkgs), check=False, capture_output=True, text=True,
    )
    if r.returncode != 0:
        print(f"  git apply stderr:\n  {r.stderr[:800]}", file=sys.stderr)
    return r.returncode


def _find_nixfmt() -> list[str] | None:
    """Locate nixfmt (the nixpkgs treefmt formatter). Prefer it on PATH; fall
    back to `nix run nixpkgs#nixfmt-rfc-style` when nix is available."""
    import shutil
    p = shutil.which("nixfmt")
    if p:
        return [p]
    if shutil.which("nix"):
        return ["nix", "run", "nixpkgs#nixfmt-rfc-style", "--"]
    return None


def _nixfmt_modified(nixpkgs: Path, package_dir: str, patch_text: str) -> int:
    """Run nixfmt on the .nix file(s) the patch modifies. Best-effort: a missing
    nixfmt warns + proceeds rather than blocking the PR."""
    nixfmt = _find_nixfmt()
    if nixfmt is None:
        print("  warning: nixfmt not found; skipping formatting — the PR may fail "
              "nixpkgs treefmt CI. Install nixfmt-rfc-style.", file=sys.stderr)
        return 0
    nix_files = {
        ln[6:].strip() for ln in patch_text.splitlines()
        if ln.startswith("+++ b/") and ln[6:].strip().endswith(".nix")
    }
    for nf in sorted(nix_files):
        target = nixpkgs / package_dir / nf
        if not target.is_file():
            continue
        r = subprocess.run([*nixfmt, str(target)], capture_output=True, text=True)
        if r.returncode != 0:
            print(f"  warning: nixfmt {nf} failed ({r.stderr[:200]}); proceeding unformatted",
                  file=sys.stderr)
    return 0


def _git_add(nixpkgs: Path, package_dir: str) -> int:
    """Stage all changes (incl. new files) under the package dir. `-A -- <dir>`
    keeps the staging scoped so an unrelated dirty tree can't leak into the PR."""
    r = subprocess.run(
        ["git", "add", "-A", "--", package_dir],
        cwd=str(nixpkgs), check=False, capture_output=True, text=True,
    )
    if r.returncode != 0:
        print(f"  git add stderr:\n  {r.stderr[:800]}", file=sys.stderr)
    return r.returncode


def _git_commit(nixpkgs: Path, message: str) -> int:
    # `commit -m` (NOT `-a`): the staging is done explicitly by _git_add so new
    # files (the authored <CVE>.patch) are included.
    r = subprocess.run(
        [
            "git",
            "-c", "user.email=trace@adastracomputing.com",
            "-c", "user.name=trace",
            "commit", "-m", message,
        ],
        cwd=str(nixpkgs), check=False, capture_output=True, text=True,
    )
    if r.returncode != 0:
        print(f"  git commit stderr:\n  {r.stderr[:800]}", file=sys.stderr)
    return r.returncode


def _validate_push_url_override(
    url: str, fork_owner: str, fork_repo: str
) -> str | None:
    """Validate an operator-supplied --push-url against the fork-only trust
    boundary. Returns None if the URL is an acceptable alternate-transport
    handle for the *configured fork*, else a short reason string.

    --push-url only swaps transport/auth (e.g. https when the token carries
    `workflow` scope) for the same fork; it is NOT a destination override.
    So this is a fail-closed allowlist — the only accepted shape is a plain
    `https://github.com/<fork_owner>/<fork_repo>(.git)`. Everything else
    (upstream, mirrors, bare aliases like `origin`, ssh/scp forms, embedded
    credentials, ports, query strings, fragments, extra path segments,
    non-GitHub hosts) is rejected. We reject — never strip — query/fragment/
    userinfo so the string we validate is byte-for-byte the string we push;
    silently normalizing is exactly how canonicalization bypasses arise. The
    caller passes the exact string it will push (see run()).
    """
    parsed = urlparse(url)
    if parsed.scheme != "https":
        return "must be an https:// URL (the override only swaps transport)"
    if parsed.username or parsed.password:
        return "must not embed credentials; use a git credential helper"
    if parsed.query or parsed.fragment or parsed.params:
        return "must not contain a query string, fragment, or path parameters"
    # .hostname is lowercased + strips any userinfo; .port raises on garbage.
    try:
        port = parsed.port
    except ValueError:
        return "has an invalid port"
    if port is not None:
        return "must not specify a port"
    if (parsed.hostname or "") != "github.com":
        return "host must be github.com"
    segs = [p for p in parsed.path.split("/") if p]
    if len(segs) != 2:
        return "path must be exactly /<owner>/<repo>"
    owner, repo = segs[0], segs[1]
    if repo.endswith(".git"):
        repo = repo[:-4]
    if (owner.lower(), repo.lower()) != (fork_owner.lower(), fork_repo.lower()):
        return f"must target the configured fork {fork_owner}/{fork_repo}"
    return None


def _git_push(nixpkgs: Path, fork_url: str, branch: str) -> int:
    r = subprocess.run(
        ["git", "push", fork_url, f"{branch}:{branch}"],
        cwd=str(nixpkgs), check=False, capture_output=True, text=True,
    )
    if r.returncode != 0:
        print(f"  git push stderr:\n  {r.stderr[:800]}", file=sys.stderr)
    return r.returncode


def _gh_pr_create(
    *,
    nixpkgs_dir: Path,
    fork_owner: str,
    fork_repo: str,
    base_branch: str,
    branch: str,
    title: str,
    body: str,
    draft: bool = False,
) -> tuple[str, int]:
    """Create a PR in the fork via gh CLI. Returns (pr_url, exit_code)."""
    cmd = [
        "gh", "pr", "create",
        "--repo", f"{fork_owner}/{fork_repo}",
        "--base", base_branch,
        "--head", branch,
        "--title", title,
        "--body", body,
    ]
    if draft:
        cmd.append("--draft")  # maintainer must explicitly mark Ready-for-review
    r = subprocess.run(
        cmd,
        cwd=str(nixpkgs_dir),
        check=False, capture_output=True, text=True,
    )
    if r.returncode != 0:
        print(f"  gh pr create stderr:\n  {r.stderr[:800]}", file=sys.stderr)
        return "", r.returncode
    return (r.stdout or "").strip(), 0


def _build_pr_body(
    bundle: dict[str, Any],
    bundle_dir: Path,
    cert_run_url: str | None,
    review: bool = False,
) -> str:
    """Build the PR body from pr-snippet evidence block + cert summary. In
    review mode, prepend a BLOCKING necessary-but-not-sufficient checklist the
    maintainer must tick before marking the draft Ready-for-review."""
    from tools.trace_cli import pr_snippet as _pr_snippet

    sm = bundle.get("signed_manifest", {})
    log_index = sm.get("rekor_log_index")
    rekor_url = (
        f"{_pr_snippet.REKOR_PUBLIC_LOG_URL}"
        f"/api/v1/log/entries?logIndex={log_index}"
        if log_index else None
    )
    cve_id = bundle.get("cve_id", "?")
    kind = bundle.get("kind", "?")
    bundle_id = bundle.get("bundle_id", "?")
    nixpkgs_rev = bundle.get("nixpkgs_rev", "?")
    identity_subject = sm.get("identity_subject", "")
    identity_issuer = sm.get("identity_issuer", "")
    verify_cmd = f"trace bundle verify ./artifact  # bundle_id={bundle_id}"

    lines: list[str] = []
    if review:
        # The one failure mode the apply-gate can't catch by construction: a
        # clean-applying backport that is NECESSARY BUT NOT SUFFICIENT (one of
        # several required commits). The maintainer must confirm sufficiency.
        fix_commits = []
        try:
            ur = json.loads((bundle_dir / "upstream-ref.json").read_text())
            fix_commits = ur.get("upstream_fix_commits") or []
        except Exception:
            pass
        fix_links = "\n".join(
            f"  - {c.get('repo_url','')}/commit/{c.get('commit_sha','')}"
            for c in fix_commits
        ) or "  - (see upstream-ref.json)"
        lines += [
            "## ⚠️ EXPERIMENTAL source-backport — NOT a version bump",
            "",
            "This PR **authors the upstream fix as an in-tree patch** against the "
            "current nixpkgs version (no version bump). An agent generated it; a "
            "cross-family reviewer verified it transcribes the upstream commit, and "
            "a cert proved the bundled reproducer goes red→green. **A human "
            "maintainer must still confirm sufficiency before merging:**",
            "",
            "- [ ] This applies the **COMPLETE** upstream fix, not one of several "
            "required commits.",
            "- [ ] The backported hunk matches the upstream fix commit(s):",
            fix_links,
            f"- [ ] Reviewed the cert evidence (reproducer red→green) for {cve_id}.",
            "",
            "_Opened as a **draft** deliberately — mark Ready-for-review only after "
            "the boxes above are checked._",
            "",
            "---",
            "",
        ]

    lines += [
        f"**Evidence:** {cve_id} ({kind}) trace bundle `{bundle_id}`",
        "",
    ]

    if rekor_url:
        lines += [
            f"* **Rekor entry:** {rekor_url}",
            f"* **Workflow identity:** `{identity_subject}`",
            f"* **OIDC issuer:** `{identity_issuer}`",
        ]
    if cert_run_url:
        lines.append(f"* **Cert run:** {cert_run_url}")
    lines += [
        f"* **nixpkgs rev:** `{nixpkgs_rev}`",
        "",
        "<details><summary>Verify locally</summary>",
        "",
        "```sh",
        f"gh run download <run-id> --name steward-smoke-<bundle> --dir ./artifact",
        verify_cmd,
        "```",
        "",
        "</details>",
        "",
        "_Generated by [trace](https://github.com/Ad-Astra-Computing/trace)._",
    ]
    return "\n".join(lines)


def _cleanup(tmp_dir: str | None) -> None:
    if tmp_dir is None:
        return
    import shutil
    try:
        shutil.rmtree(tmp_dir, ignore_errors=True)
    except Exception:
        pass
