"""Stage a bundle's resolver-side inputs from one screened candidate.

`eval/beat_upstream_screen.py` writes an inbox entry per CVE. Everything between
that entry and `bundle assemble` is mechanical: copy the pinned `package.nix`,
fetch the upstream fix commit as a patch, write the two placeholder documents and
tag the candidate ref as a source backport. This does that and nothing else.

It deliberately stops before the Patcher, the pinned-source fetch and preflight,
so the no-spend gates stay something an operator runs on purpose.

See docs/specs/candidate-bootstrap.md.
"""
from __future__ import annotations

import json
import re
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

_IMPACT_REASON = (
    "reverse-closure analysis was not run for this bundle. The counts here are "
    "placeholders and carry no evidentiary weight; the routing policy sends an "
    "unanalyzed impact to human review, which is the correct disposition for an "
    "experimental source backport."
)

# github.com and codeberg.org share the Gitea-style /commit/<sha>; gitlab.com puts
# a /-/ in the way. Each serves the commit as a patch with a .patch suffix.
_GITLAB_HOSTS = ("gitlab.com",)


class BootstrapError(Exception):
    """The candidate cannot be staged, with the cause named."""


@dataclass(frozen=True)
class BootstrapResult:
    out_dir: Path
    cve_id: str
    attr_path: str
    package_nix_path: str
    fix_commit_url: str


def package_nix_path_for_attr(attr_path: str) -> str | None:
    """Repository-relative path of a by-name package, or None when it is not one.

    A package-set member such as `python3Packages.foo` does not live under
    `pkgs/by-name`, and a one-character name has no two-letter shard, so both
    return None rather than a wrong guess.
    """
    if "." in attr_path or len(attr_path) < 2 or not re.fullmatch(r"[A-Za-z0-9_-]+", attr_path):
        return None
    return f"pkgs/by-name/{attr_path[:2].lower()}/{attr_path}/package.nix"


_DRV_PATH_RE = re.compile(r"/nix/store/[a-z0-9]{32}-.+\.drv")

_VERSION_RE = re.compile(r'^\s*version\s*=\s*"([^"]+)"\s*;', re.MULTILINE)


def _declared_versions(package_nix: str) -> list[str]:
    """Every literal version a package file declares. A multivariant file such as
    libxml2's declares one per variant (2.13.9 for libxml2_13, 2.15.3 for libxml2),
    so the check asks whether the candidate's version is among them."""
    return _VERSION_RE.findall(package_nix)


def _declared_version(package_nix: str) -> str | None:
    """The first literal version a package file declares, or None when it computes one."""
    found = _declared_versions(package_nix)
    return found[0] if found else None

def commit_patch_url(repo_url: str, commit_sha: str) -> str:
    repo = repo_url.rstrip("/")
    host = repo.split("//", 1)[-1].split("/", 1)[0].lower()
    infix = "/-/commit/" if host in _GITLAB_HOSTS else "/commit/"
    return f"{repo}{infix}{commit_sha}.patch"


def read_pinned_file(checkout: Path, rev: str, path: str) -> str:
    """The file's bytes at the pinned revision, not the working tree's copy."""
    proc = subprocess.run(
        ["git", "-C", str(checkout), "show", f"{rev}:{path}"],
        capture_output=True, text=True,
    )
    if proc.returncode != 0:
        raise BootstrapError(
            f"cannot read {path} at {rev[:12]} in {checkout}: {proc.stderr.strip()[:200]}"
        )
    return proc.stdout


def fetch_patch(url: str) -> str:
    import urllib.request

    try:
        with urllib.request.urlopen(url, timeout=60) as fh:
            return fh.read().decode("utf-8", errors="replace")
    except Exception as e:  # noqa: BLE001 - the URL is the useful part of the message
        raise BootstrapError(f"cannot fetch {url}: {e}") from e


def bootstrap_candidate(
    *,
    entry_dir: Path,
    out_dir: Path,
    nixpkgs_checkout: Path,
    nixpkgs_rev: str,
    package_path: str | None = None,
    force: bool = False,
    allow_version_drift: bool = False,
    read_pinned_file: Callable[[Path, str, str], str] = read_pinned_file,
    fetch_patch: Callable[[str], str] = fetch_patch,
) -> BootstrapResult:
    ri_path = entry_dir / "resolver-input.json"
    if not ri_path.is_file():
        raise BootstrapError(f"{entry_dir} has no resolver-input.json; is it a screen inbox entry?")
    resolver_input = json.loads(ri_path.read_text())

    cve_id = resolver_input.get("cve_id") or entry_dir.name
    attr_path = resolver_input.get("attr_path") or ""
    if not attr_path:
        raise BootstrapError(f"{cve_id}: resolver-input.json names no attr_path")

    refs = resolver_input.get("candidate_refs") or []
    ref = next((r for r in refs if r.get("upstream_fix_commits")), None)
    if ref is None:
        raise BootstrapError(
            f"{cve_id}: no candidate ref carries a fix commit, so there is nothing to backport"
        )
    commit = ref["upstream_fix_commits"][0]
    patch_url = commit_patch_url(commit.get("repo_url", ""), commit.get("commit_sha", ""))

    rel_path = package_path or package_nix_path_for_attr(attr_path)
    if not rel_path:
        raise BootstrapError(
            f"{cve_id}: cannot derive a package.nix path for attr {attr_path!r}; pass --package-path"
        )

    if out_dir.exists() and any(out_dir.iterdir()) and not force:
        raise BootstrapError(f"{out_dir} already exists and is not empty; pass --force to overwrite")

    package_nix = read_pinned_file(nixpkgs_checkout, nixpkgs_rev, rel_path)

    # The screen reads its own snapshot of nixpkgs; the pinned revision comes from
    # the operator. When they disagree the bundle is built against the wrong base,
    # which preflight only catches later, after the source has been fetched.
    pinned = _declared_versions(package_nix)
    candidate_version = resolver_input.get("current_version") or ""
    if pinned and candidate_version and candidate_version not in pinned and not allow_version_drift:
        raise BootstrapError(
            f"{cve_id}: the candidate names version {candidate_version} but {rel_path} at "
            f"{nixpkgs_rev[:12]} declares {', '.join(pinned)}. Pin the revision the screen ran against, "
            f"or pass --allow-version-drift if the difference is understood."
        )

    patch_text = fetch_patch(patch_url)

    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "package.nix").write_text(package_nix)
    (out_dir / "upstream-fix.patch").write_text(patch_text)

    finding_src = entry_dir / "finding.json"
    if finding_src.is_file():
        finding = json.loads(finding_src.read_text())
        for affected in finding.get("affected") or []:
            if not _DRV_PATH_RE.fullmatch(str(affected.get("drv_path") or "")):
                pname = affected.get("pname") or affected.get("attr_path", "pkg").split(".")[-1]
                affected["drv_path"] = f"/nix/store/{'0' * 32}-{pname}.drv"
        (out_dir / "finding.json").write_text(json.dumps(finding, indent=2) + "\n")

    staged_ref = dict(ref)
    staged_ref["tier_hint"] = "source-backport"
    staged_ref.setdefault("requires_review_reason", "placeholder-target-version")
    # The resolver requires these; the screen's ref does not always carry them.
    # Both point at the upstream repository and the fix commit, which is all the
    # provenance there is for a fix that has not been released.
    commit_url = patch_url[: -len(".patch")]
    staged_ref.setdefault("release_url", commit.get("repo_url", ""))
    staged_ref.setdefault("changelog_url", commit_url)
    staged_ref.setdefault("advisory_urls", [commit_url])
    staged_ref.setdefault("version", resolver_input.get("current_version", ""))
    staged_ref.setdefault("delta", {
        "transitive_package_changes": 0,
        "new_direct_deps": [],
        "removed_direct_deps": [],
        "crosses_large_delta_threshold": False,
        "threshold_policy": "v0-default",
    })
    staged_input = dict(resolver_input)
    staged_input["candidate_refs"] = [staged_ref]
    (out_dir / "resolver-input.json").write_text(json.dumps(staged_input, indent=2) + "\n")

    drv = f"/nix/store/{'0' * 32}-{attr_path.split('.')[-1]}.drv"
    impact = {
        "schema_version": "1.0.0",
        "cve_id": cve_id,
        "nixpkgs_rev": nixpkgs_rev,
        "blast_radius_threshold": 500,
        "threshold_policy": "v0-default",
        "affected_attr_paths": [attr_path],
        "reverse_closure_count": 0,
        "reverse_closure_bucket": "<50",
        "reverse_closure_sample": [],
        "critical_downstreams": [],
        "exceeds_threshold": False,
        "analysis_status": "skipped-v0",
        "analysis_reason": _IMPACT_REASON,
        "per_attr": [{
            "attr_path": attr_path,
            "drv_path": drv,
            "reverse_closure_count": 0,
            "reverse_closure_bucket": "<50",
            "reverse_closure_sample": [],
            "critical_downstreams": [],
            "exceeds_threshold": False,
        }],
        "replay_critical": True,
    }
    (out_dir / "impact.json").write_text(json.dumps(impact, indent=2) + "\n")

    maintainers = {
        "schema_version": "1.0.0",
        "cve_id": cve_id,
        "nixpkgs_rev": nixpkgs_rev,
        "attr_paths": {attr_path: {"maintainers": []}},
        "replay_critical": True,
    }
    (out_dir / "maintainers.json").write_text(json.dumps(maintainers, indent=2) + "\n")

    return BootstrapResult(
        out_dir=out_dir,
        cve_id=cve_id,
        attr_path=attr_path,
        package_nix_path=rel_path,
        fix_commit_url=patch_url,
    )


def add_parser(subs) -> None:
    """Register `bundle bootstrap` under the bundle group."""
    p = subs.add_parser(
        "bootstrap",
        help="stage a bundle's resolver-side inputs from one screened candidate",
        description=(
            "Read a beat-upstream screen inbox entry and write the staged inputs "
            "`bundle assemble` needs: the pinned package.nix, the upstream fix "
            "commit as a patch, honest impact and maintainers placeholders, and a "
            "resolver-input whose candidate ref is tagged source-backport. Stops "
            "before the Patcher and before preflight, on purpose."
        ),
    )
    p.add_argument("--inbox-entry", type=Path, required=True,
                   help="screen inbox entry for one CVE")
    p.add_argument("--out", type=Path, required=True, help="staging directory to write")
    p.add_argument("--nixpkgs-checkout", type=Path, required=True,
                   help="local nixpkgs clone to read the pinned package.nix from")
    p.add_argument("--nixpkgs-rev", required=True, help="pinned nixpkgs revision (40 chars)")
    p.add_argument("--package-path",
                   help="repository-relative path to the package file, needed when the attr "
                        "is not a pkgs/by-name package")
    p.add_argument("--force", action="store_true", help="overwrite a non-empty output directory")
    p.add_argument("--allow-version-drift", action="store_true",
                   help="proceed even when the pinned package file declares a different version "
                        "than the candidate names")


def run(args) -> int:
    try:
        result = bootstrap_candidate(
            entry_dir=args.inbox_entry,
            out_dir=args.out,
            nixpkgs_checkout=args.nixpkgs_checkout,
            nixpkgs_rev=args.nixpkgs_rev,
            package_path=args.package_path,
            force=args.force,
            allow_version_drift=args.allow_version_drift,
        )
    except BootstrapError as e:
        print(f"error: {e}")
        return 2
    print("bootstrap complete")
    print(f"  cve_id:       {result.cve_id}")
    print(f"  attr_path:    {result.attr_path}")
    print(f"  package.nix:  {result.package_nix_path}")
    print(f"  fix patch:    {result.fix_commit_url}")
    print(f"  staged in:    {result.out_dir}")
    print("  next:         bundle assemble, then bundle preflight before any model spend")
    return 0
