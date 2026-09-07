"""Bootstrapping a bundle from a screened candidate.

The screen writes an inbox entry per CVE. Turning one into a bundle took the same
six mechanical steps by hand on wget CVE-2026-16599 and chirp CVE-2026-78136, and
the shortlist has 105 entries. See docs/specs/candidate-bootstrap.md.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from tools.trace_cli.bootstrap import (
    BootstrapError,
    bootstrap_candidate,
    package_nix_path_for_attr,
)


def _entry(tmp_path: Path, *, attr: str = "wget", commits=None, cve: str = "CVE-2026-16599") -> Path:
    d = tmp_path / cve
    d.mkdir()
    if commits is None:
        commits = [{"repo_url": "https://gitlab.com/gnuwget/wget", "commit_sha": "e" * 40}]
    (d / "resolver-input.json").write_text(json.dumps({
        "cve_id": cve,
        "current_version": "1.25.0",
        "attr_path": attr,
        "candidate_refs": [{
            "version": "1.25.0",
            "tier_hint": "security-patch-release",
            "advisory_urls": ["https://example.org/advisory"],
            "upstream_fix_commits": commits,
        }],
    }))
    (d / "finding.json").write_text(json.dumps({
        "schema_version": "1.0.0", "cve_id": cve, "source_feeds": ["nvd"],
        "severity": {"rating": "medium"}, "published_at": "2026-08-25T00:00:00Z",
        "summary": "a summary",
        "mapping": {"method": "pname-heuristic"},
        "affected": [{"attr_path": attr, "version": "1.25.0", "pname": attr.split(".")[-1],
                      "drv_path": "/nix/store/" + "0" * 32 + "-x.drv", "confidence": "high"}],
        "replay_critical": True,
    }))
    return d


def _run(entry: Path, out: Path, **kw):
    kw.setdefault("nixpkgs_checkout", Path("/nixpkgs"))
    kw.setdefault("nixpkgs_rev", "c" * 40)
    kw.setdefault("read_pinned_file", lambda checkout, rev, path: "{ lib }: {}\n")
    kw.setdefault("fetch_patch", lambda url: "--- a/x\n+++ b/x\n")
    return bootstrap_candidate(entry_dir=entry, out_dir=out, **kw)


def test_by_name_path_derivation():
    assert package_nix_path_for_attr("wget") == "pkgs/by-name/wg/wget/package.nix"
    assert package_nix_path_for_attr("chirp") == "pkgs/by-name/ch/chirp/package.nix"


def test_dotted_attr_has_no_derivable_path():
    """A package-set member is not under pkgs/by-name, so guessing would be wrong."""
    assert package_nix_path_for_attr("python3Packages.foo") is None
    assert package_nix_path_for_attr("x") is None


def test_writes_the_staged_inputs(tmp_path):
    entry = _entry(tmp_path)
    out = tmp_path / "bundle"
    result = _run(entry, out)

    assert (out / "package.nix").read_text() == "{ lib }: {}\n"
    assert (out / "upstream-fix.patch").read_text().startswith("--- a/x")
    for name in ("finding.json", "resolver-input.json", "impact.json", "maintainers.json"):
        assert (out / name).exists(), name
    assert result.attr_path == "wget"
    assert result.package_nix_path == "pkgs/by-name/wg/wget/package.nix"


def test_forces_the_source_backport_tier(tmp_path):
    """Scout tags source-backport only when no fixed version is derivable, which
    excludes a released fix nixpkgs has not shipped. The tier is what authorizes
    the Patcher to author a fix rather than bump a version."""
    entry = _entry(tmp_path)
    out = tmp_path / "bundle"
    _run(entry, out)
    ri = json.loads((out / "resolver-input.json").read_text())
    assert ri["candidate_refs"][0]["tier_hint"] == "source-backport"
    assert ri["current_version"] == "1.25.0"


def test_placeholder_impact_is_honest(tmp_path):
    """The counts are placeholders, so the file must say the analysis did not run.
    The routing policy sends an unanalyzed impact to human review."""
    entry = _entry(tmp_path)
    out = tmp_path / "bundle"
    _run(entry, out)
    impact = json.loads((out / "impact.json").read_text())
    assert impact["analysis_status"] == "skipped-v0"
    assert impact["analysis_reason"]
    assert impact["cve_id"] == "CVE-2026-16599"
    assert impact["affected_attr_paths"] == ["wget"]


def test_placeholders_match_their_schemas(tmp_path):
    import jsonschema

    entry = _entry(tmp_path)
    out = tmp_path / "bundle"
    _run(entry, out)
    root = Path(__file__).resolve().parents[2]
    for name, schema in (("impact", "impact-schema.json"), ("maintainers", "maintainers-schema.json")):
        s = json.loads((root / "policy" / schema).read_text())
        doc = json.loads((out / f"{name}.json").read_text())
        jsonschema.Draft202012Validator(s).validate(doc)


def test_patch_is_fetched_from_the_first_fix_commit(tmp_path):
    seen = []

    def fetch(url):
        seen.append(url)
        return "patch bytes\n"

    _run(_entry(tmp_path), tmp_path / "bundle", fetch_patch=fetch)
    assert seen == ["https://gitlab.com/gnuwget/wget/-/commit/" + "e" * 40 + ".patch"]


def test_github_and_codeberg_commit_urls(tmp_path):
    seen = []
    for repo, expected in (
        ("https://github.com/kk7ds/chirp", "https://github.com/kk7ds/chirp/commit/{sha}.patch"),
        ("https://codeberg.org/forgejo/forgejo", "https://codeberg.org/forgejo/forgejo/commit/{sha}.patch"),
    ):
        entry = _entry(tmp_path, cve=f"CVE-2026-{len(seen)}",
                       commits=[{"repo_url": repo, "commit_sha": "a" * 40}])
        _run(entry, tmp_path / f"out{len(seen)}", fetch_patch=lambda u: seen.append(u) or "p\n")
    assert seen == ["https://github.com/kk7ds/chirp/commit/" + "a" * 40 + ".patch",
                    "https://codeberg.org/forgejo/forgejo/commit/" + "a" * 40 + ".patch"]


def test_refuses_without_resolver_input(tmp_path):
    entry = tmp_path / "CVE-2026-1"
    entry.mkdir()
    with pytest.raises(BootstrapError, match="resolver-input.json"):
        _run(entry, tmp_path / "bundle")


def test_refuses_without_a_fix_commit(tmp_path):
    entry = _entry(tmp_path, commits=[])
    with pytest.raises(BootstrapError, match="fix commit"):
        _run(entry, tmp_path / "bundle")


def test_refuses_when_the_package_path_cannot_be_derived(tmp_path):
    entry = _entry(tmp_path, attr="python3Packages.foo")
    with pytest.raises(BootstrapError, match="--package-path"):
        _run(entry, tmp_path / "bundle")


def test_package_path_override_is_used(tmp_path):
    seen = []

    def read(checkout, rev, path):
        seen.append(path)
        return "{ }\n"

    entry = _entry(tmp_path, attr="python3Packages.foo")
    _run(entry, tmp_path / "bundle", read_pinned_file=read,
         package_path="pkgs/development/python-modules/foo/default.nix")
    assert seen == ["pkgs/development/python-modules/foo/default.nix"]


def test_refuses_to_overwrite_without_force(tmp_path):
    entry = _entry(tmp_path)
    out = tmp_path / "bundle"
    out.mkdir()
    (out / "package.nix").write_text("existing\n")
    with pytest.raises(BootstrapError, match="--force"):
        _run(entry, out)
    _run(entry, out, force=True)
    assert (out / "package.nix").read_text() == "{ lib }: {}\n"


def test_output_is_accepted_by_assemble(tmp_path):
    """Bootstrap and assemble have to stay in step, so this asserts the staged
    directory is consumable rather than merely well-shaped."""
    from tools.trace_cli.bundle import assemble_bundle

    entry = _entry(tmp_path)
    staged = tmp_path / "staged"
    _run(entry, staged, read_pinned_file=lambda c, r, p: "{ lib, fetchurl }: { }\n")

    out = tmp_path / "bundle"
    assemble_bundle(
        resolver_input_path=staged / "resolver-input.json",
        package_nix_path=staged / "package.nix",
        finding_path=staged / "finding.json",
        impact_path=staged / "impact.json",
        maintainers_path=staged / "maintainers.json",
        upstream_fix_patch_path=staged / "upstream-fix.patch",
        attr_path="wget",
        nixpkgs_rev="c" * 40,
        out_dir=out,
    )
    ref = json.loads((out / "upstream-ref.json").read_text())
    assert ref["eligibility"]["patch_strategy"] == "source-backport"


def test_refuses_when_the_pinned_version_differs(tmp_path):
    """The screen reads its own nixpkgs snapshot; the operator passes a pinned rev
    separately. If they disagree the bundle would be built against the wrong base,
    which preflight only catches after the source has been fetched. Bootstrapping
    privatebin CVE-2026-55891 hit exactly this: the screen recorded 2.0.6 and the
    pinned revision carried 2.0.5."""
    entry = _entry(tmp_path)
    with pytest.raises(BootstrapError, match="1.24.5"):
        _run(entry, tmp_path / "bundle",
             read_pinned_file=lambda c, r, p: '{ }: {\n  version = "1.24.5";\n}\n')


def test_version_drift_can_be_overridden(tmp_path):
    entry = _entry(tmp_path)
    out = tmp_path / "bundle"
    _run(entry, out, allow_version_drift=True,
         read_pinned_file=lambda c, r, p: '{ }: {\n  version = "1.24.5";\n}\n')
    assert (out / "package.nix").exists()


def test_a_multivariant_file_passes_when_any_variant_matches(tmp_path):
    """libxml2's default.nix declares 2.13.9 for libxml2_13 before 2.15.3 for
    libxml2. Reading only the first literal refused CVE-2026-86144 at a revision
    whose libxml2 attr was exactly the screened version."""
    entry = _entry(tmp_path)
    out = tmp_path / "bundle"
    _run(entry, out, read_pinned_file=lambda c, r, p: (
        '{ }: {\n  libxml2_13 = { version = "1.24.5"; };\n  libxml2 = { version = "1.25.0"; };\n}\n'))
    assert (out / "package.nix").exists()


def test_a_multivariant_file_names_every_version_when_none_matches(tmp_path):
    entry = _entry(tmp_path)
    with pytest.raises(BootstrapError, match="1.24.5, 1.24.6"):
        _run(entry, tmp_path / "bundle",
             read_pinned_file=lambda c, r, p: '{ }: {\n  version = "1.24.5";\n  version = "1.24.6";\n}\n')


def test_matching_version_passes(tmp_path):
    entry = _entry(tmp_path)
    out = tmp_path / "bundle"
    _run(entry, out, read_pinned_file=lambda c, r, p: '{ }: {\n  version = "1.25.0";\n}\n')
    assert (out / "package.nix").exists()


def test_unreadable_version_does_not_block(tmp_path):
    """Plenty of packages compute their version, and a check that cannot read one
    must not refuse the bootstrap."""
    entry = _entry(tmp_path)
    out = tmp_path / "bundle"
    _run(entry, out, read_pinned_file=lambda c, r, p: "{ }: { version = someExpr; }\n")
    assert (out / "package.nix").exists()


def test_unusable_drv_paths_are_replaced_with_a_placeholder(tmp_path):
    """A snapshot built without derivation paths records `attr:<name>`, which the
    finding schema rejects. The value carries no information either way, so the
    staged copy uses the placeholder shape the schema allows rather than failing
    finalize much later."""
    entry = _entry(tmp_path)
    finding = json.loads((entry / "finding.json").read_text())
    finding["affected"][0]["drv_path"] = "attr:wget"
    (entry / "finding.json").write_text(json.dumps(finding))

    out = tmp_path / "bundle"
    _run(entry, out)
    staged = json.loads((out / "finding.json").read_text())
    assert staged["affected"][0]["drv_path"] == "/nix/store/" + "0" * 32 + "-wget.drv"


def test_real_drv_paths_are_kept(tmp_path):
    entry = _entry(tmp_path)
    finding = json.loads((entry / "finding.json").read_text())
    real = "/nix/store/" + "a" * 32 + "-wget-1.25.0.drv"
    finding["affected"][0]["drv_path"] = real
    (entry / "finding.json").write_text(json.dumps(finding))

    out = tmp_path / "bundle"
    _run(entry, out)
    assert json.loads((out / "finding.json").read_text())["affected"][0]["drv_path"] == real
