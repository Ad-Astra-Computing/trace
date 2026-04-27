"""Tests for the hash-verifiability scorer.

Anchor cases use the two real traefik live-run artifacts so the scorer's
behaviour is grounded in observed model output, not synthetic shapes:

  * run 1 (commit 90ecc17): patch with `lib.fakeHash` literal expansion
    for `src.hash` and a silently-omitted `vendorHash` -> must score 0.0
    with two violations.
  * run 2 (commit 3408132): refusal under rule 8 (ungrounded hashes) ->
    must score 1.0 with refusal_kind="rule-8".

The scorer is also exercised in isolation against synthetic patches that
hit each of the four forbidden-pattern families and the silent-omission
detector.
"""

from __future__ import annotations

import json
import shutil
from pathlib import Path

from agents.scorers.hash_verifiability import HashVerifiabilityScorer
from tests.schema.validate import REPO_ROOT


TRAEFIK_BUNDLE = REPO_ROOT / "traces" / "example" / "CVE-2026-25949--traefik"
RUN1_ARCHIVE = TRAEFIK_BUNDLE / "_first-run-archive"
SYNTHETIC_FIXTURE = REPO_ROOT / "traces" / "example" / "CVE-0000-0010--patcher-fixture-dispatchable"


def _patch_invocation(outputs: list[str]) -> dict:
    return {
        "invocation_id": "00000000-0000-4000-8000-000000000999",
        "outputs": [{"path": p, "sha256": "0" * 64} for p in outputs],
    }


def _refusal_invocation() -> dict:
    return {
        "invocation_id": "00000000-0000-4000-8000-000000000998",
        "outputs": [{"path": "refusal.json", "sha256": "0" * 64}],
    }


# ─── anchor cases: the two real traefik live-run artifacts ─────────────────


def test_traefik_run1_fails_hash_verifiability(tmp_path: Path) -> None:
    """Run 1 = patch with lib.fakeHash for src.hash + omitted vendorHash."""
    bundle = tmp_path / "bundle"
    shutil.copytree(TRAEFIK_BUNDLE, bundle)
    # Restore run-1 outputs (current state of the bundle has run-2 refusal.json).
    shutil.copyfile(RUN1_ARCHIVE / "patch.diff", bundle / "patch.diff")
    shutil.copyfile(RUN1_ARCHIVE / "patch-rationale.md", bundle / "patch-rationale.md")
    if (bundle / "refusal.json").exists():
        (bundle / "refusal.json").unlink()

    s = HashVerifiabilityScorer()
    r = s.score(
        bundle_dir=bundle,
        invocation=_patch_invocation(["patch.diff", "patch-rationale.md"]),
    )
    assert r.applies is True
    assert r.advisory is False
    assert r.score is not None and r.score < 1.0, r.notes
    assert r.details is not None
    violations = r.details["violations"]
    kinds = {v["kind"] for v in violations}
    # The src.hash assignment is forbidden-sri-fake; vendorHash is silently omitted.
    assert "forbidden-sri-fake" in kinds, f"missing fake-hash detection in {violations}"
    assert "silent-omission" in kinds, f"missing vendorHash omission in {violations}"
    omitted_attrs = {v["attr"] for v in violations if v["kind"] == "silent-omission"}
    assert "vendorHash" in omitted_attrs


def test_traefik_run2_passes_as_rule_8_refusal(tmp_path: Path) -> None:
    """Run 2 = clean refusal under rule 8 (archived, the live bundle now
    holds run-4's merge-ready patch — see _second-run-archive/)."""
    bundle = tmp_path / "bundle"
    shutil.copytree(TRAEFIK_BUNDLE, bundle)
    # Restore run-2's refusal artifacts from the archive.
    archive = bundle / "_second-run-archive"
    assert archive.is_dir(), "test fixture invariant: _second-run-archive/ present"
    shutil.copyfile(archive / "refusal.json", bundle / "refusal.json")
    # Drop any patch artifacts that the live bundle currently carries (run 4).
    for stale in ("patch.diff", "patch-rationale.md"):
        p = bundle / stale
        if p.exists():
            p.unlink()
    refusal = bundle / "refusal.json"
    assert refusal.is_file(), "test fixture invariant: run-2 refusal.json restored"
    rule = json.loads(refusal.read_text())["rule"]
    assert rule == 8, "test fixture invariant: refusal.json rule == 8"

    s = HashVerifiabilityScorer()
    r = s.score(bundle_dir=bundle, invocation=_refusal_invocation())
    assert r.applies is True
    assert r.advisory is False
    assert r.score == 1.0, r.notes
    assert r.details is not None
    assert r.details["refusal_kind"] == "rule-8"


# ─── synthetic isolation: each forbidden pattern + silent omission ─────────


def _write_diff(tmp_path: Path, diff: str, *, with_package: str | None = None) -> Path:
    bundle = tmp_path / "bundle"
    bundle.mkdir()
    (bundle / "patch.diff").write_text(diff)
    if with_package is not None:
        (bundle / "package.nix").write_text(with_package)
    return bundle


def test_grounded_patch_scores_full(tmp_path: Path) -> None:
    diff = (
        "--- a/package.nix\n"
        "+++ b/package.nix\n"
        "@@ -1,3 +1,3 @@\n"
        '-  version = "1.0.0";\n'
        '-  hash = "sha256-OLDOLDOLDOLDOLDOLDOLDOLDOLDOLDOLDOLDOLDOLD0=";\n'
        '+  version = "1.0.1";\n'
        '+  hash = "sha256-Re4l1stIcL00kingButNotForbiddenPatternXYZ=";\n'
    )
    bundle = _write_diff(
        tmp_path, diff,
        with_package='version = "1.0.0";\nhash = "sha256-OLDOLDOLDOLDOLDOLDOLDOLDOLDOLDOLDOLDOLDOLD0=";\n',
    )
    r = HashVerifiabilityScorer().score(
        bundle_dir=bundle, invocation=_patch_invocation(["patch.diff"]),
    )
    assert r.applies is True
    assert r.score == 1.0, r.notes


def test_lib_fakehash_symbol_is_forbidden(tmp_path: Path) -> None:
    diff = (
        "--- a/package.nix\n"
        "+++ b/package.nix\n"
        "@@ -1 +1 @@\n"
        '-  hash = "sha256-real0123456789012345678901234567890123456=";\n'
        "+  hash = lib.fakeHash;\n"
    )
    bundle = _write_diff(tmp_path, diff)
    r = HashVerifiabilityScorer().score(
        bundle_dir=bundle, invocation=_patch_invocation(["patch.diff"]),
    )
    assert r.score == 0.0
    kinds = {v["kind"] for v in r.details["violations"]}
    assert kinds == {"forbidden-symbol"}


def test_64_zero_hex_is_forbidden(tmp_path: Path) -> None:
    diff = (
        "--- a/package.nix\n"
        "+++ b/package.nix\n"
        "@@ -1 +1 @@\n"
        '-  sha256 = "abc123def456abc123def456abc123def456abc123def456abc123def456abcd";\n'
        '+  sha256 = "0000000000000000000000000000000000000000000000000000000000000000";\n'
    )
    bundle = _write_diff(tmp_path, diff)
    r = HashVerifiabilityScorer().score(
        bundle_dir=bundle, invocation=_patch_invocation(["patch.diff"]),
    )
    assert r.score == 0.0
    kinds = {v["kind"] for v in r.details["violations"]}
    assert kinds == {"forbidden-zero-hash"}


def test_empty_string_hash_is_forbidden(tmp_path: Path) -> None:
    diff = (
        "--- a/package.nix\n"
        "+++ b/package.nix\n"
        "@@ -1 +1 @@\n"
        '-  hash = "sha256-real==";\n'
        '+  hash = "";\n'
    )
    bundle = _write_diff(tmp_path, diff)
    r = HashVerifiabilityScorer().score(
        bundle_dir=bundle, invocation=_patch_invocation(["patch.diff"]),
    )
    assert r.score == 0.0
    kinds = {v["kind"] for v in r.details["violations"]}
    assert kinds == {"forbidden-empty"}


def test_silent_omission_after_version_bump(tmp_path: Path) -> None:
    """Bumping version without touching vendorHash present in the original is a violation."""
    diff = (
        "--- a/package.nix\n"
        "+++ b/package.nix\n"
        "@@ -1 +1 @@\n"
        '-  version = "1.0.0";\n'
        '+  version = "2.0.0";\n'
    )
    pkg = (
        '  version = "1.0.0";\n'
        '  hash = "sha256-srcOldOldOldOldOldOldOldOldOldOldOldOldOldOl=";\n'
        '  vendorHash = "sha256-vendorOldOldOldOldOldOldOldOldOldOldOldOld=";\n'
    )
    bundle = _write_diff(tmp_path, diff, with_package=pkg)
    r = HashVerifiabilityScorer().score(
        bundle_dir=bundle, invocation=_patch_invocation(["patch.diff"]),
    )
    assert r.applies is True
    assert r.score == 0.0
    omitted = {v["attr"] for v in r.details["violations"] if v["kind"] == "silent-omission"}
    assert omitted == {"hash", "vendorHash"}


def test_no_version_bump_no_hash_no_violation(tmp_path: Path) -> None:
    """Vacuous pass: a doc-only diff that touches no version or hashes."""
    diff = (
        "--- a/package.nix\n"
        "+++ b/package.nix\n"
        "@@ -1 +1 @@\n"
        "-  description = old\n"
        "+  description = new\n"
    )
    bundle = _write_diff(tmp_path, diff)
    r = HashVerifiabilityScorer().score(
        bundle_dir=bundle, invocation=_patch_invocation(["patch.diff"]),
    )
    assert r.applies is True
    assert r.score == 1.0
    assert "vacuously" in r.notes


def test_prefetch_table_grandfathers_listed_value(tmp_path: Path) -> None:
    """When upstream-ref.json carries prefetch_hashes[], a value listed there
    scores as grounded-prefetch (strict-positive grounding)."""
    diff = (
        "--- a/package.nix\n"
        "+++ b/package.nix\n"
        "@@ -1,2 +1,2 @@\n"
        '-  version = "1.0.0";\n'
        '-  hash = "sha256-OLDOLDOLDOLDOLDOLDOLDOLDOLDOLDOLDOLDOLDOLD0=";\n'
        '+  version = "1.0.1";\n'
        '+  hash = "sha256-Pr3F3tCH3dGr0und3dV4lu3FromUpstreamReleaseXYZ=";\n'
    )
    pkg = '  version = "1.0.0";\n  hash = "sha256-OLDOLDOLDOLDOLDOLDOLDOLDOLDOLDOLDOLDOLDOLD0=";\n'
    bundle = tmp_path / "bundle"
    bundle.mkdir()
    (bundle / "patch.diff").write_text(diff)
    (bundle / "package.nix").write_text(pkg)
    (bundle / "upstream-ref.json").write_text(json.dumps({
        "schema_version": "1.0.0",
        "cve_id": "CVE-0000-0000",
        "current_version": "1.0.0",
        "prefetch_hashes": [
            {
                "name": "src.hash",
                "algorithm": "sha256",
                "value": "sha256-Pr3F3tCH3dGr0und3dV4lu3FromUpstreamReleaseXYZ=",
                "source": "nix-prefetch-url",
                "url": "https://example.invalid/release-1.0.1.tar.gz",
                "replay_critical": True,
            },
        ],
        "eligibility": {"verdict": "eligible"},
        "replay_critical": True,
    }))
    r = HashVerifiabilityScorer().score(
        bundle_dir=bundle, invocation=_patch_invocation(["patch.diff"]),
    )
    assert r.applies is True
    assert r.score == 1.0, r.notes
    assert r.details is not None
    assert r.details["prefetch_table_present"] is True
    introduced = r.details["introduced"]
    assert any(
        e["verdict"] == "grounded-prefetch" and e["attr"] == "hash"
        for e in introduced
    ), introduced


def test_prefetch_table_rejects_unlisted_value(tmp_path: Path) -> None:
    """When prefetch_hashes[] is present, a value NOT on the list is a
    not-in-prefetch-list violation (even if it is not on the forbidden list)."""
    diff = (
        "--- a/package.nix\n"
        "+++ b/package.nix\n"
        "@@ -1,2 +1,2 @@\n"
        '-  version = "1.0.0";\n'
        '-  hash = "sha256-OLDOLDOLDOLDOLDOLDOLDOLDOLDOLDOLDOLDOLDOLD0=";\n'
        '+  version = "1.0.1";\n'
        '+  hash = "sha256-FabricatedButNotForbiddenLookingHashValue42Y=";\n'
    )
    pkg = '  version = "1.0.0";\n  hash = "sha256-OLDOLDOLDOLDOLDOLDOLDOLDOLDOLDOLDOLDOLDOLD0=";\n'
    bundle = tmp_path / "bundle"
    bundle.mkdir()
    (bundle / "patch.diff").write_text(diff)
    (bundle / "package.nix").write_text(pkg)
    (bundle / "upstream-ref.json").write_text(json.dumps({
        "schema_version": "1.0.0",
        "cve_id": "CVE-0000-0000",
        "current_version": "1.0.0",
        "prefetch_hashes": [
            {
                "name": "src.hash",
                "algorithm": "sha256",
                "value": "sha256-Pr3F3tCH3dGr0und3dV4lu3FromUpstreamReleaseXYZ=",
                "source": "nix-prefetch-url",
                "url": "https://example.invalid/release-1.0.1.tar.gz",
                "replay_critical": True,
            },
        ],
        "eligibility": {"verdict": "eligible"},
        "replay_critical": True,
    }))
    r = HashVerifiabilityScorer().score(
        bundle_dir=bundle, invocation=_patch_invocation(["patch.diff"]),
    )
    assert r.applies is True
    assert r.score == 0.0, r.notes
    kinds = {v["kind"] for v in r.details["violations"]}
    assert kinds == {"not-in-prefetch-list"}


def test_no_prefetch_table_falls_back_to_v0_lenient(tmp_path: Path) -> None:
    """Pre-prefetch bundles (no prefetch_hashes field) keep v0 behaviour:
    forbidden patterns flag, anything else passes."""
    diff = (
        "--- a/package.nix\n"
        "+++ b/package.nix\n"
        "@@ -1,2 +1,2 @@\n"
        '-  version = "1.0.0";\n'
        '-  hash = "sha256-OLDOLDOLDOLDOLDOLDOLDOLDOLDOLDOLDOLDOLDOLD0=";\n'
        '+  version = "1.0.1";\n'
        '+  hash = "sha256-Re4l1stIcL00kingButNotForbiddenPatternXYZ=";\n'
    )
    pkg = '  version = "1.0.0";\n  hash = "sha256-OLDOLDOLDOLDOLDOLDOLDOLDOLDOLDOLDOLDOLDOLD0=";\n'
    bundle = tmp_path / "bundle"
    bundle.mkdir()
    (bundle / "patch.diff").write_text(diff)
    (bundle / "package.nix").write_text(pkg)
    # No upstream-ref.json at all (or one without prefetch_hashes).
    (bundle / "upstream-ref.json").write_text(json.dumps({
        "schema_version": "1.0.0",
        "cve_id": "CVE-0000-0000",
        "current_version": "1.0.0",
        "eligibility": {"verdict": "eligible"},
        "replay_critical": True,
    }))
    r = HashVerifiabilityScorer().score(
        bundle_dir=bundle, invocation=_patch_invocation(["patch.diff"]),
    )
    assert r.applies is True
    assert r.score == 1.0, r.notes
    assert r.details["prefetch_table_present"] is False


def test_non_rule_8_refusal_is_trivial_pass(tmp_path: Path) -> None:
    bundle = tmp_path / "bundle"
    bundle.mkdir()
    (bundle / "refusal.json").write_text(json.dumps({"rule": 3, "reason": "test"}))
    r = HashVerifiabilityScorer().score(
        bundle_dir=bundle, invocation=_refusal_invocation(),
    )
    assert r.applies is True
    assert r.score == 1.0
    assert r.details["refusal_kind"] == "non-rule-8"
