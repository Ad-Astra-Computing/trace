"""Tests for the source-backport behavioral-validation gate.

The gate encodes Jason's hard requirement (2026-06-15): a source-backport only
counts toward the training corpus if it is *behaviorally validated* — the cert
built the vulnerable baseline and the agent-backported tree at the same version
and observed the vuln fire on one but not the other. Reviewer semantic-match is
necessary but not sufficient.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from eval.backport_validation import (
    Assertion,
    BackportValidation,
    is_source_backport,
    scan_source_backports,
    validate_backport,
)

REPO = Path(__file__).resolve().parents[2]
CORPUS = REPO / "traces" / "example"


def _bundle(substr: str) -> Path:
    hits = [d for d in CORPUS.glob("CVE-*") if substr in d.name]
    assert hits, f"no corpus bundle matching {substr!r}"
    return hits[0]


# ─── detection ──────────────────────────────────────────────────────────────


def test_source_backports_detected():
    for sub in ("proxychains-ng-backport", "libxmp-backport", "graphite2-backport"):
        assert is_source_backport(_bundle(sub)), f"{sub} should be a source-backport"


def test_version_bumps_are_not_source_backports():
    # neovim/freerdp/putty are clean version-bump positives, not source-backports.
    for sub in ("neovim", "freerdp", "putty"):
        bd = next((d for d in CORPUS.glob(f"CVE-*{sub}*")), None)
        if bd is None:
            pytest.skip(f"no {sub} bundle present")
        assert not is_source_backport(bd), f"{sub} is a version bump, not a backport"
        v = validate_backport(bd)
        assert v.disposition == "not-source-backport"
        assert v.validated is False


# ─── the validated baseline (discriminating reproducers) ──────────────────────


@pytest.mark.parametrize("sub", ["proxychains-ng-backport", "libxmp-backport", "graphite2-backport"])
def test_discriminating_source_backports_validate(sub):
    """These three carry a hand-authored discriminating reproducer whose
    SIGNAL_UNPATCHED/SIGNAL_PATCHED landed in build.json — they are validated."""
    v = validate_backport(_bundle(sub))
    assert v.is_source_backport
    assert v.validated, f"{sub} failed load-bearing: {v.failed_load_bearing()}"
    assert v.disposition == "validated"
    # the two behavioral assertions specifically must pass
    by = {a.name: a for a in v.assertions}
    assert by["unpatched-reproducer-fires"].passed
    assert by["backported-reproducer-clean"].passed
    assert by["no-version-bump"].passed


def test_timed_out_patched_run_is_verified_only():
    """bzip2's patched run timed out — it is built + reviewer-accepted but NOT
    behaviorally proven (patched-clean never observed). The gate must classify
    it verified-only, not validated, and name the recoverable reason."""
    v = validate_backport(_bundle("bzip2-backport"))
    assert v.is_source_backport
    assert not v.validated
    assert v.disposition == "verified-only"
    assert "backported-reproducer-clean" in v.failed_load_bearing()
    detail = next(a.detail for a in v.assertions if a.name == "backported-reproducer-clean")
    assert "timed-out" in detail


# ─── no-version-bump assertion ────────────────────────────────────────────────


def test_no_version_bump_rejects_version_change(tmp_path):
    bd = tmp_path / "CVE-2099-0001--fake-backport"
    bd.mkdir()
    (bd / "upstream-ref.json").write_text(json.dumps(
        {"eligibility": {"patch_strategy": "source-backport"}}))
    (bd / "patch.diff").write_text(
        "--- a/pkgs/by-name/fa/fake/package.nix\n"
        "+++ b/pkgs/by-name/fa/fake/package.nix\n"
        '@@ -1 +1 @@\n-  version = "1.0";\n+  version = "1.1";\n'
    )
    (bd / "build.json").write_text(json.dumps({"patch_apply": {"applied": True}}))
    v = validate_backport(bd)
    nb = next(a for a in v.assertions if a.name == "no-version-bump")
    assert not nb.passed
    assert "version" in nb.detail.lower()


def test_no_version_bump_rejects_hash_change(tmp_path):
    bd = tmp_path / "CVE-2099-0002--fake-backport"
    bd.mkdir()
    (bd / "upstream-ref.json").write_text(json.dumps(
        {"eligibility": {"patch_strategy": "source-backport"}}))
    (bd / "patch.diff").write_text(
        "--- a/pkgs/by-name/fa/fake/package.nix\n"
        "+++ b/pkgs/by-name/fa/fake/package.nix\n"
        '@@ -1 +1 @@\n-  hash = "sha256-AAA";\n+  hash = "sha256-BBB";\n'
    )
    v = validate_backport(bd)
    nb = next(a for a in v.assertions if a.name == "no-version-bump")
    assert not nb.passed


def test_no_version_bump_accepts_added_patch_file(tmp_path):
    bd = tmp_path / "CVE-2099-0003--fake-backport"
    bd.mkdir()
    (bd / "upstream-ref.json").write_text(json.dumps(
        {"eligibility": {"patch_strategy": "source-backport"}}))
    (bd / "patch.diff").write_text(
        "--- /dev/null\n"
        "+++ b/pkgs/by-name/fa/fake/CVE-2099-0003.patch\n"
        "@@ -0,0 +1 @@\n+real source fix hunk\n"
    )
    (bd / "build.json").write_text(json.dumps({"patch_apply": {
        "applied": True,
        "files_changed": ["pkgs/by-name/fa/fake/CVE-2099-0003.patch",
                          "pkgs/by-name/fa/fake/package.nix"]}}))
    v = validate_backport(bd)
    nb = next(a for a in v.assertions if a.name == "no-version-bump")
    assert nb.passed, nb.detail


# ─── scan over the corpus ─────────────────────────────────────────────────────


def test_scan_returns_all_source_backports():
    results = scan_source_backports(CORPUS)
    names = {r.bundle for r in results}
    assert any("proxychains-ng-backport" in n for n in names)
    assert all(r.is_source_backport for r in results)
    # every result is either validated or verified-only, never not-source-backport
    assert all(r.disposition in ("validated", "verified-only") for r in results)
