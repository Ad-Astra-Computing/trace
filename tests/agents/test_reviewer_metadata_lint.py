"""Tests for the deterministic reviewer metadata-consistency lint.

The lint is a contract-layer gate: it must (a) fire on the metadata-defect
negatives it is designed to catch and (b) NEVER fire on an honest patch (a
false-reject on a real bundle is the cardinal sin for a merge gate). Both
properties are asserted against the real corpus under ``traces/``.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from agents.reviewer.metadata_lint import (
    MetadataViolation,
    check_metadata_consistency,
)

ROOT = Path(__file__).resolve().parents[2]
NEG = ROOT / "traces" / "negatives"
POS = ROOT / "traces" / "example"


def _mutation_type(d: Path) -> str | None:
    p = d / "mutation.json"
    if not p.exists():
        return None
    try:
        return json.load(open(p)).get("mutation_type")
    except (json.JSONDecodeError, OSError):
        return None


def _codes(d: Path) -> set[str]:
    return {v.code for v in check_metadata_consistency(d)}


# ---- No false-rejects on honest patches (the load-bearing property) --------

@pytest.mark.skipif(not POS.exists(), reason="corpus not present")
def test_no_false_positive_on_any_honest_positive():
    offenders = {
        d.name: sorted(_codes(d))
        for d in sorted(POS.glob("*/"))
        if (d / "patch.diff").exists() and check_metadata_consistency(d)
    }
    assert offenders == {}, f"lint false-rejected honest positives: {offenders}"


# ---- Fires on the metadata-defect negatives it targets ---------------------

@pytest.mark.skipif(not NEG.exists(), reason="corpus not present")
@pytest.mark.parametrize(
    "mutation_type, expected_code",
    [
        ("version-without-hash", "version-without-hash"),
        ("wrong-src-hash", "wrong-src-hash"),
        ("wrong-target-version", "version-mismatch-vs-resolver"),
        ("hash-from-other-bundle", "wrong-src-hash"),
    ],
)
def test_fires_on_metadata_negatives(mutation_type, expected_code):
    dirs = [d for d in NEG.glob("*/") if _mutation_type(d) == mutation_type]
    if not dirs:
        pytest.skip(f"no {mutation_type} negative in corpus")
    # every negative of this type must be flagged with the expected code
    for d in dirs:
        codes = _codes(d)
        assert expected_code in codes, f"{d.name}: expected {expected_code}, got {codes}"


@pytest.mark.skipif(not NEG.exists(), reason="corpus not present")
def test_does_not_fire_on_pure_code_mutations():
    # A condition mutation lives entirely in the code hunks; the metadata lint
    # has no opinion on it (that is the model's job) and must stay silent.
    for d in NEG.glob("*condition-mutation*"):
        assert _codes(d) == set(), f"{d.name} unexpectedly flagged: {_codes(d)}"


# ---- Unit behaviour on synthetic bundles -----------------------------------

def _write_bundle(tmp_path: Path, diff: str, upstream_ref: dict | None = None) -> Path:
    # Real bundle diffs carry a `+++ b/<file>` header; the lint only scans .nix
    # hunks. Bare synthetic diffs get a package.nix header so they exercise the
    # nix-hunk path; diffs that already declare their own file header (e.g. an
    # added .patch file) are left untouched.
    if "+++ " not in diff:
        diff = "--- a/package.nix\n+++ b/package.nix\n@@ -1,9 +1,9 @@\n" + diff
    (tmp_path / "patch.diff").write_text(diff)
    if upstream_ref is not None:
        (tmp_path / "upstream-ref.json").write_text(json.dumps(upstream_ref))
    return tmp_path


def test_version_without_hash(tmp_path):
    # Version bumped but the src hash line is unchanged (context, not a +/- change).
    diff = (
        '-  version = "1.2.3";\n'
        '+  version = "1.2.4";\n'
        '     hash = "sha256-unchanged";\n'
    )
    ref = {
        "target_version": "1.2.4",
        "prefetch_hashes": [{"name": "src.hash", "value": "sha256-correct-new"}],
    }
    v = check_metadata_consistency(_write_bundle(tmp_path, diff, ref))
    assert "version-without-hash" in {x.code for x in v}


def test_honest_version_bump_is_clean(tmp_path):
    diff = (
        '-  version = "1.2.3";\n'
        '+  version = "1.2.4";\n'
        '-    hash = "sha256-OLD";\n'
        '+    hash = "sha256-NEW";\n'
    )
    ref = {
        "target_version": "1.2.4",
        "prefetch_hashes": [{"name": "src.hash", "value": "sha256-NEW"}],
    }
    assert check_metadata_consistency(_write_bundle(tmp_path, diff, ref)) == []


def test_wrong_src_hash(tmp_path):
    diff = (
        '-  version = "1.2.3";\n'
        '+  version = "1.2.4";\n'
        '-    hash = "sha256-OLD";\n'
        '+    hash = "sha256-WRONG";\n'
    )
    ref = {
        "target_version": "1.2.4",
        "prefetch_hashes": [{"name": "src.hash", "value": "sha256-EXPECTED"}],
    }
    assert "wrong-src-hash" in {x.code for x in check_metadata_consistency(
        _write_bundle(tmp_path, diff, ref))}


def test_version_mismatch_vs_resolver(tmp_path):
    diff = '-  version = "1.2.3";\n+  version = "9.9.9";\n+    hash = "sha256-NEW";\n'
    ref = {"target_version": "1.2.4",
           "prefetch_hashes": [{"name": "src.hash", "value": "sha256-NEW"}]}
    assert "version-mismatch-vs-resolver" in {
        x.code for x in check_metadata_consistency(_write_bundle(tmp_path, diff, ref))}


def test_multi_hash_bump_with_correct_src_is_clean(tmp_path):
    # A Go package bumps src.hash and vendorHash. The gate keys on PRESENCE of the
    # resolver's source hash among the diff's added hashes (not on classifying each
    # `hash` line), so an honest multi-hash bump — src hash present — is clean, and
    # the ambiguous bare-`hash` classification problem never arises.
    diff = (
        '-  version = "1.0";\n'
        '+  version = "1.1";\n'
        '-  vendorHash = "sha256-VOLD";\n'
        '+  vendorHash = "sha256-VNEW";\n'
        '-    hash = "sha256-SOLD";\n'
        '+    hash = "sha256-SNEW";\n'
    )
    ref = {
        "target_version": "1.1",
        "prefetch_hashes": [
            {"name": "src.hash", "value": "sha256-SNEW"},
            {"name": "vendorHash", "value": "sha256-VNEW"},
        ],
    }
    assert check_metadata_consistency(_write_bundle(tmp_path, diff, ref)) == []


def test_src_hash_present_alongside_fetchpatch_hash_is_clean(tmp_path):
    # The correct source hash and an (ambiguous) sub-fetcher `hash` both change.
    # Because the resolver's src hash IS present among the additions, the gate stays
    # quiet — it never false-rejects an honest patch that also touches a patch hash.
    diff = (
        '-  version = "1.0";\n'
        '+  version = "1.1";\n'
        '-    hash = "sha256-SRC_OLD";\n'
        '+    hash = "sha256-SRC_NEW";\n'
        '-      hash = "sha256-PATCH_OLD";\n'
        '+      hash = "sha256-PATCH_NEW";\n'
    )
    ref = {
        "target_version": "1.1",
        "prefetch_hashes": [{"name": "src.hash", "value": "sha256-SRC_NEW"}],
    }
    assert check_metadata_consistency(_write_bundle(tmp_path, diff, ref)) == []


def test_src_hash_on_vendor_line_does_not_satisfy_src_check(tmp_path):
    # Contrived multi-hash defect: the real source `hash` is left stale while the
    # resolver's source value is (mis)placed on the vendorHash line. The source-hash
    # presence check must NOT be satisfied by a non-source attribute, so this is
    # still flagged as a wrong/stale source hash.
    diff = (
        '-  version = "1.0";\n'
        '+  version = "1.1";\n'
        '     hash = "sha256-STALE_SRC";\n'          # src hash unchanged (context)
        '-  vendorHash = "sha256-VOLD";\n'
        '+  vendorHash = "sha256-EXPECTED_SRC";\n'   # src value on the wrong attr
    )
    ref = {
        "target_version": "1.1",
        "prefetch_hashes": [{"name": "src.hash", "value": "sha256-EXPECTED_SRC"}],
    }
    codes = {x.code for x in check_metadata_consistency(_write_bundle(tmp_path, diff, ref))}
    assert codes & {"wrong-src-hash", "version-without-hash"}


def test_wrong_src_hash_with_src_sha256_resolver_name(tmp_path):
    # Resolver grounds the source hash under the legacy name "src.sha256"; a wrong
    # source hash must still be caught (the src-hash name set includes src.sha256).
    diff = (
        '-  version = "1.0";\n'
        '+  version = "1.1";\n'
        '-    sha256 = "sha256-OLD";\n'
        '+    sha256 = "sha256-WRONG";\n'
    )
    ref = {
        "target_version": "1.1",
        "prefetch_hashes": [{"name": "src.sha256", "value": "sha256-EXPECTED"}],
    }
    assert "wrong-src-hash" in {
        x.code for x in check_metadata_consistency(_write_bundle(tmp_path, diff, ref))}


def test_src_hash_check_skipped_when_resolver_ungrounded(tmp_path):
    # Without a resolver source hash the gate cannot ground the check, so it stays
    # silent rather than guess (never false-reject).
    diff = '-  version = "1.0";\n+  version = "1.1";\n'  # version-only, no src hash
    ref = {"target_version": "1.1"}
    assert check_metadata_consistency(_write_bundle(tmp_path, diff, ref)) == []


def test_source_backport_no_version_change_is_clean(tmp_path):
    # Adds a .patch file, no version/hash change -> no metadata opinion.
    diff = (
        "+++ b/pkgs/foo/CVE-2025-0001.patch\n"
        "+--- a/foo.c\n"
        "+++ b/foo.c\n"
        "+ if (len <= max) {\n"
    )
    ref = {"target_version": "1.2.3"}
    assert check_metadata_consistency(_write_bundle(tmp_path, diff, ref)) == []


def test_embedded_patch_payload_is_not_read_as_metadata(tmp_path):
    # A source-backport ADDS a .patch file whose payload happens to contain a
    # context line ` version = "9.9.9";` (part of the patched C/nix source shown in
    # the patch). In the outer git diff that is a `+` line, but it is patch payload,
    # not a package version bump — the lint must ignore it (zero-false-reject).
    diff = (
        "diff --git a/pkgs/foo/CVE-2025-0001.patch b/pkgs/foo/CVE-2025-0001.patch\n"
        "new file mode 100644\n"
        "--- /dev/null\n"
        "+++ b/pkgs/foo/CVE-2025-0001.patch\n"
        "@@ -0,0 +1,4 @@\n"
        "+--- a/src/config.def\n"
        "+++ b/src/config.def\n"
        '+ version = "9.9.9";\n'
        '+ hash = "sha256-BOGUS";\n'
    )
    ref = {
        "target_version": "1.2.3",
        "prefetch_hashes": [{"name": "src.hash", "value": "sha256-REAL"}],
    }
    (tmp_path / "patch.diff").write_text(diff)
    (tmp_path / "upstream-ref.json").write_text(json.dumps(ref))
    assert check_metadata_consistency(tmp_path) == []


@pytest.mark.xfail(
    reason="irreducible bare-`hash` ambiguity: distinguishing a wrong src.hash from "
    "a sub-fetcher hash carrying the resolver value needs fetcher-block parsing "
    "(deliberately out of scope — the gate fails safe here, see module docstring)",
    strict=True,
)
def test_known_limitation_wrong_src_with_subfetcher_coincidence(tmp_path):
    # Contrived: main src hash is WRONG, but a fetchpatch `hash` on another line
    # happens to carry the resolver's source value, so the presence check is
    # satisfied. This is a documented fail-safe miss (the model + build still
    # catch it). Marked xfail so it flips to pass if fetcher-aware parsing lands.
    diff = (
        '-  version = "1.0";\n'
        '+  version = "1.1";\n'
        '-    hash = "sha256-SRC_OLD";\n'
        '+    hash = "sha256-SRC_WRONG";\n'            # real src hash is wrong
        '-      hash = "sha256-PATCH_OLD";\n'
        '+      hash = "sha256-EXPECTED_SRC";\n'       # resolver value on a patch line
    )
    ref = {
        "target_version": "1.1",
        "prefetch_hashes": [{"name": "src.hash", "value": "sha256-EXPECTED_SRC"}],
    }
    assert check_metadata_consistency(_write_bundle(tmp_path, diff, ref)) != []


def test_missing_patch_diff_returns_empty(tmp_path):
    assert check_metadata_consistency(tmp_path) == []


def test_violation_is_frozen():
    v = MetadataViolation(code="x", message="m")
    with pytest.raises(Exception):
        v.code = "y"  # type: ignore[misc]
