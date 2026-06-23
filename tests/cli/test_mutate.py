"""Tests for `trace mutate reviewer-negative` (tools/trace_cli/mutate.py)."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from tools.trace_cli import mutate as mut


def _base_bundle(root: Path, name: str = "CVE-2025-0001--zk") -> Path:
    bd = root / name
    bd.mkdir(parents=True)
    (bd / "bundle.json").write_text(json.dumps({"bundle_id": "base123", "cve_id": "CVE-2025-0001"}))
    (bd / "finding.json").write_text(json.dumps({"cve_id": "CVE-2025-0001"}))
    (bd / "package.nix").write_text("{ }: { }\n")
    (bd / "patch.diff").write_text(
        "--- a/package.nix\n+++ b/package.nix\n@@ -1,4 +1,4 @@\n"
        '-  version = "3.9.3";\n+  version = "3.9.4";\n'
        '-    hash = "sha512-OLD0000000000000000000000000000000000000000000000000000000000000000000000000000000000==";\n'
        '+    hash = "sha512-NEW0000000000000000000000000000000000000000000000000000000000000000000000000000000000==";\n'
    )
    (bd / "review.md").write_text("## Verdict\naccept\n")  # should be stripped on copy
    (bd / "bundle.sig").write_text("sig")  # should be stripped on copy
    return bd


def _args(base: Path, mutation: str, out: Path, decoy: str | None = None) -> argparse.Namespace:
    return argparse.Namespace(
        mutate_scope="reviewer-negative", base_dir=base, mutation=mutation,
        out_dir=out, decoy_hash=decoy, format="json",
    )


def test_wrong_src_hash_corrupts_patched_hash(tmp_path):
    base = _base_bundle(tmp_path / "ex")
    out = tmp_path / "neg" / "m1"
    rc = mut.run(_args(base, "wrong-src-hash", out))
    assert rc == 0
    diff = (out / "patch.diff").read_text()
    assert "NEW000000" not in diff  # the real patched hash is gone
    assert mut._DECOY_SRI in diff
    marker = json.loads((out / "mutation.json").read_text())
    assert marker["mutation_type"] == "wrong-src-hash"
    assert marker["negative_source"] == "mutation"
    assert marker["expected_reviewer_verdict"] == "reject"


def test_copy_strips_prior_review_and_signing(tmp_path):
    base = _base_bundle(tmp_path / "ex")
    out = tmp_path / "neg" / "m2"
    mut.run(_args(base, "wrong-src-hash", out))
    assert not (out / "review.md").exists()
    assert not (out / "bundle.sig").exists()


def test_version_without_hash_reverts_hash(tmp_path):
    base = _base_bundle(tmp_path / "ex")
    out = tmp_path / "neg" / "m3"
    mut.run(_args(base, "version-without-hash", out))
    diff = (out / "patch.diff").read_text()
    # version still bumped, but the '+' hash reverted to the pre-patch value
    assert '+  version = "3.9.4";' in diff
    assert "OLD000000" in diff.split("+    hash")[1] if "+    hash" in diff else True
    marker = json.loads((out / "mutation.json").read_text())
    assert marker["mutation_type"] == "version-without-hash"


def test_hash_from_other_bundle_uses_decoy(tmp_path):
    base = _base_bundle(tmp_path / "ex")
    out = tmp_path / "neg" / "m4"
    other = "sha512-OTHERBUNDLEHASH000000000000000000000000000000000000000000000000000000000000000000=="
    mut.run(_args(base, "hash-from-other-bundle", out, decoy=other))
    diff = (out / "patch.diff").read_text()
    assert other in diff


def test_patch_touches_unrelated_file(tmp_path):
    base = _base_bundle(tmp_path / "ex")
    out = tmp_path / "neg" / "m5"
    mut.run(_args(base, "patch-touches-unrelated-file", out))
    diff = (out / "patch.diff").read_text()
    assert "pkgs/unrelated/evil.nix" in diff
    marker = json.loads((out / "mutation.json").read_text())
    assert marker["mutation_type"] == "patch-touches-unrelated-file"


def test_scrubs_reviewer_replay_and_signing(tmp_path):
    base = _base_bundle(tmp_path / "ex")
    # base carries a signed_manifest + a reviewer role in replay.json
    bj = json.loads((base / "bundle.json").read_text())
    bj["signed_manifest"] = {"rekor_log_index": 123, "signer": "x"}
    bj["auto_merge_evidence_path"] = "reviewer-attested"
    (base / "bundle.json").write_text(json.dumps(bj))
    (base / "replay.json").write_text(json.dumps({"roles": [
        {"role": "patcher", "invocations": [{"invocation_id": "p"}]},
        {"role": "reviewer", "invocations": [{"invocation_id": "r", "inputs": [{"path": "patch.diff", "sha256": "stale"}]}]},
    ]}))
    out = tmp_path / "neg" / "m7"
    mut.run(_args(base, "wrong-src-hash", out))
    # signing metadata scrubbed
    out_bj = json.loads((out / "bundle.json").read_text())
    assert "signed_manifest" not in out_bj
    assert "auto_merge_evidence_path" not in out_bj
    # reviewer role removed from replay (patcher role kept)
    out_replay = json.loads((out / "replay.json").read_text())
    roles = {r["role"] for r in out_replay["roles"]}
    assert "reviewer" not in roles
    assert "patcher" in roles


def test_drops_stale_file_manifest(tmp_path):
    base = _base_bundle(tmp_path / "ex")
    bj = json.loads((base / "bundle.json").read_text())
    bj["files"] = {"patch.diff": {"sha256": "stale"}, "bundle.sig": {"sha256": "x"}}
    (base / "bundle.json").write_text(json.dumps(bj))
    out = tmp_path / "neg" / "m8"
    mut.run(_args(base, "wrong-src-hash", out))
    out_bj = json.loads((out / "bundle.json").read_text())
    assert "files" not in out_bj  # stale manifest dropped


def test_hash_from_other_bundle_requires_decoy(tmp_path):
    base = _base_bundle(tmp_path / "ex")
    out = tmp_path / "neg" / "m9"
    rc = mut.run(_args(base, "hash-from-other-bundle", out, decoy=None))
    assert rc == 2
    assert not out.exists()  # refused before copying


def _rich_base(root: Path, name: str = "CVE-2025-0009--rz") -> Path:
    """Base with upstream-ref.json + a rationale that cites the version & hash,
    so the version/rationale mutations have something to corrupt."""
    bd = _base_bundle(root, name)
    (bd / "upstream-ref.json").write_text(json.dumps({"target_version": "3.9.4"}))
    (bd / "patch-rationale.md").write_text(
        "## Why\nBump to 3.9.4; hash "
        'sha512-NEW0000000000000000000000000000000000000000000000000000000000000000000000000000000000== '
        "grounded from prefetch.\n"
    )
    return bd


def test_wrong_target_version(tmp_path):
    base = _rich_base(tmp_path / "ex")
    out = tmp_path / "neg" / "v1"
    mut.run(_args(base, "wrong-target-version", out))
    diff = (out / "patch.diff").read_text()
    assert '+  version = "3.9.4";' not in diff  # real target replaced
    assert '+  version = "3.9.11";' in diff      # +7 on the last component
    # the now-inconsistent hash is neutralized to a decoy (single coherent defect)
    assert mut._DECOY_SRI in diff
    assert "NEW000000" not in diff
    marker = json.loads((out / "mutation.json").read_text())
    assert marker["mutation_type"] == "wrong-target-version"
    # rationale kept consistent with the mutated diff (single defect, not also a
    # rationale-contradicts-diff defect): it cites the wrong version, not 3.9.4
    rat = (out / "patch-rationale.md").read_text()
    assert "3.9.4" not in rat and "3.9.11" in rat


def test_extra_unrelated_hunk(tmp_path):
    base = _rich_base(tmp_path / "ex")
    out = tmp_path / "neg" / "v2"
    mut.run(_args(base, "extra-unrelated-hunk", out))
    diff = (out / "patch.diff").read_text()
    assert "pkgs/unrelated/cleanup.nix" in diff
    assert '+  version = "3.9.4";' in diff  # the real change is still present


def test_rationale_cites_wrong_version(tmp_path):
    base = _rich_base(tmp_path / "ex")
    out = tmp_path / "neg" / "v3"
    mut.run(_args(base, "rationale-cites-wrong-version", out))
    rat = (out / "patch-rationale.md").read_text()
    assert "3.9.11" in rat and "Bump to 3.9.4" not in rat
    # the actual patch.diff version is untouched (the contradiction is the defect)
    assert '+  version = "3.9.4";' in (out / "patch.diff").read_text()


def test_rationale_cites_wrong_hash(tmp_path):
    base = _rich_base(tmp_path / "ex")
    out = tmp_path / "neg" / "v4"
    mut.run(_args(base, "rationale-cites-wrong-hash", out))
    rat = (out / "patch-rationale.md").read_text()
    assert mut._DECOY_SRI in rat
    assert "NEW000000" not in rat


def test_rationale_mutation_refuses_when_not_cited(tmp_path):
    # base rationale does not mention the version -> mutation should fail + roll back
    base = _base_bundle(tmp_path / "ex")
    (base / "upstream-ref.json").write_text(json.dumps({"target_version": "9.9.9"}))
    out = tmp_path / "neg" / "v5"
    rc = mut.run(_args(base, "rationale-cites-wrong-version", out))
    assert rc == 2
    assert not out.exists()  # rolled back


def test_wrong_target_version_neutralizes_vendor_hash(tmp_path):
    """For a Go-style diff with both hash and vendorHash, wrong-target-version
    must neutralize BOTH so it stays a single 'wrong release' defect."""
    base = _rich_base(tmp_path / "ex")
    (base / "patch.diff").write_text(
        "--- a/package.nix\n+++ b/package.nix\n@@ -1,6 +1,6 @@\n"
        '-  version = "3.9.4";\n+  version = "3.9.4";\n'
        '-  hash = "sha256-REALSRC000000000000000000000000000000000000=";\n'
        '+  hash = "sha256-REALSRC000000000000000000000000000000000000=";\n'
        '-  vendorHash = "sha256-REALVENDOR000000000000000000000000000000=";\n'
        '+  vendorHash = "sha256-REALVENDOR000000000000000000000000000000=";\n'
    )
    out = tmp_path / "neg" / "v6"
    mut.run(_args(base, "wrong-target-version", out))
    plus = [l for l in (out / "patch.diff").read_text().splitlines() if l.startswith("+")]
    # the ADDED hash + vendorHash lines are both neutralized to the decoy
    assert not any("REALSRC000" in l for l in plus)
    assert not any("REALVENDOR000" in l for l in plus)
    assert sum(mut._DECOY_SRI in l for l in plus) >= 2


def test_refuses_existing_out_dir(tmp_path):
    base = _base_bundle(tmp_path / "ex")
    out = tmp_path / "neg" / "m6"
    out.mkdir(parents=True)
    rc = mut.run(_args(base, "wrong-src-hash", out))
    assert rc == 2


# --- reviewer-positive-reorg (structure-preserving positive variants) ----------

def _reorg_args(base: Path, reorg: str, out: Path) -> argparse.Namespace:
    return argparse.Namespace(
        mutate_scope="reviewer-positive-reorg", base_dir=base, reorg=reorg,
        out_dir=out, format="json",
    )


def _two_section_base(root: Path, name: str = "CVE-2025-0002--zr") -> Path:
    """A 'patch-file-add' style backport: two file-level diff sections (the
    zlib shape). Reordering the sections is content-preserving."""
    bd = root / name
    bd.mkdir(parents=True)
    (bd / "bundle.json").write_text(json.dumps({"bundle_id": "b2", "cve_id": "CVE-2025-0002"}))
    (bd / "patch.diff").write_text(
        "diff --git a/pkgs/x/CVE.patch b/pkgs/x/CVE.patch\n"
        "new file mode 100644\n--- /dev/null\n+++ b/pkgs/x/CVE.patch\n"
        "@@ -0,0 +1,3 @@\n+context\n+    (len = a - b) < c) {\n+more\n"
        "diff --git a/pkgs/x/default.nix b/pkgs/x/default.nix\n"
        "--- a/pkgs/x/default.nix\n+++ b/pkgs/x/default.nix\n"
        "@@ -53,6 +53,7 @@ stdenv.mkDerivation (rec {\n"
        "     ./other.patch\n+    ./CVE.patch\n   ];\n"
    )
    (bd / "review.md").write_text("## Verdict\naccept\n")
    (bd / "bundle.sig").write_text("sig")
    return bd


def _multi_hunk_base(root: Path, name: str = "CVE-2025-0003--mh") -> Path:
    """A single-file backport with two @@ hunks. Reordering the hunks within
    the file is content-preserving."""
    bd = root / name
    bd.mkdir(parents=True)
    (bd / "bundle.json").write_text(json.dumps({"bundle_id": "b3", "cve_id": "CVE-2025-0003"}))
    (bd / "patch.diff").write_text(
        "diff --git a/src/foo.c b/src/foo.c\n--- a/src/foo.c\n+++ b/src/foo.c\n"
        "@@ -10,3 +10,4 @@\n ctx1\n+added_line_A\n more1\n"
        "@@ -40,3 +40,4 @@\n ctx2\n+added_line_B\n more2\n"
    )
    return bd


def _changed_lines(diff: str) -> set:
    return {l for l in diff.splitlines() if l[:1] in "+-" and not l.startswith(("+++", "---"))}


def test_reorg_reorders_file_sections(tmp_path):
    base = _two_section_base(tmp_path / "ex")
    before = (base / "patch.diff").read_text()
    out = tmp_path / "pos" / "r1"
    rc = mut.run(_reorg_args(base, "reorder-hunks", out))
    assert rc == 0
    after = (out / "patch.diff").read_text()
    assert after != before                          # layout changed
    assert _changed_lines(after) == _changed_lines(before)  # content preserved
    # default.nix section now precedes the CVE.patch section
    assert after.index("default.nix") < after.index("CVE.patch b/")
    marker = json.loads((out / "reorg.json").read_text())
    assert marker["positive_source"] == "reorg"
    assert marker["reorg_type"] == "reorder-hunks"
    assert marker["expected_reviewer_verdict"] == "accept"


def test_reorg_reorders_hunks_within_file(tmp_path):
    base = _multi_hunk_base(tmp_path / "ex")
    before = (base / "patch.diff").read_text()
    out = tmp_path / "pos" / "r2"
    rc = mut.run(_reorg_args(base, "reorder-hunks", out))
    assert rc == 0
    after = (out / "patch.diff").read_text()
    assert _changed_lines(after) == _changed_lines(before)
    # hunk B now appears before hunk A
    assert after.index("added_line_B") < after.index("added_line_A")
    # the single file header is not duplicated
    assert after.count("diff --git a/src/foo.c") == 1


def test_reorg_strips_review_and_signing(tmp_path):
    base = _two_section_base(tmp_path / "ex")
    out = tmp_path / "pos" / "r3"
    mut.run(_reorg_args(base, "reorder-hunks", out))
    assert not (out / "review.md").exists()
    assert not (out / "bundle.sig").exists()


def test_reorg_refuses_unreorderable(tmp_path):
    # single file, single hunk -> nothing to reorder -> refuse + roll back
    base = tmp_path / "ex" / "CVE-2025-0004--one"
    base.mkdir(parents=True)
    (base / "bundle.json").write_text(json.dumps({"bundle_id": "b4", "cve_id": "CVE-2025-0004"}))
    (base / "patch.diff").write_text(
        "diff --git a/f.c b/f.c\n--- a/f.c\n+++ b/f.c\n@@ -1,2 +1,3 @@\n ctx\n+only\n more\n"
    )
    out = tmp_path / "pos" / "r4"
    rc = mut.run(_reorg_args(base, "reorder-hunks", out))
    assert rc == 2
    assert not out.exists()  # rolled back
