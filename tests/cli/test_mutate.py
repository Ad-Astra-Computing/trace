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


def test_refuses_existing_out_dir(tmp_path):
    base = _base_bundle(tmp_path / "ex")
    out = tmp_path / "neg" / "m6"
    out.mkdir(parents=True)
    rc = mut.run(_args(base, "wrong-src-hash", out))
    assert rc == 2
