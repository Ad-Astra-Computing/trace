"""finalize behaviour for the source-context manifest (semantic-backport-adaptation slice 2).

`trace bundle finalize` bumps a source-backport bundle to schema_version 1.1.0
and emits the signed source_context manifest ONLY when a source-context/ dir is
present. A source-backport WITHOUT source-context stays 1.0.0 (the v3 verbatim
lane) — this is what keeps every one of the 117 previously-signed source-backport
bundles byte-stable through a re-finalize. The produced 1.1.0 bundle.json must
validate against the amended policy/bundle-schema.json.
"""

from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest

from tools.trace_cli.bundle import BundleSchemaError, finalize_bundle
from tests.schema.validate import REPO_ROOT, load_schemas, validators

# A clean source-backport bundle whose resolver docs finalize without warnings.
_ZLIB = REPO_ROOT / "traces" / "example" / "CVE-2022-37434--zlib-backport"
_DOCS = ("finding.json", "impact.json", "maintainers.json", "upstream-ref.json",
         "package.nix", "upstream-fix.patch")


def _seed(tmp_path: Path) -> Path:
    bd = tmp_path / "bundle"
    bd.mkdir()
    for f in _DOCS:
        src = _ZLIB / f
        if src.is_file():
            shutil.copyfile(src, bd / f)
    return bd


def _write_source_context(bd: Path, rel: str, content: str) -> None:
    p = bd / "source-context" / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(content)


def _finalize(bd: Path):
    return finalize_bundle(bundle_dir=bd, bundle_kind="human-review-required",
                           created_at="2026-07-27T00:00:00Z")


def _validate_bundle_json(bd: Path) -> list[str]:
    schemas = load_schemas()
    v = validators(schemas)["bundle"]
    doc = json.loads((bd / "bundle.json").read_text())
    return [e.message for e in v.iter_errors(doc)]


# ── 1.1.0 path ────────────────────────────────────────────────────────────────

def test_source_context_bumps_to_1_1_0(tmp_path):
    bd = _seed(tmp_path)
    _write_source_context(bd, "contrib/minizip/foo.c", "int foo(void){return 0;}\n")
    _finalize(bd)
    b = json.loads((bd / "bundle.json").read_text())
    assert b["schema_version"] == "1.1.0"
    assert b["patch_strategy"] == "source-backport"
    # manifest entry present, sorted, sha matches files{} entry
    key = "source-context/contrib/minizip/foo.c"
    assert [e["path"] for e in b["source_context"]] == [key]
    assert b["source_context"][0]["sha256"] == b["files"][key]["sha256"]
    assert b["files"][key]["producer_role"] == "source-context-extractor"
    assert b["files"][key]["replay_critical"] is True
    # signed
    signed = {sf["path"] for sf in b["signed_manifest"]["signed_files"]}
    assert key in signed
    # schema-valid
    assert _validate_bundle_json(bd) == []


def test_source_context_manifest_sorted(tmp_path):
    bd = _seed(tmp_path)
    _write_source_context(bd, "zzz.c", "z\n")
    _write_source_context(bd, "aaa.c", "a\n")
    _finalize(bd)
    b = json.loads((bd / "bundle.json").read_text())
    paths = [e["path"] for e in b["source_context"]]
    assert paths == sorted(paths)
    assert paths == ["source-context/aaa.c", "source-context/zzz.c"]


# ── grandfathering: no source-context → stays 1.0.0 ─────────────────────────────

def test_no_source_context_stays_1_0_0(tmp_path):
    bd = _seed(tmp_path)
    _finalize(bd)
    b = json.loads((bd / "bundle.json").read_text())
    assert b["schema_version"] == "1.0.0"
    assert "patch_strategy" not in b
    assert "source_context" not in b
    assert _validate_bundle_json(bd) == []


# ── guards ──────────────────────────────────────────────────────────────────

def test_source_context_on_non_source_backport_rejected(tmp_path):
    """source-context on a version-bump upstream-ref is a contract violation."""
    bd = _seed(tmp_path)
    ur = json.loads((bd / "upstream-ref.json").read_text())
    ur.setdefault("eligibility", {})["patch_strategy"] = "version-bump"
    (bd / "upstream-ref.json").write_text(json.dumps(ur, indent=2))
    _write_source_context(bd, "foo.c", "x\n")
    with pytest.raises(BundleSchemaError, match="not a source-backport"):
        _finalize(bd)


def test_symlinked_source_context_root_rejected(tmp_path):
    """A source-context root that is itself a symlink must be refused before
    rglob() hashes/signs an external tree (codex P1)."""
    bd = _seed(tmp_path)
    external = tmp_path / "external"
    external.mkdir()
    (external / "secret.c").write_text("stolen\n")
    (bd / "source-context").symlink_to(external)
    with pytest.raises(BundleSchemaError, match="root is a symlink"):
        _finalize(bd)


def test_symlink_in_source_context_rejected(tmp_path):
    bd = _seed(tmp_path)
    (bd / "source-context").mkdir()
    secret = tmp_path / "secret.txt"
    secret.write_text("s\n")
    (bd / "source-context" / "foo.c").symlink_to(secret)
    with pytest.raises(BundleSchemaError, match="symlink"):
        _finalize(bd)
