"""finalize behaviour for the repro/ fixture manifest (S5, fable audit 2026-10-06).

A bundle's `repro/` fixtures (e.g. `reproducer.nix`'s crash input) are the
single most security-relevant bytes in the bundle. `finalize_bundle` must
hash, sign and mark them replay-critical, and a re-finalize must not drop
them from `files{}` / `signed_manifest.signed_files` — confirmed empirically
to be silently dropped before this fix (traces/example/CVE-2024-13978--libtiff
re-finalized with `repro/crash_poc.tif` missing from both).
"""

from __future__ import annotations

import json
import shutil
from pathlib import Path

from tools.trace_cli.bundle import finalize_bundle

_LIBTIFF = (
    Path(__file__).resolve().parents[2]
    / "traces"
    / "example"
    / "CVE-2024-13978--libtiff"
)
_DOCS = (
    "finding.json",
    "impact.json",
    "maintainers.json",
    "upstream-ref.json",
    "patch.diff",
    "patch-rationale.md",
    "passthru-tests.json",
    "reproducer.nix",
    "reproducer-log.txt",
    "build.json",
    "review.md",
    "review-scoring-report.json",
    "sbom-delta.json",
)


def _seed(tmp_path: Path) -> Path:
    bd = tmp_path / "bundle"
    bd.mkdir()
    for f in _DOCS:
        src = _LIBTIFF / f
        if src.is_file():
            shutil.copyfile(src, bd / f)
    repro_src = _LIBTIFF / "repro"
    if repro_src.is_dir():
        shutil.copytree(repro_src, bd / "repro")
    scoring = _LIBTIFF / "repro-scoring-report.json"
    if scoring.is_file():
        shutil.copyfile(scoring, bd / "repro-scoring-report.json")
    return bd


def _finalize(bd: Path):
    return finalize_bundle(
        bundle_dir=bd,
        bundle_kind="auto-merge",
        created_at="2026-04-28T20:30:00Z",
    )


def test_repro_fixtures_are_hashed_and_signed(tmp_path):
    bd = _seed(tmp_path)
    _finalize(bd)
    b = json.loads((bd / "bundle.json").read_text())
    key = "repro/crash_poc.tif"
    assert key in b["files"]
    assert b["files"][key]["producer_role"] == "reproducer"
    assert b["files"][key]["replay_critical"] is True
    signed_paths = {e["path"] for e in b["signed_manifest"]["signed_files"]}
    assert key in signed_paths
    assert "repro-scoring-report.json" in b["files"]
    assert "repro-scoring-report.json" in signed_paths


def test_repro_fixtures_survive_a_re_finalize_byte_identical(tmp_path):
    bd = _seed(tmp_path)
    _finalize(bd)
    before = json.loads((bd / "bundle.json").read_text())
    _finalize(bd)
    after = json.loads((bd / "bundle.json").read_text())
    for key in ("repro/crash_poc.tif", "repro-scoring-report.json"):
        assert after["files"][key]["sha256"] == before["files"][key]["sha256"]
        assert key in {e["path"] for e in after["signed_manifest"]["signed_files"]}


def test_absent_repro_dir_is_a_no_op(tmp_path):
    bd = tmp_path / "bundle"
    bd.mkdir()
    for f in _DOCS:
        src = _LIBTIFF / f
        if src.is_file():
            shutil.copyfile(src, bd / f)
    _finalize(bd)
    b = json.loads((bd / "bundle.json").read_text())
    assert not any(k.startswith("repro/") for k in b["files"])
