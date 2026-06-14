"""finalize-time schema guardrail (tools/trace_cli/bundle.py).

`trace bundle finalize` refuses to write bundle.json when a resolver-side
document fails policy-schema validation. This stops the recurring prefetch-pin
defect (prefetch_kind outside the enum; nixpkgs_commit/note extra fields) and
malformed impact/maintainers at bundle CREATION rather than at CI — the failure
mode that flooded the tree when ~10 concurrent sessions hand-pinned hashes
wrong (2026-06-14). DECISIONS:47 had documented the trap with no guardrail.
"""

from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest

from tools.trace_cli.bundle import (
    BundleSchemaError,
    _validate_bundle_docs,
    finalize_bundle,
)

# A committed, schema-valid human-review bundle whose upstream-ref carries a
# manual-pinned prefetch_hashes entry (prefetch_kind=fetchzip) — the clean base.
_GOOD = Path(__file__).resolve().parents[2] / "traces" / "example" / "CVE-2024-8176--expat"
_DOCS = ("finding.json", "impact.json", "maintainers.json", "upstream-ref.json",
         "package.nix")


def _seed(tmp_path: Path) -> Path:
    """Copy the clean resolver-side docs of a valid bundle into a temp dir."""
    bd = tmp_path / "bundle"
    bd.mkdir()
    for f in _DOCS:
        shutil.copyfile(_GOOD / f, bd / f)
    return bd


def _edit(bd: Path, name: str, mutate) -> None:
    p = bd / name
    doc = json.loads(p.read_text())
    mutate(doc)
    p.write_text(json.dumps(doc, indent=2))


# ── the pure validator ──────────────────────────────────────────────────────

def test_clean_bundle_validates(tmp_path):
    bd = _seed(tmp_path)
    assert _validate_bundle_docs(bd) == []


def test_bad_prefetch_kind_is_flagged(tmp_path):
    bd = _seed(tmp_path)
    _edit(bd, "upstream-ref.json",
          lambda d: d["prefetch_hashes"][0].__setitem__("prefetch_kind", "fetchurl"))
    errs = _validate_bundle_docs(bd)
    assert any("prefetch_kind" in e for e in errs), errs


def test_extra_prefetch_field_is_flagged(tmp_path):
    bd = _seed(tmp_path)
    _edit(bd, "upstream-ref.json",
          lambda d: d["prefetch_hashes"][0].update({"nixpkgs_commit": "abc123", "note": "x"}))
    errs = _validate_bundle_docs(bd)
    assert any("nixpkgs_commit" in e or "Additional properties" in e for e in errs), errs


def test_malformed_impact_is_flagged(tmp_path):
    bd = _seed(tmp_path)
    _edit(bd, "impact.json", lambda d: d.pop("per_attr", None))
    errs = _validate_bundle_docs(bd)
    assert any("impact.json" in e for e in errs), errs


# ── finalize refuses ────────────────────────────────────────────────────────

def test_finalize_succeeds_on_clean_bundle(tmp_path):
    bd = _seed(tmp_path)
    res = finalize_bundle(bundle_dir=bd, bundle_kind="human-review-required",
                          created_at="2026-06-14T00:00:00Z")
    assert (bd / "bundle.json").is_file()
    assert res.bundle_id


def test_finalize_refuses_bad_prefetch_kind(tmp_path):
    bd = _seed(tmp_path)
    _edit(bd, "upstream-ref.json",
          lambda d: d["prefetch_hashes"][0].__setitem__("prefetch_kind", "fetchurl"))
    with pytest.raises(BundleSchemaError) as exc:
        finalize_bundle(bundle_dir=bd, bundle_kind="human-review-required",
                        created_at="2026-06-14T00:00:00Z")
    assert "prefetch_kind" in str(exc.value)
    # guardrail fired BEFORE writing bundle.json
    assert not (bd / "bundle.json").is_file()


def test_finalize_refuses_extra_prefetch_field(tmp_path):
    bd = _seed(tmp_path)
    _edit(bd, "upstream-ref.json",
          lambda d: d["prefetch_hashes"][0].update({"nixpkgs_commit": "abc", "note": "n"}))
    with pytest.raises(BundleSchemaError):
        finalize_bundle(bundle_dir=bd, bundle_kind="human-review-required",
                        created_at="2026-06-14T00:00:00Z")
    assert not (bd / "bundle.json").is_file()
