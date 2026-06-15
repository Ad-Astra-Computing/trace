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


# ── kind_reason mapping + replay-drift refresh (codex review 2026-06-15) ──────

def test_ambiguous_changelog_maps_to_its_own_kind_reason(tmp_path):
    """human_review_trigger=ambiguous-changelog must NOT fall back to the
    major-version-jump kind_reason (which polluted routing/training metadata)."""
    bd = _seed(tmp_path)
    _edit(bd, "upstream-ref.json", lambda d: d.setdefault("eligibility", {}).update(
        {"verdict": "eligible-requires-human-review",
         "verdict_reason": "multi-release span; ambiguous changelog needs human sign-off",
         "human_review_trigger": "ambiguous-changelog"}))
    # blast-radius takes precedence over the trigger; force it off so the
    # ambiguous-changelog mapping is the one under test.
    def _blast_off(d):
        d["exceeds_threshold"] = False
        for pa in d.get("per_attr", []):
            pa["exceeds_threshold"] = False
    _edit(bd, "impact.json", _blast_off)
    res = finalize_bundle(bundle_dir=bd, bundle_kind="human-review-required",
                          created_at="2026-06-14T00:00:00Z")
    import json
    b = json.loads((bd / "bundle.json").read_text())
    assert b["kind_reason"] == "ambiguous-changelog-requires-review"


def test_refinalize_after_pin_keeps_resolver_transcript_consistent(tmp_path):
    """After a manual prefetch pin + re-finalize, the upstream-ref-resolver
    invocation's recorded output sha must match the on-disk upstream-ref.json
    (no replay drift)."""
    import json
    bd = _seed(tmp_path)
    finalize_bundle(bundle_dir=bd, bundle_kind="human-review-required",
                    created_at="2026-06-14T00:00:00Z")
    # operator pins a different prefetch value, then re-finalizes
    _edit(bd, "upstream-ref.json",
          lambda d: d["prefetch_hashes"][0].__setitem__(
              "value", "sha256-AAAA1111BBBB2222CCCC3333DDDD4444EEEE5555FFs="))
    finalize_bundle(bundle_dir=bd, bundle_kind="human-review-required",
                    created_at="2026-06-14T00:00:00Z")
    b = json.loads((bd / "bundle.json").read_text())
    r = json.loads((bd / "replay.json").read_text())
    file_sha = b["files"]["upstream-ref.json"]["sha256"]
    res_role = next(x for x in r["roles"] if x["role"] == "upstream-ref-resolver")
    out = next(o for o in res_role["invocations"][0]["outputs"] if o["path"] == "upstream-ref.json")
    assert out["sha256"] == file_sha
