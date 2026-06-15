"""Tests for the Reviewer-LoRA corpus readiness gate (eval/corpus_readiness.py).

The gate's analysis logic is tested against synthetic exporter manifests (the live
`trace export` shell-out is monkeypatched), so the test is fast + offline.
"""

from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest

_SPEC = importlib.util.spec_from_file_location(
    "corpus_readiness",
    Path(__file__).resolve().parents[2] / "eval" / "corpus_readiness.py",
)
cr = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(cr)


def _manifests(monkeypatch, reviewer: dict, authoring: dict | None = None,
               dirty: list | None = None, uncerted: list | None = None) -> None:
    def fake_export(scope: str):
        return reviewer if scope == "reviewer" else (authoring or {"eligible_examples": 0, "splits": {}})
    monkeypatch.setattr(cr, "_export", fake_export)
    # the disk cross-checks hit real disk; mock them (default: clean)
    monkeypatch.setattr(cr, "_schema_invalid_bundles", lambda: (dirty or []))
    monkeypatch.setattr(cr, "_uncerted_auto_merge_positives", lambda: (uncerted or []))


def test_not_ready_below_positive_threshold(monkeypatch):
    _manifests(monkeypatch, {
        "labels": {"positive": 28, "negative": 25},
        "leakage_check_ok": True, "splits": {"train": 38}, "families": [], "excluded": [],
    })
    r = cr.build_report(50, 25)
    assert r["pilot_ready"] is False
    assert r["reviewer"]["positive_gap"] == 22
    assert r["reviewer"]["negative_gap"] == 0
    assert any("22 cert-green positives" in b for b in r["blocking"])


def test_ready_when_thresholds_met_and_no_leakage(monkeypatch):
    _manifests(monkeypatch, {
        "labels": {"positive": 50, "negative": 25},
        "leakage_check_ok": True, "splits": {"train": 50}, "families": [], "excluded": [],
    })
    r = cr.build_report(50, 25)
    assert r["pilot_ready"] is True
    assert r["blocking"] == []


def test_schema_invalid_bundles_block_readiness_even_at_threshold(monkeypatch):
    """A nominal 50/25 with schema-invalid/uncerted bundles is NOT ready — the gate
    must not report READY while review-accept counts hide dirty bundles (codex 2026-06-15)."""
    _manifests(monkeypatch, {
        "labels": {"positive": 50, "negative": 25},
        "leakage_check_ok": True, "splits": {"train": 50}, "families": [], "excluded": [],
    }, dirty=[{"bundle": "CVE-X--foo", "error": "missing expect.json"}])
    r = cr.build_report(50, 25)
    assert r["pilot_ready"] is False
    assert r["schema_invalid"] and r["schema_invalid"][0]["bundle"] == "CVE-X--foo"
    assert any("schema-invalid" in b for b in r["blocking"])


def test_uncerted_auto_merge_blocks_readiness_even_at_threshold(monkeypatch):
    """A nominal 50/25 where some auto-merge positives are review-accept but NOT
    cert-green+signed is NOT ready: those don't count toward the 50, and they appear
    in the uncerted-auto-merge blocking bucket (codex 2026-06-15)."""
    _manifests(monkeypatch, {
        "labels": {"positive": 50, "negative": 25},
        "leakage_check_ok": True, "splits": {"train": 50}, "families": [], "excluded": [],
    }, uncerted=[{"bundle": "CVE-Y--bar", "subreason": "missing-bundle-sig"}])
    r = cr.build_report(50, 25)
    assert r["pilot_ready"] is False
    assert r["reviewer"]["positive_cert_green"] == 49      # 50 - 1 uncerted
    assert r["reviewer"]["positive_gap"] == 1
    assert r["uncerted_auto_merge"][0]["bundle"] == "CVE-Y--bar"
    assert any("uncerted-auto-merge" in b for b in r["blocking"])


def test_leakage_blocks_readiness_even_at_threshold(monkeypatch):
    _manifests(monkeypatch, {
        "labels": {"positive": 50, "negative": 25},
        "leakage_check_ok": False, "splits": {}, "families": [], "excluded": [],
    })
    r = cr.build_report(50, 25)
    assert r["pilot_ready"] is False
    assert any("leakage" in b for b in r["blocking"])


def test_exclusions_classified_recoverable_vs_structural(monkeypatch):
    _manifests(monkeypatch, {
        "labels": {"positive": 30, "negative": 25}, "leakage_check_ok": True,
        "splits": {}, "families": [],
        "excluded": [
            {"bundle": "CVE-A", "reason": "attestation mismatch (review.md vs replay): x"},
            {"bundle": "CVE-B", "reason": "no reviewer target (review.md / review-refusal.json)"},
            {"bundle": "CVE-C", "reason": "duplicate (cve_id, attr_path, mutation_type)"},
            {"bundle": "CVE-D", "reason": "review.md fails reviewer parser contract: ..."},
        ],
    })
    r = cr.build_report(50, 25)
    rec = {e["bundle"] for e in r["exclusions"]["recoverable"]}
    struct = {e["bundle"] for e in r["exclusions"]["structural"]}
    assert rec == {"CVE-A", "CVE-B"}        # attestation + no-review → triage candidates
    assert struct == {"CVE-C", "CVE-D"}     # dupe + parser-fail → structural
    assert r["exclusions"]["total"] == 4


def test_schema_invalid_flags_placeholder_nixpkgs_rev(monkeypatch, tmp_path):
    """_schema_invalid_bundles must flag a real-CVE bundle whose nixpkgs_rev is the
    all-zero placeholder — the bundle-schema pattern ^[0-9a-f]{40}$ ACCEPTS 40 zeros,
    so without this explicit check an unverifiable-provenance bundle would count toward
    the corpus (codex 2026-06-15, salvage-backport placeholder-rev bundles)."""
    import json
    import types
    ex = tmp_path / "traces" / "example"
    good = ex / "CVE-2026-1111--foo"
    bad = ex / "CVE-2026-2222--bar"
    good.mkdir(parents=True)
    bad.mkdir(parents=True)
    (good / "bundle.json").write_text(json.dumps({"nixpkgs_rev": "a" * 40}))
    (good / "expect.json").write_text("{}")
    (bad / "bundle.json").write_text(json.dumps({"nixpkgs_rev": "0" * 40}))
    (bad / "expect.json").write_text("{}")
    monkeypatch.setattr(cr, "REPO", tmp_path)
    # stub the schema validator so the good bundle isn't flagged for unrelated
    # reasons — we're testing the explicit placeholder-rev check, which runs first.
    import tests.schema.validate as v
    monkeypatch.setattr(
        v, "validate_fixture",
        lambda bd: types.SimpleNamespace(any_errors=False, per_doc_errors={}, hash_errors=[]),
    )
    flagged = {d["bundle"]: d["error"] for d in cr._schema_invalid_bundles()}
    assert "CVE-2026-2222--bar" in flagged
    assert "nixpkgs_rev" in flagged["CVE-2026-2222--bar"]
    assert "CVE-2026-1111--foo" not in flagged


def test_main_exit_code_reflects_readiness(monkeypatch, capsys):
    _manifests(monkeypatch, {
        "labels": {"positive": 10, "negative": 25}, "leakage_check_ok": True,
        "splits": {}, "families": [], "excluded": [],
    })
    assert cr.main([]) == 1          # not ready → nonzero (CI-gatable)
    assert cr.main(["--pos", "10"]) == 0   # lower the bar → ready
