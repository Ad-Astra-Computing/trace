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
               dirty: list | None = None) -> None:
    def fake_export(scope: str):
        return reviewer if scope == "reviewer" else (authoring or {"eligible_examples": 0, "splits": {}})
    monkeypatch.setattr(cr, "_export", fake_export)
    # the schema-validity cross-check hits real disk; mock it (default: clean)
    monkeypatch.setattr(cr, "_schema_invalid_bundles", lambda: (dirty or []))


def test_not_ready_below_positive_threshold(monkeypatch):
    _manifests(monkeypatch, {
        "labels": {"positive": 28, "negative": 25},
        "leakage_check_ok": True, "splits": {"train": 38}, "families": [], "excluded": [],
    })
    r = cr.build_report(50, 25)
    assert r["pilot_ready"] is False
    assert r["reviewer"]["positive_gap"] == 22
    assert r["reviewer"]["negative_gap"] == 0
    assert any("22 positives" in b for b in r["blocking"])


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


def test_main_exit_code_reflects_readiness(monkeypatch, capsys):
    _manifests(monkeypatch, {
        "labels": {"positive": 10, "negative": 25}, "leakage_check_ok": True,
        "splits": {}, "families": [], "excluded": [],
    })
    assert cr.main([]) == 1          # not ready → nonzero (CI-gatable)
    assert cr.main(["--pos", "10"]) == 0   # lower the bar → ready
