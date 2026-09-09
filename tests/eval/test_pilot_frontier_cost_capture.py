"""Token-usage capture in the authoring-pilot and frontier-baseline drivers.

Both drivers make live Anthropic calls whose responses carry a usage block;
before this slice they discarded it, so COST_REPORT §7 listed their spend as
uninstrumented. These tests pin the capture seam: the drivers now roll the
usage into a `cost` block via agents.cost.rollup_usage.
"""

from __future__ import annotations

import json
from pathlib import Path

import eval.score_authoring_pilot as ap
import eval.frontier_baseline as fb


class _FakeResp:
    def __init__(self) -> None:
        self.text = "--- a/x\n+++ b/x\n@@ -1 +1 @@\n-bad\n+good\n"
        self.input_tokens = 1000
        self.output_tokens = 500
        self.cache_creation_input_tokens = None
        self.cache_read_input_tokens = None


class _FakeAdapter:
    def __init__(self, model_id: str) -> None:
        self.model_id = model_id

    def invoke(self, *, system_prompt, user_content, sampling):
        return _FakeResp()


def _record() -> dict:
    return {
        "messages": [
            {"role": "system", "content": "sys"},
            {"role": "user", "content": "usr"},
        ],
        "provenance": {"cve_id": "CVE-2026-0001"},
    }


def test_authoring_generate_records_usage(monkeypatch) -> None:
    import agents.patcher.adapter as adapter_mod

    monkeypatch.setattr(adapter_mod, "AnthropicAdapter", _FakeAdapter)
    sink: list = []
    gen = ap._generate([_record()], "claude-opus-4-7", usage_sink=sink)
    assert "CVE-2026-0001" in gen
    assert len(sink) == 1
    assert sink[0]["input_tokens"] == 1000
    assert sink[0]["output_tokens"] == 500
    from agents.cost import rollup_usage

    cost = rollup_usage(sink)
    assert cost["observed_calls"] == 1
    assert cost["total_usd"] > 0


def test_authoring_generate_without_sink_is_unchanged(monkeypatch) -> None:
    import agents.patcher.adapter as adapter_mod

    monkeypatch.setattr(adapter_mod, "AnthropicAdapter", _FakeAdapter)
    gen = ap._generate([_record()], "claude-opus-4-7")
    assert gen["CVE-2026-0001"].startswith("--- a/x")


def test_frontier_run_baseline_emits_cost(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setattr(
        fb,
        "_call_api",
        lambda model_id, system, user: (
            "text",
            {
                "input_tokens": 2000,
                "output_tokens": 100,
                "cache_creation_input_tokens": 0,
                "cache_read_input_tokens": 0,
            },
        ),
    )
    monkeypatch.setattr(
        fb,
        "score_example",
        lambda rec, text, dry_run=False: {
            "verdict_correct": True,
            "schema_valid": True,
            "evidence_cited": True,
            "parse_failure": False,
            "label": rec.get("label", "positive"),
            "actual_verdict": "accept",
            "cve_id": rec.get("provenance", {}).get("cve_id"),
            "mutation_type": rec.get("provenance", {}).get("mutation_type"),
        },
    )

    export = tmp_path / "reviewer.jsonl"
    export.write_text(
        json.dumps(
            {
                "split": "test",
                "label": "positive",
                "messages": [
                    {"role": "system", "content": "s"},
                    {"role": "user", "content": "u"},
                ],
                "provenance": {"cve_id": "CVE-2026-0002", "attr_path": "pkg"},
            }
        )
        + "\n"
    )
    out = fb.run_baseline(export, tmp_path / "out.json", "claude-sonnet-4-5", False)
    assert out["cost"]["observed_calls"] == 1
    assert out["cost"]["total_usd"] > 0
    assert out["total_usage"]["input_tokens"] == 2000


def test_frontier_dry_run_cost_is_zero(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setattr(
        fb,
        "score_example",
        lambda rec, text, dry_run=False: {
            "verdict_correct": True,
            "schema_valid": True,
            "evidence_cited": True,
            "parse_failure": False,
            "label": rec.get("label", "positive"),
            "actual_verdict": "accept",
            "cve_id": rec.get("provenance", {}).get("cve_id"),
            "mutation_type": rec.get("provenance", {}).get("mutation_type"),
        },
    )
    export = tmp_path / "reviewer.jsonl"
    export.write_text(
        json.dumps(
            {
                "split": "test",
                "label": "positive",
                "messages": [{"role": "user", "content": "u"}],
                "provenance": {"cve_id": "CVE-2026-0003", "attr_path": "pkg"},
            }
        )
        + "\n"
    )
    out = fb.run_baseline(export, tmp_path / "out.json", "claude-sonnet-4-5", True)
    assert out["cost"]["calls"] == 0
    assert out["cost"]["total_usd"] == 0.0
