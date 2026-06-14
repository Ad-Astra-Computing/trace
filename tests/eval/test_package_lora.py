"""Tests for the Reviewer LoRA packager (eval/package_lora.py)."""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path

import pytest

_SPEC = importlib.util.spec_from_file_location(
    "package_lora", Path(__file__).resolve().parents[2] / "eval" / "package_lora.py")
pl = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(pl)


def _rec(split, label, *, asst="## Verdict\naccept\n", user="x", n_user=10):
    return {"split": split, "label": label,
            "provenance": {"cve_id": f"CVE-{label}-{split}", "reviewer_prompt_sha": "abc"},
            "messages": [{"role": "system", "content": "sys"},
                         {"role": "user", "content": user * n_user},
                         {"role": "assistant", "content": asst}]}


def _setup(monkeypatch, tmp_path, rows):
    src = tmp_path / "reviewer.jsonl"
    src.write_text("".join(json.dumps(r) + "\n" for r in rows))
    monkeypatch.setattr(pl, "SRC", src)
    monkeypatch.setattr(pl, "OUT", tmp_path / "lora")


def test_packages_messages_only_per_split(monkeypatch, tmp_path):
    _setup(monkeypatch, tmp_path, [
        _rec("train", "positive"), _rec("train", "negative"),
        _rec("dev", "positive"), _rec("test", "negative")])
    m = pl.package(seq_len=8192)
    assert m["splits"] == {"train": 2, "dev": 1, "test": 1}
    assert m["label_balance"]["train"] == {"positive": 1, "negative": 1}
    # training lines carry ONLY messages — no split/label/provenance leakage
    line = json.loads((tmp_path / "lora" / "reviewer.train.jsonl").read_text().splitlines()[0])
    assert list(line.keys()) == ["messages"]
    assert m["validation_errors"] == []
    assert m["base_model"] == "Qwen2.5-Coder-14B"


def test_flags_over_seq_len_record(monkeypatch, tmp_path):
    big = _rec("train", "positive", n_user=10000)  # ~25k chars -> ~6k tok over a 1k budget
    _setup(monkeypatch, tmp_path, [big, _rec("train", "negative")])
    m = pl.package(seq_len=1000)
    assert len(m["over_seq_len"]) == 1
    assert m["over_seq_len"][0]["est_tokens"] > 1000


def test_validation_errors_block(monkeypatch, tmp_path):
    bad = {"split": "train", "label": "positive",
           "provenance": {"cve_id": "CVE-bad"},
           "messages": [{"role": "user", "content": "only one role"}]}
    _setup(monkeypatch, tmp_path, [bad])
    m = pl.package(seq_len=8192)
    assert m["validation_errors"]
    assert pl.main([]) == 1  # nonzero exit gates CI


def test_empty_content_is_flagged(monkeypatch, tmp_path):
    r = _rec("train", "negative")
    r["messages"][2]["content"] = "   "
    _setup(monkeypatch, tmp_path, [r])
    m = pl.package(seq_len=8192)
    assert any("empty assistant" in e for e in m["validation_errors"])
