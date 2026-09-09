"""Tests for the Authoring LoRA packager (eval/package_authoring_lora.py)."""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path

import pytest

_SPEC = importlib.util.spec_from_file_location(
    "package_authoring_lora",
    Path(__file__).resolve().parents[2] / "eval" / "package_authoring_lora.py",
)
pal = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(pal)


def _rec(
    split,
    *,
    tier="behavioral-only",
    user="vuln desc",
    n_user=10,
    fix="--- a/f.c\n+++ b/f.c\n@@ -1,1 +1,1 @@\n-old\n+new\n",
):
    return {
        "split": split,
        "task": "author-from-vuln",
        "provenance": {
            "cve_id": f"CVE-test-{split}",
            "authoring_validation_tier": tier,
        },
        "messages": [
            {"role": "system", "content": "You are a security patch author."},
            {"role": "user", "content": user * n_user},
            {"role": "assistant", "content": fix},
        ],
    }


def _setup(monkeypatch, tmp_path, rows):
    src = tmp_path / "authoring.jsonl"
    src.write_text("".join(json.dumps(r) + "\n" for r in rows))
    monkeypatch.setattr(pal, "SRC", src)
    monkeypatch.setattr(pal, "OUT", tmp_path / "authoring-lora")


def test_packages_messages_only_per_split(monkeypatch, tmp_path):
    _setup(
        monkeypatch,
        tmp_path,
        [
            _rec("train"),
            _rec("train", tier="cert-green"),
            _rec("dev"),
        ],
    )
    m = pal.package(seq_len=16384)
    assert m["splits"] == {"train": 2, "dev": 1, "test": 0}
    assert m["tiers"] == {"behavioral-only": 2, "cert-green": 1}
    # training lines carry ONLY messages
    line = json.loads(
        (tmp_path / "authoring-lora" / "authoring.train.jsonl")
        .read_text()
        .splitlines()[0]
    )
    assert list(line.keys()) == ["messages"]
    assert m["validation_errors"] == []
    assert m["base_model"] == "Qwen2.5-Coder-14B"
    assert m["task"] == "author-from-vuln-sft"


def test_flags_over_seq_len_record(monkeypatch, tmp_path):
    big = _rec("train", n_user=5000)  # ~75k chars -> ~18k tokens
    _setup(monkeypatch, tmp_path, [big, _rec("train")])
    m = pal.package(seq_len=1000)
    assert len(m["over_seq_len"]) == 1
    assert m["over_seq_len"][0]["est_tokens"] > 1000


def test_validation_errors_on_wrong_task(monkeypatch, tmp_path):
    bad = _rec("train")
    bad["task"] = "reviewer-accept-reject"
    _setup(monkeypatch, tmp_path, [bad])
    m = pal.package(seq_len=16384)
    assert m["validation_errors"]
    assert pal.main([]) == 1


def test_validation_errors_on_bad_roles(monkeypatch, tmp_path):
    bad = _rec("train")
    bad["messages"] = [{"role": "user", "content": "only one role"}]
    _setup(monkeypatch, tmp_path, [bad])
    m = pal.package(seq_len=16384)
    assert m["validation_errors"]


def test_empty_content_is_flagged(monkeypatch, tmp_path):
    r = _rec("train")
    r["messages"][2]["content"] = "   "
    _setup(monkeypatch, tmp_path, [r])
    m = pal.package(seq_len=16384)
    assert any("empty assistant" in e for e in m["validation_errors"])


def test_tiers_by_split(monkeypatch, tmp_path):
    _setup(
        monkeypatch,
        tmp_path,
        [
            _rec("train"),
            _rec("train", tier="cert-green"),
            _rec("dev", tier="cert-green"),
        ],
    )
    m = pal.package(seq_len=16384)
    assert m["tiers_by_split"]["train"] == {"behavioral-only": 1, "cert-green": 1}
    assert m["tiers_by_split"]["dev"] == {"cert-green": 1}
