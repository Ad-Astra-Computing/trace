"""The authoring eval drivers must capture live-call usage.

Section 7 of COST_REPORT_v1.1.0 named this the top uninstrumented spend:
the authoring accuracy runs received adapter usage blocks and discarded
them. These tests pin the capture seam so a live run now records tokens.
"""

from __future__ import annotations

import json

import eval.author_blind_eval as abe
from eval import expand_screen as es


class _Resp:
    def __init__(self, payload: dict) -> None:
        self._payload = payload

    def read(self) -> bytes:
        return json.dumps(self._payload).encode()


def _canned(monkeypatch, text: str, usage: dict) -> None:
    monkeypatch.setattr(
        abe.urllib.request,
        "urlopen",
        lambda *a, **k: _Resp(
            {"content": [{"type": "text", "text": text}], "usage": usage}
        ),
    )
    monkeypatch.setenv("ANTHROPIC_API_KEY", "test-key")


def test_api_records_usage_into_sink(monkeypatch) -> None:
    _canned(monkeypatch, "hi", {"input_tokens": 12, "output_tokens": 3})
    sink: list = []
    out = abe._api("prompt", usage_sink=sink)
    assert out == "hi"
    assert sink == [
        {
            "model": abe.MODEL,
            "input_tokens": 12,
            "output_tokens": 3,
            "cache_creation_input_tokens": None,
            "cache_read_input_tokens": None,
        }
    ]


def test_api_without_sink_returns_text_and_records_nothing(monkeypatch) -> None:
    _canned(monkeypatch, "ok", {"input_tokens": 5, "output_tokens": 1})
    assert abe._api("prompt") == "ok"  # no sink -> unchanged behavior


def test_screen_bundle_feeds_sink_through_default_judge(tmp_path, monkeypatch) -> None:
    (tmp_path / "upstream-fix.patch").write_text("--- a\n+++ b\n@@ -1 +1 @@\n-x\n+y\n")
    monkeypatch.setattr(es, "_reproducer_kind", lambda d: "behavioral")
    _canned(monkeypatch, "GOLD\nequivalent", {"input_tokens": 40, "output_tokens": 8})
    sink: list = []
    r = es.screen_bundle(
        tmp_path,
        traces_root=tmp_path,
        author_fn=lambda d: {
            "cve": "CVE-X",
            "verdict": "differs",
            "authored_diff": "--- a\n+++ b\n@@ -1 +1 @@\n-x\n+y\n",
            "src_origin": "cache",
        },
        usage_sink=sink,
    )
    assert r["judge"]["judge"] == "GOLD"
    # the default judge (_api) fed the sink; the injected author_fn did not
    assert len(sink) == 1
    assert sink[0]["model"] == abe.MODEL
    assert sink[0]["input_tokens"] == 40 and sink[0]["output_tokens"] == 8


def test_screen_bundle_injected_judge_leaves_sink_untouched(
    tmp_path, monkeypatch
) -> None:
    """An injected judge_api keeps its single-arg convention and is not
    forced to feed the sink; only the default real seam does."""
    (tmp_path / "upstream-fix.patch").write_text("--- a\n+++ b\n@@ -1 +1 @@\n-x\n+y\n")
    monkeypatch.setattr(es, "_reproducer_kind", lambda d: "behavioral")
    sink: list = []
    r = es.screen_bundle(
        tmp_path,
        traces_root=tmp_path,
        author_fn=lambda d: {
            "cve": "CVE-X",
            "verdict": "differs",
            "authored_diff": "d",
            "src_origin": "cache",
        },
        judge_api=lambda p: "GOLD\n",
        usage_sink=sink,
    )
    assert r["judge"]["judge"] == "GOLD"
    assert sink == []
