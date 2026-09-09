"""Tests for the reproducer-gated candidate-expansion screening harness
(eval/expand_screen.py). Verifies the disposition logic, the judge parsing, and
the blind-author → Tier 2 gate → judge wiring with injected functions (no API,
no builds). The load-bearing property: a behaviorally-failing candidate is never
'viable', and the harness never emits a training label.
"""

from __future__ import annotations

import json

from eval import expand_screen as es


# ── disposition logic ─────────────────────────────────────────────────────────


def test_disposition_exact_and_gold():
    assert es._disposition("exact", {"status": "not-gated"}, None) == "viable-exact"
    assert (
        es._disposition("differs", {"status": "ran", "pass": True}, {"judge": "GOLD"})
        == "viable-gold"
    )


def test_disposition_behavioral_fail_is_task_viable_not_gold():
    # candidate doesn't fix the bug, but the CVE is still a reproducible authoring task
    for v in ("exact", "differs"):
        assert (
            es._disposition(v, {"status": "ran", "pass": False}, {"judge": "GOLD"})
            == "task-viable-candidate-wrong"
        )


def test_disposition_differs_pass_judge_variants():
    assert (
        es._disposition("differs", {"status": "ran", "pass": True}, {"judge": "WRONG"})
        == "behavioral-pass-judge-wrong"
    )
    assert (
        es._disposition(
            "differs", {"status": "ran", "pass": True}, {"judge": "PARTIAL"}
        )
        == "needs-review"
    )
    assert (
        es._disposition("differs", {"status": "ran", "pass": True}, None)
        == "needs-review"
    )


def test_disposition_not_gated_uses_judge():
    assert (
        es._disposition("differs", {"status": "not-gated"}, {"judge": "GOLD"})
        == "viable-judge-only"
    )
    assert (
        es._disposition("differs", {"status": "not-gated"}, {"judge": "WRONG"})
        == "reject-judge"
    )
    assert (
        es._disposition("differs", {"status": "not-gated"}, {"judge": "PARTIAL"})
        == "needs-review"
    )


def test_disposition_no_candidate():
    assert (
        es._disposition("skip", {"status": "not-gated"}, None)
        == "unscreenable-no-candidate"
    )
    assert (
        es._disposition("no-attempt", {"status": "not-gated"}, None)
        == "unscreenable-no-candidate"
    )


# ── judge parsing ─────────────────────────────────────────────────────────────


def test_judge_parses_first_word():
    assert (
        es.judge_differs("CVE-X", "d", "u", api_fn=lambda p: "GOLD\nequivalent")[
            "judge"
        ]
        == "GOLD"
    )
    assert (
        es.judge_differs("CVE-X", "d", "u", api_fn=lambda p: "PARTIAL — misses a path")[
            "judge"
        ]
        == "PARTIAL"
    )
    assert (
        es.judge_differs("CVE-X", "d", "u", api_fn=lambda p: "WRONG, no fix")["judge"]
        == "WRONG"
    )
    assert (
        es.judge_differs("CVE-X", "d", "u", api_fn=lambda p: "hmm not sure")["judge"]
        == "UNCLEAR"
    )


def test_judge_prompt_contains_both_patches_not_a_label():
    captured = {}
    es.judge_differs(
        "CVE-7",
        "CAND-DIFF",
        "REF-DIFF",
        api_fn=lambda p: captured.update(p=p) or "GOLD",
    )
    p = captured["p"]
    assert "REF-DIFF" in p and "CAND-DIFF" in p and "every" in p.lower()


# ── screen_bundle wiring (injected author / build / judge) ─────────────────────


def _fake_author(verdict, authored="--- a/x\n@@ -1 +1 @@\n-a\n+b\n"):
    return lambda bd: {
        "cve": "CVE-2099-1",
        "verdict": verdict,
        "authored_diff": authored,
        "src_origin": "cache",
    }


def _scaffold(tmp_path, kind="behavioral"):
    bd = tmp_path / "CVE-2099-1--demo-backport"
    bd.mkdir(parents=True)
    (bd / "bundle.json").write_text(
        json.dumps({"bundle_id": "b1", "cve_id": "CVE-2099-1"})
    )
    (bd / "finding.json").write_text(json.dumps({"cve_id": "CVE-2099-1"}))
    (bd / "upstream-fix.patch").write_text("--- a/x\n@@ -1 +1 @@\n-a\n+b\n")
    expect = (
        {} if kind == "behavioral" else {"reproducer_kind": "text-inspection-proxy"}
    )
    (bd / "expect.json").write_text(json.dumps(expect))
    return bd


def test_screen_behavioral_pass_differs_gold(tmp_path):
    bd = _scaffold(tmp_path)
    r = es.screen_bundle(
        bd,
        traces_root=tmp_path,
        build_fn=lambda d: {},  # presence triggers the gate
        author_fn=_fake_author("differs"),
        judge_api=lambda p: "GOLD\nequivalent",
    )
    # inject behavioral pass via score_behavioral monkeypatch would be heavier; instead
    # assert the gate WAS attempted (status set) and the judge ran on a differs candidate.
    assert r["verdict"] == "differs"
    assert r["judge"]["judge"] == "GOLD"
    assert r["behavioral"]["status"] is not None  # gate attempted (real reproducer)


def test_screen_proxy_reproducer_not_gated_but_judged(tmp_path):
    bd = _scaffold(tmp_path, kind="proxy")
    r = es.screen_bundle(
        bd,
        traces_root=tmp_path,
        build_fn=lambda d: {},
        author_fn=_fake_author("differs"),
        judge_api=lambda p: "GOLD\n",
    )
    assert r["behavioral"]["status"] == "not-gated"
    assert r["reproducer_kind"] == "text-inspection-proxy"
    assert r["disposition"] == "viable-judge-only"  # judge GOLD, no behavioral gate


def test_screen_cleans_fenced_candidate_before_gate(tmp_path, monkeypatch):
    # A fenced/prefaced authored diff must be normalized to the diff body before
    # score_behavioral (else _rewrite_embedded_patch embeds the fence) (codex).
    bd = _scaffold(tmp_path)
    captured = {}
    monkeypatch.setattr(
        es,
        "score_behavioral",
        lambda gen, rec, **k: (
            captured.update(gen=gen)
            or {"behavioral_status": "ran", "behavioral_pass": True}
        ),
    )
    fenced = "Here is the fix:\n```diff\n--- a/x\n@@ -1 +1 @@\n-a\n+b\n```\n"
    es.screen_bundle(
        bd,
        traces_root=tmp_path,
        build_fn=lambda d: {},
        author_fn=_fake_author("differs", authored=fenced),
        judge_api=lambda p: "GOLD\n",
    )
    assert captured["gen"].startswith("--- a/x")  # fence + preface stripped
    assert "```" not in captured["gen"] and "Here is" not in captured["gen"]


def test_screen_skip_is_unscreenable(tmp_path):
    bd = _scaffold(tmp_path)
    r = es.screen_bundle(
        bd,
        traces_root=tmp_path,
        author_fn=lambda d: {
            "cve": "CVE-2099-1",
            "status": "skip",
            "reason": "no source",
        },
    )
    assert r["disposition"] == "unscreenable-no-source"


def test_screen_no_gate_without_build_fn_judges_differs(tmp_path):
    bd = _scaffold(tmp_path)
    r = es.screen_bundle(
        bd,
        traces_root=tmp_path,
        build_fn=None,
        author_fn=_fake_author("differs"),
        judge_api=lambda p: "WRONG\n",
    )
    assert r["behavioral"]["status"] == "not-gated"
    assert r["disposition"] == "reject-judge"
