"""Tests for the authoring gate-pilot structural scorer (eval/score_authoring_pilot.py).

Tier 0 (format/safety) + Tier 1 (structural reference vs the curated
upstream-fix.patch) scoring of a generated diff, offline (no build). The
load-bearing property: the reference label self-scores as a full pass, and each
individual defect (wrong file, version bump, test file, missing hunk, ungrounded,
missing fix-symbols) trips exactly its own check.
"""
from __future__ import annotations

import json

from eval import score_authoring_pilot as sp


# A 2-hunk reference fix whose removed lines all appear in the pre-fix window
# below, so a faithful candidate grounds and covers both hunks.
_REFERENCE = (
    "diff --git a/impl.c b/impl.c\n--- a/impl.c\n+++ b/impl.c\n"
    "@@ -2,1 +2,1 @@\n-    int n = read_unbounded();\n+    int n = read_bounded();\n"
    "@@ -7,1 +7,1 @@\n-    deallocate(p);\n+    deallocate_checked(p);\n"
)
_PREFIX = (
    "int f() {\n    int n = read_unbounded();\n    use(n);\n}\n"
    "void g() {\n    char *p = alloc();\n    deallocate(p);\n}\n"
)


def _record(cve: str = "CVE-2099-0001", family: str = "impl",
            reference: str = _REFERENCE, prefix: str = _PREFIX) -> dict:
    user = (f"# CVE\n{cve}: A bug.\n\n# Vulnerable source (impl.c)\n```c\n{prefix}\n```")
    return {
        "messages": [
            {"role": "system", "content": "Author the minimal fix."},
            {"role": "user", "content": user},
            {"role": "assistant", "content": reference},
        ],
        "provenance": {"cve_id": cve, "split_family": family},
    }


# ── pure helpers ──────────────────────────────────────────────────────────────

def test_has_version_bump_nix_and_python():
    assert sp._has_version_bump('+    version = "2.13.0";')      # nix
    assert sp._has_version_bump('+__version__ = "2.13.0"')        # python (pyjwt tell)
    assert sp._has_version_bump('+    sha256 = "abc";')           # hash
    assert not sp._has_version_bump("+    if (n > 255) return -1;")
    assert not sp._has_version_bump("+++ b/version_utils.c")      # file header, not a bump


def test_target_files_includes_nonsource_and_handles_devnull():
    diff = ("diff --git a/src/x.c b/src/x.c\n--- a/src/x.c\n+++ b/src/x.c\n@@ -1 +1 @@\n-a\n+b\n"
            "diff --git a/tests/t.c b/tests/t.c\n--- a/tests/t.c\n+++ b/tests/t.c\n@@ -1 +1 @@\n-c\n+d\n"
            "diff --git a/old.c b/old.c\n--- a/old.c\n+++ /dev/null\n@@ -1 +0,0 @@\n-gone\n")
    files = sp._target_files(diff)
    assert "src/x.c" in files and "tests/t.c" in files
    assert "old.c" in files and "/dev/null" not in files   # deletion names the --- side


def test_prefix_window_extracts_fenced_block():
    rec = _record()
    assert "read_unbounded()" in sp._prefix_window(rec["messages"][1]["content"])
    assert sp._prefix_window("no source block here") == ""


def test_clean_generated_fenced_and_raw():
    assert sp._clean_generated("Here you go:\n```diff\ndiff --git a/x b/x\n@@\n```\n").startswith("diff --git")
    assert sp._clean_generated("blah\n--- a/x\n+++ b/x\n@@ -1 +1 @@\n-a\n+b\n").startswith("--- a/x")
    assert sp._clean_generated("diff --git a/x b/x\n@@\n").startswith("diff --git")


# ── Tier 0 / Tier 1 scoring ───────────────────────────────────────────────────

def test_reference_self_scores_full_pass():
    s = sp.score_candidate(_REFERENCE, _record())
    assert s["format_pass"] and s["structural_pass"]
    assert all(s["tier0"].values()) and all(s["tier1"].values())
    assert s["detail"]["fix_symbol_fraction"] == 1.0
    assert s["detail"]["gen_hunks"] == 2 and s["detail"]["ref_hunks"] == 2


def test_prose_refusal_fails_parse():
    s = sp.score_candidate("I cannot help author this fix.", _record())
    assert not s["tier0"]["parses"]
    assert not s["format_pass"] and not s["structural_pass"]


def test_version_bump_fails_tier0():
    bumped = _REFERENCE + ("diff --git a/impl.c b/impl.c\n--- a/impl.c\n+++ b/impl.c\n"
                           "@@ -20 +20 @@\n-version = \"1.0\"\n+version = \"2.0\"\n")
    s = sp.score_candidate(bumped, _record())
    assert not s["tier0"]["no_version_bump"]
    assert not s["format_pass"]


def test_test_file_fails_tier0():
    with_test = (_REFERENCE + "diff --git a/tests/test_impl.c b/tests/test_impl.c\n"
                 "--- a/tests/test_impl.c\n+++ b/tests/test_impl.c\n@@ -1 +1 @@\n-x\n+y\n")
    s = sp.score_candidate(with_test, _record())
    assert not s["tier0"]["no_test_or_doc_files"]


def test_wrong_file_fails_same_impl_file():
    other = ("diff --git a/other.c b/other.c\n--- a/other.c\n+++ b/other.c\n"
             "@@ -2,1 +2,1 @@\n-    int n = read_unbounded();\n+    int n = read_bounded();\n")
    s = sp.score_candidate(other, _record())
    assert not s["tier1"]["same_impl_file"]   # other.c not in reference's files
    assert not s["structural_pass"]


def test_missing_hunk_fails_covers_all_reference_hunks():
    # Only the first of the reference's two hunks.
    one_hunk = ("diff --git a/impl.c b/impl.c\n--- a/impl.c\n+++ b/impl.c\n"
                "@@ -2,1 +2,1 @@\n-    int n = read_unbounded();\n+    int n = read_bounded();\n")
    s = sp.score_candidate(one_hunk, _record())
    assert not s["tier1"]["covers_all_reference_hunks"]
    assert s["detail"]["gen_hunks"] == 1 and s["detail"]["ref_hunks"] == 2


def test_ungrounded_diff_fails_grounds_in_prefix():
    # Removes a line absent from the shown pre-fix window.
    ungrounded = ("diff --git a/impl.c b/impl.c\n--- a/impl.c\n+++ b/impl.c\n"
                  "@@ -2,1 +2,1 @@\n-    int n = totally_absent_call();\n+    int n = read_bounded();\n"
                  "@@ -7,1 +7,1 @@\n-    deallocate(p);\n+    deallocate_checked(p);\n")
    s = sp.score_candidate(ungrounded, _record())
    assert not s["tier1"]["grounds_in_prefix"]


def test_missing_fix_symbols_fails():
    # Grounded at the right region + covers both hunks, but the ADDED lines carry
    # none of the reference's fix-symbols (a plausible-looking but wrong fix).
    no_syms = ("diff --git a/impl.c b/impl.c\n--- a/impl.c\n+++ b/impl.c\n"
               "@@ -2,1 +2,2 @@\n     int n = read_unbounded();\n+    if (n < 0) abort();\n"
               "@@ -7,1 +7,2 @@\n     deallocate(p);\n+    log_event();\n")
    s = sp.score_candidate(no_syms, _record())
    assert s["detail"]["fix_symbol_fraction"] < sp._FIX_SYMBOL_THRESHOLD
    assert not s["tier1"]["fix_symbols_present"]
    assert s["tier1"]["grounds_in_prefix"]              # it IS at the right place...
    assert not s["structural_pass"]                     # ...but not the right fix


def test_multi_file_reference_requires_every_file():
    # Reference touches a.c AND b.c; a candidate that patches only a.c (even
    # perfectly) must fail same_impl_file + covers_all_reference_hunks (codex).
    multi_ref = (
        "diff --git a/a.c b/a.c\n--- a/a.c\n+++ b/a.c\n@@ -1,1 +1,1 @@\n-int bad_a;\n+int good_a;\n"
        "diff --git a/b.c b/b.c\n--- a/b.c\n+++ b/b.c\n@@ -1,1 +1,1 @@\n-int bad_b;\n+int good_b;\n")
    rec = _record(reference=multi_ref, prefix="int bad_a;\nint bad_b;\n")
    only_a = "diff --git a/a.c b/a.c\n--- a/a.c\n+++ b/a.c\n@@ -1,1 +1,1 @@\n-int bad_a;\n+int good_a;\n"
    s = sp.score_candidate(only_a, rec)
    assert not s["tier1"]["same_impl_file"]             # {a.c} != {a.c, b.c}
    assert not s["tier1"]["covers_all_reference_hunks"]  # b.c has 0 generated hunks
    assert not s["structural_pass"]
    # the complete candidate (both files) passes both
    both = multi_ref
    s2 = sp.score_candidate(both, rec)
    assert s2["tier1"]["same_impl_file"] and s2["tier1"]["covers_all_reference_hunks"]


# ── aggregation ───────────────────────────────────────────────────────────────

def test_aggregate_rates_and_deferred_behavioral():
    scored = [
        sp.score_candidate(_REFERENCE, _record(cve="CVE-1")),
        sp.score_candidate("I refuse.", _record(cve="CVE-2")),
    ]
    agg = sp._aggregate(scored, "test-model")
    assert agg["n"] == 2
    assert agg["format_pass_rate"] == 0.5
    assert agg["structural_pass_rate"] == 0.5
    assert agg["behavioral_pass_rate"] is None      # Tier 2 not run, never reported as 0
    assert agg["behavioral_attempted_n"] == 0
    assert agg["tier0_check_rates"]["parses"] == 0.5
    assert agg["model_id"] == "test-model"


# ── Tier 2: embedded-patch rewrite + behavioral gate ─────────────────────────

# A source-backport patch.diff: creates pkgs/demo/CVE.patch (the embedded source
# fix) AND appends it to default.nix patches=[]. The embedded body is what Tier 2
# rewrites to inject a candidate.
_TREE_DIFF = (
    "diff --git a/pkgs/demo/CVE.patch b/pkgs/demo/CVE.patch\n"
    "new file mode 100644\n--- /dev/null\n+++ b/pkgs/demo/CVE.patch\n"
    "@@ -0,0 +1,3 @@\n+--- a/impl.c\n+old line\n+new line\n"
    "diff --git a/pkgs/demo/default.nix b/pkgs/demo/default.nix\n"
    "--- a/pkgs/demo/default.nix\n+++ b/pkgs/demo/default.nix\n"
    "@@ -1,2 +1,3 @@\n patches = [\n+    ./CVE.patch\n ];\n")


def test_rewrite_embedded_patch_single():
    cand = "diff --git a/impl.c b/impl.c\n--- a/impl.c\n+++ b/impl.c\n@@ -1 +1 @@\n-a\n+b\n"
    out = sp._rewrite_embedded_patch(_TREE_DIFF, cand)
    assert out is not None
    assert "@@ -0,0 +1,6 @@" in out                       # candidate has 6 lines
    assert "+diff --git a/impl.c b/impl.c" in out          # candidate body, +-prefixed
    assert "old line" not in out                           # original embedded body replaced
    assert "./CVE.patch" in out and "default.nix" in out   # default.nix hunk preserved


def test_rewrite_embedded_patch_requires_exactly_one():
    # zero embedded .patch files -> None
    no_patch = ("diff --git a/pkgs/demo/default.nix b/pkgs/demo/default.nix\n"
                "--- a/pkgs/demo/default.nix\n+++ b/pkgs/demo/default.nix\n@@ -1 +1 @@\n-a\n+b\n")
    assert sp._rewrite_embedded_patch(no_patch, "x") is None
    # two embedded .patch files -> ambiguous -> None
    two = (_TREE_DIFF + "diff --git a/pkgs/demo/OTHER.patch b/pkgs/demo/OTHER.patch\n"
           "new file mode 100644\n--- /dev/null\n+++ b/pkgs/demo/OTHER.patch\n@@ -0,0 +1,1 @@\n+x\n")
    assert sp._rewrite_embedded_patch(two, "x") is None


def _scaffold_backport_bundle(traces_root, cve="CVE-2099-0001"):
    bd = traces_root / f"{cve}--demo-backport"
    bd.mkdir(parents=True)
    (bd / "finding.json").write_text(json.dumps(
        {"cve_id": cve, "affected": [{"attr_path": "demo"}], "summary": "bug"}))
    (bd / "bundle.json").write_text(json.dumps(
        {"bundle_id": "x", "cve_id": cve, "nixpkgs_rev": "0" * 40}))
    (bd / "upstream-ref.json").write_text(json.dumps(
        {"eligibility": {"patch_strategy": "source-backport"}}))
    # reproducer defines BOTH signals (so no-proxy-signal is satisfied)
    (bd / "reproducer.nix").write_text("# emits SIGNAL_UNPATCHED or SIGNAL_PATCHED\n")
    (bd / "patch.diff").write_text(_TREE_DIFF)
    return bd


def _build_json(*, applied=True, unpatched_sig=True, patched_sig=True):
    return {
        "patch_apply": {"applied": applied, "files_changed": ["pkgs/demo/CVE.patch"]},
        "unpatched": {"outcome": "succeeded",
                      "stdout_stderr": "SIGNAL_UNPATCHED" if unpatched_sig else "nothing"},
        "patched": {"outcome": "succeeded",
                    "stdout_stderr": "SIGNAL_PATCHED" if patched_sig else "still broken"},
    }


def test_behavioral_pass(tmp_path):
    root = tmp_path / "traces"
    _scaffold_backport_bundle(root)
    rec = _record(cve="CVE-2099-0001")
    cand = "diff --git a/impl.c b/impl.c\n--- a/impl.c\n+++ b/impl.c\n@@ -1 +1 @@\n-a\n+b\n"
    r = sp.score_behavioral(cand, rec, traces_root=root, build_fn=lambda d: _build_json())
    assert r["behavioral_status"] == "ran" and r["behavioral_pass"] is True
    assert r["assertions"]["patch-applies"] and r["assertions"]["backported-reproducer-clean"]
    assert r["candidate_sha256"] and r["rewritten_patch_sha256"]


def test_behavioral_precondition_failed_when_unpatched_silent(tmp_path):
    root = tmp_path / "traces"
    _scaffold_backport_bundle(root)
    r = sp.score_behavioral("diff --git a/impl.c b/impl.c\n--- a/impl.c\n+++ b/impl.c\n@@ -1 +1 @@\n-a\n+b\n",
                            _record(cve="CVE-2099-0001"), traces_root=root,
                            build_fn=lambda d: _build_json(unpatched_sig=False))
    # reproducer can't fire unpatched -> invalid/skipped, NOT a candidate failure
    assert r["behavioral_status"] == "precondition_failed"
    assert r["behavioral_pass"] is False


def test_behavioral_fail_when_not_clean(tmp_path):
    root = tmp_path / "traces"
    _scaffold_backport_bundle(root)
    r = sp.score_behavioral("diff --git a/impl.c b/impl.c\n--- a/impl.c\n+++ b/impl.c\n@@ -1 +1 @@\n-a\n+b\n",
                            _record(cve="CVE-2099-0001"), traces_root=root,
                            build_fn=lambda d: _build_json(patched_sig=False))
    assert r["behavioral_status"] == "ran" and r["behavioral_pass"] is False


def test_reproducer_kind_marker_and_default(tmp_path):
    root = tmp_path / "traces"
    bd = _scaffold_backport_bundle(root, cve="CVE-2099-0002")
    assert sp._reproducer_kind(bd) == "behavioral"            # no marker -> default
    (bd / "expect.json").write_text(json.dumps({"reproducer_kind": "text-inspection-proxy"}))
    assert sp._reproducer_kind(bd) == "text-inspection-proxy"


def test_detect_proxy_reproducer_pattern():
    proxy = ('let t = pkgs.runCommand "x" { inherit (pkgs.zlib) patches; } '
             "''\n for p in $patches; do\n if grep -qF \"extra_max)\" \"$p\"; then :; fi\n done\n'';")
    real = ('let e = pkgs.python3.withPackages (ps: [ ps.requests ]); '
            "in pkgs.runCommand \"x\" {} '' ${e}/bin/python poc.py '';")
    import tempfile, os
    from pathlib import Path as _P
    for body, want in [(proxy, True), (real, False)]:
        d = _P(tempfile.mkdtemp())
        (d / "reproducer.nix").write_text(body)
        assert sp._detect_proxy_reproducer(d) is want


def test_marker_matches_autodetect_on_real_canaries():
    # The explicit expect.json marker must agree with auto-detection on the four
    # shipped canaries (codex 2026-06-26: auto-detect verifies the marker).
    from pathlib import Path as _P
    cases = {
        "CVE-2022-37434--zlib-backport": False,        # upgraded: cache-warm ASAN source oracle
        "CVE-2026-42250--bzip2-backport": False,       # upgraded to a real ASAN build+execute reproducer
        "CVE-2024-47081--requests-backport": False,
        "CVE-2026-48526--pyjwt-backport": False,
    }
    for name, is_proxy in cases.items():
        b = _P("traces/example") / name
        if not b.is_dir():
            continue
        marked_proxy = sp._reproducer_kind(b) == "text-inspection-proxy"
        assert marked_proxy == is_proxy, f"{name}: marker"
        assert sp._detect_proxy_reproducer(b) == is_proxy, f"{name}: autodetect"


def test_behavioral_exempts_proxy_without_building(tmp_path):
    root = tmp_path / "traces"
    bd = _scaffold_backport_bundle(root, cve="CVE-2099-0003")
    (bd / "expect.json").write_text(json.dumps({"reproducer_kind": "text-inspection-proxy"}))
    def boom(d):
        raise AssertionError("build_fn must not run for an exempt proxy")
    r = sp.score_behavioral("x", _record(cve="CVE-2099-0003"), traces_root=root, build_fn=boom)
    assert r["behavioral_status"] == "exempt_proxy_reproducer"
    assert r["behavioral_pass"] is False


def test_behavioral_bundle_not_found(tmp_path):
    r = sp.score_behavioral("x", _record(cve="CVE-9999-0000"),
                            traces_root=tmp_path / "traces", build_fn=lambda d: {})
    assert r["behavioral_status"] == "bundle_not_found"


def test_bundle_for_disambiguates_by_provenance_bundle_id(tmp_path):
    # Two dirs share the CVE (corpus has original + *-backport); pick the one whose
    # bundle.json matches the record's provenance bundle_id (codex 2026-06-25).
    root = tmp_path / "traces"
    cve = "CVE-2025-34451"
    for slug, bid in [("proxychains-ng", "AAAA"), ("proxychains-ng-backport", "BBBB")]:
        d = root / f"{cve}--{slug}"
        d.mkdir(parents=True)
        (d / "bundle.json").write_text(json.dumps({"bundle_id": bid, "cve_id": cve}))
    rec = _record(cve=cve)
    rec["provenance"]["bundle_id"] = "BBBB"
    assert sp._bundle_for(root, rec).name == f"{cve}--proxychains-ng-backport"
    rec["provenance"]["bundle_id"] = "AAAA"
    assert sp._bundle_for(root, rec).name == f"{cve}--proxychains-ng"


def test_aggregate_behavioral_excludes_precondition_from_denominator():
    s_pass = sp.score_candidate(_REFERENCE, _record(cve="CVE-1"))
    s_pass["behavioral"] = {"cve_id": "CVE-1", "behavioral_status": "ran", "behavioral_pass": True}
    s_pre = sp.score_candidate(_REFERENCE, _record(cve="CVE-2"))
    s_pre["behavioral"] = {"cve_id": "CVE-2", "behavioral_status": "precondition_failed",
                           "behavioral_pass": False}
    s_fail = sp.score_candidate(_REFERENCE, _record(cve="CVE-3"))
    s_fail["behavioral"] = {"cve_id": "CVE-3", "behavioral_status": "ran", "behavioral_pass": False}
    agg = sp._aggregate([s_pass, s_pre, s_fail], "m")
    # attempted = 2 (the two "ran"); precondition_failed is excluded
    assert agg["behavioral_attempted_n"] == 2
    assert agg["behavioral_pass_rate"] == 0.5            # 1 of 2 ran passed
    assert agg["behavioral_statuses"]["precondition_failed"] == 1
