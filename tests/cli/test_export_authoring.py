"""Tests for `trace export authoring` (tools/trace_cli/export.py).

The authoring exporter turns cert-green source-backport bundles into
(CVE-vuln-only + pre-fix source) -> upstream-fix training pairs. The load-bearing
property is LEAKAGE CONTROL: the input must never name what the fix changes. These
tests pin the scrub (`_fix_symbols` / `_scrub_summary`) and the end-to-end record
shape, using a cached `authoring-example.json` so no network fetch is needed.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from tools.trace_cli import export as ex


# A realistic source-backport fix: removing a type-gate so an existing bounds
# check applies to all proxy types (mirrors the proxychains CVE-2025-34451 shape).
_FIX_DIFF = (
    "diff --git a/src/libproxychains.c b/src/libproxychains.c\n"
    "--- a/src/libproxychains.c\n"
    "+++ b/src/libproxychains.c\n"
    "@@ -241,7 +241,7 @@ static int proxy_from_string(const char *proxystring,\n"
    " \t\tpl = at-p;\n"
    "-\t\tif(proxytype == RS_PT_SOCKS5 && (ul > 255 || pl > 255))\n"
    "+\t\tif(ul > 255 || pl > 255)\n"
    " \t\t\treturn 0;\n"
)


def _cached_bundle(root: Path, name: str, *, cve: str, attr: str, summary: str,
                   fix_diff: str = _FIX_DIFF, kind: str = "human-review-required",
                   rekor: int | None = 1796253004) -> Path:
    bd = root / name
    bd.mkdir(parents=True)
    bundle = {"bundle_id": "deadbeef", "cve_id": cve, "kind": kind}
    if rekor is not None:
        bundle["signed_manifest"] = {"rekor_log_index": rekor}
    (bd / "bundle.json").write_text(json.dumps(bundle))
    (bd / "finding.json").write_text(json.dumps(
        {"cve_id": cve, "summary": summary, "affected": [{"attr_path": attr}]}))
    (bd / "upstream-ref.json").write_text(json.dumps({"cve_id": cve}))
    # Pre-built cache so _authoring_pair returns offline.
    (bd / "authoring-example.json").write_text(json.dumps({
        "cve_id": cve, "attr_path": attr, "vuln_raw": summary,
        "file": "src/libproxychains.c",
        "pre_fix_source": "static int proxy_from_string(...) {\n  /* vulnerable body */\n}",
        "fix_diff": fix_diff,
        "fix_commit": {"repo_url": "https://github.com/rofl0r/proxychains-ng",
                       "commit_sha": "cc005b713281"},
    }))
    return bd


def _args(out: Path, root: Path) -> argparse.Namespace:
    return argparse.Namespace(export_scope="authoring", out=out, traces_root=root,
                              format="json")


# --- pure scrub functions -------------------------------------------------

def test_fix_symbols_only_from_changed_lines():
    syms = ex._fix_symbols(_FIX_DIFF)
    assert "RS_PT_SOCKS5" in syms          # on a removed line
    assert "proxytype" in syms             # changed line (len>=6, no '_': proxytype is 9)
    assert "proxy_from_string" not in syms  # only in the @@ hunk header (context)


def test_fix_symbols_skips_generic_short_tokens():
    syms = ex._fix_symbols("--- a/x\n+++ b/x\n@@ -1 +1 @@\n-if (a > b)\n+if (a >= b)\n")
    assert "if" not in syms  # too short / generic
    assert syms == set()     # nothing distinctive changed


def test_fix_symbols_extracts_only_moved_numeric_literal():
    # a bound that moved (10 -> 8) is a tell; an unchanged constant is not.
    diff = "--- a/x\n+++ b/x\n@@ -1 +1 @@\n-if (n > 10 && cap == 256)\n+if (n > 8 && cap == 256)\n"
    syms = ex._fix_symbols(diff)
    assert "10" in syms and "8" not in syms  # 8 is single-digit (too generic)
    assert "256" not in syms                 # unchanged on both sides — a vuln fact


def test_fix_symbols_ignores_single_digit_offbyone():
    # bzip2 shape: `MAX` -> `MAX - 1`. The `1` is too generic; the identifier carries it.
    diff = ("--- a/x\n+++ b/x\n@@ -1 +1 @@\n"
            "-if (c >= BZ_MAX_HANDLED_BLOCKS)\n+if (c >= BZ_MAX_HANDLED_BLOCKS - 1)\n")
    syms = ex._fix_symbols(diff)
    assert "BZ_MAX_HANDLED_BLOCKS" in syms
    assert "1" not in syms


def test_mentions_word_boundary_for_numbers():
    assert ex._mentions("the limit is 50 blocks", "50")
    assert not ex._mentions("version 1.0.8 is affected", "50")  # 50 not inside 5000/1.0.8
    assert not ex._mentions("more than 50000 magics", "50")     # boundary, not substring
    assert ex._mentions("calls slotat() directly", "slotat")    # identifier substring


def test_scrub_summary_drops_sentence_naming_the_fix_symbol():
    summary = ("Stack overflow in proxy_from_string when a credential exceeds 255 bytes. "
               "The bounds check was gated on proxytype == RS_PT_SOCKS5, excluding HTTP.")
    scrubbed = ex._scrub_summary(summary, _FIX_DIFF)
    assert "RS_PT_SOCKS5" not in scrubbed         # the leaky sentence is gone
    assert "Stack overflow" in scrubbed           # the vuln description survives


def test_scrub_summary_drops_remediation_language():
    summary = "Heap overflow in foo(). Fixed upstream in commit abc1234 by adding a length check."
    scrubbed = ex._scrub_summary(summary, "--- a/x\n+++ b/x\n@@ -1 +1 @@\n-a\n+b\n")
    assert "Fixed upstream" not in scrubbed
    assert "Heap overflow" in scrubbed


# --- end-to-end export ----------------------------------------------------

def test_authoring_export_builds_clean_pair(tmp_path, capsys):
    root = tmp_path / "traces"
    summary = ("Stack-based buffer overflow in proxy_from_string when a username exceeds "
               "255 bytes. It was gated on proxytype == RS_PT_SOCKS5.")
    _cached_bundle(root, "CVE-2025-34451--proxychains-ng-backport",
                   cve="CVE-2025-34451", attr="proxychains-ng", summary=summary)
    rc = ex.run(_args(tmp_path / "out", root))
    assert rc == 0
    lines = (tmp_path / "out" / "authoring.jsonl").read_text().splitlines()
    assert len(lines) == 1
    ex_rec = json.loads(lines[0])
    roles = [m["role"] for m in ex_rec["messages"]]
    assert roles == ["system", "user", "assistant"]
    user = ex_rec["messages"][1]["content"]
    assert "RS_PT_SOCKS5" not in user           # fix symbol scrubbed from input
    assert "buffer overflow" in user            # vuln preserved
    assert ex_rec["messages"][2]["content"].startswith("diff --git")  # label = the fix
    assert ex_rec["task"] == "author-from-vuln"
    assert ex_rec["provenance"]["cve_id"] == "CVE-2025-34451"
    assert ex_rec["provenance"]["steward_signed"] is True


def test_authoring_export_excludes_unscrubbable_summary(tmp_path):
    """If every sentence names a fix symbol, the summary scrubs to empty and the
    bundle is excluded rather than shipping a leaky/empty input."""
    root = tmp_path / "traces"
    _cached_bundle(root, "CVE-2025-34451--leaky-backport", cve="CVE-2025-34451",
                   attr="leaky", summary="proxytype RS_PT_SOCKS5 gate removed.")
    rc = ex.run(_args(tmp_path / "out", root))
    assert rc == 0
    manifest = json.loads((tmp_path / "out" / "manifest.json").read_text())
    assert manifest["eligible_examples"] == 0
    assert manifest["excluded"]
    assert "scrub" in manifest["excluded"][0]["reason"]


def test_authoring_manifest_records_leakage_partition(tmp_path):
    root = tmp_path / "traces"
    _cached_bundle(root, "CVE-2025-34451--proxychains-ng-backport",
                   cve="CVE-2025-34451", attr="proxychains-ng",
                   summary="Stack overflow in proxy_from_string with long credentials.")
    ex.run(_args(tmp_path / "out", root))
    manifest = json.loads((tmp_path / "out" / "manifest.json").read_text())
    assert manifest["scope"] == "authoring"
    assert "author-from-vuln" in manifest["note"]
    assert "leakage" in manifest["note"].lower()
    assert manifest["families"] == ["proxychains-ng"]
