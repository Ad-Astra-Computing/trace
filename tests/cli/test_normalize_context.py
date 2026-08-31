"""Tests for `trace bundle normalize-context` (tools/trace_cli/normalize_context.py).

Covers the load-bearing cases:
  (a) perl-shaped defect (extra leading space on every context line) with
      --apply -> hunks substituted from ground truth, attestation valid,
      normalized payload applies at fuzz=0
  (b) same, without --apply -> gate FAILS closed, nothing written
  (c) ADDED lines differ from ground truth -> INELIGIBLE (refuses)
  (d) DELETED lines differ from ground truth -> INELIGIBLE (refuses)
  (e) hunk count differs -> INELIGIBLE
  (f) file set differs -> INELIGIBLE
  (g) payload already byte-identical to ground truth -> no-op pass
  (h) git trailer (`-- ` / version) after the last hunk is not misread as a
      deletion line (count-driven body parsing)

All cases run via `--source-tree` (no network / nix fetch).
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

import pytest

from tools.trace_cli import normalize_context as ctx


_SRC = (
    "static int study(void) {\n"
    "    long l = get_len();\n"
    "    l -= old;\n"
    "    grow(l);\n"
    "    return l;\n"
    "}\n"
)

# Ground truth: guard inserted after `l -= old;`, context transcribed exactly.
_GT_INNER = (
    "From deadbeef Mon Sep 17 00:00:00 2001\n"
    "Subject: [PATCH] add overflow guard\n"
    "---\n"
    "diff --git a/study.c b/study.c\n"
    "index 1111111..2222222 100644\n"
    "--- a/study.c\n"
    "+++ b/study.c\n"
    "@@ -2,4 +2,7 @@ static int study(void) {\n"
    "     long l = get_len();\n"
    "     l -= old;\n"
    "+    if (l > 0 && overflows(l)) {\n"
    "+        fail();\n"
    "+    }\n"
    "     grow(l);\n"
    "     return l;\n"
    "--\n"
    "2.43.0\n"
)


def _corrupt_context(inner: str) -> str:
    """The observed Patcher defect: one extra leading space on CONTEXT lines
    (inside hunks) only; added lines and headers untouched."""
    out = []
    in_hunk = False
    seen = 0
    for ln in inner.splitlines():
        if ln.startswith("@@"):
            in_hunk = True
            seen = 0
            out.append(ln)
            continue
        # 4 context lines in the single hunk (old side count 4, no deletions)
        if in_hunk and ln.startswith(" ") and seen < 4:
            out.append(" " + ln)
            seen += 1
            continue
        out.append(ln)
    return "\n".join(out) + ("\n" if inner.endswith("\n") else "")


def _wrap(inner: str, patch_name: str = "CVE-0000-0000.patch") -> str:
    lines = inner.splitlines()
    body = "\n".join("+" + ln for ln in lines)
    return (
        f"diff --git a/{patch_name} b/{patch_name}\n"
        f"new file mode 100644\n"
        f"--- /dev/null\n"
        f"+++ b/{patch_name}\n"
        f"@@ -0,0 +1,{len(lines)} @@\n"
        f"{body}\n"
        f"diff --git a/package.nix b/package.nix\n"
        f"--- a/package.nix\n"
        f"+++ b/package.nix\n"
        f"@@ -1,1 +1,2 @@\n"
        f" keep = 1;\n"
        f"+  patches = [ ./{patch_name} ];\n"
    )


def _bundle(tmp_path: Path, inner: str) -> tuple[Path, Path]:
    bd = tmp_path / "bundle"
    bd.mkdir(exist_ok=True)
    (bd / "patch.diff").write_text(_wrap(inner))
    (bd / "upstream-fix.patch").write_text(_GT_INNER)
    root = tmp_path / "effective-root"
    root.mkdir(exist_ok=True)
    (root / "study.c").write_text(_SRC)
    return bd, root


def _args(bundle_dir: Path, source_tree: Path, apply: bool = False) -> argparse.Namespace:
    return argparse.Namespace(
        bundle_dir=bundle_dir, ground_truth=None, source_tree=source_tree,
        patch_flags=None, apply=apply, format="json",
    )


def test_corrupt_context_fixture_does_not_apply(tmp_path: Path) -> None:
    """Sanity: the corrupted fixture reproduces the failure mode (raw payload
    does not apply, ground truth does)."""
    bd, root = _bundle(tmp_path, _corrupt_context(_GT_INNER))
    ok_raw, _ = ctx._dry_run(root, _corrupt_context(_GT_INNER), ["-p1"])
    ok_gt, _ = ctx._dry_run(root, _GT_INNER, ["-p1"])
    assert not ok_raw
    assert ok_gt


def test_apply_substitutes_and_attests(tmp_path: Path, capsys: pytest.CaptureFixture) -> None:
    bd, root = _bundle(tmp_path, _corrupt_context(_GT_INNER))
    rc = ctx.run(_args(bd, root, apply=True), repo_root=tmp_path)
    out = capsys.readouterr().out
    assert rc == ctx.EXIT_OK, out
    payload = json.loads(out)
    att = payload["attestation"]
    assert att["added_lines_identity_proof"]["identical"] is True
    assert att["deleted_lines_identity_proof"]["identical"] is True
    assert att["raw_dry_run"]["applies"] is False
    assert att["dry_run"]["applies"] is True
    assert len(att["hunk_substitutions"]) == 1
    assert att["reviewer_attestation"] is None
    # attestation file written and internally consistent with the new bytes
    sidecar = json.loads((bd / ctx.ATTESTATION_FILENAME).read_text())
    new_patch = (bd / "patch.diff").read_text()
    assert sidecar["normalized_patch_diff_sha256"] == ctx.sha256_text(new_patch)
    # the normalized payload re-extracts and applies at fuzz=0
    from tools.trace_cli import nested_patch
    inner, _names = nested_patch.extract_nested_source_patch(new_patch)
    ok, output = ctx._dry_run(root, inner, ["-p1"])
    assert ok, output
    # package.nix wiring section preserved byte-identical
    assert "patches = [ ./CVE-0000-0000.patch ];" in new_patch
    # the payload preamble (model-authored From/Subject) is preserved
    assert "Subject: [PATCH] add overflow guard" in inner


def test_no_apply_fails_closed(tmp_path: Path, capsys: pytest.CaptureFixture) -> None:
    bd, root = _bundle(tmp_path, _corrupt_context(_GT_INNER))
    before = (bd / "patch.diff").read_text()
    rc = ctx.run(_args(bd, root, apply=False), repo_root=tmp_path)
    payload = json.loads(capsys.readouterr().out)
    assert rc == ctx.EXIT_APPLY_FAILED
    assert payload["normalization_needed"] is True
    assert payload["raw_payload_applies"] is False
    assert (bd / "patch.diff").read_text() == before
    assert not (bd / ctx.ATTESTATION_FILENAME).exists()


def test_added_line_divergence_refused(tmp_path: Path, capsys: pytest.CaptureFixture) -> None:
    diverged = _corrupt_context(_GT_INNER).replace("fail();", "exploit();")
    bd, root = _bundle(tmp_path, diverged)
    rc = ctx.run(_args(bd, root, apply=True), repo_root=tmp_path)
    payload = json.loads(capsys.readouterr().out)
    assert rc == ctx.EXIT_REFUSED
    assert "ADDED lines differ" in payload["error"]
    assert not (bd / ctx.ATTESTATION_FILENAME).exists()


def test_deleted_line_divergence_refused(tmp_path: Path, capsys: pytest.CaptureFixture) -> None:
    # Ground truth variant that also deletes a line; raw payload does not.
    gt_del = _GT_INNER.replace(
        "@@ -2,4 +2,7 @@ static int study(void) {\n",
        "@@ -2,5 +2,7 @@ static int study(void) {\n",
    ).replace(
        "     grow(l);\n     return l;\n",
        "-    grow(l);\n     grow(l);\n     return l;\n",
    )
    bd, root = _bundle(tmp_path, _corrupt_context(_GT_INNER))
    (bd / "upstream-fix.patch").write_text(gt_del)
    rc = ctx.run(_args(bd, root, apply=True), repo_root=tmp_path)
    payload = json.loads(capsys.readouterr().out)
    assert rc == ctx.EXIT_REFUSED
    assert "DELETED lines differ" in payload["error"]


def test_hunk_count_mismatch_refused(tmp_path: Path, capsys: pytest.CaptureFixture) -> None:
    two_hunks = _GT_INNER.replace(
        "--\n2.43.0\n",
        "@@ -6,1 +9,2 @@ static int study(void) {\n"
        " }\n"
        "+// end\n"
        "--\n2.43.0\n",
    )
    bd, root = _bundle(tmp_path, _corrupt_context(_GT_INNER))
    (bd / "upstream-fix.patch").write_text(two_hunks)
    rc = ctx.run(_args(bd, root, apply=True), repo_root=tmp_path)
    payload = json.loads(capsys.readouterr().out)
    assert rc == ctx.EXIT_REFUSED
    assert "hunk" in payload["error"]


def test_file_set_mismatch_refused(tmp_path: Path, capsys: pytest.CaptureFixture) -> None:
    bd, root = _bundle(tmp_path, _corrupt_context(_GT_INNER))
    (bd / "upstream-fix.patch").write_text(_GT_INNER.replace("study.c", "other.c"))
    rc = ctx.run(_args(bd, root, apply=True), repo_root=tmp_path)
    payload = json.loads(capsys.readouterr().out)
    assert rc == ctx.EXIT_REFUSED


def test_already_canonical_is_noop(tmp_path: Path, capsys: pytest.CaptureFixture) -> None:
    bd, root = _bundle(tmp_path, _GT_INNER)
    before = (bd / "patch.diff").read_text()
    rc = ctx.run(_args(bd, root, apply=True), repo_root=tmp_path)
    payload = json.loads(capsys.readouterr().out)
    assert rc == ctx.EXIT_OK
    assert payload["normalization_needed"] is False
    assert (bd / "patch.diff").read_text() == before
    assert not (bd / ctx.ATTESTATION_FILENAME).exists()


def test_trailer_not_misread_as_deletion() -> None:
    """`-- ` + version after the last hunk must not be counted as a deletion
    line: parsing is driven by the @@ header counts."""
    files = ctx._parse_unified_diff(_GT_INNER, "gt")
    assert len(files) == 1
    (f,) = files
    assert ctx._hunk_deleted(f["hunks"][0]) == []
    assert len(ctx._hunk_added(f["hunks"][0])) == 3


def test_count_mismatch_body_fails_closed() -> None:
    bad = _GT_INNER.replace("@@ -2,4 +2,7 @@", "@@ -2,9 +2,12 @@")
    with pytest.raises(ctx.ContextNormalizationError, match="declared counts"):
        ctx._parse_unified_diff(bad, "bad")
