"""Tests for `trace bundle normalize-sourceroot` (tools/trace_cli/normalize_sourceroot.py).

Covers the 4 load-bearing cases:
  (a) tarball-root paths + subdir sourceRoot, no --apply -> gate FAILS closed
  (b) same, with --apply -> normalizes + emits a valid attestation whose
      body-identity proof holds (raw and normalized hunk BODIES hash equal)
  (c) an ambiguous patch (more than one strip depth applies) -> FAILS closed
  (d) an already-applying patch -> passes, no normalization performed

All cases run via `--source-tree` (no network / nix fetch) — `--source-tree`
is taken to already be the derivation's EFFECTIVE sourceRoot.
"""

from __future__ import annotations

import argparse
import json
import subprocess
from pathlib import Path

import pytest

from tools.trace_cli import normalize_sourceroot as norm


_SRC_BEFORE = "int main(void) {\n    int x = 1;\n    return x;\n}\n"
_SRC_AFTER = "int main(void) {\n    int x = 2;\n    return x;\n}\n"


def _diff_text(tmp: Path, tag: str, label: str, before: str, after: str) -> str:
    a = tmp / f"{tag}-before.c"
    b = tmp / f"{tag}-after.c"
    a.write_text(before)
    b.write_text(after)
    proc = subprocess.run(
        [
            "diff",
            "-u",
            "--label",
            f"a/{label}",
            "--label",
            f"b/{label}",
            str(a),
            str(b),
        ],
        capture_output=True,
        text=True,
    )
    assert proc.returncode == 1, proc.stderr
    return proc.stdout


def _wrap_as_added_patch_file(
    inner_diff_text: str, patch_filename: str = "CVE-9999.patch"
) -> str:
    lines = inner_diff_text.splitlines()
    n = len(lines)
    body = "\n".join("+" + line for line in lines)
    return (
        f"diff --git a/{patch_filename} b/{patch_filename}\n"
        f"new file mode 100644\n"
        f"--- /dev/null\n"
        f"+++ b/{patch_filename}\n"
        f"@@ -0,0 +1,{n} @@\n"
        f"{body}\n"
    )


def _effective_root(tmp: Path, rel_file: str, content: str) -> Path:
    root = tmp / "effective-root"
    target = root / rel_file
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(content)
    return root


def test_patch_flags_cli_accepts_dash_prefixed_value() -> None:
    """`--patch-flags=-p0` must parse: argparse would treat a space-separated
    `-p0` as an option, so the CLI takes one `=`-attached string and splits it."""
    parser = argparse.ArgumentParser()
    subs = parser.add_subparsers()
    norm.add_parser(subs)
    args = parser.parse_args(
        [
            "normalize-sourceroot",
            "bundle",
            "--source-tree",
            "tree",
            "--patch-flags=-p0 -d sub",
        ]
    )
    assert args.patch_flags == "-p0 -d sub"
    assert args.patch_flags.split() == ["-p0", "-d", "sub"]


def _make_flat_bundle_with_wrong_prefix(tmp_path: Path) -> tuple[Path, Path]:
    """Flat shape (no nested *.patch): patch.diff edits the source file
    directly + a package.nix section, and carries one extra `src/` component.
    Exercises the flat-diff --apply write-back path."""
    root = _effective_root(tmp_path, "lib/foo.c", _SRC_BEFORE)
    inner = _diff_text(tmp_path, "flat", "src/lib/foo.c", _SRC_BEFORE, _SRC_AFTER)
    flat = (
        "diff --git a/src/lib/foo.c b/src/lib/foo.c\n"
        + inner
        + "diff --git a/package.nix b/package.nix\n"
        + "--- a/package.nix\n+++ b/package.nix\n@@ -1,1 +1,2 @@\n"
        + " keep = 1;\n+  patches = [ ./x.patch ];\n"
    )
    bd = tmp_path / "flat-bundle"
    bd.mkdir()
    (bd / "patch.diff").write_text(flat)
    return bd, root


def test_apply_normalizes_flat_shape(
    tmp_path: Path, capsys: pytest.CaptureFixture
) -> None:
    """The advertised flat-diff fallback must actually rewrite + attest (guards
    against a regression where the flat write-back called a removed helper)."""
    bd, root = _make_flat_bundle_with_wrong_prefix(tmp_path)
    rc = norm.run(_args(bd, root, apply=True), repo_root=tmp_path)
    assert rc == norm.EXIT_OK, capsys.readouterr().out
    payload = json.loads(capsys.readouterr().out)
    assert payload["ok"] is True
    assert payload["attestation"]["body_identity_proof"]["identical"] is True
    rewritten = (bd / "patch.diff").read_text()
    assert "a/src/lib/foo.c" not in rewritten
    assert "a/lib/foo.c" in rewritten
    assert "patches = [ ./x.patch ];" in rewritten  # package.nix section preserved


def _args(
    bundle_dir: Path, source_tree: Path, apply: bool = False, **kw: object
) -> argparse.Namespace:
    base: dict[str, object] = dict(
        bundle_dir=bundle_dir,
        source_tree=source_tree,
        strip_max=norm.DEFAULT_MAX_EXTRA_STRIP,
        apply=apply,
        format="json",
    )
    base.update(kw)
    return argparse.Namespace(**base)


def _make_bundle_with_wrong_prefix(tmp_path: Path) -> tuple[Path, Path]:
    """krb5 shape: effective root has `lib/gssapi/spnego/negoex_util.c`
    (sourceRoot already descended past `src/`); patch.diff carries one extra
    `src/` component. Returns (bundle_dir, effective_root)."""
    root = _effective_root(tmp_path, "lib/gssapi/spnego/negoex_util.c", _SRC_BEFORE)
    inner = _diff_text(
        tmp_path,
        "wrong",
        "src/lib/gssapi/spnego/negoex_util.c",
        _SRC_BEFORE,
        _SRC_AFTER,
    )
    bd = tmp_path / "bundle"
    bd.mkdir()
    (bd / "patch.diff").write_text(_wrap_as_added_patch_file(inner))
    return bd, root


# ─── (a) fails closed without --apply ──────────────────────────────────────


def test_no_apply_fails_closed_on_mismatch(
    tmp_path: Path, capsys: pytest.CaptureFixture
) -> None:
    bd, root = _make_bundle_with_wrong_prefix(tmp_path)

    rc = norm.run(_args(bd, root, apply=False), repo_root=tmp_path)

    assert rc == norm.EXIT_APPLY_FAILED
    payload = json.loads(capsys.readouterr().out)
    assert payload["ok"] is False
    assert payload["normalization_needed"] is True
    assert payload["extra_path_components_stripped"] == 1
    # No write on the gate-only path.
    assert not (bd / norm.ATTESTATION_FILENAME).exists()
    original = (bd / "patch.diff").read_text()
    assert "src/lib/gssapi/spnego/negoex_util.c" in original  # untouched


# ─── (b) --apply normalizes + valid attestation ────────────────────────────


def test_apply_normalizes_and_emits_valid_attestation(
    tmp_path: Path, capsys: pytest.CaptureFixture
) -> None:
    bd, root = _make_bundle_with_wrong_prefix(tmp_path)

    rc = norm.run(_args(bd, root, apply=True), repo_root=tmp_path)

    assert rc == norm.EXIT_OK
    payload = json.loads(capsys.readouterr().out)
    assert payload["ok"] is True
    attestation = payload["attestation"]

    assert attestation["extra_path_components_stripped"] == 1
    assert attestation["path_mappings"] == [
        {
            "old_path": "src/lib/gssapi/spnego/negoex_util.c",
            "new_path": "lib/gssapi/spnego/negoex_util.c",
        }
    ]
    proof = attestation["body_identity_proof"]
    assert proof["identical"] is True
    assert proof["raw_body_sha256"] == proof["normalized_body_sha256"]
    assert attestation["dry_run"]["applies"] is True
    assert attestation["dry_run"]["fuzz"] == 0

    # patch.diff was rewritten in place.
    rewritten = (bd / "patch.diff").read_text()
    assert "src/lib/gssapi/spnego/negoex_util.c" not in rewritten
    assert "lib/gssapi/spnego/negoex_util.c" in rewritten

    # attestation persisted to disk, matches stdout payload.
    on_disk = json.loads((bd / norm.ATTESTATION_FILENAME).read_text())
    assert on_disk == attestation

    # the guard now passes against the rewritten patch.diff.
    from tools.trace_cli import preflight

    gate = preflight.check_patch_diff_effective_root(bd, source_tree=root)
    assert gate["ok"] is True


def test_apply_body_identity_proof_survives_reextraction(tmp_path: Path) -> None:
    """Directly exercise the hunk-body-only claim: re-extracting the source
    patch from the rewritten patch.diff and stripping path headers from BOTH
    the original and the rewritten text must hash identically."""
    bd, root = _make_bundle_with_wrong_prefix(tmp_path)
    raw_text = (bd / "patch.diff").read_text()

    from tools.trace_cli import nested_patch

    raw_inner, _ = nested_patch.extract_nested_source_patch(raw_text)
    normalized_inner = norm.rewrite_patch_paths(raw_inner, 1)

    raw_body = norm.strip_path_headers(raw_inner)
    norm_body = norm.strip_path_headers(normalized_inner)
    assert norm.sha256_text(raw_body) == norm.sha256_text(norm_body)
    # Sanity: the bodies actually contain the guard content (proof isn't
    # vacuous because everything got stripped).
    assert "x = 1" in raw_body or "x = 2" in raw_body


# ─── (c) ambiguous strip -> fail closed ────────────────────────────────────


def test_ambiguous_strip_fails_closed(
    tmp_path: Path, capsys: pytest.CaptureFixture
) -> None:
    """A pathological tree where BOTH extra=0 and extra=1 resolve to a real,
    applying file — the tool must refuse to guess which one is "the" fix
    rather than silently picking one."""
    root = tmp_path / "effective-root"
    (root / "x" / "y").mkdir(parents=True)
    (root / "y").mkdir(parents=True)
    (root / "x" / "y" / "file.c").write_text(_SRC_BEFORE)
    (root / "y" / "file.c").write_text(_SRC_BEFORE)

    inner = _diff_text(tmp_path, "ambig", "x/y/file.c", _SRC_BEFORE, _SRC_AFTER)
    bd = tmp_path / "bundle"
    bd.mkdir()
    (bd / "patch.diff").write_text(_wrap_as_added_patch_file(inner))

    rc = norm.run(_args(bd, root, apply=True), repo_root=tmp_path)

    assert rc == norm.EXIT_AMBIGUOUS
    payload = json.loads(capsys.readouterr().out)
    assert payload["ok"] is False
    assert not (bd / norm.ATTESTATION_FILENAME).exists()
    # Neither copy was mutated by the ambiguous run.
    assert (root / "x" / "y" / "file.c").read_text() == _SRC_BEFORE
    assert (root / "y" / "file.c").read_text() == _SRC_BEFORE


# ─── (d) already-applying patch -> pass, no normalization ─────────────────


def test_already_applying_patch_passes_without_normalizing(
    tmp_path: Path, capsys: pytest.CaptureFixture
) -> None:
    root = _effective_root(tmp_path, "foo.c", _SRC_BEFORE)
    inner = _diff_text(tmp_path, "clean", "foo.c", _SRC_BEFORE, _SRC_AFTER)
    bd = tmp_path / "bundle"
    bd.mkdir()
    original_patch_diff = _wrap_as_added_patch_file(inner)
    (bd / "patch.diff").write_text(original_patch_diff)

    rc = norm.run(_args(bd, root, apply=False), repo_root=tmp_path)

    assert rc == norm.EXIT_OK
    payload = json.loads(capsys.readouterr().out)
    assert payload["ok"] is True
    assert payload["normalization_needed"] is False
    # Nothing written — there was nothing to normalize.
    assert not (bd / norm.ATTESTATION_FILENAME).exists()
    assert (bd / "patch.diff").read_text() == original_patch_diff

    # Also true with --apply: still a no-op (extra_strip == 0 short-circuits
    # before any write).
    rc2 = norm.run(_args(bd, root, apply=True), repo_root=tmp_path)
    assert rc2 == norm.EXIT_OK
    assert not (bd / norm.ATTESTATION_FILENAME).exists()


# ─── error paths ────────────────────────────────────────────────────────────


def test_missing_patch_diff_not_found(
    tmp_path: Path, capsys: pytest.CaptureFixture
) -> None:
    bd = tmp_path / "bundle"
    bd.mkdir()
    root = tmp_path / "root"
    root.mkdir()
    rc = norm.run(_args(bd, root), repo_root=tmp_path)
    assert rc == norm.EXIT_NOT_FOUND


# ─── pure-logic unit tests ──────────────────────────────────────────────────


def test_rewrite_patch_paths_identity_at_zero() -> None:
    text = "diff --git a/src/foo.c b/src/foo.c\n--- a/src/foo.c\n+++ b/src/foo.c\n"
    assert norm.rewrite_patch_paths(text, 0) == text


def test_rewrite_patch_paths_drops_leading_component() -> None:
    text = "diff --git a/src/foo.c b/src/foo.c\n--- a/src/foo.c\n+++ b/src/foo.c\n"
    out = norm.rewrite_patch_paths(text, 1)
    assert "diff --git a/foo.c b/foo.c" in out
    assert "--- a/foo.c" in out
    assert "+++ b/foo.c" in out
    assert "src/" not in out


def test_rewrite_patch_paths_refuses_too_shallow() -> None:
    text = "--- a/foo.c\n+++ b/foo.c\n"
    with pytest.raises(norm.NormalizationError):
        norm.rewrite_patch_paths(text, 3)


_HEADER_LOOKALIKE_PATCH = (
    "--- a/src/doc.txt\n"
    "+++ b/src/doc.txt\n"
    "@@ -1,2 +1,3 @@\n"
    " line one\n"
    "+++ b/injected.c\n"  # ADDED source content that looks like a +++ header
    " line two\n"
)


def test_hunk_content_lookalike_is_not_a_file_header() -> None:
    """A hunk-body line that textually looks like `+++ b/…` must classify as
    content, never a file header — else normalization corrupts source bytes and
    the identity proof silently drops it."""
    roles = dict(norm._iter_line_roles(_HEADER_LOOKALIKE_PATCH))
    assert roles["+++ b/injected.c"] == "content"
    assert roles["--- a/src/doc.txt"] == "file_header"
    assert roles["+++ b/src/doc.txt"] == "file_header"


def test_rewrite_leaves_header_lookalike_content_untouched() -> None:
    out = norm.rewrite_patch_paths(_HEADER_LOOKALIKE_PATCH, 1)
    # The real header strips src/ ; the content lookalike is preserved verbatim.
    assert "--- a/doc.txt" in out
    assert "+++ b/doc.txt" in out
    assert "+++ b/injected.c" in out  # NOT rewritten to +++ b/... stripped


def test_strip_path_headers_keeps_hunk_content_lookalike() -> None:
    body = norm.strip_path_headers(_HEADER_LOOKALIKE_PATCH)
    assert "+++ b/injected.c" in body  # content stays in the body
    assert "--- a/src/doc.txt" not in body  # real header removed
    assert "+++ b/src/doc.txt" not in body


def test_identity_proof_catches_content_change_in_header_lookalike(
    tmp_path: Path,
) -> None:
    """The soundness gate: two patches identical except for a hunk-content line
    that looks like a header must NOT attest as a path-only change."""
    raw = (
        "--- a/src/doc.txt\n+++ b/src/doc.txt\n@@ -1,2 +1,3 @@\n"
        " line one\n+++ b/injected.c\n line two\n"
    )
    tampered = (  # only the header-lookalike content line differs
        "--- a/doc.txt\n+++ b/doc.txt\n@@ -1,2 +1,3 @@\n"
        " line one\n+++ b/DIFFERENT.c\n line two\n"
    )
    with pytest.raises(norm.NormalizationError, match="body-identity proof FAILED"):
        norm.build_attestation(
            bundle_dir=tmp_path,
            raw_patch_diff_text=raw,
            normalized_patch_diff_text=tampered,
            raw_source_patch_text=raw,
            normalized_source_patch_text=tampered,
            extra_strip=1,
            nixpkgs_rev=None,
            source_root=None,
            effective_root=tmp_path,
            source_hash=None,
            dry_run_output="",
            patch_flags=["-p1"],
            patcher_invocation_sha=None,
        )


def test_normalize_rejects_patch_diff_with_preamble() -> None:
    """--apply must fail closed on a patch.diff with a pre-`diff --git`
    preamble (rebuild-from-sections would drop it, breaking the path-only
    attestation)."""
    with_preamble = (
        "From abc123 Mon Sep 17 00:00:00 2001\n"
        "Subject: [PATCH] fix\n\n"
        "diff --git a/src/foo.c b/src/foo.c\n"
        "--- a/src/foo.c\n+++ b/src/foo.c\n@@ -1,1 +1,1 @@\n-old\n+new\n"
    )
    with pytest.raises(norm.NormalizationError, match="preamble"):
        norm.normalize_patch_diff(with_preamble, 1)


def test_rewrap_rejects_no_trailing_newline_nested_patch() -> None:
    """--apply rewrapping must fail closed on a nested *.patch with no trailing
    newline (round-tripping the `\\ No newline` marker isn't supported), so the
    written bytes can never diverge from the attested normalized hash."""
    section = {
        "raw_lines": [
            "diff --git a/CVE.patch b/CVE.patch",
            "new file mode 100644",
            "--- /dev/null",
            "+++ b/CVE.patch",
            "@@ -0,0 +1,1 @@",
            "+diff --git a/src/lib/foo.c b/src/lib/foo.c",
            "\\ No newline at end of file",
        ],
    }
    with pytest.raises(norm.NormalizationError, match="no trailing newline"):
        norm._rewrap_nested_section(section, 1)


def test_build_attestation_refuses_on_body_mismatch(tmp_path: Path) -> None:
    """The hard safety gate: if the (contrived) "normalized" text actually
    changes hunk bodies, build_attestation must refuse, never attest."""
    raw = "--- a/src/foo.c\n+++ b/src/foo.c\n@@ -1,1 +1,1 @@\n-a\n+b\n"
    tampered = "--- a/foo.c\n+++ b/foo.c\n@@ -1,1 +1,1 @@\n-a\n+DIFFERENT\n"
    with pytest.raises(norm.NormalizationError, match="body-identity proof FAILED"):
        norm.build_attestation(
            bundle_dir=tmp_path,
            raw_patch_diff_text=raw,
            normalized_patch_diff_text=tampered,
            raw_source_patch_text=raw,
            normalized_source_patch_text=tampered,
            extra_strip=1,
            nixpkgs_rev=None,
            source_root=None,
            effective_root=tmp_path,
            source_hash=None,
            dry_run_output="",
            patch_flags=["-p1"],
            patcher_invocation_sha=None,
        )


def test_strip_search_uses_supplied_patch_flags(tmp_path: Path) -> None:
    """The strip-search must dry-run with the package's own patchFlags, not a
    hard-coded -p1. The identical git-style patch resolves differently under
    -p1 vs -p0, proving the resolved flags are actually threaded through: at
    -p1 the `a/` prefix strips to `foo.c` (applies at extra=0); at -p0 the
    literal `a/foo.c` path has no in-tree file and never applies."""
    src = tmp_path / "tree"
    src.mkdir()
    (src / "foo.c").write_text("old\n")
    git_patch = "--- a/foo.c\n+++ b/foo.c\n@@ -1,1 +1,1 @@\n-old\n+new\n"
    strip_p1, _ = norm.find_unique_normalizing_strip(
        src, git_patch, 3, patch_flags=["-p1"]
    )
    strip_p0, _ = norm.find_unique_normalizing_strip(
        src, git_patch, 3, patch_flags=["-p0"]
    )
    assert strip_p1 == 0  # default nixpkgs strip: applies as-authored
    assert strip_p0 is None  # -p0 keeps `a/foo.c`, which is not in the tree


def test_strip_search_empty_flags_not_defaulted_to_p1(
    tmp_path: Path, monkeypatch
) -> None:
    """An explicitly empty patchFlags list is a valid value and must reach
    `patch` verbatim (just `--fuzz=0`, no injected -p1) — only None means 'use
    the -p1 default'. Capture the flags handed to apply_patch to prove it."""
    src = tmp_path / "tree"
    src.mkdir()
    (src / "foo.c").write_text("old\n")
    patch = "--- a/foo.c\n+++ b/foo.c\n@@ -1,1 +1,1 @@\n-old\n+new\n"
    seen: list[list[str]] = []

    def fake_apply(work, patch_file, flags):
        seen.append(list(flags))
        return True, "ok"

    monkeypatch.setattr(norm.preflight, "apply_patch", fake_apply)
    norm.find_unique_normalizing_strip(src, patch, 0, patch_flags=[])
    assert seen == [["--fuzz=0"]]  # empty flags honored, no -p1
    seen.clear()
    norm.find_unique_normalizing_strip(src, patch, 0, patch_flags=None)
    assert seen == [["-p1", "--fuzz=0"]]  # None → nixpkgs default
