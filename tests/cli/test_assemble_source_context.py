"""assemble-side source-context staging (tools/trace_cli/bundle._stage_source_context).

Exercises the bootstrap extraction path with a pre-unpacked --source-tree (no nix
fetch): copy the pre-patch source the upstream fix touches into source-context/,
and bake the deterministic applies_verbatim verdict into preflight.json. The
verdict is a real `patch` dry-run, so the divergent-base case (the libarchive
shape) yields applies_verbatim=false while still capturing the affected source.
"""

from __future__ import annotations

import json
import subprocess
from pathlib import Path

from tools.trace_cli.bundle import _stage_source_context


def _make_patch(tmp: Path, before: str, after: str) -> Path:
    a, b = tmp / "a", tmp / "b"
    a.write_text(before)
    b.write_text(after)
    proc = subprocess.run(
        ["diff", "-u", "--label", "a/foo.c", "--label", "b/foo.c", str(a), str(b)],
        capture_output=True, text=True,
    )
    assert proc.returncode == 1, proc.stderr
    p = tmp / "upstream-fix.patch"
    p.write_text(proc.stdout)
    return p


def _source_tree(tmp: Path, name: str, content: str) -> Path:
    root = tmp / name
    root.mkdir()
    (root / "foo.c").write_text(content)
    return root


_BEFORE = "int main(void) {\n    int x = 1;\n    return x;\n}\n"
_AFTER = "int main(void) {\n    int x = 2;\n    return x;\n}\n"
_DIVERGENT = "int other(void) {\n    long y = 9;\n    return 0;\n}\n"


def test_stage_writes_source_context_and_verbatim_true(tmp_path):
    patch = _make_patch(tmp_path, _BEFORE, _AFTER)
    tree = _source_tree(tmp_path, "src", _BEFORE)
    out = tmp_path / "bundle"
    out.mkdir()
    written: list[str] = []
    _stage_source_context(
        out_dir=out, upstream_fix_patch_path=patch, source_tree=tree,
        write_source_context=True, files_written=written,
    )
    assert (out / "upstream-fix.patch").is_file()
    assert (out / "source-context" / "foo.c").read_text() == _BEFORE
    pf = json.loads((out / "preflight.json").read_text())
    assert pf["applies_verbatim"] is True
    assert "source-context/foo.c" in written
    assert "preflight.json" in written
    # dry-run left the source tree untouched
    assert (tree / "foo.c").read_text() == _BEFORE


def test_stage_divergent_base_yields_verbatim_false(tmp_path):
    """libarchive shape: the fix's context is absent from the pinned base."""
    patch = _make_patch(tmp_path, _BEFORE, _AFTER)
    tree = _source_tree(tmp_path, "src", _DIVERGENT)
    out = tmp_path / "bundle"
    out.mkdir()
    _stage_source_context(
        out_dir=out, upstream_fix_patch_path=patch, source_tree=tree,
        write_source_context=True, files_written=[],
    )
    # the affected file is still captured (it exists; the PATCH is what fails)
    assert (out / "source-context" / "foo.c").read_text() == _DIVERGENT
    pf = json.loads((out / "preflight.json").read_text())
    assert pf["applies_verbatim"] is False
    assert pf["diagnostics"]


def test_stage_addition_only_fix_stays_on_verbatim_lane(tmp_path):
    """An upstream fix that only ADDS files has no pre-patch source to adapt
    against: no source-context/ or preflight.json is created, so the bundle stays
    on the v3 verbatim lane and never routes to v4 with an empty context (codex P2)."""
    patch = tmp_path / "upstream-fix.patch"
    patch.write_text(
        "diff --git a/newfile.c b/newfile.c\n"
        "new file mode 100644\n"
        "--- /dev/null\n"
        "+++ b/newfile.c\n"
        "@@ -0,0 +1 @@\n"
        "+int added(void){return 0;}\n"
    )
    tree = _source_tree(tmp_path, "src", _BEFORE)
    out = tmp_path / "bundle"
    out.mkdir()
    written: list[str] = []
    _stage_source_context(
        out_dir=out, upstream_fix_patch_path=patch, source_tree=tree,
        write_source_context=True, files_written=written,
    )
    assert (out / "upstream-fix.patch").is_file()
    assert not (out / "source-context").exists()
    assert not (out / "preflight.json").exists()
    assert written == ["upstream-fix.patch"]


def test_restage_clears_stale_source_context(tmp_path):
    """Re-assembling with an addition-only patch must drop the source-context/ +
    preflight.json a prior run left behind (codex P2 — no stale signed context)."""
    out = tmp_path / "bundle"
    out.mkdir()
    # first run: a real adaptation-lane patch → source-context/foo.c + preflight.json
    patch1 = _make_patch(tmp_path, _BEFORE, _AFTER)
    tree = _source_tree(tmp_path, "src", _BEFORE)
    _stage_source_context(out_dir=out, upstream_fix_patch_path=patch1,
                          source_tree=tree, write_source_context=True, files_written=[])
    assert (out / "source-context" / "foo.c").is_file()
    assert (out / "preflight.json").is_file()
    # second run: addition-only patch → both stale artifacts removed
    add_only = tmp_path / "add.patch"
    add_only.write_text(
        "diff --git a/new.c b/new.c\nnew file mode 100644\n--- /dev/null\n"
        "+++ b/new.c\n@@ -0,0 +1 @@\n+int x;\n"
    )
    _stage_source_context(out_dir=out, upstream_fix_patch_path=add_only,
                          source_tree=tree, write_source_context=True, files_written=[])
    assert not (out / "source-context").exists()
    assert not (out / "preflight.json").exists()


def test_stage_without_source_tree_stages_diff_only(tmp_path):
    patch = _make_patch(tmp_path, _BEFORE, _AFTER)
    out = tmp_path / "bundle"
    out.mkdir()
    written: list[str] = []
    _stage_source_context(
        out_dir=out, upstream_fix_patch_path=patch, source_tree=None,
        write_source_context=False, files_written=written,
    )
    assert (out / "upstream-fix.patch").is_file()
    assert not (out / "source-context").exists()
    assert not (out / "preflight.json").exists()
    assert written == ["upstream-fix.patch"]
