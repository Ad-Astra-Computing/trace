"""finalize-time tautology guard for stub-harness fixtures.

Per docs/specs/stub-harness-fixtures.md: `trace bundle finalize` refuses a
bundle whose `reproducer-log.txt` carries a `=== harness ===` section that
either targets a file neither `patch.diff` nor `upstream-fix.patch` touches,
or stubs something the patch itself changed. A log without the section is
unaffected.
"""

from __future__ import annotations

import shutil
from pathlib import Path

import pytest

from tools.trace_cli.bundle import BundleSchemaError, finalize_bundle

_GOOD = (
    Path(__file__).resolve().parents[2] / "traces" / "example" / "CVE-2024-8176--expat"
)
_DOCS = (
    "finding.json",
    "impact.json",
    "maintainers.json",
    "upstream-ref.json",
    "package.nix",
)


def _seed(tmp_path: Path) -> Path:
    bd = tmp_path / "bundle"
    bd.mkdir()
    for f in _DOCS:
        shutil.copyfile(_GOOD / f, bd / f)
    return bd


_NESTED_PATCH_DIFF = """\
--- /dev/null
+++ b/pkgs/by-name/xy/xy/xy-CVE-9999.patch
@@ -0,0 +1,4 @@
+--- a/scripts/lua/rest/v2/delete/endpoints.lua
++++ b/scripts/lua/rest/v2/delete/endpoints.lua
+@@ -1,1 +1,1 @@
+-old
--- a/pkgs/by-name/xy/xy/package.nix
+++ b/pkgs/by-name/xy/xy/package.nix
@@ -1,1 +1,1 @@
-old
+new
"""


def _harness_log(
    target_files: str = "scripts/lua/rest/v2/delete/endpoints.lua",
    stubbed: str = "ntop, rest_utils, auth",
) -> str:
    return (
        "=== unpatched ===\n"
        "SIGNAL_UNPATCHED: not-granted-check-was-bypassed-for-notifications\n"
        "EXIT: 0\n"
        "\n"
        "=== patched ===\n"
        "SIGNAL_PATCHED: not_granted-refused-before-endpoints-reset-configs\n"
        "EXIT: 0\n"
        "\n"
        "=== harness ===\n"
        "harness_class: stub-ambient\n"
        f"target_files: {target_files}\n"
        f"stubbed: {stubbed}\n"
        "effect: the handler proceeds without the capability check\n"
    )


def test_clean_harness_declaration_passes(tmp_path: Path) -> None:
    bd = _seed(tmp_path)
    (bd / "patch.diff").write_text(_NESTED_PATCH_DIFF)
    (bd / "reproducer-log.txt").write_text(_harness_log())
    res = finalize_bundle(
        bundle_dir=bd,
        bundle_kind="human-review-required",
        created_at="2026-09-07T00:00:00Z",
    )
    assert (bd / "bundle.json").is_file()
    assert res.bundle_id


def test_nested_source_patch_counts_as_touched(tmp_path: Path) -> None:
    """The target lives only inside the nested source patch carried as an
    added file within patch.diff, not in patch.diff's own outer headers."""
    bd = _seed(tmp_path)
    (bd / "patch.diff").write_text(_NESTED_PATCH_DIFF)
    (bd / "reproducer-log.txt").write_text(
        _harness_log(target_files="scripts/lua/rest/v2/delete/endpoints.lua")
    )
    finalize_bundle(
        bundle_dir=bd,
        bundle_kind="human-review-required",
        created_at="2026-09-07T00:00:00Z",
    )
    assert (bd / "bundle.json").is_file()


def test_target_not_touched_by_either_patch_refuses(tmp_path: Path) -> None:
    bd = _seed(tmp_path)
    (bd / "patch.diff").write_text(_NESTED_PATCH_DIFF)
    (bd / "reproducer-log.txt").write_text(
        _harness_log(target_files="scripts/lua/rest/v2/delete/recipients.lua")
    )
    with pytest.raises(BundleSchemaError, match="recipients.lua"):
        finalize_bundle(
            bundle_dir=bd,
            bundle_kind="human-review-required",
            created_at="2026-09-07T00:00:00Z",
        )
    assert not (bd / "bundle.json").is_file()


def test_stubbed_name_equal_to_target_basename_passes(tmp_path: Path) -> None:
    """ntopng: the `endpoints` module the handler requires shares its name with
    the handler file `delete/endpoints.lua` the harness loads unaltered. The
    target is declared, so the same-named stub is the ambient module."""
    bd = _seed(tmp_path)
    (bd / "patch.diff").write_text(_NESTED_PATCH_DIFF)
    (bd / "reproducer-log.txt").write_text(
        _harness_log(
            target_files="scripts/lua/rest/v2/delete/endpoints.lua",
            stubbed="ntop, endpoints, auth",
        )
    )
    res = finalize_bundle(
        bundle_dir=bd,
        bundle_kind="human-review-required",
        created_at="2026-09-07T00:00:00Z",
    )
    assert res.bundle_id


def test_stubbed_name_equal_to_untargeted_touched_basename_refuses(
    tmp_path: Path,
) -> None:
    """A touched file the harness does not load may not be stubbed away."""
    bd = _seed(tmp_path)
    (bd / "patch.diff").write_text(
        _NESTED_PATCH_DIFF.replace(
            "+-old\n",
            "+-old\n"
            "+--- a/scripts/lua/modules/pools/pools_rest_utils.lua\n"
            "++++ b/scripts/lua/modules/pools/pools_rest_utils.lua\n"
            "+@@ -1,1 +1,1 @@\n"
            "+-old\n",
        )
    )
    (bd / "reproducer-log.txt").write_text(
        _harness_log(
            target_files="scripts/lua/rest/v2/delete/endpoints.lua",
            stubbed="ntop, pools_rest_utils, auth",
        )
    )
    with pytest.raises(BundleSchemaError, match="pools_rest_utils"):
        finalize_bundle(
            bundle_dir=bd,
            bundle_kind="human-review-required",
            created_at="2026-09-07T00:00:00Z",
        )
    assert not (bd / "bundle.json").is_file()


def test_stubbed_name_equal_to_basename_without_extension_refuses(
    tmp_path: Path,
) -> None:
    """stubbed 'package' matches touched pkgs/by-name/xy/xy/package.nix's stem."""
    bd = _seed(tmp_path)
    (bd / "patch.diff").write_text(_NESTED_PATCH_DIFF)
    (bd / "reproducer-log.txt").write_text(
        _harness_log(
            target_files="scripts/lua/rest/v2/delete/endpoints.lua",
            stubbed="ntop, package, auth",
        )
    )
    with pytest.raises(BundleSchemaError, match="package"):
        finalize_bundle(
            bundle_dir=bd,
            bundle_kind="human-review-required",
            created_at="2026-09-07T00:00:00Z",
        )
    assert not (bd / "bundle.json").is_file()


def test_log_without_harness_section_unaffected(tmp_path: Path) -> None:
    bd = _seed(tmp_path)
    (bd / "patch.diff").write_text(_NESTED_PATCH_DIFF)
    (bd / "reproducer-log.txt").write_text(
        "=== unpatched ===\n"
        "SIGNAL_UNPATCHED: vuln-triggered-oob-read-on-malformed-input\n"
        "EXIT: 1\n"
        "\n"
        "=== patched ===\n"
        "SIGNAL_PATCHED: rejected-malformed-input-as-expected\n"
        "EXIT: 0\n"
    )
    res = finalize_bundle(
        bundle_dir=bd,
        bundle_kind="human-review-required",
        created_at="2026-09-07T00:00:00Z",
    )
    assert (bd / "bundle.json").is_file()
    assert res.bundle_id


def test_no_reproducer_log_unaffected(tmp_path: Path) -> None:
    bd = _seed(tmp_path)
    res = finalize_bundle(
        bundle_dir=bd,
        bundle_kind="human-review-required",
        created_at="2026-09-07T00:00:00Z",
    )
    assert (bd / "bundle.json").is_file()
    assert res.bundle_id


def test_malformed_harness_section_refuses(tmp_path: Path) -> None:
    """A harness header whose body does not parse is refused, not skipped."""
    bd = _seed(tmp_path)
    (bd / "patch.diff").write_text(_NESTED_PATCH_DIFF)
    (bd / "reproducer-log.txt").write_text(
        "=== unpatched ===\n"
        "SIGNAL_UNPATCHED: vuln-triggered-oob-read-on-malformed-input\n"
        "EXIT: 1\n"
        "\n"
        "=== patched ===\n"
        "SIGNAL_PATCHED: rejected-malformed-input-as-expected\n"
        "EXIT: 0\n"
        "\n"
        "=== harness ===\n"
        "harness_class: not-a-real-class\n"
        "target_files: scripts/lua/rest/v2/delete/endpoints.lua\n"
        "stubbed: ntop\n"
        "effect: the handler proceeds without the capability check\n"
    )
    with pytest.raises(BundleSchemaError, match="does not parse"):
        finalize_bundle(
            bundle_dir=bd,
            bundle_kind="human-review-required",
            created_at="2026-09-07T00:00:00Z",
        )
