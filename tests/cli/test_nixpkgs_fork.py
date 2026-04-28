"""Tests for `policy/nixpkgs-fork.json`.

Locks the canonical record of the trace project's nixpkgs fork target,
the patch-branch naming convention, and the trust boundary (trace
writes to the fork, NEVER to upstream).
"""

from __future__ import annotations

import json
import re
from pathlib import Path

from tests.schema.validate import REPO_ROOT


FORK_POLICY_PATH = REPO_ROOT / "policy" / "nixpkgs-fork.json"


def _load() -> dict:
    return json.loads(FORK_POLICY_PATH.read_text())


def test_fork_policy_parses() -> None:
    p = _load()
    assert p["schema_version"] == "1.0.0"
    assert "fork" in p
    assert "patch_branch_convention" in p
    assert "pr_convention" in p
    assert "trust_boundary" in p


def test_fork_targets_ad_astra_computing_nixpkgs() -> None:
    p = _load()
    assert p["fork"]["owner"] == "Ad-Astra-Computing"
    assert p["fork"]["repo"] == "nixpkgs"
    assert p["fork"]["url"] == "https://github.com/Ad-Astra-Computing/nixpkgs"
    assert p["fork"]["upstream"]["owner"] == "NixOS"
    assert p["fork"]["upstream"]["repo"] == "nixpkgs"


def test_tracked_channel_is_nixos_unstable() -> None:
    """SPEC §6.0 v0 gate 1: nixos-unstable only."""
    p = _load()
    assert p["fork"]["tracked_channels"] == ["nixos-unstable"]


def test_patch_branch_format_template_well_formed() -> None:
    p = _load()
    fmt = p["patch_branch_convention"]["format"]
    # Three placeholders required: cve_id, attr_path, bundle_id_short.
    for placeholder in ("{cve_id}", "{attr_path}", "{bundle_id_short}"):
        assert placeholder in fmt, f"format must contain {placeholder!r}"
    assert fmt.startswith("trace/")


def test_patch_branch_examples_match_format() -> None:
    """Each example in the examples list must be substitutable from the
    format template — sanity check that the docs and the rule agree."""
    p = _load()
    fmt = p["patch_branch_convention"]["format"]
    pattern_str = (
        re.escape(fmt)
        .replace(r"\{cve_id\}", r"(?P<cve_id>CVE-\d{4}-\d{4,19})")
        .replace(r"\{attr_path\}", r"(?P<attr_path>[A-Za-z0-9_]+)")
        .replace(r"\{bundle_id_short\}", r"(?P<bundle_id_short>[0-9a-f]{16})")
    )
    rx = re.compile(f"^{pattern_str}$")
    for example in p["patch_branch_convention"]["examples"]:
        assert rx.match(example), f"branch example {example!r} does not match format"


def test_pr_title_format_well_formed() -> None:
    p = _load()
    fmt = p["pr_convention"]["title_format"]
    for placeholder in ("{cve_id}", "{attr_path}", "{target_version}"):
        assert placeholder in fmt, f"PR title format must contain {placeholder!r}"


def test_pr_base_branch_matches_fork_default() -> None:
    p = _load()
    assert p["pr_convention"]["base_branch"] == p["fork"]["default_branch"]


def test_trust_boundary_records_no_upstream_writes() -> None:
    """Locked invariant: trace writes to the fork only, NEVER upstream.
    Any future change here demands a SPEC-level amendment + a DECISIONS
    entry, since upstream-write capability is a fundamentally different
    trust posture."""
    p = _load()
    boundary = p["trust_boundary"]
    assert boundary["trace_writes_to"] == "Ad-Astra-Computing/nixpkgs only"
    assert "NixOS/nixpkgs" in boundary["never_writes_to"]
