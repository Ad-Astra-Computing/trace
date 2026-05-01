"""SnapshotMinimalCartographerGraph tests.

The minimal graph adapter wraps the same nixpkgs snapshot Scout uses
and provides only the metadata that's actually present there
(get_node, maintainers when the snapshot carries them). It explicitly
returns empty reverse_closure / critical_downstreams so callers don't
mistake silence for absence; the analysis_status='skipped-v0' flag
on the resulting impact tells Steward to route to human review.

Slice 3 of the Patcher pipeline.
"""

from __future__ import annotations

from typing import Any

import pytest

from agents.cartographer.snapshot_graph import SnapshotMinimalCartographerGraph
from agents.scout.graph_lookup import GraphMatch


_RADARE2 = GraphMatch(
    attr_path="radare2",
    drv_path="/nix/store/aaa-radare2.drv",
    pname="radare2",
    version="6.1.2",
)


def test_get_node_returns_attr_metadata() -> None:
    g = SnapshotMinimalCartographerGraph([_RADARE2])
    node = g.get_node("radare2")
    assert node is not None
    assert node.attr_path == "radare2"
    assert node.pname == "radare2"


def test_get_node_returns_none_for_unknown() -> None:
    g = SnapshotMinimalCartographerGraph([_RADARE2])
    assert g.get_node("missing") is None


def test_reverse_closure_returns_empty_by_design() -> None:
    """The minimal adapter has no reverse-closure data. Returning empty
    is correct under analysis_status='skipped-v0'; callers must not
    interpret it as 'no dependents' (that's what the Steward gate is for)."""
    g = SnapshotMinimalCartographerGraph([_RADARE2])
    assert list(g.reverse_closure("radare2")) == []


def test_critical_downstreams_returns_empty_by_design() -> None:
    g = SnapshotMinimalCartographerGraph([_RADARE2])
    assert list(g.critical_downstreams("radare2")) == []


def test_maintainers_returns_empty_for_v0_snapshot() -> None:
    """nixpkgs snapshots produced by trace's snapshot_builder don't
    carry maintainer info today. Future enhancement could lift it from
    `meta.maintainers` per attr; v0 returns empty."""
    g = SnapshotMinimalCartographerGraph([_RADARE2])
    assert list(g.maintainers("radare2")) == []
