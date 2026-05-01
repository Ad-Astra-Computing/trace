"""Minimal CartographerGraph backed by a Scout snapshot.

The Scout snapshot lists every nixpkgs attr_path with metadata
(pname, version, optional CPEs/PURLs) but carries no rebuild graph.
That's enough for get_node, but reverse-closure, critical-downstream,
and maintainer queries return empty.

This adapter is paired with analyze(analysis_status='skipped-v0')
so impact.json carries an explicit 'unanalyzed' flag and Steward
routes auto-merge candidates to human-review-required until a real
graph backend lands. See policy/impact-schema.json's analysis_status
field and policy/steward_route.rego's impact-unanalyzed rule.
"""

from __future__ import annotations

from typing import Iterable, Sequence

from agents.cartographer.graph import GraphNode, Maintainer
from agents.scout.graph_lookup import GraphMatch


class SnapshotMinimalCartographerGraph:
    """Wraps Scout snapshot records (`GraphMatch`) into the
    CartographerGraph protocol. No reverse-closure data."""

    def __init__(self, records: Iterable[GraphMatch]):
        self._by_attr: dict[str, GraphMatch] = {r.attr_path: r for r in records}

    def get_node(self, attr_path: str) -> GraphNode | None:
        m = self._by_attr.get(attr_path)
        if m is None:
            return None
        return GraphNode(
            attr_path=m.attr_path,
            drv_path=m.drv_path,
            pname=m.pname,
            version=m.version,
            cpes=m.cpes,
            purls=m.purls,
        )

    def reverse_closure(self, attr_path: str) -> Sequence[str]:
        return ()

    def critical_downstreams(self, attr_path: str) -> Sequence[str]:
        return ()

    def maintainers(self, attr_path: str) -> Sequence[Maintainer]:
        return ()
