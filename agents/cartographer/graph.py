"""CartographerGraph contract + canned in-memory implementation for tests.

Extends the Scout lookup surface with graph-walk queries:

    * get_node(attr_path)                -> GraphNode | None
    * reverse_closure(attr_path)         -> Sequence[str]   (downstream attrs)
    * maintainers(attr_path)             -> Sequence[Maintainer]
    * critical_downstreams(attr_path)    -> Sequence[str]   (subset of
                                             reverse_closure flagged critical)

No version-range evaluation here either. Cartographer v0 asks the graph flat
questions; ranking / weighting of downstream importance belongs in the real
graph builder or a later stage.

The real nixpkgs-graph builder (planned Rust + SQLite/Parquet per SPEC §3.1)
will implement this Protocol alongside the Scout GraphLookup Protocol. Until
then tests use CannedCartographerGraph, which is a dict-backed stand-in.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Protocol, Sequence


@dataclass(frozen=True)
class GraphNode:
    attr_path: str
    drv_path: str
    pname: str
    version: str
    cpes: tuple[str, ...] = ()
    purls: tuple[str, ...] = ()


@dataclass(frozen=True)
class Maintainer:
    github: str | None = None
    email: str | None = None
    name: str | None = None


@dataclass(frozen=True)
class CannedNode:
    """Fixture-friendly node with everything a CannedCartographerGraph needs."""

    attr_path: str
    drv_path: str
    pname: str
    version: str
    cpes: tuple[str, ...] = ()
    purls: tuple[str, ...] = ()
    reverse_closure: tuple[str, ...] = ()
    critical_downstreams: tuple[str, ...] = ()
    maintainers: tuple[Maintainer, ...] = ()


class CartographerGraph(Protocol):
    def get_node(self, attr_path: str) -> GraphNode | None: ...
    def reverse_closure(self, attr_path: str) -> Sequence[str]: ...
    def maintainers(self, attr_path: str) -> Sequence[Maintainer]: ...
    def critical_downstreams(self, attr_path: str) -> Sequence[str]: ...


class CannedCartographerGraph:
    def __init__(self, nodes: Sequence[CannedNode]):
        self._by_attr: dict[str, CannedNode] = {n.attr_path: n for n in nodes}

    def get_node(self, attr_path: str) -> GraphNode | None:
        n = self._by_attr.get(attr_path)
        if n is None:
            return None
        return GraphNode(
            attr_path=n.attr_path,
            drv_path=n.drv_path,
            pname=n.pname,
            version=n.version,
            cpes=n.cpes,
            purls=n.purls,
        )

    def reverse_closure(self, attr_path: str) -> Sequence[str]:
        n = self._by_attr.get(attr_path)
        return list(n.reverse_closure) if n else []

    def maintainers(self, attr_path: str) -> Sequence[Maintainer]:
        n = self._by_attr.get(attr_path)
        return list(n.maintainers) if n else []

    def critical_downstreams(self, attr_path: str) -> Sequence[str]:
        n = self._by_attr.get(attr_path)
        return list(n.critical_downstreams) if n else []
