"""GraphLookup contract + a canned in-memory implementation for tests.

Scout only needs a read-only interface over the graph, exposed as three lookup
methods. The real nixpkgs-graph builder (future) will implement the same
Protocol backed by a SQLite / Parquet snapshot. Until then, tests construct a
CannedGraphLookup from a dict.

Deliberately minimal: no version-range evaluation, no reverse-closure queries.
Scout in v0 only asks "what derivations match this identifier?"; version-range
intersection and rebuild impact live one layer up (Cartographer + the graph
itself).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol, Sequence


@dataclass(frozen=True)
class GraphMatch:
    attr_path: str
    drv_path: str
    pname: str
    version: str
    cpes: tuple[str, ...] = ()
    purls: tuple[str, ...] = ()
    src_url: str | None = None
    src_hash: str | None = None


class GraphLookup(Protocol):
    def find_by_cpe(self, cpe: str) -> Sequence[GraphMatch]: ...
    def find_by_purl(self, purl: str) -> Sequence[GraphMatch]: ...
    def find_by_pname(self, pname: str) -> Sequence[GraphMatch]: ...


class CannedGraphLookup:
    """Build from a list of GraphMatch records. Indexes by cpe, purl, pname."""

    def __init__(self, records: Sequence[GraphMatch]):
        self._by_cpe: dict[str, list[GraphMatch]] = {}
        self._by_purl: dict[str, list[GraphMatch]] = {}
        self._by_pname: dict[str, list[GraphMatch]] = {}
        for r in records:
            for c in r.cpes:
                self._by_cpe.setdefault(c, []).append(r)
            for p in r.purls:
                self._by_purl.setdefault(p, []).append(r)
            self._by_pname.setdefault(r.pname, []).append(r)

    def find_by_cpe(self, cpe: str) -> Sequence[GraphMatch]:
        return list(self._by_cpe.get(cpe, ()))

    def find_by_purl(self, purl: str) -> Sequence[GraphMatch]:
        return list(self._by_purl.get(purl, ()))

    def find_by_pname(self, pname: str) -> Sequence[GraphMatch]:
        return list(self._by_pname.get(pname, ()))
