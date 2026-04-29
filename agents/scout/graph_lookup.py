"""GraphLookup contract + a canned in-memory implementation.

Scout only needs a read-only interface over the graph, exposed as four
lookup methods:

  find_by_cpe          exact CPE 2.3 string match
  find_by_cpe_product  match by CPE product (4th colon field) only;
                       vendor-agnostic fallback for the relevance filter
                       when a real CPE dictionary isn't available
  find_by_purl         exact PURL match
  find_by_pname        exact pname match

The snapshot builder (agents.scout.snapshot_builder) backs this with
records produced from `nix-env -qaP --json --drv-path`. Until vendor
disambiguation lands (real NVD CPE dictionary integration),
find_by_cpe_product covers the relevance-filter case where a CVE
quotes `cpe:2.3:a:libtiff:libtiff:...` and the snapshot has a record
with pname=libtiff.

Deliberately minimal: no version-range evaluation, no reverse-closure
queries. Scout asks "what derivations match this identifier?";
version-range intersection and rebuild impact live one layer up
(Cartographer + the graph itself).
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Protocol, Sequence


# cpe:2.3:<part>:<vendor>:<product>:<version>:...
_CPE_PRODUCT_RE = re.compile(r"^cpe:2\.3:[^:]+:[^:]+:([^:]+):")


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
    def find_by_cpe_product(self, product: str) -> Sequence[GraphMatch]: ...
    def find_by_purl(self, purl: str) -> Sequence[GraphMatch]: ...
    def find_by_pname(self, pname: str) -> Sequence[GraphMatch]: ...


class CannedGraphLookup:
    """Build from a list of GraphMatch records. Indexes by cpe, cpe-product,
    purl, pname.

    cpe-product index is populated from BOTH the synthetic per-record CPEs
    (when present) AND the pname (lowercased), so a snapshot built without
    a CPE dictionary still answers product queries."""

    def __init__(self, records: Sequence[GraphMatch]):
        self._by_cpe: dict[str, list[GraphMatch]] = {}
        self._by_cpe_product: dict[str, list[GraphMatch]] = {}
        self._by_purl: dict[str, list[GraphMatch]] = {}
        self._by_pname: dict[str, list[GraphMatch]] = {}
        for r in records:
            for c in r.cpes:
                self._by_cpe.setdefault(c, []).append(r)
                m = _CPE_PRODUCT_RE.match(c)
                if m:
                    self._by_cpe_product.setdefault(m.group(1).lower(), []).append(r)
            for p in r.purls:
                self._by_purl.setdefault(p, []).append(r)
            if r.pname:
                pname_key = r.pname.lower()
                self._by_pname.setdefault(pname_key, []).append(r)
                # pname doubles as a cpe-product key when no synthetic CPE
                # exists (the v0 snapshot path).
                self._by_cpe_product.setdefault(pname_key, []).append(r)

    def find_by_cpe(self, cpe: str) -> Sequence[GraphMatch]:
        return list(self._by_cpe.get(cpe, ()))

    def find_by_cpe_product(self, product: str) -> Sequence[GraphMatch]:
        return list(self._by_cpe_product.get(product.lower(), ()))

    def find_by_purl(self, purl: str) -> Sequence[GraphMatch]:
        return list(self._by_purl.get(purl, ()))

    def find_by_pname(self, pname: str) -> Sequence[GraphMatch]:
        return list(self._by_pname.get(pname.lower(), ()))


def cpe_product_of(cpe: str) -> str | None:
    """Extract the product field (4th colon-separated segment) from a
    CPE 2.3 URI. Returns None if the input isn't a parseable CPE 2.3."""
    m = _CPE_PRODUCT_RE.match(cpe)
    return m.group(1).lower() if m else None
