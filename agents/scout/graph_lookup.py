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
# Full triple parser. CPE 2.3 has 11 colon-separated fields after the prefix:
# part, vendor, product, version, update, edition, language, sw_edition,
# target_sw, target_hw, other.
_CPE_FIELDS_RE = re.compile(
    r"^cpe:2\.3:([^:]+):([^:]+):([^:]+):([^:]+):"
    r"([^:]*):([^:]*):([^:]*):([^:]*):([^:]*):([^:]*):([^:]*)$"
)
_CPE_WILDCARDS = {"*", "-", ""}


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
    def find_by_cpe_uri_match(self, cpe: str) -> Sequence[GraphMatch]: ...
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
        # (part, vendor, product) tuple -> [GraphMatch]. Populated from
        # snapshot CPEs only (NOT from pname); this is the dictionary-aware
        # vendor-product index that lets a wildcard advisory CPE
        # cpe:2.3:a:apache:activemq:*:*:... match a snapshot CPE
        # cpe:2.3:a:apache:activemq:6.2.4:*:... without crossing vendors.
        self._by_cpe_triple: dict[tuple[str, str, str], list[GraphMatch]] = {}
        self._by_purl: dict[str, list[GraphMatch]] = {}
        self._by_pname: dict[str, list[GraphMatch]] = {}
        for r in records:
            seen_triples: set[tuple[str, str, str]] = set()
            for c in r.cpes:
                self._by_cpe.setdefault(c, []).append(r)
                m = _CPE_PRODUCT_RE.match(c)
                if m:
                    self._by_cpe_product.setdefault(m.group(1).lower(), []).append(r)
                triple = _cpe_triple(c)
                if triple is not None and triple not in seen_triples:
                    seen_triples.add(triple)
                    self._by_cpe_triple.setdefault(triple, []).append(r)
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

    def find_by_cpe_uri_match(self, cpe: str) -> Sequence[GraphMatch]:
        """CPE 2.3 URI match honouring wildcards in part / vendor /
        product / version. An advisory CPE with `*` (or `-`) in any of
        those four positions matches snapshot records whose triple
        agrees on the non-wildcard fields.

        v0 only inspects (part, vendor, product). Version is left to
        the caller's range check; widening to advisory_version+
        (update / edition / etc.) is a future slice."""
        if cpe in self._by_cpe:
            return list(self._by_cpe[cpe])
        triple = _cpe_triple(cpe)
        if triple is None:
            return []
        # Build candidate triples: any wildcard slot in the advisory
        # widens to "match any concrete value at the same slot".
        out: list[GraphMatch] = []
        seen: set[str] = set()
        for snap_triple, recs in self._by_cpe_triple.items():
            if not _triple_compatible(triple, snap_triple):
                continue
            for r in recs:
                if r.attr_path not in seen:
                    seen.add(r.attr_path)
                    out.append(r)
        return out


def _cpe_triple(cpe: str) -> tuple[str, str, str] | None:
    """Parse (part, vendor, product) from a CPE 2.3 URI. Returns None
    on malformed input. Each slot keeps its raw form (so wildcards are
    preserved for the matcher to interpret)."""
    m = _CPE_FIELDS_RE.match(cpe)
    if not m:
        return None
    return (m.group(1), m.group(2).lower(), m.group(3).lower())


def _triple_compatible(advisory: tuple[str, str, str], snap: tuple[str, str, str]) -> bool:
    """advisory matches snap when each non-wildcard advisory slot
    equals the snap slot. Wildcard slots in the advisory widen the
    match."""
    for adv_slot, snap_slot in zip(advisory, snap):
        if adv_slot in _CPE_WILDCARDS:
            continue
        if snap_slot in _CPE_WILDCARDS:
            # Snapshot wildcard would match anything; treat that as
            # "no specific commitment" and fall through.
            continue
        if adv_slot != snap_slot:
            return False
    return True


def cpe_product_of(cpe: str) -> str | None:
    """Extract the product field (4th colon-separated segment) from a
    CPE 2.3 URI. Returns None if the input isn't a parseable CPE 2.3."""
    m = _CPE_PRODUCT_RE.match(cpe)
    return m.group(1).lower() if m else None
