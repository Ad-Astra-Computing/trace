"""Upfront nixpkgs-relevance filter.

Pre-flight check before invoking `agents.scout.scan`: does this
scout-input have any identifier (cpe / purl / pname) that the graph
recognises? If not, the orchestrator skips writing an inbox file
rather than emitting yet another mapping-failure record.

Walks identifiers in Scout's match priority (cpe → purl → pname) and
short-circuits on first hit. Conservative: a single hit at any layer
keeps the record; pname comparison is case-insensitive at the filter
layer in case a normalizer didn't lowercase.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from agents.scout.graph_lookup import GraphLookup


@dataclass(frozen=True)
class RelevanceDecision:
    relevant: bool
    reason: str
    layer: str | None = None
    matched_identifier: str | None = None


def is_relevant_to_nixpkgs(
    scout_input: dict[str, Any],
    graph: GraphLookup,
) -> RelevanceDecision:
    cpes = [m["cpe"] for m in scout_input.get("cpe_matches", []) if "cpe" in m]
    purls = list(scout_input.get("purl_matches", []))
    pname_hints = list(scout_input.get("pname_hints", []))

    if not (cpes or purls or pname_hints):
        return RelevanceDecision(
            relevant=False,
            reason="no-identifiers (no cpe_matches / purl_matches / pname_hints)",
        )

    for cpe in cpes:
        if graph.find_by_cpe(cpe):
            return RelevanceDecision(True, f"cpe-hit:{cpe}", "cpe", cpe)

    for purl in purls:
        if graph.find_by_purl(purl):
            return RelevanceDecision(True, f"purl-hit:{purl}", "purl", purl)

    for hint in pname_hints:
        for candidate in {hint, hint.lower()}:
            if graph.find_by_pname(candidate):
                return RelevanceDecision(True, f"pname-hit:{candidate}", "pname", candidate)

    tried = sorted(set(cpes + purls + [h.lower() for h in pname_hints]))
    return RelevanceDecision(
        relevant=False,
        reason=f"no-match in graph; tried {len(tried)} identifier(s)",
    )
