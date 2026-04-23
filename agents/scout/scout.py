"""Scout — v0 stub.

Maps a normalized advisory record (shape: `policy/scout-input-schema.json`)
onto zero or more nixpkgs derivations via a GraphLookup.

Outputs one of:
  * `finding.json`-shaped dict (schema: `policy/finding-schema.json`)
  * `mapping-failure`-shaped dict (schema: `policy/mapping-failure-schema.json`)

Confidence policy (per the Scout scope brief):

  * exact PURL/CPE match, exactly one unique derivation → **high**
  * exact PURL/CPE match, multiple unique derivations   → **low**
      (ambiguous-multi-match; all candidates recorded, Patcher will not advance)
  * no exact hits, pname heuristic yields exactly one   → **medium**
  * no exact hits, pname heuristic yields multiple      → **low**
  * no hits at any layer                                → mapping-failure, no finding

Deliberate non-goals:
  * Version-range evaluation (needs the full graph).
  * Patcher-advancement decisions beyond emitting confidence and mapping method.
  * Feed-parsing. Scout starts from an already-normalized advisory record.

No network. No I/O outside what the caller provides.
"""

from __future__ import annotations

import re
from typing import Any

from agents.scout.graph_lookup import GraphLookup, GraphMatch


FINDING_SCHEMA_VERSION = "1.0.0"
MAPPING_FAILURE_SCHEMA_VERSION = "1.0.0"


def scan(feed_record: dict[str, Any], graph: GraphLookup) -> dict[str, Any]:
    """Run Scout against a single normalized advisory.

    Returns a dict with key `status` of either:
      * "finding"          → dict also contains `finding` (schema: finding.json)
      * "mapping-failure"  → dict also contains `mapping_failure` (schema: mapping-failure.json)
    """
    cve_id = feed_record["cve_id"]
    feed = feed_record["feed"]
    cpes = [m["cpe"] for m in feed_record.get("cpe_matches", [])]
    purls = list(feed_record.get("purl_matches", []))
    pname_hints = list(feed_record.get("pname_hints", []))

    attempted: list[dict[str, Any]] = []

    exact_hits, tried_exact = _collect_exact_hits(cpes, purls, graph)
    attempted.extend(tried_exact)

    if exact_hits:
        method, confidence, notes = _classify_exact(exact_hits)
        return {
            "status": "finding",
            "finding": _build_finding(
                cve_id=cve_id,
                feed=feed,
                feed_record=feed_record,
                matches=exact_hits,
                method=method,
                confidence=confidence,
                confidence_reason=notes,
                mapping_notes=notes,
                cpes_used=cpes,
                purls_used=purls,
            ),
        }

    # Derive pname candidates from CPE/PURL if hints are absent.
    pname_candidates = _pname_candidates(pname_hints, cpes, purls)
    pname_hits, tried_pname = _collect_pname_hits(pname_candidates, graph)
    attempted.extend(tried_pname)

    if pname_hits:
        confidence = "medium" if len(pname_hits) == 1 else "low"
        notes = (
            "pname heuristic match (no CPE/PURL hit)"
            if len(pname_hits) == 1
            else f"pname heuristic, ambiguous {len(pname_hits)}-way match"
        )
        return {
            "status": "finding",
            "finding": _build_finding(
                cve_id=cve_id,
                feed=feed,
                feed_record=feed_record,
                matches=[(m, "pname-heuristic") for m in pname_hits],
                method="pname-heuristic",
                confidence=confidence,
                confidence_reason=notes,
                mapping_notes=notes,
                cpes_used=cpes,
                purls_used=purls,
            ),
        }

    return {
        "status": "mapping-failure",
        "mapping_failure": _build_mapping_failure(
            cve_id=cve_id,
            feed=feed,
            attempted=attempted,
        ),
    }


# ─── exact-hit collection + classification ──────────────────────────────────


def _collect_exact_hits(
    cpes: list[str],
    purls: list[str],
    graph: GraphLookup,
) -> tuple[list[tuple[GraphMatch, str]], list[dict[str, Any]]]:
    """Query graph for exact CPE/PURL hits; deduplicate by attr_path.

    Returns (unique_hits, attempted_records). `unique_hits` preserves the first
    method that produced each attr_path. `attempted_records` is a per-method
    log of identifiers tried and hit counts for mapping-failure replay.
    """
    hits: list[tuple[GraphMatch, str]] = []
    seen: set[str] = set()
    tried: list[dict[str, Any]] = []

    if cpes:
        total = 0
        for cpe in cpes:
            matches = list(graph.find_by_cpe(cpe))
            total += len(matches)
            for m in matches:
                if m.attr_path not in seen:
                    seen.add(m.attr_path)
                    hits.append((m, "cpe-exact"))
        tried.append({"method": "cpe-exact", "identifiers_tried": cpes, "hits": total})

    if purls:
        total = 0
        for purl in purls:
            matches = list(graph.find_by_purl(purl))
            total += len(matches)
            for m in matches:
                if m.attr_path not in seen:
                    seen.add(m.attr_path)
                    hits.append((m, "purl-exact"))
        tried.append({"method": "purl-exact", "identifiers_tried": purls, "hits": total})

    return hits, tried


def _classify_exact(
    hits: list[tuple[GraphMatch, str]],
) -> tuple[str, str, str | None]:
    """Decide (mapping.method, confidence, notes) for an exact-hit set."""
    assert hits
    if len(hits) == 1:
        method = hits[0][1]
        return method, "high", None
    # Multi-hit: ambiguous. Pick the dominant method; fall back to cpe-exact.
    methods = [h[1] for h in hits]
    method = "cpe-exact" if methods.count("cpe-exact") >= methods.count("purl-exact") else "purl-exact"
    note = f"ambiguous {len(hits)}-way exact match across {sorted(set(m.attr_path for m, _ in hits))}"
    return method, "low", note


# ─── pname fallback ─────────────────────────────────────────────────────────


_CPE_PRODUCT_RE = re.compile(r"^cpe:2\.3:[aho]:[^:]+:([^:]+):")


def _pname_from_cpe(cpe: str) -> str | None:
    m = _CPE_PRODUCT_RE.match(cpe)
    return m.group(1) if m else None


def _pname_from_purl(purl: str) -> str | None:
    # pkg:<type>/<namespace>/<name>@<version>  OR  pkg:<type>/<name>@<version>
    body = purl[len("pkg:"):]
    # Strip query + version
    body = body.split("?", 1)[0]
    body = body.split("@", 1)[0]
    segs = body.split("/")
    if len(segs) < 2:
        return None
    name = segs[-1]
    return name or None


def _pname_candidates(
    hints: list[str],
    cpes: list[str],
    purls: list[str],
) -> list[str]:
    seen: set[str] = set()
    ordered: list[str] = []

    for h in hints:
        if h and h not in seen:
            seen.add(h)
            ordered.append(h)
    for c in cpes:
        p = _pname_from_cpe(c)
        if p and p not in seen:
            seen.add(p)
            ordered.append(p)
    for u in purls:
        p = _pname_from_purl(u)
        if p and p not in seen:
            seen.add(p)
            ordered.append(p)
    return ordered


def _collect_pname_hits(
    candidates: list[str],
    graph: GraphLookup,
) -> tuple[list[GraphMatch], list[dict[str, Any]]]:
    hits: list[GraphMatch] = []
    seen: set[str] = set()
    total = 0
    for pname in candidates:
        matches = list(graph.find_by_pname(pname))
        total += len(matches)
        for m in matches:
            if m.attr_path not in seen:
                seen.add(m.attr_path)
                hits.append(m)

    tried: list[dict[str, Any]] = []
    if candidates:
        tried.append({"method": "pname-heuristic", "identifiers_tried": candidates, "hits": total})
    return hits, tried


# ─── output builders ────────────────────────────────────────────────────────


def _build_finding(
    cve_id: str,
    feed: str,
    feed_record: dict[str, Any],
    matches: list[tuple[GraphMatch, str]],
    method: str,
    confidence: str,
    confidence_reason: str | None,
    mapping_notes: str | None,
    cpes_used: list[str],
    purls_used: list[str],
) -> dict[str, Any]:
    affected: list[dict[str, Any]] = []
    for m, _hit_method in matches:
        entry: dict[str, Any] = {
            "attr_path": m.attr_path,
            "drv_path": m.drv_path,
            "pname": m.pname,
            "version": m.version,
            "confidence": confidence,
        }
        if m.src_url:
            entry["src_url"] = m.src_url
        if m.src_hash:
            entry["src_hash"] = m.src_hash
        if confidence != "high":
            entry["confidence_reason"] = confidence_reason or "non-high confidence"
        affected.append(entry)

    finding: dict[str, Any] = {
        "schema_version": FINDING_SCHEMA_VERSION,
        "cve_id": cve_id,
        "source_feeds": [feed],
        "severity": _severity(feed_record),
        "published_at": feed_record["published_at"],
        "affected": affected,
        "mapping": _mapping(method, cpes_used, purls_used, mapping_notes),
        "replay_critical": True,
    }
    if "summary" in feed_record:
        finding["summary"] = feed_record["summary"]
    if feed_record.get("references"):
        finding["references"] = [
            {"url": r["url"], "kind": r["kind"]}
            for r in feed_record["references"]
        ]
    return finding


def _severity(feed_record: dict[str, Any]) -> dict[str, Any]:
    sev = feed_record.get("severity") or {}
    out: dict[str, Any] = {
        "rating": sev.get("rating", "unknown"),
        "cvss_v3_score": sev.get("cvss_v3_score") if sev else None,
    }
    if "cvss_v3_vector" in sev:
        out["cvss_v3_vector"] = sev["cvss_v3_vector"]
    return out


def _mapping(
    method: str,
    cpes: list[str],
    purls: list[str],
    mapping_notes: str | None,
) -> dict[str, Any]:
    m: dict[str, Any] = {"method": method}
    if cpes:
        m["cpe"] = list(cpes)
    if purls:
        m["purl"] = list(purls)
    if mapping_notes:
        m["mapping_notes"] = mapping_notes
    return m


def _build_mapping_failure(
    cve_id: str,
    feed: str,
    attempted: list[dict[str, Any]],
) -> dict[str, Any]:
    if attempted:
        reason = "no-match"
    else:
        reason = "empty-identifier-set"
        attempted = [{
            "method": "cpe-exact",
            "identifiers_tried": ["(none supplied)"],
            "hits": 0,
        }]
    return {
        "schema_version": MAPPING_FAILURE_SCHEMA_VERSION,
        "cve_id": cve_id,
        "source_feed": feed,
        "attempted_methods": attempted,
        "reason": reason,
        "replay_critical": True,
    }
