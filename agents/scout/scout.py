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
    cpe_matches = feed_record.get("cpe_matches") or []
    cpes = [m["cpe"] for m in cpe_matches]
    purls = list(feed_record.get("purl_matches", []))
    pname_hints = list(feed_record.get("pname_hints", []))
    version_bounds = feed_record.get("version_bounds") or []

    attempted: list[dict[str, Any]] = []

    exact_hits, tried_exact, rejected_attr_paths = _collect_exact_hits(
        cpe_matches=cpe_matches,
        purls=purls,
        graph=graph,
        version_bounds=version_bounds,
    )
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

    # Suppress pname-heuristic matches that the wildcard-CPE branch
    # already proved out-of-scope. Same attr_path can't simultaneously
    # be "advisory says you're not affected" and "pname says you might be".
    if rejected_attr_paths:
        pname_hits = [m for m in pname_hits if m.attr_path not in rejected_attr_paths]

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
    *,
    cpe_matches: list[dict[str, Any]],
    purls: list[str],
    graph: GraphLookup,
    version_bounds: list[dict[str, Any]],
) -> tuple[list[tuple[GraphMatch, str]], list[dict[str, Any]], set[str]]:
    """Query graph for exact CPE/PURL hits; deduplicate by attr_path.

    Returns (unique_hits, attempted_records). `unique_hits` preserves the first
    method that produced each attr_path. `attempted_records` is a per-method
    log of identifiers tried and hit counts for mapping-failure replay.

    CPE handling has two layers:
      * exact-string match (cpe-exact)            advisory CPE byte-equal to
                                                    a snapshot CPE
      * vendor-product wildcard match              advisory CPE has a wildcard
                                                    (`*`/`-`) in part/vendor/
                                                    product/version; we widen
                                                    via find_by_cpe_uri_match.

    Confidence for the wildcard branch is gated on whether the snapshot's
    version is actually in the advisory's affected range. The advisory
    range comes from cpe_matches[].version_range OR version_bounds[]
    for the matched product. Out-of-scope wildcard matches are silently
    dropped: the package is not affected; emitting a finding would be
    a false positive.
    """
    hits: list[tuple[GraphMatch, str]] = []
    seen: set[str] = set()
    rejected_attr_paths: set[str] = set()
    tried: list[dict[str, Any]] = []

    cpes = [m["cpe"] for m in cpe_matches]
    if cpes:
        total_exact = 0
        total_vp = 0
        for cm in cpe_matches:
            cpe = cm["cpe"]
            advisory_range = cm.get("version_range")
            exact_matches = list(graph.find_by_cpe(cpe))
            if exact_matches:
                total_exact += len(exact_matches)
                for m in exact_matches:
                    if m.attr_path not in seen:
                        seen.add(m.attr_path)
                        hits.append((m, "cpe-exact"))
                continue
            # Wildcard expansion via vendor-product triple. Each candidate
            # record is gated on the advisory's affected-version range.
            wildcard_matches = list(graph.find_by_cpe_uri_match(cpe))
            for m in wildcard_matches:
                if m.attr_path in seen:
                    continue
                in_scope = _snapshot_in_scope(
                    snapshot_version=m.version,
                    pname=m.pname,
                    advisory_range=advisory_range,
                    version_bounds=version_bounds,
                )
                if in_scope is False:
                    # Out-of-scope: snapshot is past the fix or below the
                    # introduced bound. Don't emit a finding, and prevent
                    # pname-heuristic from re-matching this attr_path
                    # (the advisory itself proved the package is not affected).
                    rejected_attr_paths.add(m.attr_path)
                    continue
                seen.add(m.attr_path)
                if in_scope is True:
                    # Verifiably in scope -> promote to cpe-exact.
                    hits.append((m, "cpe-exact"))
                else:
                    # Unknown scope (no range info) -> conservative cpe-vendor-product.
                    hits.append((m, "cpe-vendor-product"))
                total_vp += 1
        tried.append({"method": "cpe-exact", "identifiers_tried": cpes, "hits": total_exact + total_vp})

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

    return hits, tried, rejected_attr_paths


def _snapshot_in_scope(
    *,
    snapshot_version: str,
    pname: str,
    advisory_range: str | None,
    version_bounds: list[dict[str, Any]],
) -> bool | None:
    """Return True / False / None for whether a snapshot version is in
    the advisory's affected range.

      True:  verifiably in scope (range or bound says snapshot is affected)
      False: verifiably out of scope (snapshot is past the fix or below floor)
      None:  no range info; caller must downgrade confidence

    advisory_range examples (as emitted by the dossier normalizer):
      "<5.19.6"
      ">=6.0.0,<6.2.5"
      ">=4.0,<5.0"
    """
    if advisory_range:
        return _eval_range(snapshot_version, advisory_range)
    pname_lc = (pname or "").lower()
    matched_bounds = [b for b in version_bounds if b.get("product") == pname_lc]
    if not matched_bounds:
        return None
    # If ANY bound says in-scope, we're in scope. Conservative for the
    # common case where one bound covers the snapshot.
    saw_decision = False
    for b in matched_bounds:
        verdict = _bound_in_scope(snapshot_version, b)
        if verdict is True:
            return True
        if verdict is False:
            saw_decision = True
    return False if saw_decision else None


def _bound_in_scope(snapshot_version: str, bound: dict[str, Any]) -> bool | None:
    if bound.get("version_type") != "semver":
        return None
    fixed = bound.get("fixed")
    kind = bound.get("fixed_kind")
    introduced = bound.get("introduced")
    snap = _parse_semver(snapshot_version)
    if snap is None:
        return None
    if introduced and introduced not in {"0", "0.0", "0.0.0"}:
        intro = _parse_semver(introduced)
        if intro is not None and snap < intro:
            return False
    if not isinstance(fixed, str):
        return None
    fix = _parse_semver(fixed)
    if fix is None:
        return None
    if kind in {"lessThan", "versionEndExcluding"}:
        return snap < fix
    if kind in {"lessThanOrEqual", "versionEndIncluding"}:
        return snap <= fix
    return None


_RANGE_PART_RE = re.compile(r"^\s*(<=|>=|<|>|==|=)?\s*(.+?)\s*$")


def _eval_range(snapshot_version: str, advisory_range: str) -> bool | None:
    """Evaluate a comma-joined semver constraint expression against the
    snapshot version. Returns None if any part can't be parsed (do not
    guess; let the caller downgrade)."""
    snap = _parse_semver(snapshot_version)
    if snap is None:
        return None
    for part in advisory_range.split(","):
        m = _RANGE_PART_RE.match(part)
        if not m:
            return None
        op = m.group(1) or "="
        val = m.group(2).strip()
        target = _parse_semver(val)
        if target is None:
            return None
        if op == "<" and not (snap < target):
            return False
        if op == "<=" and not (snap <= target):
            return False
        if op == ">" and not (snap > target):
            return False
        if op == ">=" and not (snap >= target):
            return False
        if op in {"=", "=="} and snap != target:
            return False
    return True


def _parse_semver(v: str) -> tuple[int, int, int] | None:
    if not isinstance(v, str):
        return None
    m = re.match(r"^(\d+)\.(\d+)(?:\.(\d+))?", v.strip())
    if not m:
        return None
    return (int(m.group(1)), int(m.group(2)), int(m.group(3) or 0))


def _classify_exact(
    hits: list[tuple[GraphMatch, str]],
) -> tuple[str, str, str | None]:
    """Decide (mapping.method, confidence, notes) for an exact-hit set.

    cpe-vendor-product hits (advisory wildcard CPE matched on
    vendor+product but no version range satisfied) are intentionally
    medium-confidence: we proved vendor identity but not that the
    snapshot version is in the advisory's affected range. Steward
    blocks these from auto-merge."""
    assert hits
    if len(hits) == 1:
        method = hits[0][1]
        confidence = "medium" if method == "cpe-vendor-product" else "high"
        notes = (
            "vendor+product match without verifiable version range"
            if method == "cpe-vendor-product" else None
        )
        return method, confidence, notes
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
