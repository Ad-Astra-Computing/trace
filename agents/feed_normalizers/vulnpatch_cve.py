"""Vulnpatch → scout-input normalizer.

Takes a validated Vulnpatch CVE lookup response (shape:
`policy/vulnpatch-cve-source-schema.json`) plus the fetch metadata and emits
a `policy/scout-input-schema.json`-shaped dict.

No network. The caller fetches bytes and hands them in:

    normalize(response_dict, request_url, fetched_at, raw_response_bytes)

Trust boundary (SPEC §2 + DECISIONS 2026-04-23):
  * Vulnpatch aggregation is NOT authoritative for merge decisions.
  * feed / source_feeds keep their existing meaning — they identify the
    underlying authoritative feed (nvd/ghsa/osv), not the aggregator.
  * Aggregator metadata (request URL, sha256 of raw response, integrity
    hashes from Vulnpatch, EPSS/KEV) lands in the optional `aggregator` block
    on scout-input, which Steward explicitly ignores.
  * Scout still computes confidence from graph lookup. Vulnpatch's own
    severity/affected data only seeds the input; the finding's confidence is
    earned by Scout's own CPE/PURL/pname match against the graph.
"""

from __future__ import annotations

import hashlib
from typing import Any


SUMMARY_MAX = 2000  # matches scout-input-schema.json severity-sibling constraint.

_FEED_FROM_PRIMARY_SOURCE = {
    "cve-list-v5": "nvd",
    "nvd": "nvd",
    "github": "ghsa",
    "ghsa": "ghsa",
    "osv": "osv",
}


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def normalize(
    response: dict[str, Any],
    *,
    request_url: str,
    fetched_at: str,
    raw_response_bytes: bytes,
    api_version: str | None = None,
) -> dict[str, Any]:
    """Convert a Vulnpatch response into a scout-input dict."""
    data = response["data"]
    integrity = response["integrity"]
    primary = data.get("primary") or _pick_first_source(data)
    if primary is None:
        raise ValueError(
            "vulnpatch response has neither data.primary nor any data.sources blob; "
            "refusing to normalize — there is no advisory payload to map."
        )

    cve_id = data["cve_id"]
    feed = _underlying_feed(primary)

    cpe_matches = _collect_cpes(primary, data)
    purl_matches = _collect_purls(data)
    pname_hints = _collect_pnames(primary, data)
    severity = _build_severity(primary)
    references = _collect_references(primary)
    summary = _build_summary(primary)

    aggregator = _build_aggregator(
        integrity=integrity,
        data=data,
        request_url=request_url,
        fallback_fetched_at=fetched_at,
        raw_response_bytes=raw_response_bytes,
        api_version=api_version,
    )

    out: dict[str, Any] = {
        "feed": feed,
        "cve_id": cve_id,
        "published_at": primary.get("datePublished") or primary.get("published_at") or fetched_at,
    }
    if severity:
        out["severity"] = severity
    if summary:
        out["summary"] = summary
    if references:
        out["references"] = references
    if cpe_matches:
        out["cpe_matches"] = cpe_matches
    if purl_matches:
        out["purl_matches"] = purl_matches
    if pname_hints:
        out["pname_hints"] = pname_hints
    if data.get("aliases"):
        out["aliases"] = list(data["aliases"])
    else:
        aliases = _collect_aliases(data)
        if aliases:
            out["aliases"] = aliases
    out["aggregator"] = aggregator
    return out


# ─── field builders ─────────────────────────────────────────────────────────


def _pick_first_source(data: dict[str, Any]) -> dict[str, Any] | None:
    sources = data.get("sources") or {}
    for key in ("cve_list_v5", "github", "osv", "nixpkgs"):
        blob = sources.get(key)
        if isinstance(blob, dict):
            return blob
    return None


def _underlying_feed(primary: dict[str, Any]) -> str:
    marker = primary.get("source")
    if isinstance(marker, str):
        mapped = _FEED_FROM_PRIMARY_SOURCE.get(marker.lower())
        if mapped:
            return mapped
    # If `primary` came from GHSA (has ghsa_id) or OSV (has schema_version/aliases+details), infer.
    if primary.get("ghsa_id"):
        return "ghsa"
    if primary.get("schema_version") and primary.get("details") is not None:
        return "osv"
    return "nvd"  # cve_list_v5 is the common default


def _collect_cpes(primary: dict[str, Any], data: dict[str, Any]) -> list[dict[str, Any]]:
    seen: set[str] = set()
    out: list[dict[str, Any]] = []

    def _add(cpe: str | None) -> None:
        if not cpe or not isinstance(cpe, str):
            return
        normalized = _normalize_cpe_to_23(cpe)
        if normalized and normalized not in seen:
            seen.add(normalized)
            out.append({"cpe": normalized})

    for aff in primary.get("affected") or []:
        for cpe in aff.get("cpes") or []:
            _add(cpe)
    for src in (data.get("sources") or {}).values():
        if not isinstance(src, dict):
            continue
        for aff in src.get("affected") or []:
            if not isinstance(aff, dict):
                continue
            for cpe in aff.get("cpes") or []:
                _add(cpe)
    return out


def _normalize_cpe_to_23(cpe: str) -> str | None:
    """Convert CPE 2.2 (`cpe:/...`) to CPE 2.3 (`cpe:2.3:...`). Pass-through for 2.3.

    CPE 2.3 reserves 11 colon-separated fields after the `cpe:2.3:` prefix:
    part, vendor, product, version, update, edition, language, sw_edition,
    target_sw, target_hw, other. Missing trailing fields become '*'.
    CPE 2.2 uses up to 7 of those (part..language) and elides later fields.
    Returns None for unrecognized shapes.
    """
    if cpe.startswith("cpe:2.3:"):
        return cpe
    if cpe.startswith("cpe:/"):
        body = cpe[len("cpe:/"):]
        fields = body.split(":")
        # Pad 2.2 up to 7 then extend to 11 for 2.3.
        while len(fields) < 11:
            fields.append("*")
        fields = fields[:11]
        return "cpe:2.3:" + ":".join(f if f else "*" for f in fields)
    return None


def _collect_purls(data: dict[str, Any]) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    osv = (data.get("sources") or {}).get("osv")
    if isinstance(osv, dict):
        for aff in osv.get("affected") or []:
            if not isinstance(aff, dict):
                continue
            pkg = aff.get("package") or {}
            purl = pkg.get("purl")
            if purl and purl not in seen and purl.startswith("pkg:"):
                seen.add(purl)
                out.append(purl)
    return out


def _collect_pnames(primary: dict[str, Any], data: dict[str, Any]) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []

    def _add(p: str | None) -> None:
        if p and p != "unknown" and p not in seen:
            seen.add(p)
            out.append(p)

    for aff in primary.get("affected") or []:
        _add(aff.get("product"))
    osv = (data.get("sources") or {}).get("osv")
    if isinstance(osv, dict):
        for aff in osv.get("affected") or []:
            if isinstance(aff, dict):
                _add((aff.get("package") or {}).get("name"))
    return out


def _build_severity(primary: dict[str, Any]) -> dict[str, Any]:
    rating = primary.get("severity") or "unknown"
    if isinstance(rating, str):
        rating = rating.lower()
        if rating not in {"critical", "high", "medium", "low", "none", "unknown"}:
            rating = "unknown"
    else:
        rating = "unknown"

    out: dict[str, Any] = {
        "rating": rating,
        "cvss_v3_score": primary.get("cvssScore"),
    }
    if primary.get("cvssVector"):
        out["cvss_v3_vector"] = primary["cvssVector"]
    return out


def _collect_references(primary: dict[str, Any]) -> list[dict[str, str]]:
    seen: set[str] = set()
    out: list[dict[str, str]] = []
    for ref in primary.get("references") or []:
        if isinstance(ref, dict):
            url = ref.get("url")
        elif isinstance(ref, str):
            url = ref
        else:
            continue
        if not url or url in seen:
            continue
        seen.add(url)
        out.append({"url": url, "kind": _reference_kind(ref if isinstance(ref, dict) else {})})
    return out


def _reference_kind(ref: dict[str, Any]) -> str:
    tags = set(ref.get("tags") or [])
    if "vendor-advisory" in tags or "vdb-entry" in tags:
        return "advisory"
    if "patch" in tags or "x_refsource_CONFIRM" in tags:
        return "upstream-commit"
    if "release-notes" in tags:
        return "release-notes"
    if "issue-tracking" in tags:
        return "bug-tracker"
    return "advisory"


def _build_summary(primary: dict[str, Any]) -> str:
    title = primary.get("title")
    description = primary.get("description") or primary.get("details")
    parts: list[str] = []
    if isinstance(title, str) and title:
        parts.append(title.strip())
    if isinstance(description, str) and description:
        parts.append(description.strip())
    text = ". ".join(parts) if parts else ""
    if len(text) > SUMMARY_MAX:
        text = text[: SUMMARY_MAX - 1] + "…"
    return text


def _collect_aliases(data: dict[str, Any]) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for src in (data.get("sources") or {}).values():
        if not isinstance(src, dict):
            continue
        for alias in src.get("aliases") or []:
            if isinstance(alias, str) and alias not in seen:
                seen.add(alias)
                out.append(alias)
        ghsa = src.get("ghsa_id")
        if isinstance(ghsa, str) and ghsa not in seen:
            seen.add(ghsa)
            out.append(ghsa)
    return out


def _build_aggregator(
    *,
    integrity: dict[str, Any],
    data: dict[str, Any],
    request_url: str,
    fallback_fetched_at: str,
    raw_response_bytes: bytes,
    api_version: str | None,
) -> dict[str, Any]:
    underlying: list[dict[str, str]] = []
    for source_key, h in (integrity.get("sources") or {}).items():
        if not h:
            continue
        if source_key not in {"cve_list_v5", "github", "osv", "nixpkgs"}:
            continue
        underlying.append({"source": source_key, "sha256": h})

    agg: dict[str, Any] = {
        "name": "vulnpatch",
        "fetched_at": integrity.get("fetchedAt") or fallback_fetched_at,
        "request_url": request_url,
        "response_sha256": sha256_hex(raw_response_bytes),
    }
    if api_version:
        agg["api_version"] = api_version
    if integrity.get("primaryHash"):
        agg["primary_source_hash"] = integrity["primaryHash"]
    if underlying:
        agg["underlying_source_hashes"] = underlying

    epss = data.get("epss")
    if isinstance(epss, dict) and ("epss" in epss or "percentile" in epss):
        agg_epss: dict[str, Any] = {}
        if isinstance(epss.get("epss"), (int, float)):
            agg_epss["score"] = float(epss["epss"])
        if isinstance(epss.get("percentile"), (int, float)):
            agg_epss["percentile"] = float(epss["percentile"])
        if agg_epss:
            agg["epss"] = agg_epss

    kev = data.get("kev")
    if isinstance(kev, dict) and kev:
        agg_kev: dict[str, Any] = {"in_catalog": True}
        if kev.get("dateAdded"):
            agg_kev["added_date"] = kev["dateAdded"]
        if kev.get("dueDate"):
            agg_kev["due_date"] = kev["dueDate"]
        if kev.get("knownRansomwareCampaignUse"):
            agg_kev["known_ransomware_campaign_use"] = kev["knownRansomwareCampaignUse"]
        if kev.get("requiredAction"):
            agg_kev["required_action"] = kev["requiredAction"]
        agg["cisa_kev"] = agg_kev

    return agg
