"""Vulnpatch dossier (cve.vulnpatch.dev) → scout-input normalizer.

The dossier endpoint (`/api/v1/cve/:id/dossier`) is the agent-tailored
route on cve.vulnpatch.dev. It bundles raw NVD/GHSA/OSV/MITRE/EPSS/KEV
payloads with quality metrics + agentHints (safeForAutomation,
knownFixedVersions, needsIngest) into a single request.

Per the existing trust boundary (DECISIONS 2026-04-23, vulnpatch_cve.py):
  * Vulnpatch aggregation is NOT authoritative for merge decisions.
  * `feed` reflects the underlying authoritative source (nvd > ghsa > osv);
    aggregator metadata lands in the optional aggregator block on
    scout-input, which Steward explicitly ignores.
  * Scout still computes mapping confidence from graph lookup; the
    dossier's agentHints are surfaced to downstream consumers via the
    raw payload but do NOT short-circuit Scout's match logic.

CPE extraction operates on the dossier's flattened sources.nvd shape
(cpeMatches[] of {cpe, versionStart, versionEnd}), which is NOT raw
NVD JSON 2.0 and therefore does not compose with the nvd.py
normalizer's configurations[].nodes[].cpeMatch[] walker.

No network. Caller fetches and passes raw bytes + parsed dict.
"""

from __future__ import annotations

import hashlib
import re
from typing import Any


SUMMARY_MAX = 2000

_VALID_RATINGS = {"critical", "high", "medium", "low", "none", "unknown"}

# cpe:2.3:<part>:<vendor>:<product>:<version>:...
_CPE_PRODUCT_RE = re.compile(r"^cpe:2\.3:[^:]+:[^:]+:([^:]+):")


def normalize(
    response: dict[str, Any],
    *,
    request_url: str,
    fetched_at: str,
    raw_response_bytes: bytes,
) -> dict[str, Any]:
    cve_id = response.get("cveId") or response.get("canonical", {}).get("id", "")
    if not cve_id.startswith("CVE-"):
        raise ValueError(
            f"dossier cveId is not a CVE id: {cve_id!r}. trace findings are CVE-keyed."
        )

    canonical = response.get("canonical") or {}
    sources = response.get("sources") or {}

    out: dict[str, Any] = {
        "feed": _select_feed(sources),
        "cve_id": cve_id,
        "published_at": canonical["publishedAt"],
        "aggregator": {
            "name": "vulnpatch-dossier",
            "request_url": request_url,
            "fetched_at": fetched_at,
            "response_sha256": hashlib.sha256(raw_response_bytes).hexdigest(),
        },
    }

    summary = (canonical.get("description") or "")[:SUMMARY_MAX]
    if summary:
        out["summary"] = summary

    severity = _extract_severity(canonical)
    if severity:
        out["severity"] = severity

    refs = _extract_references(response)
    if refs:
        out["references"] = refs

    cpe_matches = _extract_cpe_matches(sources)
    if cpe_matches:
        out["cpe_matches"] = cpe_matches

    pname_hints = _derive_pname_hints(cpe_matches)
    if not pname_hints:
        # Fallback: derive from canonical.affectedPackages[].name (lowercased
        # to match the CPE-product convention).
        pname_hints = _pname_hints_from_packages(canonical)
    if pname_hints:
        out["pname_hints"] = pname_hints

    return out


def _select_feed(sources: dict[str, Any]) -> str:
    """Pick the underlying authoritative feed. Order: nvd > ghsa > osv.
    Aggregator metadata is in the aggregator block; this is the
    real-source-of-truth attribution Scout uses for finding source_feeds."""
    if isinstance(sources.get("nvd"), dict):
        return "nvd"
    if isinstance(sources.get("github"), dict):
        return "ghsa"
    if isinstance(sources.get("osv"), dict):
        return "osv"
    return "nvd"


def _extract_severity(canonical: dict[str, Any]) -> dict[str, Any]:
    rating_raw = (canonical.get("severity") or "").lower()
    if not rating_raw:
        return {}
    rating = rating_raw if rating_raw in _VALID_RATINGS else "unknown"
    sev: dict[str, Any] = {"rating": rating}
    score = canonical.get("cvssScore")
    if isinstance(score, (int, float)):
        sev["cvss_v3_score"] = float(score)
    vector = canonical.get("cvssVector")
    if vector:
        sev["cvss_v3_vector"] = vector
    return sev


_REF_KIND_BY_HOST = (
    ("github.com/advisories", "advisory"),
    ("/commit/", "upstream-commit"),
    ("github.com", "upstream-commit"),
    ("gitlab.com", "upstream-commit"),
    ("nvd.nist.gov", "advisory"),
    ("cve.org", "advisory"),
    ("cve.vulnpatch.dev", "advisory"),
    ("/issues/", "bug-tracker"),
)


_NVD_TAG_TO_KIND: dict[str, str] = {
    "Patch": "upstream-commit",
    "Issue Tracking": "bug-tracker",
    "Release Notes": "release-notes",
    "Vendor Advisory": "advisory",
    "Third Party Advisory": "advisory",
}


def _classify_url(url: str) -> str:
    for needle, kind in _REF_KIND_BY_HOST:
        if needle in url:
            return kind
    return "other"


def _classify_nvd_ref(url: str, tags: list[str]) -> str:
    for tag in tags:
        if tag in _NVD_TAG_TO_KIND:
            return _NVD_TAG_TO_KIND[tag]
    return _classify_url(url)


def _extract_references(response: dict[str, Any]) -> list[dict[str, str]]:
    """Build references[] from the dossier's links, provenance, and
    embedded sources.nvd.nvdReferences. Tag-based classification wins
    for NVD references (Patch -> upstream-commit etc.); host-based
    fallback otherwise. Dedupe on URL."""
    seen: set[str] = set()
    refs: list[dict[str, str]] = []
    links = response.get("links") or {}
    for key in ("html", "api"):
        url = links.get(key)
        if url and url not in seen:
            seen.add(url)
            refs.append({"url": url, "kind": _classify_url(url)})
    for entry in response.get("provenance") or []:
        url = entry.get("url")
        if url and url not in seen:
            seen.add(url)
            refs.append({"url": url, "kind": _classify_url(url)})
    sources = response.get("sources") or {}
    nvd = sources.get("nvd") if isinstance(sources, dict) else None
    if isinstance(nvd, dict):
        for entry in nvd.get("nvdReferences") or []:
            url = entry.get("url")
            if not url or url in seen:
                continue
            seen.add(url)
            refs.append({"url": url, "kind": _classify_nvd_ref(url, entry.get("tags") or [])})
    return refs


def _extract_cpe_matches(sources: dict[str, Any]) -> list[dict[str, str]]:
    """Lift CPE matches from the dossier's flattened sources.nvd.cpeMatches[]
    list. Each entry is {cpe, versionStart?, versionEnd?}."""
    nvd = sources.get("nvd")
    if not isinstance(nvd, dict):
        return []
    out: list[dict[str, str]] = []
    for match in nvd.get("cpeMatches") or []:
        cpe = match.get("cpe")
        if not cpe:
            continue
        entry: dict[str, str] = {"cpe": cpe}
        vr = _format_version_range(match)
        if vr:
            entry["version_range"] = vr
        out.append(entry)
    return out


def _format_version_range(match: dict[str, Any]) -> str:
    parts: list[str] = []
    if match.get("versionStart"):
        parts.append(f">={match['versionStart']}")
    if match.get("versionEnd"):
        parts.append(f"<{match['versionEnd']}")
    return ",".join(parts)


def _derive_pname_hints(cpe_matches: list[dict[str, str]]) -> list[str]:
    seen: set[str] = set()
    hints: list[str] = []
    for entry in cpe_matches:
        m = _CPE_PRODUCT_RE.match(entry["cpe"])
        if not m:
            continue
        product = m.group(1).lower()
        if product in {"*", "-"} or product in seen:
            continue
        seen.add(product)
        hints.append(product)
    return hints


def _pname_hints_from_packages(canonical: dict[str, Any]) -> list[str]:
    seen: set[str] = set()
    hints: list[str] = []
    for pkg in canonical.get("affectedPackages") or []:
        name = (pkg.get("name") or "").strip().lower()
        if name and name not in seen:
            seen.add(name)
            hints.append(name)
    return hints
