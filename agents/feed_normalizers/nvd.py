"""NVD → scout-input normalizer.

Takes a single NVD JSON 2.0 CVE record (the `.vulnerabilities[N].cve`
sub-document, validated against `policy/nvd-source-schema.json`) and
emits a `policy/scout-input-schema.json`-shaped dict. Direct-source
path; provenance for the fetch lives in the caller's replay.json
invocation record, not inline.

Trust boundary (mirrors ghsa.py):
  * `feed` is always "nvd"; no aggregator block emitted.
  * Scout still computes confidence from graph lookup. NVD's severity /
    affected data only seeds the input.
  * Records without a CVE id are refused (trace findings are CVE-keyed).

No network. Caller fetches and passes in the parsed `.cve` dict.
"""

from __future__ import annotations

import re
from typing import Any


SUMMARY_MAX = 2000


_TAG_TO_KIND: dict[str, str] = {
    "Patch": "upstream-commit",
    "Issue Tracking": "bug-tracker",
    "Release Notes": "release-notes",
    "Vendor Advisory": "advisory",
    "Third Party Advisory": "advisory",
    "Mailing List": "other",
    "Mitigation": "other",
    "Press/Media Coverage": "blog",
    "Technical Description": "other",
    "Exploit": "other",
    "VDB Entry": "other",
    "Broken Link": "other",
    "Not Applicable": "other",
}


_VALID_RATINGS = {"critical", "high", "medium", "low", "none", "unknown"}


def normalize(cve: dict[str, Any]) -> dict[str, Any]:
    cve_id = cve.get("id", "")
    if not cve_id.startswith("CVE-"):
        raise ValueError(
            f"NVD record id is not a CVE id: {cve_id!r}. trace findings are CVE-keyed."
        )

    out: dict[str, Any] = {
        "feed": "nvd",
        "cve_id": cve_id,
        "published_at": cve["published"],
    }

    summary = _extract_summary(cve)
    if summary:
        out["summary"] = summary

    severity = _extract_severity(cve)
    if severity:
        out["severity"] = severity

    refs = _extract_references(cve)
    if refs:
        out["references"] = refs

    cpe_matches = _extract_cpe_matches(cve)
    if cpe_matches:
        out["cpe_matches"] = cpe_matches

    pname_hints = _derive_pname_hints(cpe_matches)
    if pname_hints:
        out["pname_hints"] = pname_hints

    bounds = _extract_version_bounds(cve)
    if bounds:
        out["version_bounds"] = bounds

    return out


def _extract_version_bounds(cve: dict[str, Any]) -> list[dict[str, Any]]:
    """Lift configurations[].nodes[].cpeMatch[].versionEndExcluding /
    versionEndIncluding to scout-input version_bounds. The cpe-product
    field of the matched CPE supplies the bound's product key."""
    bounds: list[dict[str, Any]] = []
    seen: set[tuple[str, str, str]] = set()
    for cfg in cve.get("configurations") or []:
        for node in cfg.get("nodes") or []:
            for match in node.get("cpeMatch") or []:
                if not match.get("vulnerable"):
                    continue
                criteria = match.get("criteria") or ""
                m = _CPE_PRODUCT_RE.match(criteria)
                if not m:
                    continue
                product = m.group(1).lower()
                if product in {"*", "-"}:
                    continue
                kind: str | None = None
                value: str | None = None
                if isinstance(match.get("versionEndExcluding"), str):
                    kind, value = "versionEndExcluding", match["versionEndExcluding"]
                elif isinstance(match.get("versionEndIncluding"), str):
                    kind, value = "versionEndIncluding", match["versionEndIncluding"]
                if not kind or not value:
                    continue
                key = (product, kind, value)
                if key in seen:
                    continue
                seen.add(key)
                bound: dict[str, Any] = {
                    "product": product,
                    "fixed": value,
                    "fixed_kind": kind,
                    "version_type": "semver",
                    "source": "nvd_configurations",
                }
                if isinstance(match.get("versionStartIncluding"), str):
                    bound["introduced"] = match["versionStartIncluding"]
                elif isinstance(match.get("versionStartExcluding"), str):
                    bound["introduced"] = match["versionStartExcluding"]
                bounds.append(bound)
    return bounds


def _extract_summary(cve: dict[str, Any]) -> str:
    descriptions = cve.get("descriptions") or []
    en = next((d.get("value", "") for d in descriptions if d.get("lang") == "en"), "")
    if not en and descriptions:
        en = descriptions[0].get("value", "")
    return en[:SUMMARY_MAX]


def _extract_severity(cve: dict[str, Any]) -> dict[str, Any]:
    metrics = cve.get("metrics") or {}
    v31 = metrics.get("cvssMetricV31") or []
    v30 = metrics.get("cvssMetricV30") or []
    chosen = v31 or v30
    if not chosen:
        return {}
    data = chosen[0].get("cvssData", {})
    rating_raw = (data.get("baseSeverity") or "").lower()
    rating = rating_raw if rating_raw in _VALID_RATINGS else "unknown"
    severity: dict[str, Any] = {"rating": rating}
    score = data.get("baseScore")
    if isinstance(score, (int, float)):
        severity["cvss_v3_score"] = float(score)
    vector = data.get("vectorString")
    if vector:
        severity["cvss_v3_vector"] = vector
    return severity


def _extract_references(cve: dict[str, Any]) -> list[dict[str, str]]:
    out: list[dict[str, str]] = []
    for r in cve.get("references") or []:
        url = r.get("url")
        if not url:
            continue
        kind = "other"
        for tag in r.get("tags") or []:
            if tag in _TAG_TO_KIND:
                kind = _TAG_TO_KIND[tag]
                break
        out.append({"url": url, "kind": kind})
    return out


def _extract_cpe_matches(cve: dict[str, Any]) -> list[dict[str, str]]:
    """Walk configurations[].nodes[].cpeMatch[] and emit one entry per
    vulnerable CPE. Synthesise a version_range string from
    versionStart/End fields when present so downstream graph code can
    reason about them."""
    out: list[dict[str, str]] = []
    for cfg in cve.get("configurations") or []:
        for node in cfg.get("nodes") or []:
            for match in node.get("cpeMatch") or []:
                if match.get("vulnerable") is False:
                    continue
                cpe = match.get("criteria")
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
    if match.get("versionStartIncluding"):
        parts.append(f">={match['versionStartIncluding']}")
    elif match.get("versionStartExcluding"):
        parts.append(f">{match['versionStartExcluding']}")
    if match.get("versionEndIncluding"):
        parts.append(f"<={match['versionEndIncluding']}")
    elif match.get("versionEndExcluding"):
        parts.append(f"<{match['versionEndExcluding']}")
    return ",".join(parts)


# cpe:2.3:<part>:<vendor>:<product>:<version>:...
_CPE_PRODUCT_RE = re.compile(r"^cpe:2\.3:[^:]+:[^:]+:([^:]+):")


def _derive_pname_hints(cpe_matches: list[dict[str, str]]) -> list[str]:
    seen: set[str] = set()
    hints: list[str] = []
    for entry in cpe_matches:
        m = _CPE_PRODUCT_RE.match(entry["cpe"])
        if not m:
            continue
        product = m.group(1)
        if product in {"*", "-"} or product in seen:
            continue
        seen.add(product)
        hints.append(product)
    return hints
