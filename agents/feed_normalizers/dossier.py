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

    bounds = _extract_version_bounds(sources)
    if bounds:
        out["version_bounds"] = bounds

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
    # Kernel CVEs publish patches as cgit links on git.kernel.org. The
    # /stable/c/, /torvalds/c/, /linus/ shorthand forms don't contain
    # "/commit/" so they need an explicit needle. The full cgit form
    # already matches "/commit/" above. Processor's regex is the
    # source of truth for which kernel.org URLs are actually fetchable;
    # this needle just gets them the right kind tag so they reach the
    # processor in the first place.
    ("git.kernel.org/stable/c/", "upstream-commit"),
    ("git.kernel.org/torvalds/c/", "upstream-commit"),
    ("git.kernel.org/linus/", "upstream-commit"),
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


_FIX_KIND_KEYS = ("lessThan", "lessThanOrEqual", "versionEndExcluding", "versionEndIncluding")
_RANGE_PART_RE = re.compile(r"^\s*(<=|>=|<|>|==|=)?\s*([0-9][0-9A-Za-z.\-+]*)\s*$")

# Slice 5h status-list fallback: classify unaffected-entry version strings.
_SEMVER_BASE_RE = re.compile(r"^\d+\.\d+(?:\.\d+)?(?:[-+].*)?$")
# Mirrors resolver._PRE_RELEASE_RE so the dossier path agrees with the
# resolver's pre-release detection. Drift here would mean we'd emit a
# "stable" bound that the resolver then flags as pre-release, or vice versa.
_DOSSIER_PRE_RELEASE_RE = re.compile(
    r"[-+](?:rc|alpha|beta|dev|pre|preview|nightly|snapshot|m\d|a\d|b\d)",
    re.IGNORECASE,
)
_COMMIT_SHA_RE = re.compile(r"^[0-9a-f]{7,40}$", re.IGNORECASE)


def _extract_version_bounds(sources: dict[str, Any]) -> list[dict[str, Any]]:
    """Lift CVE-list-v5 affected[].versions[] entries to scout-input
    version_bounds. Conservative: only status=affected, only semver,
    and the source form (lessThan vs lessThanOrEqual) is preserved
    distinctly so the processor can decide whether to synthesize a
    candidate target_version. Multiple distinct fix-bounds for the
    same product are surfaced as separate entries; the resolver picks
    smallest-upgrade or routes to human review.
    """
    cve_list_v5 = sources.get("cve_list_v5")
    if not isinstance(cve_list_v5, dict):
        return []
    bounds: list[dict[str, Any]] = []
    for affected in cve_list_v5.get("affected") or []:
        if not isinstance(affected, dict):
            continue
        product = (affected.get("product") or "").strip().lower()
        if not product:
            continue
        versions_block = affected.get("versions") or []
        product_bounds: list[dict[str, Any]] = []
        for entry in versions_block:
            if not isinstance(entry, dict):
                continue
            if entry.get("status") != "affected":
                continue
            structured = _structured_bound(product, entry)
            if structured is not None:
                product_bounds.append(structured)
                continue
            free_text = _free_text_bound(product, entry)
            if free_text is not None:
                product_bounds.append(free_text)
        if not product_bounds:
            fallback = _status_list_bound(product, versions_block)
            if fallback is not None:
                product_bounds.append(fallback)
        bounds.extend(product_bounds)
    return bounds


def _structured_bound(product: str, entry: dict[str, Any]) -> dict[str, Any] | None:
    if entry.get("versionType") != "semver":
        return None
    fixed_kind, fixed = _pick_fix_signal(entry)
    if not fixed_kind:
        return None
    bound: dict[str, Any] = {
        "product": product,
        "fixed": fixed,
        "fixed_kind": fixed_kind,
        "version_type": "semver",
        "source": "cve_list_v5",
    }
    introduced = entry.get("version")
    if isinstance(introduced, str) and introduced:
        bound["introduced"] = introduced
    return bound


def _free_text_bound(product: str, entry: dict[str, Any]) -> dict[str, Any] | None:
    """Parse free-text ranges in the `version` field (e.g. '< 1.17.2',
    '>= 0.32.0, < 0.43.4'). Returns a single bound shaped like the
    structured path. Conservative: skip when no upper-bound operator
    can be parsed (treats unrecognized strings like 'all versions' as
    'no signal' rather than guessing)."""
    raw = entry.get("version")
    if not isinstance(raw, str) or not raw.strip():
        return None
    upper_kind: str | None = None
    upper_value: str | None = None
    introduced: str | None = None
    for part in raw.split(","):
        m = _RANGE_PART_RE.match(part)
        if not m:
            return None
        op = m.group(1) or "="
        val = m.group(2)
        if op == "<":
            upper_kind, upper_value = "lessThan", val
        elif op == "<=":
            upper_kind, upper_value = "lessThanOrEqual", val
        elif op == ">=":
            introduced = val
        elif op == ">":
            # Strict-greater-than is rare; record as introduced for
            # information; processor only uses it for the in-scope
            # check, not the candidate version.
            introduced = val
        else:
            # bare or = pinned; treat as introduced
            introduced = val
    if upper_kind is None or upper_value is None:
        return None
    bound: dict[str, Any] = {
        "product": product,
        "fixed": upper_value,
        "fixed_kind": upper_kind,
        "version_type": "semver",
        "source": "cve_list_v5",
    }
    if introduced is not None:
        bound["introduced"] = introduced
    return bound


def _pick_fix_signal(entry: dict[str, Any]) -> tuple[str | None, str]:
    """Return the first fix-bound key that's set on this version entry.
    Each version entry typically carries exactly one of these; if more
    than one is present we honour the first matched key in declaration
    order to keep behaviour deterministic."""
    for key in _FIX_KIND_KEYS:
        v = entry.get(key)
        if isinstance(v, str) and v:
            return key, v
    return None, ""


def _status_list_bound(
    product: str, versions: list[Any]
) -> dict[str, Any] | None:
    """Status-list fallback (slice 5h). When no status=affected entry
    yields a structured or free-text bound for this product, infer one
    from the status=unaffected entries in the same affected[] block.

    Sub-cases the slice 5g characterization surfaced:
      * fixed-version-from-status-list — smallest stable-semver
        unaffected entry, emitted as a lessThan equivalent. Lets the
        processor synthesize a real target_version instead of falling
        back to current_version (placeholder-target-version).
      * pre-release-from-status-list — when no stable unaffected exists,
        smallest pre-release unaffected entry. The processor still
        synthesizes the target; the resolver's existing pre-release-target
        trigger fires on the rc/alpha/beta version.

    Commit-hash unaffected entries (CImg-shape advisories) are recognized
    but not emitted as bounds in v0 — without a semver-typed value to
    expose the resolver/Steward path stays on placeholder-target-version.
    Provenance for that sub-case will be added when the schema can carry
    a non-semver bound type; tracked separately, not part of slice 5h.
    """
    stable: list[str] = []
    prerelease: list[str] = []
    for entry in versions:
        if not isinstance(entry, dict):
            continue
        if entry.get("status") != "unaffected":
            continue
        v = entry.get("version")
        kind = _classify_unaffected_version(v)
        if kind == "stable-semver":
            stable.append(v.strip())
        elif kind == "pre-release":
            prerelease.append(v.strip())

    if stable:
        chosen = min(stable, key=_semver_sort_key)
        provenance = "fixed-version-from-status-list"
    elif prerelease:
        chosen = min(prerelease, key=_semver_sort_key)
        provenance = "pre-release-from-status-list"
    else:
        return None

    return {
        "product": product,
        "fixed": chosen,
        "fixed_kind": "lessThan",
        "version_type": "semver",
        "source": "cve_list_v5",
        "provenance": provenance,
    }


def _classify_unaffected_version(v: Any) -> str | None:
    """Classify the version string on a status=unaffected entry.
    Returns 'stable-semver', 'pre-release', 'commit', or None for
    unparseable / wildcard / range expressions (skipped in v0)."""
    if not isinstance(v, str):
        return None
    s = v.strip()
    if not s:
        return None
    if _SEMVER_BASE_RE.match(s):
        return "pre-release" if _DOSSIER_PRE_RELEASE_RE.search(s) else "stable-semver"
    if _COMMIT_SHA_RE.match(s):
        return "commit"
    return None


def _semver_sort_key(v: str) -> tuple:
    """Coarse sort key for picking the smallest unaffected version.
    Sorts by (major, minor, patch) then ranks pre-release < stable for
    the same base triple (semver: 1.0.0-rc1 < 1.0.0). Unparseable bits
    fall back to a string compare so the output stays deterministic."""
    m = re.match(r"^(\d+)\.(\d+)(?:\.(\d+))?(.*)$", v)
    if not m:
        return (10**9, 10**9, 10**9, 1, v)
    major = int(m.group(1))
    minor = int(m.group(2))
    patch = int(m.group(3) or 0)
    suffix = m.group(4) or ""
    pre_marker = 0 if suffix else 1
    return (major, minor, patch, pre_marker, suffix)


def _pname_hints_from_packages(canonical: dict[str, Any]) -> list[str]:
    seen: set[str] = set()
    hints: list[str] = []
    for pkg in canonical.get("affectedPackages") or []:
        name = (pkg.get("name") or "").strip().lower()
        if name and name not in seen:
            seen.add(name)
            hints.append(name)
    return hints
