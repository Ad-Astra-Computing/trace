"""GHSA → scout-input normalizer.

Takes a validated GitHub security advisory (shape:
`policy/ghsa-source-schema.json`) and emits a `policy/scout-input-schema.json`-
shaped dict. Direct-source normalizer (no aggregator layer); provenance for
the fetch lives in the caller's replay.json invocation record, not inline in
the scout-input.

Trust boundary (mirrors vulnpatch_cve.py):
  * `feed` is always "ghsa"; no aggregator block emitted.
  * Scout still computes confidence from graph lookup. GHSA's severity/
    package data only seeds the input.
  * GHSAs without a CVE mapping are refused — trace findings are CVE-keyed.

No network. Caller fetches and passes in the parsed response.
"""

from __future__ import annotations

import re
import urllib.parse
from typing import Any


SUMMARY_MAX = 2000


# GitHub ecosystem → PURL type. Per https://github.com/package-url/purl-spec
# and GitHub's advisory taxonomy. Unknown ecosystems become pname hints only.
_ECOSYSTEM_TO_PURL_TYPE = {
    "actions": "github",
    "composer": "composer",
    "erlang": "hex",
    "go": "golang",
    "maven": "maven",
    "npm": "npm",
    "nuget": "nuget",
    "pip": "pypi",
    "pub": "pub",
    "rubygems": "gem",
    "rust": "cargo",
    "swift": "swift",
}


def normalize(response: dict[str, Any]) -> dict[str, Any]:
    """Convert a GHSA response into a scout-input dict.

    Raises ValueError if the advisory has no CVE id — trace findings are
    CVE-keyed and GHSA-only advisories are out of scope for Scout v0. The
    caller is expected to route those to a future "ghsa-only-queue" instead.
    """
    cve_id = response.get("cve_id")
    if not isinstance(cve_id, str) or not cve_id:
        raise ValueError(
            f"GHSA {response.get('ghsa_id')!r} has no CVE mapping; trace findings are "
            f"CVE-keyed. Skip or route to the GHSA-only queue."
        )

    published_at = (
        response.get("published_at")
        or response.get("nvd_published_at")
        or response.get("updated_at")
        or "1970-01-01T00:00:00Z"
    )

    severity = _build_severity(response)
    summary = _build_summary(response)
    references = _collect_references(response)
    purls, pname_hints = _collect_packages(response)
    aliases = _collect_aliases(response)

    out: dict[str, Any] = {
        "feed": "ghsa",
        "cve_id": cve_id,
        "published_at": published_at,
        "severity": severity,
    }
    if summary:
        out["summary"] = summary
    if references:
        out["references"] = references
    if purls:
        out["purl_matches"] = purls
    if pname_hints:
        out["pname_hints"] = pname_hints
    if aliases:
        out["aliases"] = aliases
    # GHSA does not carry CPE identifiers natively.
    return out


# ─── field builders ─────────────────────────────────────────────────────────


def _build_severity(response: dict[str, Any]) -> dict[str, Any]:
    rating = response.get("severity") or "unknown"
    if isinstance(rating, str):
        rating = rating.lower()
        if rating not in {"critical", "high", "medium", "low", "none", "unknown"}:
            rating = "unknown"
    else:
        rating = "unknown"

    score: Any = None
    vector: str | None = None
    cvss = response.get("cvss")
    if isinstance(cvss, dict):
        raw_score = cvss.get("score")
        if isinstance(raw_score, (int, float)) and raw_score > 0:
            score = raw_score
        raw_vector = cvss.get("vector_string")
        if isinstance(raw_vector, str) and raw_vector:
            vector = raw_vector

    out: dict[str, Any] = {"rating": rating, "cvss_v3_score": score}
    if vector:
        out["cvss_v3_vector"] = vector
    return out


def _build_summary(response: dict[str, Any]) -> str:
    summary = response.get("summary") or ""
    description = response.get("description") or ""
    parts: list[str] = []
    if isinstance(summary, str) and summary.strip():
        parts.append(summary.strip())
    if (
        isinstance(description, str)
        and description.strip()
        and description.strip() != summary.strip()
    ):
        parts.append(description.strip())
    text = ". ".join(parts)
    if len(text) > SUMMARY_MAX:
        text = text[: SUMMARY_MAX - 1] + "…"
    return text


def _collect_references(response: dict[str, Any]) -> list[dict[str, str]]:
    refs = response.get("references") or []
    seen: set[str] = set()
    out: list[dict[str, str]] = []
    for url in refs:
        if not isinstance(url, str) or url in seen:
            continue
        seen.add(url)
        out.append({"url": url, "kind": _reference_kind(url)})
    return out


def _reference_kind(url: str) -> str:
    """GHSA references are plain URLs with no tags. Infer kind from domain/path; default to 'advisory'."""
    lowered = url.lower()
    if re.search(r"github\.com/.+/commit/", lowered):
        return "upstream-commit"
    if re.search(r"github\.com/.+/(releases|tags)/", lowered):
        return "release-notes"
    if "github.com/advisories/" in lowered or "nvd.nist.gov/vuln" in lowered:
        return "advisory"
    if re.search(r"(bugzilla|bugs\.|issue|jira)", lowered):
        return "bug-tracker"
    if re.search(r"(blog|mailing-list|openwall|oss-security)", lowered):
        return "blog"
    return "advisory"


def _collect_packages(response: dict[str, Any]) -> tuple[list[str], list[str]]:
    purls: list[str] = []
    purl_seen: set[str] = set()
    pname_hints: list[str] = []
    pname_seen: set[str] = set()

    for vuln in response.get("vulnerabilities") or []:
        if not isinstance(vuln, dict):
            continue
        package = vuln.get("package")
        if not isinstance(package, dict):
            continue
        eco = package.get("ecosystem")
        name = package.get("name")
        if not isinstance(name, str) or not name:
            continue

        if name not in pname_seen:
            pname_seen.add(name)
            pname_hints.append(name)

        purl = _build_purl(eco, name) if isinstance(eco, str) else None
        if purl and purl not in purl_seen:
            purl_seen.add(purl)
            purls.append(purl)
    return purls, pname_hints


def _build_purl(ecosystem: str, name: str) -> str | None:
    purl_type = _ECOSYSTEM_TO_PURL_TYPE.get(ecosystem.lower())
    if purl_type is None:
        return None

    # Maven packages use `groupId:artifactId` in GHSA; PURL splits into
    # namespace/name with `/`.
    if purl_type == "maven" and ":" in name:
        group, _, artifact = name.partition(":")
        return f"pkg:maven/{_quote(group)}/{_quote(artifact)}"

    # npm scoped packages: `@scope/name` in GHSA; PURL uses namespace=@scope,
    # name=name with `@` URL-encoded as %40.
    if purl_type == "npm" and name.startswith("@") and "/" in name:
        scope, _, rest = name[1:].partition("/")
        return f"pkg:npm/%40{_quote(scope)}/{_quote(rest)}"

    return f"pkg:{purl_type}/{_quote(name)}"


def _quote(segment: str) -> str:
    return urllib.parse.quote(segment, safe="")


def _collect_aliases(response: dict[str, Any]) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    ghsa = response.get("ghsa_id")
    if isinstance(ghsa, str) and ghsa:
        seen.add(ghsa)
        out.append(ghsa)
    for ident in response.get("identifiers") or []:
        if not isinstance(ident, dict):
            continue
        value = ident.get("value")
        if isinstance(value, str) and value and value not in seen:
            seen.add(value)
            out.append(value)
    return out
