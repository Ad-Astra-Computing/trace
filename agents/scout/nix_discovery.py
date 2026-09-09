"""Vulnpatch Nix-native CVE discovery feed.

    list_nixpkgs_cves(*, http=...) -> NixCvesSnapshot

GET https://api.vulnpatch.dev/api/v1/nix/cves — the NixOS security tracker's
view (`source: github`) of open nixpkgs-affecting CVEs, each ALREADY mapped to
a nixpkgs attribute with current/fixed version and PR status. Unlike the NVD
discovery walk (`agents.scout.discovery.list_recent_cves`, which returns raw CVE
ids that Scout must graph-map itself), the nixpkgs join is pre-computed here.

Endpoint semantics (probed 2026-07-20): the endpoint IGNORES `limit` / `offset`
/ `since` / `status` / `page` / `severity` query params and returns a fixed
snapshot of the latest ~100 open entries with NO pagination. So this client
fetches the whole snapshot; callers window-filter client-side on `published_at`.
The 100-item server cap is surfaced on the snapshot (`.capped`) so a caller
never mistakes a truncated snapshot for the full recent set.

Trust boundary (mirrors the vulnpatch dossier normalizer, DECISIONS 2026-04-23):
this is a DISCOVERY source only — it seeds *which* CVEs to look at, exactly like
the NVD walk. It is NOT authoritative for merge decisions; Scout still earns a
finding's confidence via its own CPE/PURL/pname graph lookup. The vulnpatch
nixpkgs mapping is a hint to compare against, never a fact to trust.

No auth. Read-only. HTTP transport injected so tests stay fully offline; the
default transport is the same `_default_http`/`_call` shim as feed_client.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from typing import Any

from agents.scout.feed_client import (
    FeedDecodeError,
    FeedNotFound,
    FeedRateLimit,
    FeedTransientError,
    HttpFn,
    _call,
    _now_iso,
    _parse_retry_after,
)


_NIX_CVES_URL = "https://api.vulnpatch.dev/api/v1/nix/cves"
_USER_AGENT = "trace-scout/0.1 (+https://github.com/Ad-Astra-Computing/trace)"

# The endpoint returns a fixed snapshot capped at this many entries and ignores
# pagination params, so len(data) == cap means "there may be more we can't see".
_SNAPSHOT_CAP = 100


@dataclass(frozen=True)
class NixpkgsCve:
    """One open nixpkgs-affecting CVE as the NixOS security tracker sees it."""

    nixpkgs_id: str
    cve_id: str
    cve_ids: list[str]
    status: str
    published_at: str
    summary: str = ""
    nixpkgs_attribute: str | None = None
    current_version: str | None = None
    fixed_version: str | None = None
    severity: str = "unknown"
    updated_at: str | None = None
    has_pr: bool = False
    has_open_pr: bool = False
    has_merged_pr: bool = False
    tracker_url: str | None = None
    nvd_url: str | None = None

    @property
    def has_fixed_version(self) -> bool:
        """Upstream has a fixed release; a bump/backport candidate signal."""
        return bool(self.fixed_version)


@dataclass(frozen=True)
class NixCvesSnapshot:
    """A single fetch of the /nix/cves snapshot plus provenance."""

    entries: list[NixpkgsCve]
    count: int
    source: str
    request_url: str
    fetched_at: str
    response_sha256: str
    capped: bool
    stats: dict[str, Any] = field(default_factory=dict)


def list_nixpkgs_cves(*, http: HttpFn | None = None) -> NixCvesSnapshot:
    """Fetch the /nix/cves snapshot. Raises the same typed Feed* errors as the
    NVD walk so a caller can treat both discovery sources uniformly."""
    headers = {"Accept": "application/json", "User-Agent": _USER_AGENT}
    status, body, resp_headers = _call(http, _NIX_CVES_URL, headers)

    if status == 429:
        raise FeedRateLimit(_parse_retry_after(resp_headers))
    if status >= 500:
        raise FeedTransientError(f"vulnpatch /nix/cves returned {status}")
    if status == 404:
        raise FeedNotFound("vulnpatch /nix/cves endpoint returned 404")
    if status != 200:
        raise FeedDecodeError(
            f"vulnpatch /nix/cves returned unexpected status {status}"
        )

    try:
        payload = json.loads(body)
    except json.JSONDecodeError as e:
        raise FeedDecodeError(f"vulnpatch /nix/cves body is not valid JSON: {e}") from e
    if not isinstance(payload, dict):
        raise FeedDecodeError("vulnpatch /nix/cves payload is not an object")

    data = payload.get("data")
    if not isinstance(data, list):
        raise FeedDecodeError("vulnpatch /nix/cves payload has no `data` array")

    # Fail closed on a non-object entry rather than silently dropping it — a
    # partial parse would return a successful-but-undercounted snapshot and skew
    # every downstream metric (codex review 2026-07-20).
    for i, item in enumerate(data):
        if not isinstance(item, dict):
            raise FeedDecodeError(
                f"vulnpatch /nix/cves data[{i}] is {type(item).__name__}, not an object"
            )
    entries = [_parse_entry(item) for item in data]
    count = payload.get("count")
    if not isinstance(count, int):
        count = len(data)

    return NixCvesSnapshot(
        entries=entries,
        count=count,
        source=str(payload.get("source") or "unknown"),
        request_url=_NIX_CVES_URL,
        fetched_at=str(payload.get("timestamp") or _now_iso()),
        response_sha256=hashlib.sha256(body).hexdigest(),
        # A full page (>= cap) means the server truncated — there may be older
        # open entries the snapshot can't show. Surfaced, never silently dropped.
        capped=len(data) >= _SNAPSHOT_CAP,
        stats=payload.get("stats") if isinstance(payload.get("stats"), dict) else {},
    )


def _parse_entry(item: dict[str, Any]) -> NixpkgsCve:
    """Map one snapshot item to NixpkgsCve. Missing/mistyped optional fields
    degrade to safe defaults; the load-bearing ids/status/published_at must be
    strings or the whole snapshot is refused (FeedDecodeError)."""
    for req in ("nixpkgsId", "cveId", "status", "publishedAt"):
        if not isinstance(item.get(req), str):
            raise FeedDecodeError(
                f"vulnpatch /nix/cves entry missing/invalid required field {req!r}: "
                f"{item.get('nixpkgsId')!r}"
            )
    raw_ids = item.get("cveIds")
    cve_ids = (
        [c for c in raw_ids if isinstance(c, str)] if isinstance(raw_ids, list) else []
    )
    return NixpkgsCve(
        nixpkgs_id=item["nixpkgsId"],
        cve_id=item["cveId"],
        cve_ids=cve_ids,
        status=item["status"],
        published_at=item["publishedAt"],
        summary=str(item.get("summary") or ""),
        nixpkgs_attribute=_opt_str(item.get("nixpkgsAttribute")),
        current_version=_opt_str(item.get("currentVersion")),
        fixed_version=_opt_str(item.get("fixedVersion")),
        severity=str(item.get("severity") or "unknown"),
        updated_at=_opt_str(item.get("updatedAt")),
        has_pr=_opt_bool(item.get("hasPR")),
        has_open_pr=_opt_bool(item.get("hasOpenPR")),
        has_merged_pr=_opt_bool(item.get("hasMergedPR")),
        tracker_url=_opt_str(item.get("trackerUrl")),
        nvd_url=_opt_str(item.get("nvdUrl")),
    )


def _opt_str(v: Any) -> str | None:
    """A present non-empty string, else None (the feed uses '' for 'unknown')."""
    return v if isinstance(v, str) and v else None


def _opt_bool(v: Any) -> bool:
    """Only an actual JSON boolean is trusted; anything else degrades to False.
    Truthiness would misread a mistyped `"false"` string as True and invert the
    PR signal — the safe default is "no PR", which keeps the entry visible as a
    beat-upstream candidate rather than silently dropping it."""
    return v if isinstance(v, bool) else False
