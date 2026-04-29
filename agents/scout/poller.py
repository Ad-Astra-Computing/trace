"""Scout cron poller orchestrator.

Composes the pieces from slices 2-5 into one end-to-end call:

  fetch (dossier-primary, NVD-direct fallback)
       ↓
  normalize (dossier or nvd normalizer)
       ↓
  relevance filter (graph lookup, short-circuits)
       ↓
  inbox write (atomic, schema-validated, idempotent)

`poll_one(cve_id, ...)` returns a `PollOutcome` recording exactly
what happened; the cron workflow logs one line per CVE and
aggregates a per-run summary.

Locked decisions (user direction, 28 April 2026):
  * Anonymous-first NVD; NVD_API_KEY optional, threaded through.
  * Dossier-primary; NVD-direct kicks in when the dossier 404s OR
    when the dossier response is decode-broken (so a partial
    aggregator outage does not block the inbox).
  * Both feeds 404 → fetch-failed (not silently dropped); rate-limit
    on both → rate-limited with the longer Retry-After surfaced.
  * Irrelevant CVEs are NOT persisted; the decision lives in the
    PollOutcome the cron logs.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

from agents.feed_normalizers.dossier import normalize as normalize_dossier
from agents.feed_normalizers.nvd import normalize as normalize_nvd
from agents.scout.feed_client import (
    FeedDecodeError,
    FeedNotFound,
    FeedRateLimit,
    FeedTransientError,
    FetchResult,
    HttpFn,
    fetch_dossier,
    fetch_nvd_direct,
)
from agents.scout.graph_lookup import GraphLookup
from agents.scout.inbox import write_inbox_entry
from agents.scout.relevance import is_relevant_to_nixpkgs


@dataclass(frozen=True)
class PollOutcome:
    cve_id: str
    action: str  # "written" | "skipped-irrelevant" | "fetch-failed" | "rate-limited"
    reason: str
    feed_used: str | None = None
    entry_path: Path | None = None
    retry_after_seconds: int | None = None


def poll_one(
    cve_id: str,
    *,
    graph: GraphLookup,
    root: Path,
    http: HttpFn | None = None,
    nvd_api_key: str | None = None,
) -> PollOutcome:
    if not isinstance(cve_id, str) or not cve_id.startswith("CVE-"):
        raise ValueError(f"not a CVE id: {cve_id!r}")

    dossier_attempt = _try_dossier(cve_id, http=http)
    if dossier_attempt.outcome is not None:
        return dossier_attempt.outcome

    if dossier_attempt.scout_input is not None:
        return _filter_and_write(
            cve_id=cve_id,
            scout_input=dossier_attempt.scout_input,
            fetch=dossier_attempt.fetch,
            raw_source="dossier",
            graph=graph,
            root=root,
        )

    nvd_attempt = _try_nvd(cve_id, http=http, api_key=nvd_api_key)
    if nvd_attempt.outcome is not None:
        return _merge_dossier_rate_limit(nvd_attempt.outcome, dossier_attempt.rate_limited_seconds)

    if nvd_attempt.scout_input is not None:
        return _filter_and_write(
            cve_id=cve_id,
            scout_input=nvd_attempt.scout_input,
            fetch=nvd_attempt.fetch,
            raw_source="nvd",
            graph=graph,
            root=root,
        )

    return PollOutcome(
        cve_id=cve_id,
        action="fetch-failed",
        reason="both dossier and NVD-direct returned no usable record",
    )


@dataclass
class _Attempt:
    outcome: PollOutcome | None = None
    scout_input: dict[str, Any] | None = None
    fetch: FetchResult | None = None
    rate_limited_seconds: int | None = None


def _try_dossier(cve_id: str, *, http: HttpFn | None) -> _Attempt:
    try:
        result = fetch_dossier(cve_id, http=http)
    except FeedNotFound:
        return _Attempt()
    except FeedRateLimit as e:
        return _Attempt(rate_limited_seconds=e.retry_after)
    except FeedTransientError:
        return _Attempt()
    except FeedDecodeError:
        return _Attempt()

    try:
        scout_input = normalize_dossier(
            result.data,
            request_url=result.request_url,
            fetched_at=result.fetched_at,
            raw_response_bytes=result.raw_bytes,
        )
    except (KeyError, ValueError):
        return _Attempt()

    return _Attempt(scout_input=scout_input, fetch=result)


def _try_nvd(cve_id: str, *, http: HttpFn | None, api_key: str | None) -> _Attempt:
    try:
        result = fetch_nvd_direct(cve_id, http=http, api_key=api_key)
    except FeedNotFound as e:
        return _Attempt(outcome=PollOutcome(
            cve_id=cve_id,
            action="fetch-failed",
            reason=f"NVD-direct: {e}",
        ))
    except FeedRateLimit as e:
        return _Attempt(outcome=PollOutcome(
            cve_id=cve_id,
            action="rate-limited",
            reason=f"NVD-direct rate-limited (retry after {e.retry_after}s)",
            retry_after_seconds=e.retry_after,
        ))
    except FeedTransientError as e:
        return _Attempt(outcome=PollOutcome(
            cve_id=cve_id,
            action="fetch-failed",
            reason=f"NVD-direct transient: {e}",
        ))
    except FeedDecodeError as e:
        return _Attempt(outcome=PollOutcome(
            cve_id=cve_id,
            action="fetch-failed",
            reason=f"NVD-direct decode: {e}",
        ))

    try:
        scout_input = normalize_nvd(result.data)
    except (KeyError, ValueError) as e:
        return _Attempt(outcome=PollOutcome(
            cve_id=cve_id,
            action="fetch-failed",
            reason=f"NVD normalizer rejected record: {e}",
        ))

    return _Attempt(scout_input=scout_input, fetch=result)


def _filter_and_write(
    *,
    cve_id: str,
    scout_input: dict[str, Any],
    fetch: FetchResult,
    raw_source: str,
    graph: GraphLookup,
    root: Path,
) -> PollOutcome:
    decision = is_relevant_to_nixpkgs(scout_input, graph)
    if not decision.relevant:
        return PollOutcome(
            cve_id=cve_id,
            action="skipped-irrelevant",
            reason=decision.reason,
            feed_used=raw_source,
        )

    entry_dir = write_inbox_entry(
        scout_input=scout_input,
        raw_bytes=fetch.raw_bytes,
        raw_source=raw_source,
        request_url=fetch.request_url,
        fetched_at=fetch.fetched_at,
        relevance=decision,
        root=root,
    )
    return PollOutcome(
        cve_id=cve_id,
        action="written",
        reason=decision.reason,
        feed_used=raw_source,
        entry_path=entry_dir,
    )


def _merge_dossier_rate_limit(
    nvd_outcome: PollOutcome,
    dossier_retry_after: int | None,
) -> PollOutcome:
    """If both dossier and NVD rate-limited, surface the longer
    Retry-After so the cron sleeps long enough."""
    if nvd_outcome.action != "rate-limited" or dossier_retry_after is None:
        return nvd_outcome
    longer = max(nvd_outcome.retry_after_seconds or 0, dossier_retry_after)
    return PollOutcome(
        cve_id=nvd_outcome.cve_id,
        action="rate-limited",
        reason=f"both feeds rate-limited (longest retry after {longer}s)",
        retry_after_seconds=longer,
    )
