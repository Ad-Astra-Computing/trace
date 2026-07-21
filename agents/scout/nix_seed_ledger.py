"""Evaluation ledger for the vulnpatch /nix/cves seed source.

State file: state/nix-seed-seen.jsonl, one LedgerEntry per line, persisted in
the same actions/cache as state/scout-cursor.json + state/scout-retry.jsonl.

  LedgerEntry {cve_id, first_seen, last_evaluated, outcome, fingerprint}

Why a ledger and not a bare seen-set (DECISIONS 2026-07-21): the /nix/cves
endpoint returns a fixed ~235-entry snapshot of currently-open nixpkgs CVEs,
mostly published far outside any recent NVD window. Windowing the seed to the
6h NVD lookback made it emit ~1/run — inert. Emitting the whole snapshot every
run instead re-walks ~235 CVEs every 6h (~940/day) with no coverage gain. The
ledger drains the backlog ONCE, then emits only entries that are new or have
changed, while still letting a once-irrelevant CVE resurface as the graph gains
packages (TTL) or the upstream record changes (fingerprint).

Re-emit predicate (`should_emit`):
  * never evaluated (no ledger entry)               -> emit
  * prior outcome retryable/error (not terminal)    -> emit
  * upstream record changed (fingerprint mismatch)  -> emit
  * terminal result older than TTL (default 30d)    -> emit
  * otherwise                                        -> skip

Marking discipline (mirrors retry_queue): a CVE is marked terminal ONLY after
processing completes, computed post-run from run-summary.jsonl. Emission itself
writes an ephemeral sidecar (cve_id -> fingerprint) so the post-run update knows
what fingerprint each id was evaluated at; the ledger has a single writer, the
update step, so a crash mid-run leaves an id re-emittable rather than falsely
marked seen.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Iterable


# Outcomes that mean "handled, don't re-walk until it changes or ages out".
_TERMINAL_ACTIONS = frozenset({"written", "skipped-irrelevant"})
# Outcomes that mean "not evaluated to conclusion; keep re-emitting".
_RETRYABLE_ACTIONS = frozenset({"fetch-failed", "rate-limited", "error"})

_DEFAULT_TTL_DAYS = 30


def _has_downstream_error(record: dict[str, Any]) -> bool:
    """A CVE can poll as `written` (inbox entry created) but then fail the
    process or steward step; batch_cli keeps `action: written` and adds an error
    marker (finding_status=error / process_error / steward_error). Such an
    evaluation never reached a terminal conclusion, so it must NOT be suppressed
    for the full TTL — treat it as retryable."""
    return (
        record.get("finding_status") == "error"
        or bool(record.get("process_error"))
        or bool(record.get("steward_error"))
    )


def _effective_outcome(record: dict[str, Any]) -> str | None:
    """Map a run-summary record to the outcome the ledger should record, or
    None if the record is not ledger-relevant. A terminal action masking a
    downstream processing error is demoted to `error` (retryable)."""
    action = record.get("action")
    if not isinstance(action, str):
        return None
    if action in _TERMINAL_ACTIONS:
        return "error" if _has_downstream_error(record) else action
    if action in _RETRYABLE_ACTIONS:
        return action
    return None


@dataclass(frozen=True)
class LedgerEntry:
    cve_id: str
    first_seen: str
    last_evaluated: str
    outcome: str
    fingerprint: str


def fingerprint_fields(
    *,
    status: str,
    fixed_version: str | None,
    updated_at: str | None,
    has_pr: bool,
    has_open_pr: bool,
    has_merged_pr: bool,
) -> str:
    """Short digest of the mutable upstream state that would make a previously
    evaluated CVE worth reconsidering. Prefers the feed's own `updated_at`; if
    absent, hashes the state tuple (status / fixed_version / PR flags)."""
    if updated_at:
        return f"u:{updated_at}"
    raw = "|".join(
        [
            status or "",
            fixed_version or "",
            "1" if has_pr else "0",
            "1" if has_open_pr else "0",
            "1" if has_merged_pr else "0",
        ]
    )
    return "h:" + hashlib.sha256(raw.encode("utf-8")).hexdigest()[:16]


def read_ledger(path: Path) -> dict[str, LedgerEntry]:
    """Load the ledger keyed by cve_id. Malformed lines are skipped (a corrupt
    line must never wedge discovery); last entry for a cve_id wins."""
    out: dict[str, LedgerEntry] = {}
    if not path.is_file():
        return out
    for line in path.read_text().splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            data = json.loads(line)
        except json.JSONDecodeError:
            continue
        try:
            entry = LedgerEntry(
                cve_id=str(data["cve_id"]),
                first_seen=str(data["first_seen"]),
                last_evaluated=str(data["last_evaluated"]),
                outcome=str(data["outcome"]),
                fingerprint=str(data["fingerprint"]),
            )
        except (KeyError, TypeError, ValueError):
            continue
        out[entry.cve_id] = entry
    return out


def write_ledger(path: Path, entries: Iterable[LedgerEntry]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    ordered = sorted(entries, key=lambda e: (e.first_seen, e.cve_id))
    payload = "".join(json.dumps(asdict(e), sort_keys=True) + "\n" for e in ordered)
    path.write_text(payload)


def _parse_iso(s: str) -> datetime | None:
    try:
        dt = datetime.fromisoformat(s.replace("Z", "+00:00"))
    except (ValueError, AttributeError):
        return None
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def should_emit(
    entry: LedgerEntry | None,
    *,
    current_fingerprint: str,
    now: datetime,
    ttl_days: int = _DEFAULT_TTL_DAYS,
) -> bool:
    """Decide whether a snapshot CVE should be (re)emitted this run."""
    if entry is None:
        return True
    if entry.outcome not in _TERMINAL_ACTIONS:
        # Never reached a terminal conclusion (retryable/error/pending) -> retry.
        return True
    if entry.fingerprint != current_fingerprint:
        # Upstream record moved (new fixed_version, PR merged, ...) -> reconsider.
        return True
    when = _parse_iso(entry.last_evaluated)
    if when is None:
        return True
    return now - when > timedelta(days=ttl_days)


def update_ledger(
    *,
    existing: dict[str, LedgerEntry],
    emitted_fingerprints: dict[str, str],
    run_summary: list[dict[str, Any]],
    run_at: str,
) -> dict[str, LedgerEntry]:
    """Post-run: fold this run's outcomes into the ledger. Only CVEs that were
    emitted THIS run (present in the sidecar) are touched. Terminal outcomes are
    recorded with last_evaluated=run_at; retryable/error outcomes leave the entry
    re-emittable (recorded but with the retryable outcome, so should_emit fires
    again next run). CVEs emitted but absent from the run summary (crash before
    poll) are left untouched -> re-emitted next run."""
    result = dict(existing)
    outcome_by_id: dict[str, str] = {}
    for record in run_summary:
        cve_id = record.get("cve_id")
        outcome = _effective_outcome(record)
        if isinstance(cve_id, str) and outcome is not None:
            outcome_by_id[cve_id] = outcome

    for cve_id, fingerprint in emitted_fingerprints.items():
        action = outcome_by_id.get(cve_id)
        if action is None:
            # Emitted but no ledger-relevant outcome (process crash, or a
            # written-but-errored record demoted to nothing) — do not mark;
            # a missing/stale ledger entry re-emits next run.
            continue
        prior = result.get(cve_id)
        first_seen = prior.first_seen if prior else run_at
        result[cve_id] = LedgerEntry(
            cve_id=cve_id,
            first_seen=first_seen,
            last_evaluated=run_at,
            outcome=action,
            fingerprint=fingerprint,
        )
    return result
