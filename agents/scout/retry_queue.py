"""Retry queue for transient cron failures.

State file: state/scout-retry.jsonl, one RetryEntry per line, persisted
in the same actions/cache as state/scout-cursor.json.

  RetryEntry {cve_id, attempts, first_seen, last_seen, last_error}

Lifecycle:
  * `fetch-failed` / `rate-limited` / `error` outcomes → entry added or
    attempts++.
  * `written` / `skipped-irrelevant` → entry removed (handled).
  * attempts >= max_attempts and still failing → entry dropped with a
    warning. Better than infinite retry; the data point is lost (the
    operator can re-trigger workflow_dispatch with --since to recover
    a specific window).

Workflow integration:
  1. Discover writes new-window CVE ids.
  2. cve_ids_for_retry(queue) is prepended (deduped).
  3. batch_cli runs.
  4. update_queue(existing, run_summary, run_at, max_attempts) computes
     the new persisted queue from the run summary.
"""

from __future__ import annotations

import json
import sys
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Iterable


_TRANSIENT_ACTIONS = frozenset({"fetch-failed", "rate-limited", "error"})
_TERMINAL_ACTIONS = frozenset({"written", "skipped-irrelevant"})


@dataclass(frozen=True)
class RetryEntry:
    cve_id: str
    attempts: int
    first_seen: str
    last_seen: str
    last_error: str


def read_queue(path: Path) -> list[RetryEntry]:
    if not path.is_file():
        return []
    out: list[RetryEntry] = []
    for line in path.read_text().splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            data = json.loads(line)
        except json.JSONDecodeError:
            continue
        try:
            out.append(
                RetryEntry(
                    cve_id=data["cve_id"],
                    attempts=int(data["attempts"]),
                    first_seen=data["first_seen"],
                    last_seen=data["last_seen"],
                    last_error=data["last_error"],
                )
            )
        except (KeyError, TypeError, ValueError):
            continue
    return out


def write_queue(path: Path, entries: Iterable[RetryEntry]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = "".join(json.dumps(asdict(e), sort_keys=True) + "\n" for e in entries)
    path.write_text(payload)


def cve_ids_for_retry(queue: list[RetryEntry]) -> list[str]:
    """Return CVE ids ordered by first_seen ascending so older entries
    get the chance to progress (or be dropped) before newer ones."""
    return [e.cve_id for e in sorted(queue, key=lambda e: e.first_seen)]


def enqueue_ids(
    queue: list[RetryEntry],
    cve_ids: Iterable[str],
    *,
    run_at: str,
    reason: str = "displaced-by-cap",
) -> list[RetryEntry]:
    """Add carry-over ids that were DISCOVERED but not processed this run (e.g.
    displaced past the per-run cap) so the next run picks them up instead of
    losing them — the discovery cursor advances past the window regardless.
    Entries enter at attempts=0 (a displacement is not a failure), so they still
    get the full max_attempts once actually processed. Ids already in the queue
    are left untouched (their attempts/first_seen are preserved)."""
    by_id = {e.cve_id: e for e in queue}
    for raw in cve_ids:
        cve_id = raw.strip() if isinstance(raw, str) else ""
        if not cve_id or cve_id in by_id:
            continue
        by_id[cve_id] = RetryEntry(
            cve_id=cve_id,
            attempts=0,
            first_seen=run_at,
            last_seen=run_at,
            last_error=reason,
        )
    return list(by_id.values())


def update_queue(
    *,
    existing: list[RetryEntry],
    run_summary: list[dict[str, Any]],
    run_at: str,
    max_attempts: int,
) -> list[RetryEntry]:
    by_id = {e.cve_id: e for e in existing}

    for record in run_summary:
        cve_id = record.get("cve_id")
        action = record.get("action")
        if not isinstance(cve_id, str) or not isinstance(action, str):
            continue

        if action in _TERMINAL_ACTIONS:
            by_id.pop(cve_id, None)
            continue

        if action not in _TRANSIENT_ACTIONS:
            continue

        prior = by_id.get(cve_id)
        attempts = (prior.attempts if prior else 0) + 1
        first_seen = prior.first_seen if prior else run_at
        last_error = (record.get("reason") or "") + f" (action={action})"

        if attempts > max_attempts:
            print(
                f"::warning::dropping CVE {cve_id} from retry queue after "
                f"{attempts - 1} attempts (last error: {last_error})",
                file=sys.stderr,
            )
            by_id.pop(cve_id, None)
            continue

        by_id[cve_id] = RetryEntry(
            cve_id=cve_id,
            attempts=attempts,
            first_seen=first_seen,
            last_seen=run_at,
            last_error=last_error,
        )

    return list(by_id.values())
