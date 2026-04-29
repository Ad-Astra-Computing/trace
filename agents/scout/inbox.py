"""Scout inbox writer.

Atomic, schema-validated, idempotent persistence for one CVE per
directory. Layout:

  <root>/<CVE-ID>/scout-input.json    normalized record
  <root>/<CVE-ID>/raw-<source>.json   unmodified upstream bytes
  <root>/<CVE-ID>/fetch-meta.json     request URL, fetched_at, sha256
  <root>/<CVE-ID>/relevance.json      relevance-filter decision

Idempotency: two writes for the same CVE+raw_bytes are a no-op.
A different sha256 raises InboxConflict so the caller (cron) can
decide whether to bump (overwrite=True) or leave the older record.

No network, no globals. Caller passes `root` explicitly so the
writer is callable from both the cron orchestrator and tests.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import tempfile
from dataclasses import asdict
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator

from agents.scout.relevance import RelevanceDecision


_REPO_ROOT = Path(__file__).resolve().parents[2]
_SCOUT_INPUT_SCHEMA_PATH = _REPO_ROOT / "policy" / "scout-input-schema.json"

_RAW_SOURCE_RE = re.compile(r"^[a-z][a-z0-9_-]{0,31}$")


class InboxRefused(Exception):
    """The input failed validation; nothing was written."""


class InboxConflict(Exception):
    """An entry already exists for this CVE with different raw bytes."""


_validator: Draft202012Validator | None = None


def _scout_input_validator() -> Draft202012Validator:
    global _validator
    if _validator is None:
        schema = json.loads(_SCOUT_INPUT_SCHEMA_PATH.read_text())
        _validator = Draft202012Validator(schema)
    return _validator


def write_inbox_entry(
    *,
    scout_input: dict[str, Any],
    raw_bytes: bytes,
    raw_source: str,
    request_url: str,
    fetched_at: str,
    relevance: RelevanceDecision,
    root: Path,
    overwrite: bool = False,
) -> Path:
    if not _RAW_SOURCE_RE.match(raw_source):
        raise InboxRefused(
            f"raw_source must match {_RAW_SOURCE_RE.pattern!r}, got {raw_source!r}"
        )

    cve_id = scout_input.get("cve_id")
    if not isinstance(cve_id, str) or not cve_id.startswith("CVE-"):
        raise InboxRefused(
            f"scout_input.cve_id missing or not CVE-shaped: {cve_id!r}"
        )

    errors = sorted(_scout_input_validator().iter_errors(scout_input), key=lambda e: e.path)
    if errors:
        first = errors[0]
        raise InboxRefused(f"scout_input failed schema: {first.message} at {list(first.path)}")

    raw_sha256 = hashlib.sha256(raw_bytes).hexdigest()
    raw_filename = f"raw-{raw_source}.json"

    entry_dir = root / cve_id
    raw_path = entry_dir / raw_filename

    if entry_dir.exists() and raw_path.exists() and not overwrite:
        existing = raw_path.read_bytes()
        if existing == raw_bytes:
            return entry_dir
        raise InboxConflict(
            f"{cve_id} already in inbox with different raw bytes "
            f"(existing sha256={hashlib.sha256(existing).hexdigest()[:12]}, "
            f"new sha256={raw_sha256[:12]}); pass overwrite=True to replace"
        )

    entry_dir.mkdir(parents=True, exist_ok=True)

    fetch_meta = {
        "request_url": request_url,
        "fetched_at": fetched_at,
        "raw_source": raw_source,
        "raw_filename": raw_filename,
        "raw_sha256": raw_sha256,
    }

    _atomic_write_bytes(raw_path, raw_bytes)
    _atomic_write_json(entry_dir / "scout-input.json", scout_input)
    _atomic_write_json(entry_dir / "fetch-meta.json", fetch_meta)
    _atomic_write_json(entry_dir / "relevance.json", asdict(relevance))

    return entry_dir


def _atomic_write_bytes(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix=path.name + ".", dir=str(path.parent))
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(data)
        os.replace(tmp, path)
    except Exception:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def _atomic_write_json(path: Path, data: Any) -> None:
    payload = json.dumps(data, indent=2, sort_keys=True).encode() + b"\n"
    _atomic_write_bytes(path, payload)
