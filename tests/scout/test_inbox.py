"""Scout inbox writer tests.

Slice 5 of Scout autonomy. The inbox is an on-disk staging area where
the cron poller deposits one directory per CVE that survived the
upfront relevance filter. Layout:

  inbox/<CVE-ID>/scout-input.json    normalized record (validated)
  inbox/<CVE-ID>/raw-<feed>.json     unmodified upstream bytes
  inbox/<CVE-ID>/fetch-meta.json     request_url, fetched_at, sha256
  inbox/<CVE-ID>/relevance.json      filter decision (provenance)

Properties:
  * Atomic per-file writes (temp + rename) so a crash never leaves a
    half-written scout-input.json.
  * Schema validation before write; bad records are refused, not
    written.
  * Idempotent: re-running on the same CVE+raw-bytes is a no-op.
    A different sha256 for the same CVE raises InboxConflict so the
    caller can decide whether to bump or refuse.
  * The raw payload sha256 in fetch-meta.json matches the actual
    bytes on disk (replay-critical: this is the chain of custody for
    "what did upstream say at fetch time").
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

import pytest

from agents.scout.inbox import (
    InboxConflict,
    InboxRefused,
    write_inbox_entry,
)
from agents.scout.relevance import RelevanceDecision


_VALID_INPUT: dict[str, Any] = {
    "feed": "nvd",
    "cve_id": "CVE-2024-13978",
    "published_at": "2025-08-01T21:32:07Z",
    "summary": "LibTIFF null pointer dereference",
    "severity": {"rating": "low", "cvss_v3_score": 3.3},
    "cpe_matches": [{"cpe": "cpe:2.3:a:libtiff:libtiff:*:*:*:*:*:*:*:*"}],
    "pname_hints": ["libtiff"],
    "references": [
        {"url": "https://cve.org/CVERecord?id=CVE-2024-13978", "kind": "advisory"},
    ],
}


_RAW_BYTES = b'{"data":{"cveId":"CVE-2024-13978"}}'
_REQUEST_URL = "https://api.vulnpatch.dev/api/v1/cve/CVE-2024-13978/dossier"
_FETCHED_AT = "2026-04-29T01:39:42Z"
_RELEVANCE = RelevanceDecision(
    relevant=True,
    reason="cpe-hit:cpe:2.3:a:libtiff:libtiff:*:*:*:*:*:*:*:*",
    layer="cpe",
    matched_identifier="cpe:2.3:a:libtiff:libtiff:*:*:*:*:*:*:*:*",
)


def _write(root: Path, **overrides: Any) -> Path:
    kwargs: dict[str, Any] = {
        "scout_input": _VALID_INPUT,
        "raw_bytes": _RAW_BYTES,
        "raw_source": "dossier",
        "request_url": _REQUEST_URL,
        "fetched_at": _FETCHED_AT,
        "relevance": _RELEVANCE,
        "root": root,
    }
    kwargs.update(overrides)
    return write_inbox_entry(**kwargs)


def test_write_creates_directory_named_after_cve(tmp_path: Path) -> None:
    out = _write(tmp_path)
    assert out == tmp_path / "CVE-2024-13978"
    assert out.is_dir()


def test_scout_input_written_and_parseable(tmp_path: Path) -> None:
    out = _write(tmp_path)
    payload = json.loads((out / "scout-input.json").read_text())
    assert payload["cve_id"] == "CVE-2024-13978"
    assert payload["feed"] == "nvd"


def test_raw_payload_written_unmodified(tmp_path: Path) -> None:
    out = _write(tmp_path)
    raw = (out / "raw-dossier.json").read_bytes()
    assert raw == _RAW_BYTES


def test_fetch_meta_records_provenance(tmp_path: Path) -> None:
    out = _write(tmp_path)
    meta = json.loads((out / "fetch-meta.json").read_text())
    assert meta["request_url"] == _REQUEST_URL
    assert meta["fetched_at"] == _FETCHED_AT
    assert meta["raw_source"] == "dossier"
    assert meta["raw_filename"] == "raw-dossier.json"
    expected_sha = hashlib.sha256(_RAW_BYTES).hexdigest()
    assert meta["raw_sha256"] == expected_sha


def test_fetch_meta_sha_matches_bytes_on_disk(tmp_path: Path) -> None:
    """Replay-critical: the recorded sha must always match what was
    actually written, even if the caller passed mismatched bytes."""
    out = _write(tmp_path)
    raw = (out / "raw-dossier.json").read_bytes()
    meta = json.loads((out / "fetch-meta.json").read_text())
    assert meta["raw_sha256"] == hashlib.sha256(raw).hexdigest()


def test_relevance_decision_persisted(tmp_path: Path) -> None:
    out = _write(tmp_path)
    decision = json.loads((out / "relevance.json").read_text())
    assert decision["relevant"] is True
    assert decision["layer"] == "cpe"
    assert decision["matched_identifier"].startswith("cpe:2.3:a:libtiff")


def test_invalid_scout_input_refused(tmp_path: Path) -> None:
    """Schema validation runs before any file is written. Bad records
    don't leave half-written entries on disk."""
    bad = dict(_VALID_INPUT)
    del bad["cve_id"]
    with pytest.raises(InboxRefused, match="cve_id"):
        _write(tmp_path, scout_input=bad)
    assert not (tmp_path / "CVE-2024-13978").exists()


def test_idempotent_same_bytes_is_noop(tmp_path: Path) -> None:
    """Running the writer twice with identical raw_bytes is a no-op
    (stable mtime would be nice but not required); the existing entry
    survives unchanged."""
    out_first = _write(tmp_path)
    first_input = (out_first / "scout-input.json").read_bytes()
    first_meta = (out_first / "fetch-meta.json").read_bytes()

    out_second = _write(tmp_path)

    assert out_first == out_second
    assert (out_second / "scout-input.json").read_bytes() == first_input
    assert (out_second / "fetch-meta.json").read_bytes() == first_meta


def test_conflicting_bytes_for_same_cve_raises(tmp_path: Path) -> None:
    """If the same CVE is re-fetched and the raw bytes disagree with
    what's already on disk, the writer refuses rather than silently
    overwriting. Caller decides whether to overwrite (e.g. by passing
    overwrite=True later) or to leave the older record."""
    _write(tmp_path)
    different_bytes = _RAW_BYTES + b"x"
    with pytest.raises(InboxConflict):
        _write(tmp_path, raw_bytes=different_bytes)


def test_overwrite_flag_replaces_entry(tmp_path: Path) -> None:
    _write(tmp_path)
    different_bytes = _RAW_BYTES + b"x"
    out = _write(tmp_path, raw_bytes=different_bytes, overwrite=True)
    assert (out / "raw-dossier.json").read_bytes() == different_bytes
    meta = json.loads((out / "fetch-meta.json").read_text())
    assert meta["raw_sha256"] == hashlib.sha256(different_bytes).hexdigest()


def test_root_created_if_missing(tmp_path: Path) -> None:
    """The inbox root may not yet exist on a fresh checkout; the writer
    creates it (and any missing parents)."""
    fresh_root = tmp_path / "deep" / "inbox"
    out = write_inbox_entry(
        scout_input=_VALID_INPUT,
        raw_bytes=_RAW_BYTES,
        raw_source="dossier",
        request_url=_REQUEST_URL,
        fetched_at=_FETCHED_AT,
        relevance=_RELEVANCE,
        root=fresh_root,
    )
    assert out.is_dir()
    assert out.parent == fresh_root


def test_irrelevant_decision_still_writes_for_audit(tmp_path: Path) -> None:
    """The orchestrator may choose not to call the writer for
    irrelevant CVEs, but if it does, the writer accepts and persists
    the record. The decision file documents *why* it was kept."""
    irrelevant = RelevanceDecision(False, "no-match", None, None)
    out = _write(tmp_path, relevance=irrelevant)
    decision = json.loads((out / "relevance.json").read_text())
    assert decision["relevant"] is False


def test_raw_filename_reflects_source(tmp_path: Path) -> None:
    out = _write(tmp_path, raw_source="nvd")
    assert (out / "raw-nvd.json").exists()
    assert not (out / "raw-dossier.json").exists()


def test_invalid_raw_source_refused(tmp_path: Path) -> None:
    with pytest.raises(InboxRefused, match="raw_source"):
        _write(tmp_path, raw_source="../../etc/passwd")
