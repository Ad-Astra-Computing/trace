"""Vulnpatch /nix/cves discovery client tests. Fully offline (http injected).

Two things are nailed down:
  1. The client parses the real snapshot shape into NixpkgsCve records and
     surfaces provenance (source, sha256, capped).
  2. A representative payload validates against policy/vulnpatch-nix-cves-schema.json
     — the client could parse a shape the schema (and future Steward) would reject.
"""

from __future__ import annotations

import json
from typing import Any
from unittest.mock import MagicMock

import pytest
from jsonschema import Draft202012Validator

from agents.scout.feed_client import (
    FeedDecodeError,
    FeedNotFound,
    FeedRateLimit,
    FeedTransientError,
)
from agents.scout.nix_discovery import _SNAPSHOT_CAP, list_nixpkgs_cves
from tests.schema.validate import load_schemas, validators


def _entry(**over: Any) -> dict[str, Any]:
    base = {
        "nixpkgsId": "NIXPKGS-2026-2172",
        "cveId": "CVE-2026-5663",
        "cveIds": ["CVE-2026-5663"],
        "status": "open",
        "summary": "OFFIS DCMTK os command injection",
        "affectedPackages": ["OFFIS"],
        "nixpkgsAttribute": "pkgs.OFFIS",
        "currentVersion": "3.7.0",
        "fixedVersion": "",
        "severity": "unknown",
        "publishedAt": "2026-07-20T08:29:21Z",
        "updatedAt": "2026-07-20T08:29:21Z",
        "maintainers": ["nixos-unstable"],
        "assignees": [],
        "githubIssue": "https://github.com/NixOS/nixpkgs/issues/543762",
        "githubIssueNumber": 543762,
        "linkedPRs": [],
        "hasPR": False,
        "hasOpenPR": False,
        "hasMergedPR": False,
        "trackerUrl": "https://tracker.security.nixos.org/issues/NIXPKGS-2026-2172",
        "nvdUrl": "https://nvd.nist.gov/vuln/detail/CVE-2026-5663",
    }
    base.update(over)
    return base


def _payload(entries: list[dict[str, Any]], **env: Any) -> bytes:
    body = {"success": True, "count": env.get("count", len(entries)),
            "data": entries, "source": "github",
            "stats": {"total": len(entries)}, "timestamp": "2026-07-20T13:45:20.724Z"}
    body.update({k: v for k, v in env.items() if k != "count"})
    return json.dumps(body).encode()


def _http(body: bytes, status: int = 200, headers: dict[str, str] | None = None) -> Any:
    return MagicMock(return_value=(status, body, headers or {}))


@pytest.fixture(scope="module")
def nix_cves_validator() -> Draft202012Validator:
    return validators(load_schemas())["vulnpatch_nix_cves"]


def test_parses_entries_and_provenance() -> None:
    snap = list_nixpkgs_cves(http=_http(_payload([_entry()])))
    assert snap.source == "github"
    assert len(snap.entries) == 1
    e = snap.entries[0]
    assert e.cve_id == "CVE-2026-5663"
    assert e.nixpkgs_attribute == "pkgs.OFFIS"
    assert e.current_version == "3.7.0"
    assert e.fixed_version is None            # "" collapses to None
    assert e.has_fixed_version is False
    assert e.has_pr is False
    assert len(snap.response_sha256) == 64
    assert snap.capped is False


def test_capped_flag_set_when_snapshot_full() -> None:
    entries = [_entry(nixpkgsId=f"NIXPKGS-{i}", cveId=f"CVE-2026-{1000 + i}",
                      cveIds=[f"CVE-2026-{1000 + i}"]) for i in range(_SNAPSHOT_CAP)]
    snap = list_nixpkgs_cves(http=_http(_payload(entries)))
    assert len(snap.entries) == _SNAPSHOT_CAP
    assert snap.capped is True                # a full page → there may be more unseen


def test_fixed_version_signal_and_multi_cve() -> None:
    snap = list_nixpkgs_cves(http=_http(_payload([
        _entry(cveId="CVE-2026-1", cveIds=["CVE-2026-1", "CVE-2026-2"], fixedVersion="1.2.4"),
    ])))
    e = snap.entries[0]
    assert e.has_fixed_version is True
    assert e.fixed_version == "1.2.4"
    assert e.cve_ids == ["CVE-2026-1", "CVE-2026-2"]


def test_missing_required_field_refuses_snapshot() -> None:
    bad = _entry()
    del bad["publishedAt"]
    with pytest.raises(FeedDecodeError):
        list_nixpkgs_cves(http=_http(_payload([bad])))


def test_non_object_entry_refuses_snapshot() -> None:
    # a stray non-object item must fail closed, not be silently dropped (an
    # undercounted snapshot would skew the comparison metrics).
    body = json.dumps({"success": True, "count": 2, "data": [_entry(), "oops"],
                       "source": "github", "timestamp": "t"}).encode()
    with pytest.raises(FeedDecodeError):
        list_nixpkgs_cves(http=_http(body))


def test_mistyped_optional_fields_degrade_safely() -> None:
    # cveIds as a non-list and hasPR as the string "false" must NOT crash or
    # invert the signal — they degrade to [] and False (codex 2026-07-20).
    snap = list_nixpkgs_cves(http=_http(_payload([
        _entry(cveIds=5, hasPR="false", hasOpenPR="false"),
    ])))
    e = snap.entries[0]
    assert e.cve_ids == []
    assert e.has_pr is False          # "false" string is not truthy-coerced to True
    assert e.has_open_pr is False


def test_no_data_array_raises_decode() -> None:
    with pytest.raises(FeedDecodeError):
        list_nixpkgs_cves(http=_http(json.dumps({"success": True}).encode()))


def test_invalid_json_raises_decode() -> None:
    with pytest.raises(FeedDecodeError):
        list_nixpkgs_cves(http=_http(b"not json"))


def test_404_and_429_and_5xx_map_to_typed_errors() -> None:
    with pytest.raises(FeedNotFound):
        list_nixpkgs_cves(http=_http(b"", status=404))
    with pytest.raises(FeedRateLimit):
        list_nixpkgs_cves(http=_http(b"", status=429, headers={"Retry-After": "30"}))
    with pytest.raises(FeedTransientError):
        list_nixpkgs_cves(http=_http(b"", status=503))


def test_payload_validates_against_schema(nix_cves_validator: Draft202012Validator) -> None:
    payload = json.loads(_payload([_entry(), _entry(nixpkgsId="NIXPKGS-2", cveId="CVE-2026-9",
                                                    cveIds=["CVE-2026-9"], fixedVersion="2.0")]))
    errors = [f"{'/'.join(str(p) for p in e.absolute_path)}: {e.message}"
              for e in nix_cves_validator.iter_errors(payload)]
    assert not errors, errors
