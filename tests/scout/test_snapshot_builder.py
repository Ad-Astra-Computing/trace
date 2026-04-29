"""Snapshot builder tests.

Slice 9 of Scout autonomy. Closes the relevance-filter gap: builds a
real nixpkgs graph snapshot from `nix-env -qaP --json` output so the
poller's relevance filter recognises the actual nixpkgs surface
(not just a single hand-written attr).

What's in v0:
  * attr_path + pname (lowercased) + version per derivation
  * drv_path placeholder ("attr:<attr_path>") since `nix-env -qaP`
    does not emit drvPath; full evaluation is a future slice
  * cpes / purls left empty; the relevance filter matches via the
    pname layer, which the existing CVE normalizers already populate
    via pname_hints

What is NOT in v0:
  * CPE indexing (vendor disambiguation is its own ranking problem)
  * Reverse-closure / dependency graph (Cartographer concern)
  * drvPath resolution (slow; future slice)

Tests stay offline by injecting a runner that returns captured
nix-env JSON. A live smoke is gated on TRACE_REAL_NIX_ENV=1.
"""

from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path
from typing import Any

import pytest

from agents.scout.graph_lookup import CannedGraphLookup, GraphMatch
from agents.scout.snapshot_builder import (
    SnapshotBuildError,
    build_snapshot,
    snapshot_to_json,
    snapshot_from_json,
)


_FIXTURE = Path(__file__).parent / "fixtures" / "nix-env-sample.json"


def _runner_returning(payload: bytes | str) -> Any:
    raw = payload if isinstance(payload, bytes) else payload.encode()

    def _run(cmd: list[str], **_: Any) -> subprocess.CompletedProcess[bytes]:
        return subprocess.CompletedProcess(args=cmd, returncode=0, stdout=raw, stderr=b"")

    return _run


def _runner_failing(returncode: int = 1, stderr: bytes = b"nix-env failed") -> Any:
    def _run(cmd: list[str], **_: Any) -> subprocess.CompletedProcess[bytes]:
        return subprocess.CompletedProcess(args=cmd, returncode=returncode, stdout=b"", stderr=stderr)

    return _run


def test_build_extracts_one_record_per_attr() -> None:
    runner = _runner_returning(_FIXTURE.read_bytes())
    records = build_snapshot(runner=runner)
    attr_paths = sorted(r.attr_path for r in records)
    # broken-no-pname is dropped (no pname); LibreSSL kept (pname present)
    assert "libtiff" in attr_paths
    assert "openssl" in attr_paths
    assert "python311Packages.requests" in attr_paths
    assert "LibreSSL" in attr_paths
    assert "broken-no-pname" not in attr_paths


def test_build_lowercases_pname() -> None:
    """nixpkgs attrs sometimes carry mixed-case pnames (LibreSSL).
    The relevance filter does case-insensitive lookup but exact-match
    on the GraphLookup, so we lowercase here to keep both sides
    aligned."""
    runner = _runner_returning(_FIXTURE.read_bytes())
    records = build_snapshot(runner=runner)
    libressl = next(r for r in records if r.attr_path == "LibreSSL")
    assert libressl.pname == "libressl"


def test_drv_path_placeholder_synthetic() -> None:
    """`nix-env -qaP --json` does not emit drvPath; we synthesise a
    stable placeholder so GraphMatch's required-string contract holds.
    Explicit prefix prevents collisions with real /nix/store/... paths."""
    runner = _runner_returning(_FIXTURE.read_bytes())
    records = build_snapshot(runner=runner)
    libtiff = next(r for r in records if r.attr_path == "libtiff")
    assert libtiff.drv_path == "attr:libtiff"


def test_version_preserved() -> None:
    runner = _runner_returning(_FIXTURE.read_bytes())
    records = build_snapshot(runner=runner)
    libtiff = next(r for r in records if r.attr_path == "libtiff")
    assert libtiff.version == "4.7.1"


def test_cpes_purls_empty_in_v0() -> None:
    runner = _runner_returning(_FIXTURE.read_bytes())
    records = build_snapshot(runner=runner)
    for r in records:
        assert r.cpes == ()
        assert r.purls == ()


def test_subprocess_failure_raises_build_error() -> None:
    runner = _runner_failing(returncode=2, stderr=b"error: file not found")
    with pytest.raises(SnapshotBuildError, match="returncode=2"):
        build_snapshot(runner=runner)


def test_invalid_json_raises_build_error() -> None:
    runner = _runner_returning(b"<html>not json</html>")
    with pytest.raises(SnapshotBuildError, match="JSON"):
        build_snapshot(runner=runner)


def test_unexpected_top_level_shape_raises() -> None:
    """nix-env -qaP --json emits a JSON object keyed by attr path; a
    top-level array means the caller passed wrong flags."""
    runner = _runner_returning(b'["not", "an object"]')
    with pytest.raises(SnapshotBuildError, match="object"):
        build_snapshot(runner=runner)


def test_runner_invoked_with_default_nix_env_args() -> None:
    seen: dict[str, Any] = {}

    def runner(cmd: list[str], **kwargs: Any) -> subprocess.CompletedProcess[bytes]:
        seen["cmd"] = cmd
        seen["kwargs"] = kwargs
        return subprocess.CompletedProcess(args=cmd, returncode=0, stdout=b"{}", stderr=b"")

    build_snapshot(runner=runner)

    cmd = seen["cmd"]
    assert cmd[0] == "nix-env"
    assert "-qaP" in cmd
    assert "--json" in cmd
    # default file pinned to <nixpkgs> unless caller overrides
    assert "-f" in cmd
    f_idx = cmd.index("-f")
    assert cmd[f_idx + 1] == "<nixpkgs>"


def test_build_with_explicit_nixpkgs_expr() -> None:
    seen: dict[str, Any] = {}

    def runner(cmd: list[str], **kwargs: Any) -> subprocess.CompletedProcess[bytes]:
        seen["cmd"] = cmd
        return subprocess.CompletedProcess(args=cmd, returncode=0, stdout=b"{}", stderr=b"")

    build_snapshot(runner=runner, nixpkgs="/path/to/nixpkgs")
    f_idx = seen["cmd"].index("-f")
    assert seen["cmd"][f_idx + 1] == "/path/to/nixpkgs"


# ─── serialization roundtrip ────────────────────────────────────────────────


def test_snapshot_to_and_from_json_roundtrip(tmp_path: Path) -> None:
    runner = _runner_returning(_FIXTURE.read_bytes())
    original = build_snapshot(runner=runner)

    payload = snapshot_to_json(original)
    assert isinstance(payload, str)
    parsed = json.loads(payload)
    assert isinstance(parsed, list)
    assert len(parsed) == len(original)

    reloaded = snapshot_from_json(payload)
    assert reloaded == original


def test_snapshot_loads_into_canned_graph_lookup() -> None:
    """The snapshot CLI hands its output to CannedGraphLookup at
    cron time. This must round-trip cleanly without a custom loader."""
    runner = _runner_returning(_FIXTURE.read_bytes())
    records = build_snapshot(runner=runner)
    graph = CannedGraphLookup(records)
    assert graph.find_by_pname("libtiff")
    assert graph.find_by_pname("libressl")
    assert not graph.find_by_pname("not-in-nixpkgs")


def test_compatible_with_existing_smoke_fixture_format(tmp_path: Path) -> None:
    """The poll_cli loader (agents/scout/poll_cli.py) reads a JSON
    array of {attr_path, drv_path, pname, version, cpes, purls,
    src_url, src_hash}. snapshot_to_json must emit exactly that shape."""
    runner = _runner_returning(_FIXTURE.read_bytes())
    records = build_snapshot(runner=runner)
    payload = json.loads(snapshot_to_json(records))
    sample = payload[0]
    assert {"attr_path", "drv_path", "pname", "version", "cpes", "purls"} <= set(sample)


# ─── live smoke ─────────────────────────────────────────────────────────────


@pytest.mark.skipif(
    os.environ.get("TRACE_REAL_NIX_ENV") != "1",
    reason="real nix-env evaluation; set TRACE_REAL_NIX_ENV=1 to enable",
)
def test_live_nix_env_smoke() -> None:
    records = build_snapshot()
    pnames = {r.pname for r in records}
    # Sanity: nixpkgs always has these.
    assert "libtiff" in pnames or "openssl" in pnames
    assert len(records) > 1000  # nixpkgs ships tens of thousands of attrs
