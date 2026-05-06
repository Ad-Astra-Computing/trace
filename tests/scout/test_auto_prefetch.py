"""Tests for the auto-prefetch orchestrator.

Pins the v0 contract for slice 5d:

  * env-gated: TRACE_REAL_PREFETCH=1 required (else skip silently)
  * nixpkgs_root required (else skip with reason)
  * narrow scope: plain-fetchurl auto-prefetched; fetchFromGitHub /
    fetchzip / vendor-style detected for metrics but not prefetched
  * idempotent: re-running on a bundle with prefetch_hashes already
    populated is a no-op
  * upstream-ref.json mutated atomically only on actual prefetch run
  * aggregate metrics are partition-friendly (each entry classified
    into exactly one src class for primary counting)
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from agents.scout.auto_prefetch import (
    AutoPrefetchStats,
    aggregate_stats,
    auto_prefetch_for_entry,
)


def _seed_entry(
    tmp_path: Path,
    *,
    cve_id: str = "CVE-2099-0001",
    target_version: str = "1.0.1",
    extra_upstream: dict[str, Any] | None = None,
) -> Path:
    entry = tmp_path / "inbox" / cve_id
    entry.mkdir(parents=True)
    upstream_ref: dict[str, Any] = {
        "schema_version": "1.0.0",
        "cve_id": cve_id,
        "current_version": "1.0.0",
        "target_version": target_version,
        "fix_tier": "security-patch-release",
        "release_url": "https://example.test/r",
        "delta": {
            "transitive_package_changes": 0,
            "new_direct_deps": [],
            "removed_direct_deps": [],
            "crosses_large_delta_threshold": False,
            "threshold_policy": "v0-default",
        },
        "replay_critical": True,
        "eligibility": {"verdict": "eligible"},
    }
    if extra_upstream:
        upstream_ref.update(extra_upstream)
    (entry / "upstream-ref.json").write_text(json.dumps(upstream_ref))
    return entry


def _mk_nixpkgs_with_package(
    root: Path, *, attr: str = "foo", contents: str | None = None,
) -> Path:
    pkg_dir = root / "pkgs" / "by-name" / attr[:2] / attr
    pkg_dir.mkdir(parents=True)
    src = contents or '{ ... }: { version = "1.0.0"; src = fetchurl { url = "https://example.test/${pname}-${version}.tar.gz"; }; }'
    (pkg_dir / "package.nix").write_text(src)
    return root


def _ok_prefetch(url: str, algo: str) -> tuple[str, str, str | None]:
    return ("ok", "sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", "nix-prefetch-url 2.18.1")


def _failing_prefetch(url: str, algo: str) -> tuple[str, str, str | None]:
    return ("fetch-error-404", "404 Not Found", "nix-prefetch-url 2.18.1")


def test_env_gate_skips_silently(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """With NEITHER TRACE_REAL_PREFETCH nor TRACE_REAL_FETCHZIP set,
    auto-prefetch skips silently."""
    monkeypatch.delenv("TRACE_REAL_PREFETCH", raising=False)
    monkeypatch.delenv("TRACE_REAL_FETCHZIP", raising=False)
    entry = _seed_entry(tmp_path)
    nixpkgs = _mk_nixpkgs_with_package(tmp_path / "nixpkgs")
    stats = auto_prefetch_for_entry(
        entry, attr_path="foo", nixpkgs_root=nixpkgs, prefetch_url_fn=_ok_prefetch,
    )
    assert stats.skipped_reason == "env-not-set"
    upstream = json.loads((entry / "upstream-ref.json").read_text())
    assert "prefetch_hashes" not in upstream


def test_no_nixpkgs_root_skips(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("TRACE_REAL_PREFETCH", "1")
    entry = _seed_entry(tmp_path)
    stats = auto_prefetch_for_entry(
        entry, attr_path="foo", nixpkgs_root=None, prefetch_url_fn=_ok_prefetch,
    )
    assert stats.skipped_reason == "no-nixpkgs-root"


def test_plain_fetchurl_attempted_and_succeeds(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("TRACE_REAL_PREFETCH", "1")
    src = (
        '{ stdenv, fetchurl }: stdenv.mkDerivation {\n'
        '  pname = "foo";\n'
        '  version = "1.0.0";\n'
        '  src = fetchurl {\n'
        '    url = "https://example.test/foo-${version}.tar.gz";\n'
        '    hash = "sha256-OLD";\n'
        '  };\n'
        '}\n'
    )
    entry = _seed_entry(tmp_path)
    nixpkgs = _mk_nixpkgs_with_package(tmp_path / "nixpkgs", contents=src)
    stats = auto_prefetch_for_entry(
        entry, attr_path="foo", nixpkgs_root=nixpkgs, prefetch_url_fn=_ok_prefetch,
    )
    assert stats.skipped_reason is None
    assert stats.primary_src_class == "plain-fetchurl"
    assert stats.plain_fetchurl_attempted == 1
    assert stats.plain_fetchurl_succeeded == 1
    assert stats.plain_fetchurl_failed == 0
    upstream = json.loads((entry / "upstream-ref.json").read_text())
    assert upstream["prefetch_hashes"][0]["value"].startswith("sha256-")
    assert upstream["prefetch_hashes"][0]["url"] == "https://example.test/foo-1.0.1.tar.gz"


def test_plain_fetchurl_prefetch_failure_records_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("TRACE_REAL_PREFETCH", "1")
    src = (
        '{ fetchurl }: { src = fetchurl { url = "https://example.test/foo-${version}.tar.gz"; }; }'
    )
    entry = _seed_entry(tmp_path)
    nixpkgs = _mk_nixpkgs_with_package(tmp_path / "nixpkgs", contents=src)
    stats = auto_prefetch_for_entry(
        entry, attr_path="foo", nixpkgs_root=nixpkgs, prefetch_url_fn=_failing_prefetch,
    )
    assert stats.plain_fetchurl_failed == 1
    upstream = json.loads((entry / "upstream-ref.json").read_text())
    assert upstream["prefetch_failures"][0]["reason"] == "fetch-error-404"
    assert upstream["prefetch_failures"][0]["required_for_patch"] is True


def test_fetchfromgithub_skipped_without_fetchzip_gate(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Without TRACE_REAL_FETCHZIP, fetchFromGitHub is detected and
    counted but NOT prefetched. The plain-fetchurl gate alone does
    not unlock the fetchzip path."""
    monkeypatch.setenv("TRACE_REAL_PREFETCH", "1")
    monkeypatch.delenv("TRACE_REAL_FETCHZIP", raising=False)
    src = (
        '{ fetchFromGitHub }: { src = fetchFromGitHub {\n'
        '  owner = "nicolargo"; repo = "glances";\n'
        '  tag = "v${version}"; hash = "sha256-OLD"; }; }'
    )
    entry = _seed_entry(tmp_path)
    nixpkgs = _mk_nixpkgs_with_package(tmp_path / "nixpkgs", contents=src)
    invoked: list[str] = []

    def spy(url: str, algo: str) -> tuple[str, str, str | None]:
        invoked.append(url)
        return _ok_prefetch(url, algo)

    stats = auto_prefetch_for_entry(
        entry, attr_path="foo", nixpkgs_root=nixpkgs, prefetch_url_fn=spy,
    )
    assert stats.primary_src_class == "fetchFromGitHub"
    assert stats.fetchFromGitHub_present_but_skipped == 1
    assert stats.fetchFromGitHub_attempted == 0
    assert invoked == [], "nix-prefetch-url must NOT be called for fetchFromGitHub"


def _ok_fetchzip(expr: str, req: Any) -> tuple[str, str, str, str]:
    return ("ok", "sha256-NEWGITHUBHASHFROMFAKEHASHEXTRACTION12345=",
            "nix-build 2.18.1", f"nix-build -E '<expr>'")


def _failing_fetchzip(expr: str, req: Any) -> tuple[str, str, str, str]:
    return ("err", "exit 1: hash mismatch parser saw nothing",
            "nix-build 2.18.1", f"nix-build -E '<expr>'")


def test_fetchfromgithub_attempted_when_fetchzip_gate_set(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """With TRACE_REAL_FETCHZIP=1, fetchFromGitHub IS prefetched via
    the fetchzip FOD-extraction path. Hash lands in prefetch_hashes."""
    monkeypatch.setenv("TRACE_REAL_FETCHZIP", "1")
    src = (
        '{ fetchFromGitHub }: { src = fetchFromGitHub {\n'
        '  owner = "nicolargo"; repo = "glances";\n'
        '  tag = "v${version}"; hash = "sha256-OLD"; }; }'
    )
    entry = _seed_entry(tmp_path)
    nixpkgs = _mk_nixpkgs_with_package(tmp_path / "nixpkgs", contents=src)
    stats = auto_prefetch_for_entry(
        entry, attr_path="foo", nixpkgs_root=nixpkgs,
        fetchzip_command_runner=_ok_fetchzip,
    )
    assert stats.primary_src_class == "fetchFromGitHub"
    assert stats.fetchFromGitHub_attempted == 1
    assert stats.fetchFromGitHub_succeeded == 1
    assert stats.fetchFromGitHub_failed == 0
    upstream = json.loads((entry / "upstream-ref.json").read_text())
    h = upstream["prefetch_hashes"][0]
    assert h["prefetch_kind"] == "fetchzip"
    assert h["source"] == "fetchzip-src-extract"
    assert h["value"].startswith("sha256-NEWGITHUB")


def test_fetchfromgithub_failure_records_prefetch_failures(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Prefetch failure produces a structured prefetch_failures[]
    entry with required_for_patch=True. Steward then routes to
    human-review-required via the existing patcher-not-ready rule."""
    monkeypatch.setenv("TRACE_REAL_FETCHZIP", "1")
    src = (
        '{ fetchFromGitHub }: { src = fetchFromGitHub {\n'
        '  owner = "x"; repo = "y"; tag = "v${version}"; hash = "sha256-OLD"; }; }'
    )
    entry = _seed_entry(tmp_path)
    nixpkgs = _mk_nixpkgs_with_package(tmp_path / "nixpkgs", contents=src)
    stats = auto_prefetch_for_entry(
        entry, attr_path="foo", nixpkgs_root=nixpkgs,
        fetchzip_command_runner=_failing_fetchzip,
    )
    assert stats.fetchFromGitHub_attempted == 1
    assert stats.fetchFromGitHub_failed == 1
    upstream = json.loads((entry / "upstream-ref.json").read_text())
    f = upstream["prefetch_failures"][0]
    assert f["reason"] == "fetchzip-prefetch-failed"
    assert f["required_for_patch"] is True
    assert "prefetch_hashes" not in upstream


def test_fetchzip_detected_but_not_prefetched(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("TRACE_REAL_PREFETCH", "1")
    src = '{ fetchzip }: { src = fetchzip { url = "https://example.test/foo-${version}.tar.gz"; }; }'
    entry = _seed_entry(tmp_path)
    nixpkgs = _mk_nixpkgs_with_package(tmp_path / "nixpkgs", contents=src)
    stats = auto_prefetch_for_entry(
        entry, attr_path="foo", nixpkgs_root=nixpkgs, prefetch_url_fn=_ok_prefetch,
    )
    assert stats.primary_src_class == "fetchzip"
    assert stats.fetchzip_present_but_skipped == 1
    assert stats.plain_fetchurl_attempted == 0


def test_vendor_style_hash_co_occurs_with_src_class(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A Go module typically pairs fetchFromGitHub with vendorHash. Both
    are reported so the operator can see the second-tier prefetch
    needed beyond src.hash."""
    monkeypatch.setenv("TRACE_REAL_PREFETCH", "1")
    src = (
        '{ buildGoModule, fetchFromGitHub }: buildGoModule {\n'
        '  src = fetchFromGitHub { owner = "x"; repo = "y"; tag = "v${version}"; hash = "sha256-A"; };\n'
        '  vendorHash = "sha256-B";\n'
        '}'
    )
    entry = _seed_entry(tmp_path)
    nixpkgs = _mk_nixpkgs_with_package(tmp_path / "nixpkgs", contents=src)
    stats = auto_prefetch_for_entry(
        entry, attr_path="foo", nixpkgs_root=nixpkgs, prefetch_url_fn=_ok_prefetch,
    )
    assert stats.primary_src_class == "fetchFromGitHub"
    assert stats.has_vendor_style_hash is True
    assert stats.go_mod_vendor_present_but_skipped == 1


def test_idempotent_when_prefetch_hashes_already_populated(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("TRACE_REAL_PREFETCH", "1")
    entry = _seed_entry(
        tmp_path,
        extra_upstream={"prefetch_hashes": [{
            "name": "src",
            "algorithm": "sha256",
            "value": "sha256-EXISTING",
            "source": "manual",
            "prefetch_kind": "release-archive",
            "replay_critical": True,
        }]},
    )
    nixpkgs = _mk_nixpkgs_with_package(tmp_path / "nixpkgs")
    invoked: list[str] = []

    def spy(url: str, algo: str) -> tuple[str, str, str | None]:
        invoked.append(url)
        return _ok_prefetch(url, algo)

    stats = auto_prefetch_for_entry(
        entry, attr_path="foo", nixpkgs_root=nixpkgs, prefetch_url_fn=spy,
    )
    assert stats.skipped_reason == "already-populated"
    assert invoked == []
    upstream = json.loads((entry / "upstream-ref.json").read_text())
    # Existing hashes preserved.
    assert upstream["prefetch_hashes"][0]["value"] == "sha256-EXISTING"


def test_no_package_source_resolved_records_skip(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("TRACE_REAL_PREFETCH", "1")
    entry = _seed_entry(tmp_path)
    empty_nixpkgs = tmp_path / "empty"
    empty_nixpkgs.mkdir()
    stats = auto_prefetch_for_entry(
        entry, attr_path="not-found",
        nixpkgs_root=empty_nixpkgs, prefetch_url_fn=_ok_prefetch,
    )
    assert stats.skipped_reason == "no-package-source"
    # Slice 5j: surface the resolver's diagnostic so the cron run summary
    # can distinguish "no by-name + no eval fallback" from a nix-eval
    # timeout, an outside-root rejection, etc. The kernel CVE work hit a
    # silent no-package-source for every entry and we couldn't tell why.
    assert stats.path_resolver_diag == "by-name-miss-no-eval-fallback"


def test_normalize_diag_buckets() -> None:
    """Each PackageSourceNotFound message shape maps to a stable
    bucket key. Counting is what makes the diagnostic actionable —
    raw messages aren't aggregable across entries."""
    from agents.scout.auto_prefetch import _normalize_diag

    cases = {
        "nix eval did not return a meta.position for 'linux': nix-eval-timeout-120s": "nix-eval-timeout",
        "nix eval did not return a meta.position for 'linux': nix-eval-empty-output": "nix-eval-empty-output",
        "nix eval did not return a meta.position for 'linux': nix-eval-exit-2:bad attribute": "nix-eval-exit-nonzero",
        "nix eval did not return a meta.position for 'linux': nix-not-on-path": "nix-not-on-path",
        "nix eval returned PosixPath('/etc/foo') outside nixpkgs root /nix/store/xyz; refusing to read": "outside-nixpkgs-root",
        "nix eval position PosixPath('/nix/store/x/y') is not a file": "eval-position-not-a-file",
        "no package.nix at pkgs/by-name/li/linux/package.nix; pass use_nix_eval=True to fall back to `nix eval` for the long-tail layout": "by-name-miss-no-eval-fallback",
        "namespaced attr_path 'haskellPackages.requests' cannot be resolved without use_nix_eval=True": "namespaced-no-eval-fallback",
        "attr_path 'a' too short for by-name shard": "attr-path-too-short",
        "nixpkgs root does not exist or is not a directory: /missing": "nixpkgs-root-missing",
        "something nobody has seen before": "other",
    }
    for message, expected in cases.items():
        assert _normalize_diag(message) == expected, (
            f"diag {message!r} bucketed as {_normalize_diag(message)!r}, "
            f"expected {expected!r}"
        )


def test_aggregate_stats_buckets_path_resolver_diag() -> None:
    """The aggregator counts diag buckets per kind so the cron summary
    can show 'nix-eval-timeout: 4, by-name-miss-no-eval-fallback: 12'
    and the operator knows which gap to address."""
    stats = [
        AutoPrefetchStats(
            skipped_reason="no-package-source",
            path_resolver_diag="nix-eval-timeout",
        ),
        AutoPrefetchStats(
            skipped_reason="no-package-source",
            path_resolver_diag="nix-eval-timeout",
        ),
        AutoPrefetchStats(
            skipped_reason="no-package-source",
            path_resolver_diag="outside-nixpkgs-root",
        ),
        # An entry with no diagnostic should NOT crash the aggregator.
        AutoPrefetchStats(skipped_reason="no-package-source"),
    ]
    agg = aggregate_stats(stats)
    assert agg["skipped-no-source-resolved"] == 4
    assert agg["path-resolver-diag"] == {
        "nix-eval-timeout": 2,
        "outside-nixpkgs-root": 1,
    }


def test_aggregate_stats_partitions_by_class() -> None:
    """Aggregate must add up across mixed entries."""
    stats = [
        AutoPrefetchStats(
            primary_src_class="plain-fetchurl",
            plain_fetchurl_attempted=1, plain_fetchurl_succeeded=1,
        ),
        AutoPrefetchStats(
            primary_src_class="plain-fetchurl",
            plain_fetchurl_attempted=1, plain_fetchurl_failed=1,
        ),
        AutoPrefetchStats(
            primary_src_class="fetchFromGitHub",
            fetchFromGitHub_present_but_skipped=1,
        ),
        AutoPrefetchStats(
            primary_src_class="fetchzip",
            fetchzip_present_but_skipped=1,
        ),
        AutoPrefetchStats(
            primary_src_class="fetchFromGitHub",
            fetchFromGitHub_present_but_skipped=1,
            has_vendor_style_hash=True,
            go_mod_vendor_present_but_skipped=1,
        ),
        AutoPrefetchStats(skipped_reason="env-not-set"),
        AutoPrefetchStats(skipped_reason="no-nixpkgs-root"),
        AutoPrefetchStats(skipped_reason="no-package-source"),
    ]
    # Add a fetchFromGitHub-attempted entry to confirm 5e fields aggregate.
    stats.append(AutoPrefetchStats(
        primary_src_class="fetchFromGitHub",
        fetchFromGitHub_attempted=1, fetchFromGitHub_succeeded=1,
    ))
    agg = aggregate_stats(stats)
    assert agg["plain-fetchurl-attempted"] == 2
    assert agg["plain-fetchurl-succeeded"] == 1
    assert agg["plain-fetchurl-failed"] == 1
    assert agg["fetchFromGitHub-attempted"] == 1
    assert agg["fetchFromGitHub-succeeded"] == 1
    assert agg["fetchFromGitHub-failed"] == 0
    assert agg["fetchFromGitHub-present-but-skipped"] == 2
    assert agg["fetchzip-present-but-skipped"] == 1
    assert agg["go-mod-vendor-present-but-skipped"] == 1
    assert agg["skipped-env-not-set"] == 1
    assert agg["skipped-no-nixpkgs-root"] == 1
    assert agg["skipped-no-source-resolved"] == 1


def test_atomic_write_does_not_leak_temps(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("TRACE_REAL_PREFETCH", "1")
    src = '{ fetchurl }: { src = fetchurl { url = "https://example.test/foo-${version}.tar.gz"; }; }'
    entry = _seed_entry(tmp_path)
    nixpkgs = _mk_nixpkgs_with_package(tmp_path / "nixpkgs", contents=src)
    auto_prefetch_for_entry(
        entry, attr_path="foo", nixpkgs_root=nixpkgs, prefetch_url_fn=_ok_prefetch,
    )
    leftovers = [p for p in entry.iterdir() if p.name.startswith("upstream-ref.json.")]
    assert leftovers == []
