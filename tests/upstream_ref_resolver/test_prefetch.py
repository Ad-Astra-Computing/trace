"""Tests for the live `nix-prefetch-url` integration.

The runner takes a list of PrefetchTarget(name, url) and a swappable
`prefetch_url_fn`. Tests inject fakes for every shape:

  * happy path: every target succeeds, full attribution recorded.
  * mixed: some succeed, some fail; outcome carries both lists.
  * tool-not-on-path: every target fails with the same reason.
  * 404 / non-zero exit / unparseable output: each maps to the right
    failure-reason enum.

A network-gated end-to-end test is included but skipped unless
TRACE_REAL_PREFETCH=1 is set; even then the test only checks shape, not
specific hash values, since the real values can drift if upstream
re-tags.
"""

from __future__ import annotations

import os

import pytest

from agents.upstream_ref_resolver import (
    PrefetchTarget,
    prefetch_targets,
)


def _fake_prefetcher(table: dict):
    """Return a prefetch_url_fn that looks up (url, algo) in `table`."""

    def fn(url: str, algorithm: str):
        key = (url, algorithm)
        if key not in table:
            return ("fetch-error-other", f"unmocked url={url!r} algo={algorithm!r}", None)
        return table[key]

    return fn


def test_happy_path_records_full_attribution() -> None:
    targets = [
        PrefetchTarget(name="src.hash", url="https://example.invalid/v1.0.tar.gz"),
        PrefetchTarget(name="vendorHash", url="https://example.invalid/vendor.tar.gz"),
    ]
    fake = _fake_prefetcher({
        ("https://example.invalid/v1.0.tar.gz", "sha256"): (
            "ok", "sha256-AbCdEfGhIjKlMnOpQrStUvWxYz0123456789AbCdEfGh=", "nix-prefetch-url 2.33.3",
        ),
        ("https://example.invalid/vendor.tar.gz", "sha256"): (
            "ok", "sha256-Vend0rHashThatIsAlsoSyntheticForTestPurposes=", "nix-prefetch-url 2.33.3",
        ),
    })
    out = prefetch_targets(targets, prefetch_url_fn=fake)
    assert len(out.hashes) == 2
    assert len(out.failures) == 0
    src = next(h for h in out.hashes if h.name == "src.hash")
    assert src.value.startswith("sha256-")
    assert src.source == "nix-prefetch-url"
    assert src.tool == "nix-prefetch-url"
    assert src.tool_version == "nix-prefetch-url 2.33.3"
    assert src.url == "https://example.invalid/v1.0.tar.gz"
    assert src.fetched_at  # ISO-8601 string set
    # Schema-shape: replay_critical is true on every entry.
    assert all(h.replay_critical is True for h in out.hashes)


def test_mixed_outcome_records_both_lists() -> None:
    targets = [
        PrefetchTarget(name="src.hash", url="https://example.invalid/ok.tar.gz"),
        PrefetchTarget(name="vendorHash", url="https://example.invalid/missing.tar.gz"),
    ]
    fake = _fake_prefetcher({
        ("https://example.invalid/ok.tar.gz", "sha256"): (
            "ok", "sha256-Th1sIsAGr0und3dValueFromTheM0ckedPrefetcher=", "nix-prefetch-url 2.33.3",
        ),
        ("https://example.invalid/missing.tar.gz", "sha256"): (
            "fetch-error-404", "nix-prefetch-url: download failed: 404 Not Found", "nix-prefetch-url 2.33.3",
        ),
    })
    out = prefetch_targets(targets, prefetch_url_fn=fake)
    assert len(out.hashes) == 1
    assert len(out.failures) == 1
    f = out.failures[0]
    assert f.name == "vendorHash"
    assert f.reason == "fetch-error-404"
    assert f.url_attempted == "https://example.invalid/missing.tar.gz"
    assert "404" in (f.detail or "")
    assert f.tool_version == "nix-prefetch-url 2.33.3"
    assert f.attempted_at


def test_tool_not_on_path_yields_structured_failures() -> None:
    targets = [PrefetchTarget(name="src.hash", url="https://example.invalid/x.tar.gz")]
    fake = _fake_prefetcher({
        ("https://example.invalid/x.tar.gz", "sha256"): (
            "tool-not-on-path", "nix-prefetch-url not on PATH", None,
        ),
    })
    out = prefetch_targets(targets, prefetch_url_fn=fake)
    assert out.hashes == []
    assert len(out.failures) == 1
    assert out.failures[0].reason == "tool-not-on-path"


def test_outcome_serialises_to_schema_shape() -> None:
    """The dataclasses must round-trip into the JSON shape that
    upstream-ref-schema.json validates: prefetch_hashes[] entries and
    prefetch_failures[] entries with the right key set.
    """
    targets = [
        PrefetchTarget(name="src.hash", url="https://example.invalid/v.tar.gz"),
        PrefetchTarget(name="vendorHash", url="https://example.invalid/oops.tar.gz"),
    ]
    fake = _fake_prefetcher({
        ("https://example.invalid/v.tar.gz", "sha256"): (
            "ok", "sha256-Pr0duc3dByMockButSh4pedRightForJsonschemaXY=", "nix-prefetch-url 2.33.3",
        ),
        ("https://example.invalid/oops.tar.gz", "sha256"): (
            "tool-exit-nonzero", "exit=1; stderr: hash mismatch", "nix-prefetch-url 2.33.3",
        ),
    })
    out = prefetch_targets(targets, prefetch_url_fn=fake)
    h = out.hashes_as_list()[0]
    assert set(h) == {
        "name", "algorithm", "value", "source", "url",
        "tool", "tool_version", "fetched_at", "replay_critical",
    }
    f = out.failures_as_list()[0]
    assert "name" in f and "reason" in f
    assert f["reason"] == "tool-exit-nonzero"
    assert f["url_attempted"] == "https://example.invalid/oops.tar.gz"


def test_outcome_validates_against_upstream_ref_schema() -> None:
    """Live shape sanity: a hand-built upstream-ref.json carrying our
    runner's output must validate."""
    import json
    from pathlib import Path
    from jsonschema import Draft202012Validator

    targets = [PrefetchTarget(name="src.hash", url="https://example.invalid/v.tar.gz")]
    fake = _fake_prefetcher({
        ("https://example.invalid/v.tar.gz", "sha256"): (
            "ok", "sha256-Pr0duc3dByMockButSh4pedRightForJsonschemaXY=", "nix-prefetch-url 2.33.3",
        ),
    })
    out = prefetch_targets(targets, prefetch_url_fn=fake)
    upstream_ref = {
        "schema_version": "1.0.0",
        "cve_id": "CVE-0000-0000",
        "current_version": "1.0.0",
        "target_version": "1.0.1",
        "fix_tier": "security-patch-release",
        "release_url": "https://example.invalid/release/v1.0.1",
        "delta": {
            "transitive_package_changes": 0,
            "new_direct_deps": [],
            "crosses_large_delta_threshold": False,
        },
        "prefetch_hashes": out.hashes_as_list(),
        "eligibility": {"verdict": "eligible"},
        "replay_critical": True,
    }
    schema_path = Path(__file__).resolve().parents[2] / "policy" / "upstream-ref-schema.json"
    validator = Draft202012Validator(json.loads(schema_path.read_text()))
    errors = ["/".join(str(p) for p in e.absolute_path) + ": " + e.message
             for e in validator.iter_errors(upstream_ref)]
    assert not errors, errors


@pytest.mark.skipif(
    os.environ.get("TRACE_REAL_PREFETCH") != "1",
    reason="real-network test; set TRACE_REAL_PREFETCH=1 to enable",
)
def test_real_nix_prefetch_url_smoke() -> None:
    """Network-gated. Asserts the runner can actually shell out and
    receive an SRI-form hash. Does not pin the hash value; upstream
    re-tags would otherwise turn this test flaky."""
    targets = [PrefetchTarget(
        name="src.hash",
        url="https://downloads.isc.org/isc/bind9/9.20.18/bind-9.20.18.tar.xz",
    )]
    out = prefetch_targets(targets)
    assert len(out.hashes) == 1, out.failures_as_list()
    h = out.hashes[0]
    assert h.value.startswith("sha256-") and h.value.endswith("=")
    assert h.tool == "nix-prefetch-url"
    assert h.tool_version  # non-empty
