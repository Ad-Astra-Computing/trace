"""Pure-function tests for the cross-distro screening study. No network."""
from __future__ import annotations

from scripts import crossdistro_screen as cs


def test_pool_prefix():
    assert cs.pool_prefix("curl") == "c"
    assert cs.pool_prefix("nginx") == "n"
    assert cs.pool_prefix("libwebp") == "libw"
    assert cs.pool_prefix("libc") == "libc"
    assert cs.pool_prefix("lib") == "l"  # degenerate 3-char: falls through, no crash


def test_debian_patch_url_matches_known_good():
    # The URL the July pilot recorded for nginx CVE-2021-23017.
    url = cs.debian_patch_url("nginx", "1.14.2-2+deb10u4", "CVE-2021-23017")
    assert url == (
        "https://sources.debian.org/data/main/n/nginx/"
        "1.14.2-2+deb10u4/debian/patches/CVE-2021-23017.patch"
    )


def test_resolve_upstream_github_gitlab_and_none():
    assert cs.resolve_upstream(
        "see github.com/nginx/nginx/commit/7199ebc203f74fd9e44595474de6bdc41740c5cf"
    ) == "https://github.com/nginx/nginx/commit/7199ebc203f74fd9e44595474de6bdc41740c5cf.patch"
    assert cs.resolve_upstream(
        "Origin: gitlab.com/foo/bar/-/commit/abcdef1234567890abcdef1234567890abcdef12"
    ) == "https://gitlab.com/foo/bar/-/commit/abcdef1234567890abcdef1234567890abcdef12.patch"
    assert cs.resolve_upstream("no ref, just prose") is None


def test_build_census_picks_security_suite_versions():
    tracker = {
        "curl": {
            "CVE-2020-1111": {
                "releases": {
                    "bullseye": {
                        "status": "resolved",
                        "repositories": {
                            "bullseye": "7.74.0-1",
                            "bullseye-security": "7.74.0-1+deb11u2",
                        },
                    }
                }
            },
            "CVE-2019-2222": {  # open, no security version → excluded
                "releases": {"bookworm": {"status": "open", "repositories": {}}}
            },
        },
        "notadict": "ignored",
    }
    census = cs.build_census(tracker)
    assert census == [
        {"package": "curl", "cve": "CVE-2020-1111", "version": "7.74.0-1+deb11u2"}
    ]


def test_wilson_ci_bounds():
    lo, hi = cs.wilson_ci(8, 41)
    assert 0.0 <= lo < 8 / 41 < hi <= 1.0
    assert cs.wilson_ci(0, 0) == (0.0, 0.0)


def test_host_allowlist_gate(monkeypatch):
    # A non-allowlisted host is refused before any network call.
    assert cs.fetch("https://evil.example.com/x.patch") is None
