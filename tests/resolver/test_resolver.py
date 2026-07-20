"""UpstreamRefResolver tests.

Table-driven. Every fixture is a pair of files:

  tests/resolver/fixtures/<name>/input.json
  tests/resolver/fixtures/<name>/expected-upstream-ref.json

For each fixture the runner asserts two things:

  1. resolver.resolve(input) equals expected exactly (deep dict equality).
     Order-independent because we compare dicts; key presence/absence is
     load-bearing.

  2. The resolver output validates against policy/upstream-ref-schema.json.
     Belt-and-braces: the stub could pass case (1) and still emit a document
     that the real Steward layer would reject.

No network. No upstream parsing. The stub is intentionally dumb; these tests
nail down the contract it must satisfy.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator

from agents.upstream_ref_resolver import resolve
from tests.schema.validate import load_schemas, validators


FIXTURES = Path(__file__).parent / "fixtures"


def _fixture_dirs() -> list[Path]:
    return sorted(p for p in FIXTURES.iterdir() if p.is_dir())


@pytest.fixture(scope="session")
def upstream_ref_validator() -> Draft202012Validator:
    schemas = load_schemas()
    return validators(schemas)["upstream_ref"]


@pytest.mark.parametrize("fixture_dir", _fixture_dirs(), ids=lambda p: p.name)
def test_resolver_exact_output(fixture_dir, upstream_ref_validator):
    input_doc = json.loads((fixture_dir / "input.json").read_text())
    expected = json.loads((fixture_dir / "expected-upstream-ref.json").read_text())

    output = resolve(input_doc)

    assert output == expected, (
        f"{fixture_dir.name}: resolver output differs from expected.\n"
        f"  expected keys: {sorted(expected.keys())}\n"
        f"  got keys:      {sorted(output.keys())}"
    )

    errors = [
        f"{'/'.join(str(p) for p in e.absolute_path)}: {e.message}"
        for e in upstream_ref_validator.iter_errors(output)
    ]
    assert not errors, (
        f"{fixture_dir.name}: resolver output violates upstream-ref-schema.json: {errors}"
    )


def test_resolver_covers_every_verdict_enum_relevant_to_v0(upstream_ref_validator):
    """Sanity: fixtures collectively exercise every verdict value the v0 resolver can emit."""
    verdicts_seen = set()
    triggers_seen = set()
    for fixture_dir in _fixture_dirs():
        expected = json.loads((fixture_dir / "expected-upstream-ref.json").read_text())
        verdicts_seen.add(expected["eligibility"]["verdict"])
        t = expected["eligibility"].get("human_review_trigger")
        if t:
            triggers_seen.add(t)

    assert verdicts_seen >= {
        "eligible",
        "eligible-requires-human-review",
        "ineligible-no-fix-available",
    }, f"missing verdict coverage: {verdicts_seen}"

    assert triggers_seen == {
        "major-version-jump",
        "ambiguous-changelog",
        "large-sbom-delta",
        "ambiguous-fixed-version",
        "no-target-version-derived",
        "placeholder-target-version",
        "pre-release-target",
        # added 2026-06-11: resolver now emits the source-backport contract
        # (fixture 11-source-backport) from an explicit harvest signal.
        "source-backport-experimental",
        # added 2026-07-20: current or target version not semver-shaped (nixpkgs
        # git-snapshot / unstable pin); ordering unknowable so never auto-merge.
        "unparseable-version-comparison",
    }, f"missing human_review_trigger coverage: {triggers_seen}"


def test_unstable_pin_routes_to_human_review_not_crash():
    """A nixpkgs git-snapshot / unstable current version (e.g. '0-unstable-DATE')
    is not semver-shaped. The resolver must NOT crash (it did — a ValueError from
    _parse_semver blew up a whole screen run) and must NOT auto-merge; it routes to
    human review because upgrade ordering cannot be established."""
    from agents.upstream_ref_resolver import resolve

    out = resolve({
        "cve_id": "CVE-0000-2100",
        "current_version": "0-unstable-2026-01-30",
        "candidate_refs": [{
            "version": "1.2.3",
            "release_url": "https://ex.invalid/r/1.2.3",
            "changelog_url": "https://ex.invalid/c#1.2.3",
            "advisory_urls": ["https://ex.invalid/a"],
            "delta": {"transitive_package_changes": 0, "new_direct_deps": [], "removed_direct_deps": [],
                      "crosses_large_delta_threshold": False, "threshold_policy": "v0-default"},
            "tier_hint": "point-release-small-delta",
        }],
    })
    el = out["eligibility"]
    assert el["verdict"] == "eligible-requires-human-review"
    assert el["human_review_trigger"] == "unparseable-version-comparison"
    assert "current_version is" in el["verdict_reason"]


def test_unstable_target_does_not_auto_merge():
    """An unstable/git-snapshot TARGET does not match the pre-release regex, so
    without the ordering guard it would fall through to auto-merge `eligible`.
    The guard must dominate and route to human review."""
    from agents.upstream_ref_resolver import resolve

    out = resolve({
        "cve_id": "CVE-0000-2101",
        "current_version": "1.2.3",
        "candidate_refs": [{
            "version": "0-unstable-2026-02-01",
            "release_url": "https://ex.invalid/r/unstable",
            "changelog_url": "https://ex.invalid/c#unstable",
            "advisory_urls": ["https://ex.invalid/a"],
            "delta": {"transitive_package_changes": 0, "new_direct_deps": [], "removed_direct_deps": [],
                      "crosses_large_delta_threshold": False, "threshold_policy": "v0-default"},
            "tier_hint": "point-release-small-delta",
        }],
    })
    el = out["eligibility"]
    assert el["verdict"] == "eligible-requires-human-review"
    assert el["human_review_trigger"] == "unparseable-version-comparison"
    assert "target_version is" in el["verdict_reason"]


def test_parseable_upgrade_wins_over_unstable_pin():
    """When candidates mix a real semver upgrade with an unstable-pin target and
    current is semver, the resolver picks the real upgrade and auto-merges — the
    unparseable candidate must not shadow a genuine fixed release."""
    from agents.upstream_ref_resolver import resolve

    out = resolve({
        "cve_id": "CVE-0000-2102",
        "current_version": "1.2.3",
        "candidate_refs": [
            {"version": "0-unstable-2026-02-01",
             "release_url": "https://ex.invalid/r/unstable",
             "changelog_url": "https://ex.invalid/c#unstable",
             "advisory_urls": ["https://ex.invalid/a"],
             "delta": {"transitive_package_changes": 0, "new_direct_deps": [], "removed_direct_deps": [],
                       "crosses_large_delta_threshold": False, "threshold_policy": "v0-default"},
             "tier_hint": "point-release-small-delta"},
            {"version": "1.2.4",
             "release_url": "https://ex.invalid/r/1.2.4",
             "changelog_url": "https://ex.invalid/c#1.2.4",
             "advisory_urls": ["https://ex.invalid/a"],
             "delta": {"transitive_package_changes": 0, "new_direct_deps": [], "removed_direct_deps": [],
                       "crosses_large_delta_threshold": False, "threshold_policy": "v0-default"},
             "tier_hint": "point-release-small-delta"},
        ],
    })
    assert out["eligibility"]["verdict"] == "eligible"
    assert out["target_version"] == "1.2.4"


def test_unparseable_candidate_beats_equal_version_placeholder():
    """An equal-version placeholder (target == current -> no-op, routes to
    no-target-version-derived) must NOT shadow a real unstable-pin candidate.
    Equality is a last-resort fallback, ranked BELOW unknowable ordering
    (codex review 2026-07-20). The real fix candidate wins even at lower
    caller priority, and the verdict reflects it (unparseable, not no-target)."""
    from agents.upstream_ref_resolver import resolve

    out = resolve({
        "cve_id": "CVE-0000-2103",
        "current_version": "1.2.3",
        "candidate_refs": [
            {"version": "1.2.3",  # equal-version placeholder, listed FIRST
             "release_url": "https://ex.invalid/r/1.2.3",
             "delta": {"transitive_package_changes": 0, "new_direct_deps": [], "removed_direct_deps": [],
                       "crosses_large_delta_threshold": False, "threshold_policy": "v0-default"}},
            {"version": "0-unstable-2026-02-01",  # real unstable-pin fix, listed second
             "release_url": "https://ex.invalid/r/unstable",
             "changelog_url": "https://ex.invalid/c#unstable",
             "advisory_urls": ["https://ex.invalid/a"],
             "delta": {"transitive_package_changes": 0, "new_direct_deps": [], "removed_direct_deps": [],
                       "crosses_large_delta_threshold": False, "threshold_policy": "v0-default"}},
        ],
    })
    el = out["eligibility"]
    assert out["target_version"] == "0-unstable-2026-02-01"
    assert el["human_review_trigger"] == "unparseable-version-comparison"


def test_source_backport_signal_precedence():
    """patch_strategy is authoritative; tier_hint is the lighter hint (peer 2026-06-11)."""
    from agents.upstream_ref_resolver.resolver import _is_source_backport_signal
    # explicit patch_strategy wins, even against a contradicting tier_hint
    assert _is_source_backport_signal(
        {"eligibility": {"patch_strategy": "source-backport"}, "tier_hint": "point-release-small-delta"}
    ) is True
    assert _is_source_backport_signal(
        {"eligibility": {"patch_strategy": "version-bump"}, "tier_hint": "source-backport"}
    ) is False
    # tier_hint consulted only when patch_strategy absent
    assert _is_source_backport_signal({"tier_hint": "source-backport"}) is True
    assert _is_source_backport_signal({"tier_hint": "point-release-small-delta"}) is False
    assert _is_source_backport_signal({}) is False


def test_source_backport_carries_through_review_reason():
    """When a Scout-tagged backport candidate also carries the 'no fixed release
    derivable' fact (requires_review_reason), the source-backport verdict must
    SURFACE it (peer 2026-06-11): a clean-applying backport may still be
    necessary-but-not-sufficient, so the human must confirm sufficiency."""
    from agents.upstream_ref_resolver import resolve
    out = resolve({
        "cve_id": "CVE-0000-2099", "current_version": "1.0.8",
        "candidate_refs": [{
            "version": "1.0.8", "release_url": "https://ex.invalid/c/deadbeef",
            "upstream_fix_commits": [{"repo_url": "https://ex.invalid/r", "commit_sha": "deadbeef"}],
            "delta": {"transitive_package_changes": 0, "new_direct_deps": [], "removed_direct_deps": [],
                      "crosses_large_delta_threshold": False, "threshold_policy": "v0-default"},
            "tier_hint": "source-backport",
            "requires_review_reason": "placeholder-target-version",
        }],
    })
    el = out["eligibility"]
    assert el["verdict"] == "eligible-requires-human-review"
    assert el["patch_strategy"] == "source-backport"
    assert el["human_review_trigger"] == "source-backport-experimental"
    # the no-fixed-release fact survives, not erased
    assert "placeholder-target-version" in el["verdict_reason"]
    assert "COMPLETE fix" in el["verdict_reason"]
