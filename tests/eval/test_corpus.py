"""eval/corpus.json tests.

Two layers, as requested:

1. Shape layer (always runs):
   * eval-corpus-schema.json is well-formed Draft 2020-12
   * eval/corpus.json validates against the schema
   * every entry.axes.<axis> value belongs to the declared axis enum at the
     file's top-level .axes (cross-check so a typo in an axis value is caught
     even though the schema types axis fields as generic strings)

2. Composition layer (frozen corpus rules; only fires under one of):
   * eval/corpus.json .status == "frozen"
   * env var TRACE_REQUIRE_FULL_CORPUS=1 is set

   Composition rules per SPEC §5a and the build-container brief:
   (a) len(entries) >= required_size (50)
   (b) no duplicate cve_id
   (c) every axis value declared in .axes appears on at least one entry
       (so the axis declaration is load-bearing, not decorative)
   (d) for each axis, each NON-TRIVIAL bucket value has >= 3 entries
   (e) >= 10 entries with expected_v0_eligibility != "auto-merge-eligible"
       (i.e. entries that should exercise the ineligibility path)
   (f) every real (non-example) entry has historical_fix populated
"""

from __future__ import annotations

import json
import os
from collections import Counter
from pathlib import Path
from typing import Any

import pytest
from jsonschema import Draft202012Validator

from tests.schema.validate import REPO_ROOT


CORPUS_PATH = REPO_ROOT / "eval" / "corpus.json"
SCHEMA_PATH = REPO_ROOT / "policy" / "eval-corpus-schema.json"


NON_TRIVIAL_BUCKETS: dict[str, set[str]] = {
    "mapping_difficulty": {"medium", "ambiguous"},
    "version_bump_complexity": {"point-release", "multi-release", "major-jump"},
    "passthru_tests": {"minimal", "none"},
    "reproducibility": {
        "config-sensitive",
        "DoS-shaped",
        "crypto-shaped",
        "parser-heavy",
        "kernel-adjacent",
        "impractical",
    },
    "rebuild_closure_size": {"50-500", "500-5000", ">5000"},
    "human_decision_difficulty": {"routine", "contentious"},
}


@pytest.fixture(scope="module")
def schema() -> dict[str, Any]:
    return json.loads(SCHEMA_PATH.read_text())


@pytest.fixture(scope="module")
def corpus() -> dict[str, Any]:
    return json.loads(CORPUS_PATH.read_text())


@pytest.fixture(scope="module")
def frozen_required() -> bool:
    """The composition layer runs when status is frozen OR the env var is set."""
    try:
        status = json.loads(CORPUS_PATH.read_text()).get("status")
    except Exception:
        status = None
    return status == "frozen" or os.environ.get("TRACE_REQUIRE_FULL_CORPUS") == "1"


# ─── shape layer ─────────────────────────────────────────────────────────────


def test_corpus_schema_is_well_formed(schema):
    Draft202012Validator.check_schema(schema)


def test_corpus_validates_against_schema(schema, corpus):
    errors = [
        f"{'/'.join(str(p) for p in e.absolute_path)}: {e.message}"
        for e in Draft202012Validator(schema).iter_errors(corpus)
    ]
    assert not errors, f"corpus.json failed schema validation: {errors}"


def test_entry_axis_values_belong_to_declared_enums(corpus):
    declared = corpus["axes"]
    for entry in corpus["entries"]:
        for axis, value in entry["axes"].items():
            assert value in declared[axis], (
                f"{entry['cve_id']}: axes.{axis}={value!r} is not in "
                f"declared axes.{axis} enum {declared[axis]}"
            )


# ─── composition layer ──────────────────────────────────────────────────────


def test_composition__size(corpus, frozen_required):
    if not frozen_required:
        pytest.skip("corpus not frozen and TRACE_REQUIRE_FULL_CORPUS not set")
    # Example entries do not count toward required_size.
    real_entries = [e for e in corpus["entries"] if not e.get("is_example")]
    assert len(real_entries) >= corpus["required_size"], (
        f"frozen corpus must have >= {corpus['required_size']} non-example "
        f"entries; got {len(real_entries)}"
    )


def test_composition__no_duplicate_cve_ids(corpus, frozen_required):
    if not frozen_required:
        pytest.skip("corpus not frozen and TRACE_REQUIRE_FULL_CORPUS not set")
    cve_ids = [e["cve_id"] for e in corpus["entries"]]
    dupes = [c for c, n in Counter(cve_ids).items() if n > 1]
    assert not dupes, f"duplicate cve_ids: {dupes}"


def test_composition__every_declared_axis_value_is_used(corpus, frozen_required):
    if not frozen_required:
        pytest.skip("corpus not frozen and TRACE_REQUIRE_FULL_CORPUS not set")
    real_entries = [e for e in corpus["entries"] if not e.get("is_example")]
    for axis, declared_values in corpus["axes"].items():
        used = {e["axes"][axis] for e in real_entries}
        missing = set(declared_values) - used
        assert not missing, (
            f"axis {axis}: declared values {sorted(missing)} are not used by "
            f"any non-example entry"
        )


def test_composition__min_three_per_non_trivial_bucket(corpus, frozen_required):
    if not frozen_required:
        pytest.skip("corpus not frozen and TRACE_REQUIRE_FULL_CORPUS not set")
    real_entries = [e for e in corpus["entries"] if not e.get("is_example")]
    violations: list[str] = []
    for axis, non_trivial in NON_TRIVIAL_BUCKETS.items():
        counts = Counter(e["axes"][axis] for e in real_entries)
        for bucket in non_trivial:
            if counts.get(bucket, 0) < 3:
                violations.append(
                    f"{axis}.{bucket}: {counts.get(bucket, 0)} (<3 required)"
                )
    assert not violations, "non-trivial bucket minima violated:\n  " + "\n  ".join(
        violations
    )


def test_composition__at_least_10_ineligibility_entries(corpus, frozen_required):
    if not frozen_required:
        pytest.skip("corpus not frozen and TRACE_REQUIRE_FULL_CORPUS not set")
    real_entries = [e for e in corpus["entries"] if not e.get("is_example")]
    ineligible = [
        e for e in real_entries if e["expected_v0_eligibility"] != "auto-merge-eligible"
    ]
    assert len(ineligible) >= 10, (
        f"corpus must include >= 10 entries expected to fail v0 "
        f"eligibility gates; got {len(ineligible)}"
    )


def test_composition__real_entries_have_historical_fix(corpus, frozen_required):
    if not frozen_required:
        pytest.skip("corpus not frozen and TRACE_REQUIRE_FULL_CORPUS not set")
    missing: list[str] = []
    for e in corpus["entries"]:
        if e.get("is_example"):
            continue
        if not e.get("historical_fix"):
            missing.append(e["cve_id"])
    assert not missing, f"real (non-example) entries missing historical_fix: {missing}"
