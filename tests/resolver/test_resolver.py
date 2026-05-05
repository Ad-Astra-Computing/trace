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
    }, f"missing human_review_trigger coverage: {triggers_seen}"
