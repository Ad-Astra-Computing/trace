"""Validate every fixture under traces/example/* against its expect.json.

Three fixture categories, layered deliberately:

- Positive (`overall: valid`): schema validates cleanly. No per-doc errors.
- Schema-negative (`overall: invalid`): schema MUST reject the document named in `expected_failure.doc`.
- Cross-document / Steward-deferred (`overall: valid`, `steward_expected: invalid`): every individual document is schema-valid, but the bundle violates a cross-document invariant (e.g. replay.json vs provenance.jsonl disagreement) that only `steward.rego` will catch once written. These fixtures intentionally pass this test suite; a separate OPA test suite will later assert they fail Steward.

Boundary rule: JSON Schema tests validate per-document shape. Bundle-semantic / cross-document rules belong in Steward. No bespoke cross-doc checks in this runner.

Hash verification is disabled by default because fixture hashes are placeholders. Set TRACE_STRICT_HASHES=1 to enable strict mode.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from tests.schema.validate import REPO_ROOT, FixtureResult, validate_fixture


FIXTURE_ROOT = REPO_ROOT / "traces" / "example"


def _is_authoring_supplement(fixture_dir: Path) -> bool:
    """An authoring-supplement dir holds an Authoring-LoRA training example, not a
    trace evidence bundle: it carries `authoring-example.json` but has NEITHER a
    `bundle.json` NOR an `expect.json`. Such dirs are validated by
    tests/schema/test_authoring_examples.py, not by the bundle expect.json contract.

    The exemption keys on the ABSENCE of BOTH bundle markers deliberately, so nothing
    the bundle contract already covers can be silenced: a full bundle has bundle.json,
    a behavioral / reviewer-attested fixture has expect.json, and many real bundles
    ALSO ship an authoring-example.json — so requiring the absence of both markers is
    what isolates the thin training-only supplements. A dir with neither marker AND no
    authoring-example.json stays in the enumeration and fails loudly for a missing
    expect.json rather than being silently skipped.
    """
    return (
        (fixture_dir / "authoring-example.json").exists()
        and not (fixture_dir / "bundle.json").exists()
        and not (fixture_dir / "expect.json").exists()
    )


def _fixture_dirs() -> list[Path]:
    return sorted(
        p
        for p in FIXTURE_ROOT.iterdir()
        if p.is_dir() and not _is_authoring_supplement(p)
    )


@pytest.mark.parametrize("fixture_dir", _fixture_dirs(), ids=lambda p: p.name)
def test_fixture_matches_expectation(fixture_dir, schemas, strict_hashes):
    expect_path = fixture_dir / "expect.json"
    assert expect_path.exists(), f"fixture {fixture_dir.name} is missing expect.json"
    expect = json.loads(expect_path.read_text())
    expected = expect.get("overall")
    assert expected in {"valid", "invalid"}, (
        f"expect.json overall must be valid|invalid"
    )

    result: FixtureResult = validate_fixture(
        fixture_dir, schemas=schemas, strict_hashes=strict_hashes
    )

    if expected == "valid":
        assert not result.any_errors, (
            f"fixture {fixture_dir.name} expected valid but produced errors:\n"
            f"  per_doc_errors={result.per_doc_errors}\n"
            f"  hash_errors={result.hash_errors}"
        )
    else:
        target_doc = expect.get("expected_failure", {}).get("doc")
        assert target_doc, (
            f"fixture {fixture_dir.name} is marked invalid but expect.json "
            f"lacks expected_failure.doc"
        )
        errors_in_target = result.per_doc_errors.get(target_doc, [])
        assert errors_in_target, (
            f"fixture {fixture_dir.name} expected failure in {target_doc} "
            f"but that doc validated cleanly. Full errors: {result.per_doc_errors}"
        )


def test_steward_deferred_fixtures_carry_rule():
    """Fixtures marked for deferred Steward-layer failure must each declare a steward_rule.

    This keeps cross-document fixtures discoverable once steward.rego exists: the OPA test harness can simply glob for fixtures where expect.json has `steward_expected == "invalid"`.
    """
    missing: list[str] = []
    found: list[str] = []
    for fixture_dir in _fixture_dirs():
        expect_path = fixture_dir / "expect.json"
        if not expect_path.exists():
            continue
        expect = json.loads(expect_path.read_text())
        if expect.get("steward_expected") == "invalid":
            found.append(fixture_dir.name)
            if not expect.get("steward_rule"):
                missing.append(fixture_dir.name)
    assert not missing, (
        f"fixtures declared steward_expected=invalid without a steward_rule: {missing}"
    )
    # Sanity: at least one such fixture should exist so the OPA suite has targets.
    assert found, "no fixtures marked for deferred Steward-layer failure yet"


@pytest.mark.strict_hashes
def test_strict_hashes_runs_only_under_flag(strict_hashes):
    if not strict_hashes:
        pytest.skip(
            "TRACE_STRICT_HASHES=1 not set; placeholder fixture hashes are tolerated"
        )
    for fixture_dir in _fixture_dirs():
        result = validate_fixture(fixture_dir, strict_hashes=True)
        if result.hash_errors:
            pytest.fail(
                f"{fixture_dir.name} hash mismatches under strict mode:\n"
                + "\n".join(result.hash_errors)
            )
