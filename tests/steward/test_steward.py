"""OPA-driven Steward tests.

Runs `policy/steward.rego` against each fixture under traces/example/* that is
schema-valid (per tests/schema/test_fixtures.py). Expectations are read from
expect.json:

- steward_expected absent, or == "valid": OPA must return allow=true, deny set empty.
- steward_expected == "invalid": OPA must return allow=false, and the deny set
  must contain at least one decision with rule_id starting with the expected
  steward_rule_id prefix.

Schema-invalid fixtures (expect.overall == "invalid") are skipped here; they
already fail at the schema layer and never reach Steward.
"""

from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path

import pytest


REPO_ROOT = Path(__file__).resolve().parents[2]
POLICY_FILE = REPO_ROOT / "policy" / "steward.rego"
FIXTURE_ROOT = REPO_ROOT / "traces" / "example"


def _is_authoring_supplement(fixture_dir: Path) -> bool:
    """An authoring-supplement dir holds an Authoring-LoRA training example, not a
    trace evidence bundle: it carries `authoring-example.json` but has NEITHER a
    `bundle.json` NOR an `expect.json`, so the Steward contract does not reach it.
    Mirrors tests/schema/test_fixtures.py so both enumerations exempt the same dirs.
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


def _build_opa_input(fixture_dir: Path) -> dict:
    """Assemble the canonical Steward opa input doc per docs/STEWARD_V1.md §1.

    Loads bundle / finding / upstream_ref / replay / provenance plus the
    v1 additions (build / repro_scoring / review_scoring). Optional fields
    are OMITTED when their backing file is absent (rather than set to
    None); Rego treats `input.foo == null` as defined-as-null and
    `not input.foo` as false on null, but as true on absent. The rules
    use `not input.build` semantics, so we omit-on-absent to match.
    """
    def _load_json(name: str) -> dict | None:
        p = fixture_dir / name
        return json.loads(p.read_text()) if p.exists() else None

    provenance: list[dict] = []
    prov_path = fixture_dir / "provenance.jsonl"
    if prov_path.exists():
        for line in prov_path.read_text().splitlines():
            line = line.strip()
            if line:
                provenance.append(json.loads(line))

    inputs: dict = {
        "bundle": _load_json("bundle.json"),
        "finding": _load_json("finding.json"),
        "upstream_ref": _load_json("upstream-ref.json"),
        "replay": _load_json("replay.json"),
        "provenance": provenance,
    }
    for opt_field, opt_filename in (
        ("build", "build.json"),
        ("repro_scoring", "repro-scoring-report.json"),
        ("review_scoring", "review-scoring-report.json"),
        ("reproducer_refusal", "reproducer-refusal.json"),
    ):
        loaded = _load_json(opt_filename)
        if loaded is not None:
            inputs[opt_field] = loaded
    return inputs


def _run_opa(fixture_input: dict) -> dict:
    proc = subprocess.run(
        [
            "opa",
            "eval",
            "--format=json",
            "--data", str(POLICY_FILE),
            "--stdin-input",
            "data.trace.steward",
        ],
        input=json.dumps(fixture_input),
        capture_output=True,
        text=True,
        check=True,
    )
    result = json.loads(proc.stdout)
    # opa eval shape: { "result": [ { "expressions": [ { "value": <decision> } ] } ] }
    return result["result"][0]["expressions"][0]["value"]


@pytest.fixture(scope="session")
def opa_available():
    try:
        subprocess.run(["opa", "version"], check=True, capture_output=True)
    except (FileNotFoundError, subprocess.CalledProcessError) as exc:
        message = (
            "opa binary not available on PATH. Install via "
            "`nix profile install nixpkgs#open-policy-agent` "
            "or provide opa explicitly in CI."
        )
        if os.environ.get("TRACE_REQUIRE_OPA") == "1":
            pytest.fail(f"TRACE_REQUIRE_OPA=1 but {message} ({exc})")
        pytest.skip(message)
    return True


@pytest.mark.parametrize(
    "fixture_dir",
    _fixture_dirs(),
    ids=lambda p: p.name,
)
def test_steward_decision(fixture_dir, opa_available):
    expect_path = fixture_dir / "expect.json"
    assert expect_path.exists(), f"{fixture_dir.name} missing expect.json"
    expect = json.loads(expect_path.read_text())

    if expect.get("overall") == "invalid":
        pytest.skip(f"{fixture_dir.name} is schema-invalid; Steward is not reached")

    decision = _run_opa(_build_opa_input(fixture_dir))
    allow = decision.get("allow", False)
    deny = decision.get("deny", [])

    steward_expected = expect.get("steward_expected", "valid")

    # steward_expected is a strict three-value contract describing the OPA outcome:
    #   "valid" / absent  -> Steward must allow (deny set empty).
    #   "invalid"         -> Steward must deny; steward_rule_id names the rule.
    #   "escalate"        -> human-review-required bundle: the auto-merge deny rules
    #                        (all gated on bundle.kind=="auto-merge") do not apply,
    #                        so it passes the gate (allow) and is routed to human
    #                        review by policy/route (tests/steward/test_route.py).
    # Reviewer acceptance / authoring tier are separate contracts recorded in other
    # expect.json fields; steward_expected describes ONLY the allow/deny outcome.
    assert steward_expected in ("valid", "invalid", "escalate"), (
        f"{fixture_dir.name}: steward_expected must be valid|invalid|escalate, "
        f"got {steward_expected!r}"
    )

    if steward_expected == "escalate":
        bundle_kind = json.loads((fixture_dir / "bundle.json").read_text()).get("kind")
        assert bundle_kind == "human-review-required", (
            f"{fixture_dir.name}: steward_expected=escalate requires "
            f"bundle.kind=human-review-required, got {bundle_kind!r}"
        )

    if steward_expected in ("valid", "escalate"):
        assert allow is True, (
            f"{fixture_dir.name}: expected Steward allow but got deny. "
            f"Deny set: {deny}"
        )
        assert deny == [], (
            f"{fixture_dir.name}: expected empty deny set but got: {deny}"
        )
    else:
        assert allow is False, (
            f"{fixture_dir.name}: expected Steward deny but policy allowed"
        )
        expected_rule_id = expect.get("steward_rule_id")
        assert expected_rule_id, (
            f"{fixture_dir.name}: expect.json is missing steward_rule_id"
        )
        matched = [d for d in deny if d.get("rule_id") == expected_rule_id]
        assert matched, (
            f"{fixture_dir.name}: expected a deny with rule_id={expected_rule_id} "
            f"but got: {deny}"
        )
