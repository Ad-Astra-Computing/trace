"""End-to-end replay-writer test for Patcher.

Runs `execute(role="patcher", ..., adapter_factory=Fake)` against the
committed synthetic fixture at
`traces/example/CVE-0000-0010--patcher-fixture-dispatchable/`, then
asserts the canonical recorded execution artifact:

  - patch.diff present + non-empty
  - patch-rationale.md present + non-empty
  - replay.json contains a `patcher` role entry with one invocation
  - the invocation has every replay-shape field the schema requires:
    invocation_id (UUID), role, started_at, ended_at, model{...},
    prompt{path, sha256}, inputs[], outputs[], rng_seed,
    validators_passed, network_policy_applied
  - input sha256s match the actual bytes on disk
  - output sha256s match the bytes Patcher just wrote
  - the recorded entry validates against policy/replay-schema.json

Refusal-shape coverage is in test_execute_wiring.py; this file is
focused on the canonical-recorded-artifact contract.

Each test copies the fixture into tmp_path before running so the
committed fixture stays unmodified. The committed `replay.json`
shows the pre-Patcher state (roles=[]); after a run the test sees
roles[0]={role: patcher, invocations:[...]}.
"""

from __future__ import annotations

import hashlib
import json
import shutil
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator

from agents.patcher import FakeAdapter
from tools.trace_cli.execute import execute
from tests.schema.validate import REPO_ROOT


FIXTURE_SRC = REPO_ROOT / "traces" / "example" / "CVE-0000-0010--patcher-fixture-dispatchable"
REPLAY_SCHEMA_PATH = REPO_ROOT / "policy" / "replay-schema.json"


RATIONALE = """## Upstream reference
Fix lands in v1.4.8 per upstream commit abc1234 at https://example.invalid/libexample.

## Why this version
1.4.8 is the first patch release containing the fix; 1.4.7 does not.

## Why minimal
Only package.nix is touched: version + src.hash bump.

## Alternatives rejected
- Cherry-pick onto 1.4.7: requires maintaining a patch file; no benefit.
- Jump to 2.0.0: pulls in unrelated behaviour changes.

## Downstream risk
impact.json reports reverse_closure_count=42 (<50 bucket); no threshold trigger. Maintainers: alice, bob.
"""


def _patch_response() -> str:
    return (
        "=== BEGIN patch.diff ===\n"
        "--- a/package.nix\n"
        "+++ b/package.nix\n"
        "@@ -5 +5 @@\n"
        "-  version = \"1.4.7\";\n"
        "+  version = \"1.4.8\";\n"
        "=== END patch.diff ===\n"
        "=== BEGIN patch-rationale.md ===\n"
        + RATIONALE
        + "=== END patch-rationale.md ==="
    )


def _factory(text: str):
    def _make(model_id: str) -> FakeAdapter:
        return FakeAdapter(model_id, text)
    return _make


def _copy_fixture(tmp_path: Path) -> Path:
    """Copy the committed fixture into tmp_path; tests mutate the copy only."""
    dst = tmp_path / "bundle"
    shutil.copytree(FIXTURE_SRC, dst)
    return dst


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


# ─── happy path: end-to-end recorded artifact ──────────────────────────────


def test_patcher_run_writes_canonical_replay_artifact(tmp_path):
    bundle_dir = _copy_fixture(tmp_path)

    # Pre-condition: replay.json has no `patcher` role yet (seeded with a
    # single upstream-ref-resolver invocation so roles[] is non-empty per
    # the replay-schema minItems constraint).
    pre_replay = json.loads((bundle_dir / "replay.json").read_text())
    assert all(r["role"] != "patcher" for r in pre_replay["roles"])
    assert not (bundle_dir / "patch.diff").exists()
    assert not (bundle_dir / "patch-rationale.md").exists()

    result = execute(
        role="patcher",
        bundle_dir=bundle_dir,
        invocation={"invocation_id": None, "inputs": [], "outputs": []},
        verify=False,
        model_id="fake-opus-4-7",
        adapter_factory=_factory(_patch_response()),
    )

    # Output files written
    diff_path = bundle_dir / "patch.diff"
    rat_path = bundle_dir / "patch-rationale.md"
    assert diff_path.is_file() and diff_path.stat().st_size > 0
    assert rat_path.is_file() and rat_path.stat().st_size > 0

    # replay.json now contains a patcher role with one invocation
    replay = json.loads((bundle_dir / "replay.json").read_text())
    patcher_roles = [r for r in replay["roles"] if r["role"] == "patcher"]
    assert len(patcher_roles) == 1
    invocations = patcher_roles[0]["invocations"]
    assert len(invocations) == 1
    inv = invocations[0]

    # Required replay-shape fields present
    for field in (
        "invocation_id",
        "role",
        "started_at",
        "ended_at",
        "model",
        "prompt",
        "inputs",
        "outputs",
        "rng_seed",
        "validators_passed",
        "network_policy_applied",
    ):
        assert field in inv, f"missing required field {field!r}"

    # invocation_id is a uuid4
    assert len(inv["invocation_id"]) == 36
    assert inv["role"] == "patcher"

    # network_policy_applied is "none" per replay-schema patcher conditional
    assert inv["network_policy_applied"] == "none"

    # validators_passed reflects the patch path
    assert "schema-valid-output" in inv["validators_passed"]

    # model block populated
    model = inv["model"]
    assert model["model_id"] == "fake-opus-4-7"
    assert model["family"] == "deterministic-no-model"  # FakeAdapter
    assert model["sampling"]["temperature"] == 0.0
    assert model["sampling"]["max_tokens"] == 8192

    # prompt block matches the actual prompt sha256
    prompt_path = REPO_ROOT / "prompts" / "patcher.v2.2.md"
    expected_prompt_sha = hashlib.sha256(prompt_path.read_bytes()).hexdigest()
    assert inv["prompt"]["sha256"] == expected_prompt_sha
    assert inv["prompt"]["path"] == "prompts/patcher.v2.2.md"

    # inputs[] sha256s match actual file bytes on disk
    expected_inputs = {
        "finding.json": _sha(bundle_dir / "finding.json"),
        "upstream-ref.json": _sha(bundle_dir / "upstream-ref.json"),
        "impact.json": _sha(bundle_dir / "impact.json"),
        "maintainers.json": _sha(bundle_dir / "maintainers.json"),
        "package.nix": _sha(bundle_dir / "package.nix"),
    }
    recorded_inputs = {i["path"]: i["sha256"] for i in inv["inputs"]}
    assert recorded_inputs == expected_inputs

    # outputs[] sha256s match the bytes Patcher actually wrote
    expected_outputs = {
        "patch.diff": _sha(diff_path),
        "patch-rationale.md": _sha(rat_path),
    }
    recorded_outputs = {o["path"]: o["sha256"] for o in inv["outputs"]}
    assert recorded_outputs == expected_outputs

    # The execute() return shape includes the same recorded invocation
    assert result["replay_invocation"] == inv


def test_recorded_patcher_invocation_validates_against_replay_schema(tmp_path):
    bundle_dir = _copy_fixture(tmp_path)
    execute(
        role="patcher",
        bundle_dir=bundle_dir,
        invocation={"invocation_id": None, "inputs": [], "outputs": []},
        verify=False,
        model_id="fake-opus-4-7",
        adapter_factory=_factory(_patch_response()),
    )

    replay = json.loads((bundle_dir / "replay.json").read_text())
    schema = json.loads(REPLAY_SCHEMA_PATH.read_text())
    validator = Draft202012Validator(schema)
    errors = [
        f"{'/'.join(str(p) for p in e.absolute_path)}: {e.message}"
        for e in validator.iter_errors(replay)
    ]
    assert not errors, f"replay.json failed schema after Patcher run: {errors}"


def test_two_patcher_runs_append_two_invocations(tmp_path):
    """Replay history must accumulate. A second run appends, not replaces."""
    bundle_dir = _copy_fixture(tmp_path)
    for _ in range(2):
        execute(
            role="patcher",
            bundle_dir=bundle_dir,
            invocation={"invocation_id": None, "inputs": [], "outputs": []},
            verify=False,
            model_id="fake-opus-4-7",
            adapter_factory=_factory(_patch_response()),
        )

    replay = json.loads((bundle_dir / "replay.json").read_text())
    patcher_roles = [r for r in replay["roles"] if r["role"] == "patcher"]
    assert len(patcher_roles) == 1, "should be one patcher role entry, not two"
    assert len(patcher_roles[0]["invocations"]) == 2, "should be two invocations"

    # Distinct invocation ids (UUID4 collisions are not interesting)
    ids = [i["invocation_id"] for i in patcher_roles[0]["invocations"]]
    assert len(set(ids)) == 2


# ─── refusal path ──────────────────────────────────────────────────────────


def _refusal_response() -> str:
    return (
        "=== BEGIN refusal ===\n"
        "rule: 3\n"
        "reason: upstream-ref.eligibility.verdict is ineligible-cherry-pick-required\n"
        "=== END refusal ==="
    )


def test_patcher_refusal_records_refusal_validators_in_replay(tmp_path):
    bundle_dir = _copy_fixture(tmp_path)
    execute(
        role="patcher",
        bundle_dir=bundle_dir,
        invocation={"invocation_id": None, "inputs": [], "outputs": []},
        verify=False,
        model_id="fake-opus-4-7",
        adapter_factory=_factory(_refusal_response()),
    )

    assert (bundle_dir / "refusal.json").is_file()
    assert not (bundle_dir / "patch.diff").exists()

    replay = json.loads((bundle_dir / "replay.json").read_text())
    inv = [r for r in replay["roles"] if r["role"] == "patcher"][0]["invocations"][0]
    assert "refusal-shape" in inv["validators_passed"]
    output_paths = {o["path"] for o in inv["outputs"]}
    assert output_paths == {"refusal.json"}


# ─── failure paths must not mutate replay.json ─────────────────────────────


def test_malformed_output_does_not_mutate_replay_json(tmp_path):
    bundle_dir = _copy_fixture(tmp_path)
    pre_replay = (bundle_dir / "replay.json").read_text()

    from tools.trace_cli.execute import ExecutionError

    with pytest.raises(ExecutionError, match="patcher output malformed"):
        execute(
            role="patcher",
            bundle_dir=bundle_dir,
            invocation={"invocation_id": None, "inputs": [], "outputs": []},
            verify=False,
            model_id="fake-opus-4-7",
            adapter_factory=_factory("Sure, here's the patch you asked for..."),
        )

    post_replay = (bundle_dir / "replay.json").read_text()
    assert post_replay == pre_replay, "replay.json must not be mutated when parse fails"
    assert not (bundle_dir / "patch.diff").exists()
    assert not (bundle_dir / "patch-rationale.md").exists()


def test_advisory_only_dispatch_refusal_does_not_mutate_replay_json(tmp_path):
    """Dispatch guard fires before any model call; replay.json must be untouched."""
    bundle_dir = _copy_fixture(tmp_path)
    # Mutate the copy: flip kind to advisory-only.
    bundle = json.loads((bundle_dir / "bundle.json").read_text())
    bundle["kind"] = "advisory-only"
    bundle["kind_reason"] = "ineligible-no-fix-available"
    (bundle_dir / "bundle.json").write_text(json.dumps(bundle))
    pre_replay = (bundle_dir / "replay.json").read_text()

    from tools.trace_cli.execute import PatcherDispatchRefused

    with pytest.raises(PatcherDispatchRefused, match="advisory-only"):
        execute(
            role="patcher",
            bundle_dir=bundle_dir,
            invocation={"invocation_id": None, "inputs": [], "outputs": []},
            verify=False,
            model_id="fake-opus-4-7",
            adapter_factory=_factory(_patch_response()),
        )

    post_replay = (bundle_dir / "replay.json").read_text()
    assert post_replay == pre_replay
