"""End-to-end wiring of `trace replay --execute --role reproducer --model <id>`.

Tests operate at the `execute()` API level (not subprocess CLI level) so
we can inject `FakeAdapter` via `adapter_factory` without a real model
call. Mirrors the patcher executor-test shape.

Covers:
  1. Happy path: writes reproducer.nix + reproducer-log.txt +
     passthru-tests.json + replay invocation; does NOT touch build.json
     (per the 2026-04-28 architectural split).
  2. Refusal path: writes reproducer-refusal.json instead of the three
     reproducer files.
  3. Dispatch guards:
     - bundle.kind == "advisory-only" → PatcherDispatchRefused
     - patcher refusal.json present → PatcherDispatchRefused
     - missing required input → ExecutionError
  4. Cross-family rule (locked b2b3b2c):
     - same-family Patcher/Reproducer pair → ExecutionError pre-execute
     - different-family pair → success
  5. Malformed model output → ExecutionError; no files written;
     replay.json untouched.
  6. Proxy reproducer: writes all three files; replay invocation
     records is_proxy via reproducer_run; build.json still untouched.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from agents.patcher import FakeAdapter
from tools.trace_cli.execute import (
    ExecutionError,
    MODEL_BACKED_ROLES,
    PatcherDispatchRefused,
    execute,
)


# ─── canned model responses ───────────────────────────────────────────────


_REPRO_NIX = """\
{ pkgs ? import <nixpkgs> { } }:

let
  unpatched = pkgs.demo.overrideAttrs (old: {
    version = "1.0.0";
  });
  patched = pkgs.demo;
in
{
  inherit unpatched patched;

  test = pkgs.runCommand "repro-CVE-0000-0001" { } ''
    if ! ${unpatched}/bin/demo --check; then
      echo "vuln-triggered: out-of-bounds-read in deserialise() on malformed length-prefix"
    fi
    if ${patched}/bin/demo --check; then
      echo "rejected-malformed-length-prefix-as-expected-from-CVE-0000-0001"
    fi
  '';
}
"""

_REPRO_LOG = """\
The unpatched binary's deserialise() reads past the buffer end on a malformed length-prefix.

=== unpatched ===
Unpatched binary triggers the out-of-bounds-read.
+ ${unpatched}/bin/demo --check
vuln-triggered: out-of-bounds-read in deserialise() on malformed length-prefix
SIGNAL_UNPATCHED: vuln-triggered: out-of-bounds-read in deserialise() on malformed length-prefix
EXIT: 1

=== patched ===
Patched binary rejects the malformed input.
+ ${patched}/bin/demo --check
rejected-malformed-length-prefix-as-expected-from-CVE-0000-0001
SIGNAL_PATCHED: rejected-malformed-length-prefix-as-expected-from-CVE-0000-0001
EXIT: 0
"""

_PASSTHRU = '[\n  { "name": "passthru.tests.basic", "drv_path": null, "kind": "passthru.tests" }\n]\n'


def _valid_reproducer_response() -> str:
    return (
        "=== BEGIN reproducer.nix ===\n"
        + _REPRO_NIX
        + "=== END reproducer.nix ===\n"
        + "=== BEGIN reproducer-log.txt ===\n"
        + _REPRO_LOG
        + "=== END reproducer-log.txt ===\n"
        + "=== BEGIN passthru-tests.json ===\n"
        + _PASSTHRU
        + "=== END passthru-tests.json ==="
    )


def _valid_refusal_response(rule: int = 3, reason: str = "vuln class is not locally-reproducible (CAP_SYS_ADMIN required)") -> str:
    return (
        "=== BEGIN refusal ===\n"
        f"rule: {rule}\n"
        f"reason: {reason}\n"
        "=== END refusal ==="
    )


_PROXY_NIX = """\
{ pkgs ? import <nixpkgs> { } }:
let
  unpatched = pkgs.demo;
  patched = pkgs.demo;
in {
  inherit unpatched patched;
  test = pkgs.runCommand "repro-proxy" { } ''
    echo "rejected-malformed-length-prefix-as-expected-from-CVE-0000-0001"
  '' // {
    meta = {
      proxy = true;
      proxy_reason = "sandbox-cannot-trigger";
      why_not_full_repro = "Full chain requires CAP_SYS_ADMIN inside the sandbox; only the patched-rejection path is locally verifiable.";
      expected_limitations = "Verifies only the parser's malformed-input rejection, not the downstream privilege escalation.";
    };
  };
}
"""

_PROXY_LOG = """\
=== unpatched ===
Out of scope for this proxy.
SIGNAL_UNPATCHED: proxy-test: full-chain unpatched evidence intentionally omitted
EXIT: 0

=== patched ===
Patched binary rejects the malformed input.
SIGNAL_PATCHED: rejected-malformed-length-prefix-as-expected-from-CVE-0000-0001
EXIT: 0

=== proxy ===
proxy_reason: sandbox-cannot-trigger
why_not_full_repro: Full chain requires CAP_SYS_ADMIN inside the sandbox; only the patched-rejection path is locally verifiable.
expected_limitations: Verifies only the parser's malformed-input rejection, not the downstream privilege escalation.
"""


def _valid_proxy_response() -> str:
    return (
        "=== BEGIN reproducer.nix ===\n"
        + _PROXY_NIX
        + "=== END reproducer.nix ===\n"
        + "=== BEGIN reproducer-log.txt ===\n"
        + _PROXY_LOG
        + "=== END reproducer-log.txt ===\n"
        + "=== BEGIN passthru-tests.json ===\n"
        + "[]\n"
        + "=== END passthru-tests.json ==="
    )


# ─── bundle fixture ───────────────────────────────────────────────────────


def _build_post_patcher_bundle(
    tmp_path: Path,
    *,
    kind: str = "auto-merge",
    verdict: str = "eligible",
    patcher_model_id: str = "claude-opus-4-7",
    include_patcher_invocation: bool = True,
    include_patcher_outputs: bool = True,
    include_patcher_refusal: bool = False,
) -> Path:
    """Write a bundle dir as it would look after a Patcher run.

    The reproducer dispatcher reads patch.diff / patch-rationale.md plus
    the standard five inputs; replay.json must already carry the
    patcher invocation that defines the family for cross-family checks.
    """
    bundle_dir = tmp_path / "bundle"
    bundle_dir.mkdir()

    (bundle_dir / "bundle.json").write_text(json.dumps({
        "schema_version": "1.0.0",
        "bundle_id": "0000000000000001",
        "cve_id": "CVE-0000-0001",
        "nixpkgs_rev": "0" * 40,
        "kind": kind,
    }))
    (bundle_dir / "finding.json").write_text(json.dumps({
        "cve_id": "CVE-0000-0001",
        "affected": [{"attr_path": "demo", "version": "1.0.0"}],
        "summary": "out-of-bounds read in demo's deserialise() on malformed length-prefix",
    }))
    (bundle_dir / "upstream-ref.json").write_text(json.dumps({
        "cve_id": "CVE-0000-0001",
        "current_version": "1.0.0",
        "target_version": "1.0.1",
        "fix_tier": "security-patch-release",
        "eligibility": {"verdict": verdict},
        "upstream_fix_commits": [
            {"repo_url": "https://github.com/example/demo",
             "commit_sha": "deadbeefcafe"}
        ],
    }))
    (bundle_dir / "impact.json").write_text(json.dumps({
        "cve_id": "CVE-0000-0001",
        "reverse_closure_count": 42,
        "exceeds_threshold": False,
    }))
    (bundle_dir / "maintainers.json").write_text(json.dumps({
        "cve_id": "CVE-0000-0001",
        "attr_paths": {"demo": {"maintainers": [{"github": "alice"}]}},
    }))
    (bundle_dir / "package.nix").write_text('version = "1.0.0";\n')

    if include_patcher_outputs:
        (bundle_dir / "patch.diff").write_text(
            "--- a/package.nix\n"
            "+++ b/package.nix\n"
            "@@ -1 +1 @@\n"
            '-version = "1.0.0";\n'
            '+version = "1.0.1";\n'
        )
        (bundle_dir / "patch-rationale.md").write_text(
            "## Upstream reference\nupstream commit deadbeefcafe.\n"
            "## Why this version\n1.0.1 patch release.\n"
            "## Why minimal\nOnly version bumped.\n"
            "## Alternatives rejected\n- cherry-pick: rejected.\n"
            "## Downstream risk\nrev_closure=42, under threshold.\n"
        )
    if include_patcher_refusal:
        (bundle_dir / "refusal.json").write_text(json.dumps({
            "rule": 3, "reason": "advisory-only verdict",
        }))

    # Build replay.json with deterministic resolver invocation +
    # optional patcher invocation. The reproducer dispatcher reads the
    # patcher invocation's model.model_id to resolve patcher_family.
    roles = [{
        "role": "upstream-ref-resolver",
        "invocations": [{
            "invocation_id": "00000000-0000-4000-8000-000000000001",
            "role": "upstream-ref-resolver",
            "started_at": "2026-04-23T00:00:00Z",
            "ended_at": "2026-04-23T00:00:01Z",
            "model": {
                "family": "deterministic-no-model",
                "vendor": "internal",
                "model_id": "upstream-ref-resolver-deterministic",
                "version": "1.0.0",
                "sampling": {"temperature": 0, "top_p": 1, "max_tokens": 1},
            },
            "prompt": {
                "path": "prompts/upstream-ref-resolver.v1.md",
                "sha256": "7" * 64,
            },
            "inputs": [{"path": "finding.json", "sha256": "6" * 64}],
            "outputs": [{"path": "upstream-ref.json", "sha256": "8" * 64}],
            "rng_seed": None,
            "validators_passed": ["eligibility-verdict-present"],
            "network_policy_applied": "feeds-only",
        }],
    }]
    if include_patcher_invocation:
        roles.append({
            "role": "patcher",
            "invocations": [{
                "invocation_id": "11111111-1111-4111-8111-111111111111",
                "role": "patcher",
                "started_at": "2026-04-27T00:00:00Z",
                "ended_at": "2026-04-27T00:00:05Z",
                "model": {
                    "family": "anthropic",
                    "vendor": "anthropic",
                    "model_id": patcher_model_id,
                    "version": "test",
                    "sampling": {"temperature": 0, "top_p": 1, "max_tokens": 8192},
                },
                "prompt": {"path": "prompts/patcher.v2.md", "sha256": "a" * 64},
                "inputs": [],
                "outputs": [],
                "rng_seed": None,
                "validators_passed": ["schema-valid-output"],
                "network_policy_applied": "none",
            }],
        })
    replay = {
        "schema_version": "1.0.0",
        "bundle_id": "0000000000000001",
        "cve_id": "CVE-0000-0001",
        "nixpkgs_rev": "0" * 40,
        "policy_version": "0" * 64,
        "bundle_schema_sha256": "1" * 64,
        "routing_config_sha256": "2" * 64,
        "tool_manifest": {
            "flake_lock_sha256": "3" * 64,
            "tools": [{"name": "python", "version": "3.13"}],
        },
        "cross_family_rule_honored": True,
        "roles": roles,
    }
    (bundle_dir / "replay.json").write_text(json.dumps(replay))
    return bundle_dir


def _fresh_invocation() -> dict:
    return {"invocation_id": None, "inputs": [], "outputs": []}


def _factory(response_text: str):
    def _make(model_id: str) -> FakeAdapter:
        return FakeAdapter(model_id, response_text)
    return _make


# ─── happy path ───────────────────────────────────────────────────────────


def test_reproducer_happy_path_writes_three_files(tmp_path):
    bundle_dir = _build_post_patcher_bundle(tmp_path)
    result = execute(
        role="reproducer",
        bundle_dir=bundle_dir,
        invocation=_fresh_invocation(),
        verify=False,
        model_id="claude-sonnet-4-6",  # different family from opus patcher
        adapter_factory=_factory(_valid_reproducer_response()),
    )
    assert result["kind"] == "reproducer"
    assert result["is_proxy"] is False
    assert (bundle_dir / "reproducer.nix").is_file()
    assert (bundle_dir / "reproducer-log.txt").is_file()
    assert (bundle_dir / "passthru-tests.json").is_file()
    assert not (bundle_dir / "reproducer-refusal.json").exists()

    paths = {o["path"] for o in result["outputs"]}
    assert paths == {"reproducer.nix", "reproducer-log.txt", "passthru-tests.json"}
    for o in result["outputs"]:
        assert len(o["sha256"]) == 64
        assert o["bytes"] > 0

    # Architectural split: build.json must NOT be touched by the runner.
    assert not (bundle_dir / "build.json").exists()


def test_reproducer_appends_replay_invocation_with_cross_family_metadata(tmp_path):
    bundle_dir = _build_post_patcher_bundle(tmp_path)
    result = execute(
        role="reproducer",
        bundle_dir=bundle_dir,
        invocation=_fresh_invocation(),
        verify=False,
        model_id="claude-sonnet-4-6",
        adapter_factory=_factory(_valid_reproducer_response()),
    )
    inv = result["replay_invocation"]
    assert inv["role"] == "reproducer"
    # Patcher family captured from the existing patcher invocation
    assert inv["patcher_family_recorded"] == "anthropic-opus"
    # Cross-reference to the patcher invocation_id
    assert inv["patcher_invocation_id"] == "11111111-1111-4111-8111-111111111111"
    assert inv["cross_family_rule_honored"] is True
    # Reproducer model
    assert inv["model"]["model_id"] == "claude-sonnet-4-6"

    # And replay.json on disk now has a reproducer role entry.
    replay = json.loads((bundle_dir / "replay.json").read_text())
    repro_roles = [r for r in replay["roles"] if r["role"] == "reproducer"]
    assert len(repro_roles) == 1
    assert repro_roles[0]["invocations"][-1]["invocation_id"] == inv["invocation_id"]


# ─── refusal path ─────────────────────────────────────────────────────────


def test_reproducer_refusal_writes_only_refusal_file(tmp_path):
    bundle_dir = _build_post_patcher_bundle(tmp_path)
    result = execute(
        role="reproducer",
        bundle_dir=bundle_dir,
        invocation=_fresh_invocation(),
        verify=False,
        model_id="claude-sonnet-4-6",
        adapter_factory=_factory(_valid_refusal_response(rule=3)),
    )
    assert result["kind"] == "refusal"
    assert (bundle_dir / "reproducer-refusal.json").is_file()
    assert not (bundle_dir / "reproducer.nix").exists()
    assert not (bundle_dir / "reproducer-log.txt").exists()
    assert not (bundle_dir / "passthru-tests.json").exists()
    body = json.loads((bundle_dir / "reproducer-refusal.json").read_text())
    assert body["rule"] == 3
    assert "CAP_SYS_ADMIN" in body["reason"]


# ─── dispatch guards ──────────────────────────────────────────────────────


def test_reproducer_refuses_advisory_only_bundle(tmp_path):
    bundle_dir = _build_post_patcher_bundle(tmp_path, kind="advisory-only")
    with pytest.raises(PatcherDispatchRefused, match="advisory-only"):
        execute(
            role="reproducer",
            bundle_dir=bundle_dir,
            invocation=_fresh_invocation(),
            verify=False,
            model_id="claude-sonnet-4-6",
            adapter_factory=_factory(_valid_reproducer_response()),
        )


def test_reproducer_refuses_when_patcher_refused(tmp_path):
    bundle_dir = _build_post_patcher_bundle(
        tmp_path,
        include_patcher_outputs=False,
        include_patcher_refusal=True,
    )
    with pytest.raises(PatcherDispatchRefused, match="refusal.json"):
        execute(
            role="reproducer",
            bundle_dir=bundle_dir,
            invocation=_fresh_invocation(),
            verify=False,
            model_id="claude-sonnet-4-6",
            adapter_factory=_factory(_valid_reproducer_response()),
        )


def test_reproducer_refuses_when_required_input_missing(tmp_path):
    bundle_dir = _build_post_patcher_bundle(tmp_path)
    (bundle_dir / "patch.diff").unlink()
    with pytest.raises(ExecutionError, match=r"reproducer requires patch\.diff"):
        execute(
            role="reproducer",
            bundle_dir=bundle_dir,
            invocation=_fresh_invocation(),
            verify=False,
            model_id="claude-sonnet-4-6",
            adapter_factory=_factory(_valid_reproducer_response()),
        )


# ─── cross-family rule ────────────────────────────────────────────────────


def test_reproducer_rejects_same_family_as_patcher(tmp_path):
    """Patcher recorded as opus; requesting opus reproducer is forbidden."""
    bundle_dir = _build_post_patcher_bundle(
        tmp_path, patcher_model_id="claude-opus-4-7",
    )
    with pytest.raises(ExecutionError, match="cross-family"):
        execute(
            role="reproducer",
            bundle_dir=bundle_dir,
            invocation=_fresh_invocation(),
            verify=False,
            model_id="claude-opus-4-7",
            adapter_factory=_factory(_valid_reproducer_response()),
        )
    # No outputs written when the cross-family check trips.
    assert not (bundle_dir / "reproducer.nix").exists()
    assert not (bundle_dir / "reproducer-log.txt").exists()
    assert not (bundle_dir / "passthru-tests.json").exists()


def test_reproducer_accepts_different_family_pair(tmp_path):
    bundle_dir = _build_post_patcher_bundle(
        tmp_path, patcher_model_id="claude-opus-4-7",
    )
    result = execute(
        role="reproducer",
        bundle_dir=bundle_dir,
        invocation=_fresh_invocation(),
        verify=False,
        model_id="claude-sonnet-4-6",
        adapter_factory=_factory(_valid_reproducer_response()),
    )
    assert result["kind"] == "reproducer"


def test_reproducer_proceeds_when_no_patcher_recorded(tmp_path):
    """Cross-family check is conditional on a recorded patcher family.
    Without one, the reproducer can run (the cross-family rule has no
    constraint to enforce). This is for early-pipeline debugging; in
    the production path the dispatcher refuses earlier on missing
    patch.diff."""
    bundle_dir = _build_post_patcher_bundle(
        tmp_path, include_patcher_invocation=False,
    )
    # patch.diff exists; missing only the patcher REPLAY entry
    result = execute(
        role="reproducer",
        bundle_dir=bundle_dir,
        invocation=_fresh_invocation(),
        verify=False,
        model_id="claude-sonnet-4-6",
        adapter_factory=_factory(_valid_reproducer_response()),
    )
    assert result["kind"] == "reproducer"
    assert result["replay_invocation"]["patcher_family_recorded"] is None
    assert result["replay_invocation"]["patcher_invocation_id"] is None


# ─── parse-before-write contract ─────────────────────────────────────────


def test_reproducer_malformed_output_writes_no_files(tmp_path):
    bundle_dir = _build_post_patcher_bundle(tmp_path)
    pre_replay = (bundle_dir / "replay.json").read_text()

    bad_response = "Hi! Here is my reproducer.\n\n" + _valid_reproducer_response()
    with pytest.raises(ExecutionError, match=r"malformed|preamble"):
        execute(
            role="reproducer",
            bundle_dir=bundle_dir,
            invocation=_fresh_invocation(),
            verify=False,
            model_id="claude-sonnet-4-6",
            adapter_factory=_factory(bad_response),
        )

    # Parse-before-write: NO reproducer files on disk.
    assert not (bundle_dir / "reproducer.nix").exists()
    assert not (bundle_dir / "reproducer-log.txt").exists()
    assert not (bundle_dir / "passthru-tests.json").exists()
    assert not (bundle_dir / "reproducer-refusal.json").exists()

    # And replay.json is byte-identical (no mutation on parse failure).
    assert (bundle_dir / "replay.json").read_text() == pre_replay


# ─── proxy reproducer ────────────────────────────────────────────────────


def test_reproducer_proxy_path_writes_three_files_and_records_proxy_flag(tmp_path):
    bundle_dir = _build_post_patcher_bundle(tmp_path)
    result = execute(
        role="reproducer",
        bundle_dir=bundle_dir,
        invocation=_fresh_invocation(),
        verify=False,
        model_id="claude-sonnet-4-6",
        adapter_factory=_factory(_valid_proxy_response()),
    )
    assert result["kind"] == "reproducer"
    assert result["is_proxy"] is True
    assert (bundle_dir / "reproducer.nix").is_file()
    assert (bundle_dir / "reproducer-log.txt").is_file()
    assert (bundle_dir / "passthru-tests.json").is_file()
    # Architectural split: build.json untouched.
    assert not (bundle_dir / "build.json").exists()
    # The reproducer.nix must carry meta.proxy = true (lexical check).
    assert "proxy = true" in (bundle_dir / "reproducer.nix").read_text()
    # And the log must carry the proxy section.
    assert "=== proxy ===" in (bundle_dir / "reproducer-log.txt").read_text()


# ─── adapter selection ──────────────────────────────────────────────────


def test_reproducer_in_model_backed_roles_set():
    """Structural assertion the wiring lock is in place."""
    assert "reproducer" in MODEL_BACKED_ROLES


def test_reproducer_prompt_path_default_is_v9():
    """Locked: the runner loads `prompts/reproducer.v12.md` by default.

    Reproducer prompt versioning is a contract change, not a doc-only edit. v12
    bans fallback-fires-signal predicates (a reproducer must not emit SIGNAL on
    benign/success behavior — that fabricates discrimination; silent memory CVEs
    must refuse). See DECISIONS 2026-06-15 (mbedtls CVE-2024-49195 CWE-787); v11
    carried the fetchpatch + config-sensitive refusal clauses (still present).
    """
    from tools.trace_cli.execute import REPRODUCER_PROMPT_PATH_DEFAULT

    assert REPRODUCER_PROMPT_PATH_DEFAULT.name == "reproducer.v12.md", (
        f"runner default reproducer prompt should be v12 (got {REPRODUCER_PROMPT_PATH_DEFAULT.name}). "
        "If you are bumping the prompt, update this test in the same commit."
    )
    assert REPRODUCER_PROMPT_PATH_DEFAULT.is_file(), (
        f"default prompt path does not exist on disk: {REPRODUCER_PROMPT_PATH_DEFAULT}"
    )


def test_reproducer_v12_has_fetchpatch_config_sensitive_and_fallback_signal_clauses():
    """Regression lock: v12 must keep v11's clauses ((a) forbid fetchpatch even for
    extraPatches-src reconstruction, (b) config-sensitive/service-topology CVEs refuse
    not proxy) AND add (c) the fallback-fires-signal ban (mbedtls CWE-787): a
    reproducer must not emit SIGNAL on benign/success behavior."""
    from tools.trace_cli.execute import REPRODUCER_PROMPT_PATH_DEFAULT

    text = REPRODUCER_PROMPT_PATH_DEFAULT.read_text().lower()
    assert "fetchpatch" in text and "extrapatches" in text
    assert "config-sensitive" in text or "service-topology" in text
    assert "proxy" in text and "refuse" in text
    # v12 fallback-fires-signal ban
    assert "fallback-fires-signal" in text
    assert "benign" in text and "non-discriminating" in text


def test_reproducer_unknown_model_id_rejected_without_factory(tmp_path):
    bundle_dir = _build_post_patcher_bundle(tmp_path)
    with pytest.raises(ExecutionError, match="no adapter wired"):
        execute(
            role="reproducer",
            bundle_dir=bundle_dir,
            invocation=_fresh_invocation(),
            verify=False,
            model_id="not-a-claude-id",  # no adapter_factory supplied
        )


# ─── architectural split: build.json strictly out of bounds ──────────────


def test_reproducer_does_not_create_build_json_on_happy_path(tmp_path):
    bundle_dir = _build_post_patcher_bundle(tmp_path)
    execute(
        role="reproducer",
        bundle_dir=bundle_dir,
        invocation=_fresh_invocation(),
        verify=False,
        model_id="claude-sonnet-4-6",
        adapter_factory=_factory(_valid_reproducer_response()),
    )
    # Per the 2026-04-28 architectural split: runner owns shape; Builder
    # owns execution truth. build.json is exclusively Builder's.
    assert not (bundle_dir / "build.json").exists()


def test_reproducer_does_not_touch_existing_build_json(tmp_path):
    """If a build.json somehow already exists (e.g., from a previous
    Builder run), the reproducer runner must not rewrite or read it."""
    bundle_dir = _build_post_patcher_bundle(tmp_path)
    sentinel = b'{"sentinel": "untouched-by-reproducer"}\n'
    (bundle_dir / "build.json").write_bytes(sentinel)
    execute(
        role="reproducer",
        bundle_dir=bundle_dir,
        invocation=_fresh_invocation(),
        verify=False,
        model_id="claude-sonnet-4-6",
        adapter_factory=_factory(_valid_reproducer_response()),
    )
    assert (bundle_dir / "build.json").read_bytes() == sentinel


# ─── v5: bundle-local PoC artifact surfacing (DECISIONS 2026-05-19) ────────

import base64

from tools.trace_cli.execute import (
    POC_MAX_COUNT,
    POC_PER_FILE_INLINE_CAP,
    POC_PREVIEW_BYTES,
    POC_TOTAL_INLINE_CAP,
    _collect_bundle_local_pocs,
)


def _make_repro_dir(tmp_path: Path) -> Path:
    bundle_dir = tmp_path / "bundle"
    bundle_dir.mkdir()
    repro = bundle_dir / "repro"
    repro.mkdir()
    return bundle_dir


def test_collect_pocs_happy_path_small_text(tmp_path):
    """A small text file under repro/ is inlined with content_text +
    sha256 + size_bytes; kind classified as 'text'."""
    bd = _make_repro_dir(tmp_path)
    (bd / "repro" / "crash_input.txt").write_text("malformed data\n")
    pocs = _collect_bundle_local_pocs(bd)
    assert len(pocs) == 1
    entry = pocs[0]
    assert entry["path"] == "repro/crash_input.txt"
    assert entry["kind"] == "text"
    assert entry["inline"] is True
    assert entry["size_bytes"] == len("malformed data\n")
    assert entry["content_text"] == "malformed data\n"
    assert "sha256" in entry and len(entry["sha256"]) == 64


def test_collect_pocs_happy_path_small_binary(tmp_path):
    """A small binary file under repro/ is inlined as base64 with the
    kind set to 'binary'."""
    bd = _make_repro_dir(tmp_path)
    payload = bytes(range(256))  # 256 bytes, all-byte-values, clearly binary
    (bd / "repro" / "crash_poc.bin").write_bytes(payload)
    pocs = _collect_bundle_local_pocs(bd)
    assert len(pocs) == 1
    entry = pocs[0]
    assert entry["kind"] == "binary"
    assert entry["inline"] is True
    assert base64.b64decode(entry["content_base64"]) == payload


def test_collect_pocs_oversized_file_uses_previews_not_inline(tmp_path):
    """A file larger than POC_PER_FILE_INLINE_CAP is NOT inlined;
    previews of first/last 256 bytes are surfaced instead."""
    bd = _make_repro_dir(tmp_path)
    big = b"A" * (POC_PER_FILE_INLINE_CAP + 100)
    (bd / "repro" / "big.bin").write_bytes(big)
    pocs = _collect_bundle_local_pocs(bd)
    assert len(pocs) == 1
    entry = pocs[0]
    assert entry["inline"] is False
    assert "content_text" not in entry
    assert "content_base64" not in entry
    assert base64.b64decode(entry["preview_base64_first_256"]) == big[:POC_PREVIEW_BYTES]
    assert base64.b64decode(entry["preview_base64_last_256"]) == big[-POC_PREVIEW_BYTES:]


def test_collect_pocs_rejects_symlinks(tmp_path):
    """Symlinks under repro/ must be rejected with skip_reason=symlink-rejected.
    Trust boundary: a symlink could point outside the bundle dir."""
    bd = _make_repro_dir(tmp_path)
    real = bd / "real_target.txt"
    real.write_text("real content")
    link = bd / "repro" / "evil_link"
    link.symlink_to(real)
    pocs = _collect_bundle_local_pocs(bd)
    assert len(pocs) == 1
    entry = pocs[0]
    assert entry.get("skip_reason") == "symlink-rejected"
    # Skipped entries don't expose content.
    assert "sha256" not in entry


def test_collect_pocs_rejects_hidden_files(tmp_path):
    """Dotfiles under repro/ must be rejected with skip_reason=hidden-file-rejected."""
    bd = _make_repro_dir(tmp_path)
    (bd / "repro" / ".hidden").write_text("should be skipped")
    (bd / "repro" / "visible.txt").write_text("ok")
    pocs = _collect_bundle_local_pocs(bd)
    skip = [e for e in pocs if e.get("skip_reason") == "hidden-file-rejected"]
    visible = [e for e in pocs if e.get("path", "").endswith("visible.txt")]
    assert len(skip) == 1
    assert len(visible) == 1
    assert visible[0]["inline"] is True


def test_collect_pocs_count_cap_enforced(tmp_path):
    """More than POC_MAX_COUNT files in repro/ — extras get skip_reason=count-cap-exceeded.
    Prevents prompt bloat from pathological bundles."""
    bd = _make_repro_dir(tmp_path)
    for i in range(POC_MAX_COUNT + 3):
        (bd / "repro" / f"poc_{i:02d}.txt").write_text(f"poc {i}\n")
    pocs = _collect_bundle_local_pocs(bd)
    accepted = [e for e in pocs if e.get("inline") is True]
    capped = [e for e in pocs if e.get("skip_reason") == "count-cap-exceeded"]
    assert len(accepted) == POC_MAX_COUNT
    assert len(capped) == 3


def test_collect_pocs_total_inline_cap_enforced(tmp_path):
    """When the cumulative inline byte total would exceed POC_TOTAL_INLINE_CAP,
    later files use the preview form instead of inline content."""
    bd = _make_repro_dir(tmp_path)
    # 10 files at 3500 bytes each = 35,000 bytes total; cap is 32,768.
    # Files are processed in sorted order, so the 10th file should fall back to preview.
    for i in range(10):
        (bd / "repro" / f"poc_{i}.bin").write_bytes(b"X" * 3500)
    pocs = _collect_bundle_local_pocs(bd)
    inlines = [e for e in pocs if e.get("inline") is True]
    previews = [e for e in pocs if e.get("inline") is False]
    # At least the last file should be preview-only; first 9 fit (9*3500=31500 < 32768).
    assert len(inlines) <= 9
    assert len(previews) >= 1


def test_collect_pocs_empty_when_no_repro_dir(tmp_path):
    """If bundle has no repro/ directory at all, return empty list (not error)."""
    bd = tmp_path / "bundle"
    bd.mkdir()
    pocs = _collect_bundle_local_pocs(bd)
    assert pocs == []


def test_reproducer_runner_renders_pocs_block(tmp_path):
    """End-to-end: when bundle_dir/repro/ has a PoC, the Reproducer's user
    message includes the v5 bundle-local PoC artifacts section."""
    bundle_dir = _build_post_patcher_bundle(tmp_path)
    (bundle_dir / "repro").mkdir()
    (bundle_dir / "repro" / "crash_poc.csm").write_bytes(b"\x00\x01\x02malformed CSM bytes")

    captured: dict = {}

    class CapturingAdapter:
        def __init__(self, model_id: str) -> None:
            self.model_id = model_id

        def invoke(self, *, system_prompt, user_content, sampling):
            captured["user_content"] = user_content
            from agents.patcher.adapter import ModelResponse
            return ModelResponse(
                text=_valid_reproducer_response(),
                model_id=self.model_id,
                input_tokens=1,
                output_tokens=1,
                cache_creation_input_tokens=0,
                cache_read_input_tokens=0,
                stop_reason="end_turn",
            )

    execute(
        role="reproducer",
        bundle_dir=bundle_dir,
        invocation=_fresh_invocation(),
        verify=False,
        model_id="claude-sonnet-4-5-20250929",
        adapter_factory=lambda mid: CapturingAdapter(mid),
    )
    uc = captured["user_content"]
    assert "# Bundle-local PoC artifacts" in uc
    assert "repro/crash_poc.csm" in uc
