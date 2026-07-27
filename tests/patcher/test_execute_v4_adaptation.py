"""End-to-end (FakeAdapter) wiring of the patcher.v4 semantic-adaptation lane.

Slice 2 of the semantic-backport-adaptation arc. Proves the new signed contract
ships with the behaviour that consumes it: a source-backport bundle carrying a
source-context/ dir + preflight.json routes to patcher.v4, the model sees the
source-context bytes + the deterministic applies_verbatim verdict, the recorded
invocation declares the source-context files as replay-critical inputs, verify
mode hash-checks them, and finalize emits a schema-valid 1.1.0 bundle whose
source_context manifest matches the signed files. No live model spend (FakeAdapter).
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from agents.patcher import FakeAdapter
from agents.patcher.runner import assemble_user_content
from tools.trace_cli.bundle import finalize_bundle
from tools.trace_cli.execute import (
    PATCHER_PROMPT_PATH_ADAPT,
    execute,
)
from tests.schema.validate import REPO_ROOT, load_schemas, validators

# A clean source-backport bundle whose resolver docs finalize without warnings —
# reused so the finalize step exercises real, schema-valid resolver-side JSON.
_ZLIB = REPO_ROOT / "traces" / "example" / "CVE-2022-37434--zlib-backport"

_RATIONALE = """## Upstream reference
Adapted from upstream commit c161620 (repo https://github.com/libarchive/libarchive).
applies_verbatim was false: the pinned base lacks archive_ckd_mul_i64.

## Why this version
Backported in place; no version bump (source-backport).

## Why minimal
Only the overflow guard in foo.c is touched, grounded on the pinned source.

## Alternatives rejected
- Verbatim transcription: rejected, the upstream patch does not apply.
- Version bump: rejected per resolver authorization.

## Downstream risk
reverse_closure_count=42; under threshold.
"""


def _adapted_patch_response() -> str:
    # Canonical nested source-backport: the outer diff adds a .patch file whose
    # content is the inner unified diff. The inner `+++ b/foo.c` header appears in
    # the outer diff as `++++ b/foo.c` (outer `+` prefix + inner `+++`). The inner
    # header `@@ -1 +1 @@` is correct (foo.c's single source line is line 1).
    return (
        "=== BEGIN patch.diff ===\n"
        "diff --git a/CVE-0000-0002.patch b/CVE-0000-0002.patch\n"
        "new file mode 100644\n"
        "--- /dev/null\n"
        "+++ b/CVE-0000-0002.patch\n"
        "@@ -0,0 +1,5 @@\n"
        "+--- a/foo.c\n"
        "++++ b/foo.c\n"
        "+@@ -1 +1 @@\n"
        "+-    l = l * base;\n"
        "++    if (l > limit) return -1;\n"
        "diff --git a/package.nix b/package.nix\n"
        "--- a/package.nix\n"
        "+++ b/package.nix\n"
        "@@ -1 +1,2 @@\n"
        ' version = "1.0.0";\n'
        "+patches = [ ./CVE-0000-0002.patch ];\n"
        "=== END patch.diff ===\n"
        "=== BEGIN patch-rationale.md ===\n"
        + _RATIONALE
        + "=== END patch-rationale.md ===\n"
    )


def _factory(text: str):
    def _make(model_id: str) -> FakeAdapter:
        return FakeAdapter(model_id, text)
    return _make


def _fresh() -> dict:
    return {"invocation_id": None, "inputs": [], "outputs": []}


def _build_source_context_bundle(tmp_path: Path) -> Path:
    bd = tmp_path / "bundle"
    bd.mkdir()
    (bd / "finding.json").write_text(json.dumps({
        "cve_id": "CVE-0000-0002",
        "affected": [{"attr_path": "libexample", "version": "1.0.0"}],
    }))
    (bd / "upstream-ref.json").write_text(json.dumps({
        "cve_id": "CVE-0000-0002",
        "current_version": "1.0.0",
        "target_version": "1.0.0",
        "fix_tier": "security-patch-release",
        "release_url": "https://example.invalid/rel",
        "upstream_fix_commits": [
            {"repo_url": "https://github.com/libarchive/libarchive", "commit_sha": "c161620"}
        ],
        "eligibility": {"verdict": "eligible", "patch_strategy": "source-backport"},
    }))
    (bd / "impact.json").write_text(json.dumps({
        "cve_id": "CVE-0000-0002", "reverse_closure_count": 42, "exceeds_threshold": False,
    }))
    (bd / "maintainers.json").write_text(json.dumps({
        "cve_id": "CVE-0000-0002",
        "attr_paths": {"libexample": {"maintainers": [{"github": "alice"}]}},
    }))
    (bd / "package.nix").write_text('version = "1.0.0";\n')
    (bd / "upstream-fix.patch").write_text(
        "diff --git a/foo.c b/foo.c\n--- a/foo.c\n+++ b/foo.c\n"
        "@@ -1 +1 @@\n-    l = archive_ckd_mul_i64(l, base);\n"
        "+    l = archive_ckd_mul_i64(l, base);  /* upstream */\n"
    )
    # bootstrap-produced: source-context/ (pinned pre-patch source) + preflight.json
    (bd / "source-context").mkdir()
    (bd / "source-context" / "foo.c").write_text("    l = l * base;\n")
    (bd / "preflight.json").write_text(json.dumps({
        "applies_verbatim": False,
        "patch": "upstream-fix.patch",
        "patch_flags": ["-p1"],
        "diagnostics": "Hunk #1 FAILED: archive_ckd_mul_i64 absent from pinned base",
    }))
    # seed replay so the patcher metadata writer has a schema-valid file to append to
    (bd / "replay.json").write_text(json.dumps({
        "schema_version": "1.0.0",
        "bundle_id": "0000000000000002",
        "cve_id": "CVE-0000-0002",
        "nixpkgs_rev": "a" * 40,
        "policy_version": "0" * 64,
        "bundle_schema_sha256": "1" * 64,
        "routing_config_sha256": "2" * 64,
        "tool_manifest": {"flake_lock_sha256": "3" * 64,
                          "tools": [{"name": "python", "version": "3.13"}]},
        "cross_family_rule_honored": True,
        "roles": [{
            "role": "upstream-ref-resolver",
            "invocations": [{
                "invocation_id": "00000000-0000-4000-8000-000000000002",
                "role": "upstream-ref-resolver",
                "started_at": "2026-07-27T00:00:00Z",
                "ended_at": "2026-07-27T00:00:01Z",
                "model": {"family": "deterministic-no-model", "vendor": "internal",
                          "model_id": "x", "version": "1.0.0",
                          "sampling": {"temperature": 0, "top_p": 1, "max_tokens": 1}},
                "prompt": {"path": "prompts/upstream-ref-resolver.v1.md", "sha256": "7" * 64},
                "inputs": [{"path": "finding.json", "sha256": "6" * 64}],
                "outputs": [{"path": "upstream-ref.json", "sha256": "8" * 64}],
                "rng_seed": None,
                "validators_passed": ["eligibility-verdict-present"],
                "network_policy_applied": "feeds-only",
            }],
        }],
    }))
    # impact.json needs nixpkgs_rev for finalize; put a real-looking one
    imp = json.loads((bd / "impact.json").read_text())
    imp["nixpkgs_rev"] = "a" * 40
    (bd / "impact.json").write_text(json.dumps(imp))
    return bd


# ── prompt selection + rendered content ────────────────────────────────────

def test_assemble_user_content_renders_source_context_and_verdict():
    content = assemble_user_content({
        "finding": {}, "upstream_ref": {}, "impact": {}, "maintainers": {},
        "package_source": "x",
        "patch_strategy": "source-backport",
        "upstream_fix_patch": "diff --git a/foo.c b/foo.c\n",
        "source_context": {"foo.c": "    l = l * base;\n"},
        "applies_verbatim": False,
        "preflight_diagnostics": "Hunk #1 FAILED",
    })
    assert "applies_verbatim: false" in content
    assert "SEMANTIC ADAPTATION" in content
    assert "### source-context/foo.c" in content
    assert "l = l * base;" in content


def test_verbatim_true_directs_transcription():
    content = assemble_user_content({
        "finding": {}, "upstream_ref": {}, "impact": {}, "maintainers": {},
        "package_source": "x",
        "patch_strategy": "source-backport",
        "upstream_fix_patch": "diff --git a/foo.c b/foo.c\n",
        "source_context": {"foo.c": "x\n"},
        "applies_verbatim": True,
    })
    assert "applies_verbatim: true" in content
    assert "VERBATIM" in content


# ── execute end-to-end ──────────────────────────────────────────────────────

def test_execute_routes_to_v4_and_declares_source_context_inputs(tmp_path):
    bd = _build_source_context_bundle(tmp_path)
    result = execute(
        role="patcher", bundle_dir=bd, invocation=_fresh(), verify=False,
        model_id="fake-opus-4-7", adapter_factory=_factory(_adapted_patch_response()),
    )
    assert result["kind"] == "patch"
    inv = result["replay_invocation"]
    # v4 prompt recorded
    assert inv["prompt"]["path"] == f"prompts/{PATCHER_PROMPT_PATH_ADAPT.name}"
    # source-context + preflight declared as replay-critical inputs, hashed
    declared = {ref["path"] for ref in inv["inputs"]}
    assert "source-context/foo.c" in declared
    assert "preflight.json" in declared
    for ref in inv["inputs"]:
        assert len(ref["sha256"]) == 64


def test_execute_verify_mode_hash_checks_source_context(tmp_path):
    bd = _build_source_context_bundle(tmp_path)
    fresh = execute(
        role="patcher", bundle_dir=bd, invocation=_fresh(), verify=False,
        model_id="fake-opus-4-7", adapter_factory=_factory(_adapted_patch_response()),
    )
    recorded = fresh["replay_invocation"]
    # Re-run in verify mode against the recorded invocation → the generic input
    # loop hash-verifies every declared input, including source-context/foo.c.
    verified = execute(
        role="patcher", bundle_dir=bd, invocation=recorded, verify=True,
        model_id="fake-opus-4-7", adapter_factory=_factory(_adapted_patch_response()),
    )
    vpaths = {v["path"] for v in verified["input_verification"] if v.get("verified")}
    assert "source-context/foo.c" in vpaths


def _wrong_header_response() -> str:
    """Same adapted patch, but the model botched the inner hunk header (upstream
    line number + wrong-looking counts). The body is correct and grounded."""
    return (
        "=== BEGIN patch.diff ===\n"
        "diff --git a/CVE-0000-0002.patch b/CVE-0000-0002.patch\n"
        "new file mode 100644\n"
        "--- /dev/null\n"
        "+++ b/CVE-0000-0002.patch\n"
        "@@ -0,0 +1,5 @@\n"
        "+--- a/foo.c\n"
        "++++ b/foo.c\n"
        "+@@ -812,5 +812,9 @@\n"          # WRONG: source is line 1, single line
        "+-    l = l * base;\n"
        "++    if (l > limit) return -1;\n"
        "diff --git a/package.nix b/package.nix\n"
        "--- a/package.nix\n"
        "+++ b/package.nix\n"
        "@@ -1 +1,2 @@\n"
        ' version = "1.0.0";\n'
        "+patches = [ ./CVE-0000-0002.patch ];\n"
        "=== END patch.diff ===\n"
        "=== BEGIN patch-rationale.md ===\n"
        + _RATIONALE
        + "=== END patch-rationale.md ===\n"
    )


def _ungroundable_response() -> str:
    """Adapted patch whose inner deletion line does NOT exist in source-context —
    the normalizer must fail loud rather than fabricate a header."""
    return (
        "=== BEGIN patch.diff ===\n"
        "diff --git a/CVE-0000-0002.patch b/CVE-0000-0002.patch\n"
        "new file mode 100644\n"
        "--- /dev/null\n"
        "+++ b/CVE-0000-0002.patch\n"
        "@@ -0,0 +1,5 @@\n"
        "+--- a/foo.c\n"
        "++++ b/foo.c\n"
        "+@@ -1 +1 @@\n"
        "+-    this_line_is_not_in_the_pinned_source();\n"
        "++    if (l > limit) return -1;\n"
        "diff --git a/package.nix b/package.nix\n"
        "--- a/package.nix\n"
        "+++ b/package.nix\n"
        "@@ -1 +1,2 @@\n"
        ' version = "1.0.0";\n'
        "+patches = [ ./CVE-0000-0002.patch ];\n"
        "=== END patch.diff ===\n"
        "=== BEGIN patch-rationale.md ===\n"
        + _RATIONALE
        + "=== END patch-rationale.md ===\n"
    )


def test_execute_canonicalizes_wrong_inner_header_and_records_provenance(tmp_path):
    bd = _build_source_context_bundle(tmp_path)
    result = execute(
        role="patcher", bundle_dir=bd, invocation=_fresh(), verify=False,
        model_id="fake-opus-4-7", adapter_factory=_factory(_wrong_header_response()),
    )
    assert result["kind"] == "patch"
    written = (bd / "patch.diff").read_text()
    # The botched header is discarded and a canonical one re-derived from the pinned
    # source. foo.c is a single logical line (the trailing newline is NOT an extra
    # source line), so the canonical header is `@@ -1 +1 @@`.
    assert "+@@ -1 +1 @@" in written
    assert "+@@ -1,2 +1,2 @@" not in written
    assert "+@@ -812,5 +812,9 @@" not in written
    assert "+-    l = l * base;" in written
    assert "++    if (l > limit) return -1;" in written
    # Provenance recorded in patcher_run + the invocation sidecar.
    hn = result["patcher_run"]["hunk_normalization"]
    assert hn["applied"] is True
    assert len(hn["files"]) == 1
    assert hn["files"][0]["file"] == "foo.c"
    assert hn["files"][0]["canonical_hunks"] == 1
    assert len(hn["files"][0]["postimage_sha256"]) == 64
    assert hn["pre_sha256"] != hn["post_sha256"]
    sidecar = json.loads((bd / "patcher-invocation.json").read_text())
    assert sidecar["hunk_normalization"]["applied"] is True
    # The recorded output sha matches the canonicalized bytes on disk.
    from tools.trace_cli.execute import sha256_hex  # local import; test-only
    out_sha = {o["path"]: o["sha256"] for o in result["replay_invocation"]["outputs"]}
    assert out_sha["patch.diff"] == sha256_hex(written.encode("utf-8"))


def test_execute_emits_applicability_attestation(tmp_path):
    import json
    from tools.trace_cli.hunk_normalizer import CANONICALIZER_VERSION
    bd = _build_source_context_bundle(tmp_path)
    result = execute(
        role="patcher", bundle_dir=bd, invocation=_fresh(), verify=False,
        model_id="fake-opus-4-7", adapter_factory=_factory(_wrong_header_response()),
    )
    att_path = bd / "patch-applicability.json"
    assert att_path.exists()
    att = json.loads(att_path.read_text())
    assert att["canonicalizer_version"] == CANONICALIZER_VERSION
    assert att["applies_at_fuzz0"] is True
    assert att["unique_source_match"] is True
    assert att["canonicalized"] is True
    assert att["raw_patch_sha256"] != att["canonical_patch_sha256"]
    assert att["files"][0]["file"] == "foo.c"
    assert len(att["files"][0]["postimage_sha256"]) == 64
    # Declared as a hash-recorded output of the invocation.
    out_paths = {o["path"] for o in result["replay_invocation"]["outputs"]}
    assert "patch-applicability.json" in out_paths
    from tools.trace_cli.execute import sha256_hex
    out_sha = {o["path"]: o["sha256"] for o in result["replay_invocation"]["outputs"]}
    assert out_sha["patch-applicability.json"] == sha256_hex(att_path.read_bytes())


def test_execute_canonicalization_is_idempotent_fixpoint(tmp_path):
    # Canonicalizing a patch is a fixpoint: the written (already-canonical) patch,
    # fed back through the compiler, produces no further change.
    from tools.trace_cli.hunk_normalizer import canonicalize_backport_patch
    bd = _build_source_context_bundle(tmp_path)
    result = execute(
        role="patcher", bundle_dir=bd, invocation=_fresh(), verify=False,
        model_id="fake-opus-4-7", adapter_factory=_factory(_wrong_header_response()),
    )
    assert result["patcher_run"]["hunk_normalization"]["applied"] is True
    written = (bd / "patch.diff").read_text()
    ctx = {"foo.c": (bd / "source-context" / "foo.c").read_text()}
    again = canonicalize_backport_patch(written, ctx)
    assert not again.changed
    assert again.text == written


def test_execute_ungroundable_body_fails_and_persists_raw(tmp_path):
    bd = _build_source_context_bundle(tmp_path)
    with pytest.raises(Exception, match="hunk-header canonicalization failed"):
        execute(
            role="patcher", bundle_dir=bd, invocation=_fresh(), verify=False,
            model_id="fake-opus-4-7", adapter_factory=_factory(_ungroundable_response()),
        )
    # Nothing signed: no patch.diff written; raw persisted for debugging.
    assert not (bd / "patch.diff").exists()
    fails = list((bd / ".patcher-failures").rglob("raw-response.txt"))
    assert fails, "raw patch should be persisted on normalization failure"


def _build_from_zlib(tmp_path: Path) -> Path:
    """Seed real, schema-clean resolver docs from the zlib-backport bundle, then
    overlay the bootstrap-produced source-context/ + preflight.json so finalize
    exercises the true guard path (not hand-built minimal JSON)."""
    import shutil
    bd = tmp_path / "zbundle"
    bd.mkdir()
    for f in ("finding.json", "impact.json", "maintainers.json", "upstream-ref.json",
              "package.nix", "upstream-fix.patch"):
        src = _ZLIB / f
        if src.is_file():
            shutil.copyfile(src, bd / f)
    (bd / "source-context").mkdir()
    (bd / "source-context" / "gzread.c").write_text("    /* pinned pre-patch */\n")
    (bd / "preflight.json").write_text(json.dumps({
        "applies_verbatim": False, "patch": "upstream-fix.patch",
        "patch_flags": ["-p1"], "diagnostics": "base divergence",
    }))
    return bd


def test_finalize_produces_schema_valid_1_1_0(tmp_path):
    bd = _build_from_zlib(tmp_path)
    finalize_bundle(bundle_dir=bd, bundle_kind="human-review-required",
                    created_at="2026-07-27T00:00:00Z")
    b = json.loads((bd / "bundle.json").read_text())
    assert b["schema_version"] == "1.1.0"
    assert b["patch_strategy"] == "source-backport"
    key = "source-context/gzread.c"
    assert b["source_context"][0]["path"] == key
    assert b["source_context"][0]["sha256"] == b["files"][key]["sha256"]
    signed = {sf["path"] for sf in b["signed_manifest"]["signed_files"]}
    assert key in signed and "preflight.json" in signed
    v = validators(load_schemas())["bundle"]
    assert [e.message for e in v.iter_errors(b)] == []
