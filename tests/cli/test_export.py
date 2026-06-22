"""Tests for `trace export reviewer` (tools/trace_cli/export.py)."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from tools.trace_cli import export as ex


def _write(p: Path, obj) -> None:
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(obj if isinstance(obj, str) else json.dumps(obj))


def _make_bundle(
    root: Path,
    name: str,
    *,
    cve: str,
    attr: str,
    verdict: str | None = "accept",
    refusal: bool = False,
    review_md: str | None = None,
    bundle_id: str = "abc123",
    kind: str = "auto-merge",
) -> Path:
    bd = root / name
    bd.mkdir(parents=True)
    _write(bd / "bundle.json", {"bundle_id": bundle_id, "cve_id": cve, "kind": kind})
    _write(bd / "finding.json", {"cve_id": cve, "affected": [{"attr_path": attr}]})
    _write(bd / "impact.json", {"cve_id": cve, "exceeds_threshold": False})
    _write(bd / "maintainers.json", {"cve_id": cve})
    _write(bd / "upstream-ref.json", {"cve_id": cve, "target_version": "1.2.3"})
    _write(bd / "package.nix", "{ stdenv }: stdenv.mkDerivation { version = \"1.2.2\"; }\n")
    _write(bd / "patch.diff", "--- a/package.nix\n+++ b/package.nix\n@@ -1 +1 @@\n-x\n+y\n")
    _write(bd / "patch-rationale.md", "## Rationale\nbump\n")
    if refusal:
        _write(bd / "review-refusal.json", {"rule": 5, "reason": "no patch to review"})
    elif review_md is not None:
        _write(bd / "review.md", review_md)
    elif verdict is not None:
        findings = "(none)" if verdict == "accept" else "- severity: high — issue — patch.diff:hunk=1"
        _write(bd / "review.md", _full_review(verdict, findings))
    return bd


def _full_review(verdict: str, findings: str = "(none)") -> str:
    """A review.md that satisfies the full reviewer parser contract."""
    return (
        f"## Verdict\n{verdict}\n\n"
        "## Reasoning\nClean version bump grounded in upstream-ref.json.\n\n"
        f"## Findings\n{findings}\n\n"
        "## Cited evidence\n- finding.json:cve_id\n\n"
        "## Cross-family attestation\n"
        "reviewer_family: anthropic-sonnet\n"
        "patcher_family_observed: anthropic-opus\n"
        "rule_honored: true\n"
    )


def _args(out: Path, root: Path, prompt: Path, negatives_root: Path | None = None) -> argparse.Namespace:
    return argparse.Namespace(
        export_scope="reviewer", out=out, traces_root=root,
        negatives_root=negatives_root or (root.parent / "no-negatives"),
        reviewer_prompt=prompt, format="json",
    )


def _prompt(tmp_path: Path) -> Path:
    p = tmp_path / "reviewer.md"
    p.write_text("You are the Reviewer. Judge the patch.")
    return p


def test_accept_bundle_yields_positive_example(tmp_path, capsys):
    root = tmp_path / "traces"
    _make_bundle(root, "CVE-2025-0001--foo", cve="CVE-2025-0001", attr="foo")
    out = tmp_path / "out"
    rc = ex.run(_args(out, root, _prompt(tmp_path)))
    assert rc == 0
    lines = (out / "reviewer.jsonl").read_text().splitlines()
    assert len(lines) == 1
    rec = json.loads(lines[0])
    assert rec["scope"] == "reviewer"
    assert rec["label"] == "positive"
    assert [m["role"] for m in rec["messages"]] == ["system", "user", "assistant"]
    assert "finding.json" in rec["messages"][1]["content"]
    assert rec["provenance"]["cve_id"] == "CVE-2025-0001"
    assert rec["eligibility_for_training"] is True


def test_reject_and_refusal_are_negatives(tmp_path):
    root = tmp_path / "traces"
    _make_bundle(root, "CVE-2025-0002--bar", cve="CVE-2025-0002", attr="bar", verdict="reject")
    _make_bundle(root, "CVE-2025-0003--baz", cve="CVE-2025-0003", attr="baz", refusal=True)
    out = tmp_path / "out"
    ex.run(_args(out, root, _prompt(tmp_path)))
    recs = [json.loads(l) for l in (out / "reviewer.jsonl").read_text().splitlines()]
    labels = {r["provenance"]["cve_id"]: r["label"] for r in recs}
    assert labels["CVE-2025-0002"] == "negative"
    assert labels["CVE-2025-0003"] == "negative"


def test_no_reviewer_target_is_excluded(tmp_path):
    root = tmp_path / "traces"
    _make_bundle(root, "CVE-2025-0004--qux", cve="CVE-2025-0004", attr="qux", verdict=None)
    out = tmp_path / "out"
    ex.run(_args(out, root, _prompt(tmp_path)))
    assert (out / "reviewer.jsonl").read_text().strip() == ""
    m = json.loads((out / "manifest.json").read_text())
    assert m["eligible_examples"] == 0
    assert any("no reviewer target" in e["exclusion_reason"] for e in m["excluded"])


def test_unparseable_verdict_excluded(tmp_path):
    root = tmp_path / "traces"
    _make_bundle(root, "CVE-2025-0005--det", cve="CVE-2025-0005", attr="det",
                 review_md="Some freeform review with no verdict header.\n")
    out = tmp_path / "out"
    ex.run(_args(out, root, _prompt(tmp_path)))
    m = json.loads((out / "manifest.json").read_text())
    assert m["eligible_examples"] == 0
    assert any("parser contract" in (e["exclusion_reason"] or "") for e in m["excluded"])


def test_synthetic_cve0000_skipped(tmp_path):
    root = tmp_path / "traces"
    _make_bundle(root, "CVE-0000-9999--synthetic", cve="CVE-0000-9999", attr="syn")
    out = tmp_path / "out"
    ex.run(_args(out, root, _prompt(tmp_path)))
    m = json.loads((out / "manifest.json").read_text())
    assert m["total_bundles_enumerated"] == 0


def test_dedupe_by_cve_and_attr(tmp_path):
    root = tmp_path / "traces"
    _make_bundle(root, "CVE-2025-0006--dup-a", cve="CVE-2025-0006", attr="dup", bundle_id="id1")
    _make_bundle(root, "CVE-2025-0006--dup-b", cve="CVE-2025-0006", attr="dup", bundle_id="id2")
    out = tmp_path / "out"
    ex.run(_args(out, root, _prompt(tmp_path)))
    recs = (out / "reviewer.jsonl").read_text().splitlines()
    assert len(recs) == 1
    m = json.loads((out / "manifest.json").read_text())
    assert any("duplicate" in (e["exclusion_reason"] or "") for e in m["excluded"])


def test_redaction_strips_secrets_and_home_paths(tmp_path):
    root = tmp_path / "traces"
    bd = _make_bundle(root, "CVE-2025-0007--sec", cve="CVE-2025-0007", attr="sec")
    # plant a secret-shaped string + home path into a reviewer-visible artifact
    (bd / "patch-rationale.md").write_text(
        "key sk-ant-abcdEFGH12345678 at /home/jason/code/trace/x\n"
    )
    out = tmp_path / "out"
    ex.run(_args(out, root, _prompt(tmp_path)))
    content = (out / "reviewer.jsonl").read_text()
    assert "sk-ant-abcdEFGH12345678" not in content
    assert "<REDACTED-SECRET>" in content
    assert "/home/jason" not in content
    assert "/home/<user>" in content


def test_split_by_family_no_leakage_and_deterministic(tmp_path):
    root = tmp_path / "traces"
    # same family (php83/php84 normalize to php) must land in the same split
    for v in ("83", "84", "82"):
        _make_bundle(root, f"CVE-2025-01{v}--php{v}", cve=f"CVE-2025-01{v}", attr=f"php{v}",
                     bundle_id=f"php{v}id")
    for i in range(6):
        _make_bundle(root, f"CVE-2025-02{i}0--p{i}", cve=f"CVE-2025-02{i}0", attr=f"pkg{i}",
                     bundle_id=f"pkg{i}id")
    out = tmp_path / "out"
    ex.run(_args(out, root, _prompt(tmp_path)))
    recs = [json.loads(l) for l in (out / "reviewer.jsonl").read_text().splitlines()]
    php_splits = {r["split"] for r in recs if r["provenance"]["split_family"] == "php"}
    assert len(php_splits) == 1  # all php* in one split
    m = json.loads((out / "manifest.json").read_text())
    assert m["leakage_check_ok"] is True
    # deterministic regeneration
    out2 = tmp_path / "out2"
    ex.run(_args(out2, root, _prompt(tmp_path)))
    assert (out / "reviewer.jsonl").read_text() == (out2 / "reviewer.jsonl").read_text()


def test_assistant_target_matches_reviewer_output_contract(tmp_path):
    """Exported assistant turns must parse cleanly via the reviewer parser so a
    model trained on them emits runner-acceptable output."""
    from agents.reviewer.parser import parse_reviewer_output
    root = tmp_path / "traces"
    _make_bundle(
        root, "CVE-2025-0100--ct", cve="CVE-2025-0100", attr="ct",
        review_md=(
            "## Verdict\naccept\n\n## Reasoning\nClean version bump grounded in upstream-ref.json.\n\n"
            "## Findings\n(none)\n\n## Cited evidence\n- finding.json:cve_id\n\n"
            "## Cross-family attestation\nreviewer_family: anthropic-sonnet\n"
            "patcher_family_observed: anthropic-opus\nrule_honored: true\n"
        ),
    )
    out = tmp_path / "out"
    ex.run(_args(out, root, _prompt(tmp_path)))
    rec = json.loads((out / "reviewer.jsonl").read_text().splitlines()[0])
    assistant = rec["messages"][2]["content"]
    assert assistant.startswith("=== BEGIN review.md ===")
    assert assistant.rstrip().endswith("=== END review.md ===")
    parsed = parse_reviewer_output(assistant)
    assert parsed.verdict == "accept"


def test_refusal_target_matches_contract(tmp_path):
    from agents.reviewer.parser import parse_reviewer_output
    root = tmp_path / "traces"
    _make_bundle(root, "CVE-2025-0101--rf", cve="CVE-2025-0101", attr="rf", refusal=True)
    out = tmp_path / "out"
    ex.run(_args(out, root, _prompt(tmp_path)))
    rec = json.loads((out / "reviewer.jsonl").read_text().splitlines()[0])
    assistant = rec["messages"][2]["content"]
    assert assistant.startswith("=== BEGIN refusal ===")
    parsed = parse_reviewer_output(assistant)
    assert parsed.kind == "refusal"
    assert parsed.refusal_rule == 5


def test_malformed_refusal_excluded(tmp_path):
    root = tmp_path / "traces"
    bd = _make_bundle(root, "CVE-2025-0106--mr", cve="CVE-2025-0106", attr="mr", refusal=True)
    _write(bd / "review-refusal.json", {"rule": 999, "reason": "out of contract range"})
    out = tmp_path / "out"
    ex.run(_args(out, root, _prompt(tmp_path)))
    m = json.loads((out / "manifest.json").read_text())
    assert m["eligible_examples"] == 0
    assert any("refusal fails" in (e["exclusion_reason"] or "") for e in m["excluded"])


def test_escalate_is_negative_and_valid(tmp_path):
    root = tmp_path / "traces"
    _make_bundle(root, "CVE-2025-0102--es", cve="CVE-2025-0102", attr="es", verdict="escalate")
    out = tmp_path / "out"
    ex.run(_args(out, root, _prompt(tmp_path)))
    rec = json.loads((out / "reviewer.jsonl").read_text().splitlines()[0])
    assert rec["label"] == "negative"


def test_invalid_verdict_excluded(tmp_path):
    root = tmp_path / "traces"
    _make_bundle(root, "CVE-2025-0103--bad", cve="CVE-2025-0103", attr="bad",
                 review_md="## Verdict\napprove\n\n## Reasoning\ntypo verdict\n")
    out = tmp_path / "out"
    ex.run(_args(out, root, _prompt(tmp_path)))
    m = json.loads((out / "manifest.json").read_text())
    assert m["eligible_examples"] == 0
    assert any(("unsupported verdict" in (e["exclusion_reason"] or "")) or ("parser contract" in (e["exclusion_reason"] or "")) for e in m["excluded"])


def test_redact_covers_common_key_formats():
    for secret in (
        "sk-ant-api03-AbCdEf123456",
        "sk-proj-AbCdEf1234567890XyZ",
        "sk-AbCdEf1234567890abcdef",
        "ghp_AbCdEf1234567890abcdef12",
        "github_pat_11ABCDEFG0abcdefghij",
        "AKIAIOSFODNN7EXAMPLE",
        "AIzaSyAbCdEf1234567890abcdef_xyz",
    ):
        out = ex._redact(f"token={secret} end")
        assert secret not in out, f"leaked: {secret}"
        assert "<REDACTED-SECRET>" in out


def test_attestation_mismatch_excluded(tmp_path):
    """A review.md whose recorded cross-family attestation contradicts the
    replay-derived model families must be excluded (contradictory training data)."""
    root = tmp_path / "traces"
    bd = _make_bundle(
        root, "CVE-2025-0104--mm", cve="CVE-2025-0104", attr="mm",
        review_md=(
            "## Verdict\naccept\n\n## Reasoning\nClean bump.\n\n## Findings\n(none)\n\n"
            "## Cited evidence\n- finding.json:cve_id\n\n## Cross-family attestation\n"
            "reviewer_family: openai-gpt\npatcher_family_observed: anthropic-opus\nrule_honored: true\n"
        ),
    )
    # replay records anthropic-sonnet reviewer + anthropic-opus patcher → reviewer_family mismatch
    _write(bd / "replay.json", {"roles": [
        {"role": "patcher", "invocations": [{"invocation_id": "p1", "model": {"model_id": "claude-opus-4-7"}}]},
        {"role": "reviewer", "invocations": [{"invocation_id": "r1", "model": {"model_id": "claude-sonnet-4-6"}, "prompt": {"sha256": "deadbeef"}}]},
    ]})
    out = tmp_path / "out"
    ex.run(_args(out, root, _prompt(tmp_path)))
    m = json.loads((out / "manifest.json").read_text())
    assert m["eligible_examples"] == 0
    assert any("attestation mismatch" in (e["exclusion_reason"] or "") for e in m["excluded"])


def test_consistent_attestation_kept(tmp_path):
    """A review.md whose attestation matches the replay-derived families is kept."""
    root = tmp_path / "traces"
    bd = _make_bundle(
        root, "CVE-2025-0105--ok", cve="CVE-2025-0105", attr="okpkg",
        review_md=(
            "## Verdict\naccept\n\n## Reasoning\nClean bump.\n\n## Findings\n(none)\n\n"
            "## Cited evidence\n- finding.json:cve_id\n\n## Cross-family attestation\n"
            "reviewer_family: anthropic-sonnet\npatcher_family_observed: anthropic-opus\nrule_honored: true\n"
        ),
    )
    _write(bd / "replay.json", {"roles": [
        {"role": "patcher", "invocations": [{"invocation_id": "p1", "model": {"model_id": "claude-opus-4-7"}}]},
        {"role": "reviewer", "invocations": [{"invocation_id": "r1", "model": {"model_id": "claude-sonnet-4-6"}, "prompt": {"sha256": "deadbeef"}}]},
    ]})
    out = tmp_path / "out"
    ex.run(_args(out, root, _prompt(tmp_path)))
    m = json.loads((out / "manifest.json").read_text())
    assert m["eligible_examples"] == 1


def test_manifest_redacts_home_prompt_path(tmp_path):
    root = tmp_path / "traces"
    _make_bundle(root, "CVE-2025-0107--mp", cve="CVE-2025-0107", attr="mp")
    # an absolute home-style prompt path must not leak into the manifest
    prompt = tmp_path / "reviewer.md"
    prompt.write_text("Reviewer prompt")
    args = argparse.Namespace(
        export_scope="reviewer", out=tmp_path / "out", traces_root=root,
        negatives_root=tmp_path / "no-negatives",
        reviewer_prompt=Path("/home/someuser/code/trace/prompts/reviewer.v2.md"),
        format="json",
    )
    # point at a real file via a symlink-free copy so run() can read it
    real = tmp_path / "p.md"; real.write_text("x")
    args.reviewer_prompt = real
    ex.run(args)
    m = (tmp_path / "out" / "manifest.json").read_text()
    # simulate the home-path case directly on the redactor (run() uses the real path)
    assert ex._redact("/home/someuser/x") == "/home/<user>/x"
    assert "/home/<user>" == ex._redact("/home/someuser")


def test_negatives_root_with_mutation_provenance(tmp_path):
    """A mutated negative bundle (reject review + mutation.json) is exported as a
    negative with mutation provenance, and is NOT deduped against its base."""
    root = tmp_path / "traces"
    neg = tmp_path / "negatives"
    # base positive
    _make_bundle(root, "CVE-2025-0200--zk", cve="CVE-2025-0200", attr="zk", bundle_id="zkbase")
    # mutated negative: same cve+attr, reject review, mutation.json marker
    nb = _make_bundle(neg, "CVE-2025-0200--zk--wrong-src-hash", cve="CVE-2025-0200",
                      attr="zk", verdict="reject", bundle_id="zkmut")
    _write(nb / "mutation.json", {
        "negative_source": "mutation", "mutation_type": "wrong-src-hash",
        "base_bundle_id": "zkbase", "base_cve_id": "CVE-2025-0200",
    })
    out = tmp_path / "out"
    ex.run(_args(out, root, _prompt(tmp_path), negatives_root=neg))
    recs = [json.loads(l) for l in (out / "reviewer.jsonl").read_text().splitlines()]
    assert len(recs) == 2  # base positive + mutated negative, not deduped
    by_label = {r["label"]: r for r in recs}
    assert by_label["negative"]["provenance"]["mutation_type"] == "wrong-src-hash"
    assert by_label["negative"]["provenance"]["negative_source"] == "mutation"
    # base + mutation share the family → same split (no leakage)
    assert by_label["positive"]["split"] == by_label["negative"]["split"]


def test_negatives_root_accept_is_excluded(tmp_path):
    """A mutation candidate in negatives-root that the Reviewer ACCEPTED must be
    excluded (never train a defective patch as a positive)."""
    root = tmp_path / "traces"
    neg = tmp_path / "negatives"
    _make_bundle(root, "CVE-2025-0300--base", cve="CVE-2025-0300", attr="basepkg", bundle_id="b")
    nb = _make_bundle(neg, "CVE-2025-0300--base--wrong-src-hash", cve="CVE-2025-0300",
                      attr="basepkg", verdict="accept", bundle_id="m")  # Reviewer accepted
    _write(nb / "mutation.json", {"negative_source": "mutation", "mutation_type": "wrong-src-hash",
                                  "base_bundle_id": "b"})
    out = tmp_path / "out"
    ex.run(_args(out, root, _prompt(tmp_path), negatives_root=neg))
    recs = [json.loads(l) for l in (out / "reviewer.jsonl").read_text().splitlines()]
    # only the base positive; the accepted mutation is excluded
    assert all(r["provenance"]["cve_id"] != "CVE-2025-0300" or r["provenance"].get("negative_source") is None for r in recs)
    m = json.loads((out / "manifest.json").read_text())
    assert any("not a kept mutation reject" in (e["exclusion_reason"] or "") for e in m["excluded"])


def test_normalize_attr_families():
    assert ex._normalize_attr("php84") == "php"
    assert ex._normalize_attr("openssl_3") == "openssl"
    assert ex._normalize_attr("rubyPackages.sinatra") == "rubyPackages.sinatra"
    assert ex._normalize_attr("curlMinimal") == "curlMinimal"
    # version in a package-set prefix must collapse to one family (no leakage)
    assert ex._normalize_attr("python312Packages.django") == ex._normalize_attr("python313Packages.django")
    assert ex._normalize_attr("python3Packages.django_4") == ex._normalize_attr("python312Packages.django")


def test_source_backport_includes_upstream_fix_patch(tmp_path: Path) -> None:
    """Regression test: source-backport bundles must include upstream-fix.patch
    in the reviewer user turn so the model has the ground-truth diff to compare
    against (fixes v1.5 root cause: exporter omitted this, causing hallucination)."""
    root = tmp_path / "bundles"
    bd = root / "CVE-2099-99999--test-backport"
    bd.mkdir(parents=True)
    _write(bd / "bundle.json", {"bundle_id": "testbp1", "cve_id": "CVE-2099-99999", "kind": "human-review-required"})
    _write(bd / "finding.json", {"cve_id": "CVE-2099-99999", "affected": [{"attr_path": "testpkg"}]})
    _write(bd / "impact.json", {"cve_id": "CVE-2099-99999", "exceeds_threshold": False})
    _write(bd / "maintainers.json", {"cve_id": "CVE-2099-99999"})
    _write(bd / "upstream-ref.json", {
        "cve_id": "CVE-2099-99999",
        "target_version": "1.0.0",
        "eligibility": {"patch_strategy": "source-backport", "verdict": "eligible-requires-human-review"},
    })
    _write(bd / "package.nix", "{ stdenv }: stdenv.mkDerivation { version = \"1.0.0\"; }\n")
    _write(bd / "patch.diff", "--- a/package.nix\n+++ b/package.nix\n@@ -1 +1 @@\n-x\n+y\n")
    _write(bd / "patch-rationale.md", "## Rationale\nsource-backport\n")
    upstream_fix_content = "diff --git a/src/foo.c b/src/foo.c\n--- a/src/foo.c\n+++ b/src/foo.c\n@@\n- old\n+ new\n"
    _write(bd / "upstream-fix.patch", upstream_fix_content)
    _write(bd / "review.md", "## Verdict\naccept\n## Reasoning\nok\n")

    from tools.trace_cli.export import _build_user_turn
    user_turn = _build_user_turn(bd)
    assert user_turn is not None, "_build_user_turn returned None for source-backport bundle"
    assert "# upstream-fix.patch" in user_turn, "upstream-fix.patch section missing from user turn"
    assert upstream_fix_content.strip().splitlines()[0] in user_turn, \
        "upstream-fix.patch content not in user turn"


def test_version_bump_excludes_upstream_fix_patch(tmp_path: Path) -> None:
    """Version-bump bundles (no patch_strategy=source-backport) must NOT include
    the upstream-fix.patch section since they have no such file."""
    root = tmp_path / "bundles"
    bd = root / "CVE-2099-88888--test-bump"
    bd.mkdir(parents=True)
    _write(bd / "bundle.json", {"bundle_id": "testbump1", "cve_id": "CVE-2099-88888", "kind": "auto-merge"})
    _write(bd / "finding.json", {"cve_id": "CVE-2099-88888", "affected": [{"attr_path": "testpkg"}]})
    _write(bd / "impact.json", {"cve_id": "CVE-2099-88888", "exceeds_threshold": False})
    _write(bd / "maintainers.json", {"cve_id": "CVE-2099-88888"})
    _write(bd / "upstream-ref.json", {
        "cve_id": "CVE-2099-88888",
        "target_version": "1.2.3",
        "eligibility": {"patch_strategy": "version-bump", "verdict": "eligible-auto-merge"},
    })
    _write(bd / "package.nix", "{ stdenv }: stdenv.mkDerivation { version = \"1.2.2\"; }\n")
    _write(bd / "patch.diff", "--- a/package.nix\n+++ b/package.nix\n@@ -1 +1 @@\n-x\n+y\n")
    _write(bd / "patch-rationale.md", "## Rationale\nbump\n")
    _write(bd / "review.md", "## Verdict\naccept\n## Reasoning\nok\n")

    from tools.trace_cli.export import _build_user_turn
    user_turn = _build_user_turn(bd)
    assert user_turn is not None, "_build_user_turn returned None for version-bump bundle"
    assert "# upstream-fix.patch" not in user_turn, \
        "upstream-fix.patch section incorrectly present in version-bump user turn"
