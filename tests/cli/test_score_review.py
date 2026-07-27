"""`trace score review` CLI tests.

Covers the reviewer-scoring runner command: happy path (writes an atomic
review-scoring-report.json for the last reviewer invocation), the no-silent-
overwrite guard (--force), missing/malformed replay, no reviewer invocation,
the misattribution guard (on-disk review.md must match the recorded
invocation output), and malformed replay shapes that must be reported rather
than crash.
"""

from __future__ import annotations

import json
from hashlib import sha256
from pathlib import Path

import pytest

from tools.trace_cli.cli import (
    EXIT_HASH_MISMATCH,
    EXIT_INVALID,
    EXIT_NOT_FOUND,
    EXIT_OK,
    main,
)


def _run(argv: list[str], capsys: pytest.CaptureFixture[str]) -> tuple[int, str, str]:
    rc = main(argv)
    captured = capsys.readouterr()
    return rc, captured.out, captured.err


_REVIEW_MD = """## Summary

verdict: accept

## Reasoning

The patch is grounded in the finding.

## Findings

(none)

## Cited evidence

- finding.json.summary

## Cross-family attestation

reviewer_family: anthropic-sonnet
patcher_family_observed: anthropic-opus
rule_honored: true
"""


def _build_bundle(tmp_path: Path, *, review_md: str = _REVIEW_MD) -> Path:
    """A minimal bundle with a reviewer invocation in replay.json whose
    recorded review.md output AND finding.json input sha256s match the files
    on disk."""
    b = tmp_path / "CVE-2025-0001--demo"
    b.mkdir()
    (b / "review.md").write_text(review_md)
    finding_bytes = json.dumps({"cve_id": "CVE-2025-0001"}).encode("utf-8")
    (b / "finding.json").write_bytes(finding_bytes)
    (b / "bundle.json").write_text(json.dumps({"bundle_id": "abc123", "kind": "auto-merge"}))
    recorded = sha256(review_md.encode("utf-8")).hexdigest()
    replay = {
        "roles": [
            {
                "role": "reviewer",
                "invocations": [
                    {
                        "invocation_id": "inv-1",
                        "model": {"model_id": "claude-sonnet-4-5-20250929"},
                        "prompt": {"sha256": "deadbeef"},
                        "inputs": [
                            {"path": "finding.json", "sha256": sha256(finding_bytes).hexdigest()},
                        ],
                        "outputs": [{"path": "review.md", "sha256": recorded}],
                    }
                ],
            }
        ]
    }
    (b / "replay.json").write_text(json.dumps(replay))
    return b


def test_score_review_happy_path_writes_report(tmp_path, capsys):
    b = _build_bundle(tmp_path)
    rc, out, err = _run(["score", "review", str(b)], capsys)
    assert rc == EXIT_OK, err
    report_path = b / "review-scoring-report.json"
    assert report_path.is_file()
    report = json.loads(report_path.read_text())
    assert report["scope"] == "reviewer"
    assert report["cve_id"] == "CVE-2025-0001"
    assert report["invocation_id"] == "inv-1"
    names = {s["scorer_name"] for s in report["scorers"]}
    assert "review-adaptation-equivalence" in names
    # provenance carries input hashes
    assert report["provenance"]["review_md_sha256"] == sha256(_REVIEW_MD.encode()).hexdigest()
    assert report["provenance"]["scorer_schema_version"]


def test_score_review_no_overwrite_without_force(tmp_path, capsys):
    b = _build_bundle(tmp_path)
    rc1, _, _ = _run(["score", "review", str(b)], capsys)
    assert rc1 == EXIT_OK
    rc2, _, err = _run(["score", "review", str(b)], capsys)
    assert rc2 == EXIT_INVALID
    assert "already exists" in err and "--force" in err


def test_score_review_force_overwrites(tmp_path, capsys):
    b = _build_bundle(tmp_path)
    assert _run(["score", "review", str(b)], capsys)[0] == EXIT_OK
    rc, _, err = _run(["score", "review", str(b), "--force"], capsys)
    assert rc == EXIT_OK, err


def test_score_review_missing_replay(tmp_path, capsys):
    b = tmp_path / "empty"
    b.mkdir()
    rc, _, err = _run(["score", "review", str(b)], capsys)
    assert rc == EXIT_NOT_FOUND
    assert "replay.json not found" in err


def test_score_review_non_object_replay(tmp_path, capsys):
    b = tmp_path / "bad"
    b.mkdir()
    (b / "replay.json").write_text("[]")
    rc, _, err = _run(["score", "review", str(b)], capsys)
    assert rc == EXIT_INVALID
    assert "not a JSON object" in err


def test_score_review_no_reviewer_invocation(tmp_path, capsys):
    b = tmp_path / "norev"
    b.mkdir()
    (b / "replay.json").write_text(json.dumps({"roles": [{"role": "patcher", "invocations": [{"x": 1}]}]}))
    rc, _, err = _run(["score", "review", str(b)], capsys)
    assert rc == EXIT_INVALID
    assert "no reviewer invocation" in err


def test_score_review_scalar_final_invocation_reported(tmp_path, capsys):
    b = tmp_path / "scalar"
    b.mkdir()
    (b / "replay.json").write_text(
        json.dumps({"roles": [{"role": "reviewer", "invocations": [None]}]})
    )
    rc, _, err = _run(["score", "review", str(b)], capsys)
    # A scalar/null final entry is not a usable invocation -> reported, not a crash.
    assert rc == EXIT_INVALID
    assert "no reviewer invocation" in err


def test_score_review_misattribution_guard(tmp_path, capsys):
    """review.md modified after the recorded run must be rejected, not scored
    under the stale invocation's identity."""
    b = _build_bundle(tmp_path)
    (b / "review.md").write_text(_REVIEW_MD + "\n<!-- tampered -->\n")
    rc, _, err = _run(["score", "review", str(b)], capsys)
    assert rc == EXIT_HASH_MISMATCH
    assert "does not match the recorded invocation output" in err
    assert not (b / "review-scoring-report.json").exists()


def test_score_review_input_mismatch_guard(tmp_path, capsys):
    """A recorded INPUT modified after the run must be rejected — several
    scorers derive from inputs, so the report would misattribute otherwise."""
    b = _build_bundle(tmp_path)
    (b / "finding.json").write_text(json.dumps({"cve_id": "CVE-2025-0001", "tampered": True}))
    rc, _, err = _run(["score", "review", str(b)], capsys)
    assert rc == EXIT_HASH_MISMATCH
    assert "finding.json" in err
    assert not (b / "review-scoring-report.json").exists()


def test_score_review_malformed_output_record_rejected(tmp_path, capsys):
    """A non-empty outputs[] whose entry omits path/sha256 is unverifiable and
    must error, not silently score an arbitrary on-disk review.md."""
    b = _build_bundle(tmp_path)
    replay = json.loads((b / "replay.json").read_text())
    replay["roles"][0]["invocations"][0]["outputs"] = [{}]
    (b / "replay.json").write_text(json.dumps(replay))
    rc, _, err = _run(["score", "review", str(b)], capsys)
    assert rc == EXIT_HASH_MISMATCH
    assert "malformed output record" in err
    assert not (b / "review-scoring-report.json").exists()


def test_score_review_non_canonical_output_rejected(tmp_path, capsys):
    """An invocation whose only (verified) output is a non-review file cannot
    stand in for review.md — the scorers read review.md from disk."""
    b = _build_bundle(tmp_path)
    finding_sha = sha256((b / "finding.json").read_bytes()).hexdigest()
    replay = json.loads((b / "replay.json").read_text())
    replay["roles"][0]["invocations"][0]["outputs"] = [
        {"path": "finding.json", "sha256": finding_sha}
    ]
    (b / "replay.json").write_text(json.dumps(replay))
    rc, _, err = _run(["score", "review", str(b)], capsys)
    assert rc == EXIT_HASH_MISMATCH
    assert "no verified canonical output" in err
    assert not (b / "review-scoring-report.json").exists()


def test_score_review_non_list_inputs_rejected(tmp_path, capsys):
    """A present-but-non-list inputs value is malformed, not 'no inputs'."""
    b = _build_bundle(tmp_path)
    replay = json.loads((b / "replay.json").read_text())
    replay["roles"][0]["invocations"][0]["inputs"] = {"finding.json": "x"}
    (b / "replay.json").write_text(json.dumps(replay))
    rc, _, err = _run(["score", "review", str(b)], capsys)
    assert rc == EXIT_HASH_MISMATCH
    assert "malformed inputs record" in err
    assert not (b / "review-scoring-report.json").exists()


def test_score_review_missing_inputs_rejected(tmp_path, capsys):
    """An invocation that records no inputs cannot pin the evidence the scorers
    read, so it is rejected rather than scored under an unverifiable identity."""
    b = _build_bundle(tmp_path)
    replay = json.loads((b / "replay.json").read_text())
    del replay["roles"][0]["invocations"][0]["inputs"]
    (b / "replay.json").write_text(json.dumps(replay))
    rc, _, err = _run(["score", "review", str(b)], capsys)
    assert rc == EXIT_HASH_MISMATCH
    assert "records no inputs" in err


def test_score_review_empty_inputs_rejected(tmp_path, capsys):
    b = _build_bundle(tmp_path)
    replay = json.loads((b / "replay.json").read_text())
    replay["roles"][0]["invocations"][0]["inputs"] = []
    (b / "replay.json").write_text(json.dumps(replay))
    rc, _, err = _run(["score", "review", str(b)], capsys)
    assert rc == EXIT_HASH_MISMATCH
    assert "empty inputs list" in err


def test_score_review_unpinned_canonical_input_rejected(tmp_path, capsys):
    """A canonical reviewer input present on disk (patch.diff) but NOT recorded
    by the invocation could be modified undetected — reject rather than score."""
    b = _build_bundle(tmp_path)
    (b / "patch.diff").write_text("--- a/x\n+++ b/x\n@@ -1 +1 @@\n-a\n+b\n")
    # replay still records only finding.json as an input.
    rc, _, err = _run(["score", "review", str(b)], capsys)
    assert rc == EXIT_HASH_MISMATCH
    assert "patch.diff" in err and "not recorded" in err
    assert not (b / "review-scoring-report.json").exists()


def test_score_review_unpinned_source_context_rejected(tmp_path, capsys):
    """Adaptation-lane bundles feed every source-context/** file to the
    reviewer; an unrecorded one present on disk must be rejected."""
    b = _build_bundle(tmp_path)
    # Make it a source-backport adaptation-lane bundle.
    (b / "upstream-ref.json").write_text(json.dumps({
        "eligibility": {"patch_strategy": "source-backport"}
    }))
    (b / "preflight.json").write_text(json.dumps({"applies_verbatim": False}))
    sc = b / "source-context" / "src"
    sc.mkdir(parents=True)
    (sc / "x.c").write_text("int main(void){}\n")
    rc, _, err = _run(["score", "review", str(b)], capsys)
    assert rc == EXIT_HASH_MISMATCH
    # upstream-ref.json + preflight.json + source-context/src/x.c are all
    # adaptation-lane inputs present on disk but not recorded.
    assert "source-context/src/x.c" in err
    assert not (b / "review-scoring-report.json").exists()


def test_score_review_scalar_prompt_does_not_crash(tmp_path, capsys):
    """A malformed (scalar) prompt/model record must not crash the runner —
    it degrades to a null prompt_sha/model_id."""
    b = _build_bundle(tmp_path)
    replay = json.loads((b / "replay.json").read_text())
    replay["roles"][0]["invocations"][0]["prompt"] = "not-a-dict"
    replay["roles"][0]["invocations"][0]["model"] = ["also-bad"]
    (b / "replay.json").write_text(json.dumps(replay))
    rc, _, err = _run(["score", "review", str(b), "--force"], capsys)
    assert rc == EXIT_OK, err
    report = json.loads((b / "review-scoring-report.json").read_text())
    assert report["prompt_sha"] is None
    assert report["model_id"] is None


def test_score_review_rejects_path_traversal_in_record(tmp_path, capsys):
    """A recorded artifact path escaping the bundle must be refused, not read
    (and its hash must not be leaked)."""
    secret = tmp_path / "secret"
    secret.write_text("top secret\n")
    b = _build_bundle(tmp_path)
    replay = json.loads((b / "replay.json").read_text())
    replay["roles"][0]["invocations"][0]["inputs"].append(
        {"path": "../secret", "sha256": "0" * 64}
    )
    (b / "replay.json").write_text(json.dumps(replay))
    rc, _, err = _run(["score", "review", str(b)], capsys)
    assert rc == EXIT_HASH_MISMATCH
    assert "escapes the bundle" in err
    # the secret's real hash must not appear in output
    assert sha256(secret.read_bytes()).hexdigest()[:12] not in err


def test_score_review_verbatim_preflight_not_required(tmp_path, capsys):
    """A verbatim source-backport can carry preflight.json (applies_verbatim=
    true) that the reviewer never consumed; it must not be required as a pinned
    input (that would falsely reject a valid invocation)."""
    b = _build_bundle(tmp_path)
    # Verbatim lane: preflight present with applies_verbatim=true, NOT recorded.
    (b / "preflight.json").write_text(json.dumps({"applies_verbatim": True}))
    rc, _, err = _run(["score", "review", str(b)], capsys)
    assert rc == EXIT_OK, err
    assert (b / "review-scoring-report.json").is_file()


def test_score_review_malformed_patcher_role_does_not_crash(tmp_path, capsys):
    """A valid reviewer invocation alongside a MALFORMED patcher role must
    score cleanly (the cross-family scorer fails closed) rather than crash."""
    b = _build_bundle(tmp_path)
    replay = json.loads((b / "replay.json").read_text())
    replay["roles"].append({"role": "patcher", "invocations": [None]})
    (b / "replay.json").write_text(json.dumps(replay))
    rc, _, err = _run(["score", "review", str(b), "--force"], capsys)
    assert rc == EXIT_OK, err
    assert (b / "review-scoring-report.json").is_file()
