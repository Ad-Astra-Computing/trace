"""Validate eval/candidates.jsonl and eval/rejection-log.jsonl line-by-line.

Shape-only, always on. Additional composition/selection checks only fire
under TRACE_REQUIRE_FULL_CORPUS=1 — matching the existing corpus test gate.

Properties asserted under the full-corpus gate:
  * every cve_id in corpus.json (non-example) must appear in candidates.jsonl
  * every cve_id in rejection-log.jsonl must NOT appear in corpus.json
  * no cve_id is BOTH selected and rejected
"""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator

from tests.schema.validate import REPO_ROOT


CANDIDATES_PATH = REPO_ROOT / "eval" / "candidates.jsonl"
REJECTIONS_PATH = REPO_ROOT / "eval" / "rejection-log.jsonl"
CORPUS_PATH = REPO_ROOT / "eval" / "corpus.json"
CANDIDATE_SCHEMA = REPO_ROOT / "policy" / "eval-candidate-schema.json"
REJECTION_SCHEMA = REPO_ROOT / "policy" / "eval-rejection-schema.json"


def _iter_lines(path: Path) -> list[tuple[int, dict]]:
    """Returns (1-based line number, parsed JSON) for every non-empty line."""
    out: list[tuple[int, dict]] = []
    if not path.exists():
        return out
    for i, line in enumerate(path.read_text().splitlines(), start=1):
        if not line.strip():
            continue
        out.append((i, json.loads(line)))
    return out


@pytest.fixture(scope="module")
def candidate_validator() -> Draft202012Validator:
    return Draft202012Validator(json.loads(CANDIDATE_SCHEMA.read_text()))


@pytest.fixture(scope="module")
def rejection_validator() -> Draft202012Validator:
    return Draft202012Validator(json.loads(REJECTION_SCHEMA.read_text()))


@pytest.fixture(scope="module")
def frozen_required() -> bool:
    try:
        status = json.loads(CORPUS_PATH.read_text()).get("status")
    except Exception:
        status = None
    return status == "frozen" or os.environ.get("TRACE_REQUIRE_FULL_CORPUS") == "1"


# ─── shape layer (always) ───────────────────────────────────────────────────


def test_candidate_schema_is_well_formed():
    Draft202012Validator.check_schema(json.loads(CANDIDATE_SCHEMA.read_text()))


def test_rejection_schema_is_well_formed():
    Draft202012Validator.check_schema(json.loads(REJECTION_SCHEMA.read_text()))


def test_every_candidate_line_validates(candidate_validator):
    errors: list[str] = []
    for lineno, doc in _iter_lines(CANDIDATES_PATH):
        for e in candidate_validator.iter_errors(doc):
            path = "/".join(str(p) for p in e.absolute_path)
            errors.append(f"line {lineno}: {path}: {e.message}")
    assert not errors, (
        "eval/candidates.jsonl has invalid lines:\n  " + "\n  ".join(errors)
    )


def test_every_rejection_line_validates(rejection_validator):
    errors: list[str] = []
    for lineno, doc in _iter_lines(REJECTIONS_PATH):
        for e in rejection_validator.iter_errors(doc):
            path = "/".join(str(p) for p in e.absolute_path)
            errors.append(f"line {lineno}: {path}: {e.message}")
    assert not errors, (
        "eval/rejection-log.jsonl has invalid lines:\n  " + "\n  ".join(errors)
    )


def test_candidates_have_no_duplicate_cve_ids():
    seen: dict[str, int] = {}
    dupes: list[tuple[str, int, int]] = []
    for lineno, doc in _iter_lines(CANDIDATES_PATH):
        cve = doc["cve_id"]
        if cve in seen:
            dupes.append((cve, seen[cve], lineno))
        else:
            seen[cve] = lineno
    assert not dupes, (
        "duplicate cve_ids in candidates.jsonl: "
        + ", ".join(f"{c} (lines {a}, {b})" for c, a, b in dupes)
    )


# ─── selection-integrity layer (frozen-gated) ──────────────────────────────


def test_every_selected_corpus_entry_was_a_candidate(frozen_required):
    if not frozen_required:
        pytest.skip("corpus not frozen and TRACE_REQUIRE_FULL_CORPUS not set")
    corpus = json.loads(CORPUS_PATH.read_text())
    selected = {e["cve_id"] for e in corpus["entries"] if not e.get("is_example")}
    candidates = {doc["cve_id"] for _, doc in _iter_lines(CANDIDATES_PATH)}
    missing = selected - candidates
    assert not missing, (
        f"corpus entries with no candidates.jsonl record: {sorted(missing)}. "
        f"Every selected CVE must have been harvested through the candidate pool."
    )


def test_rejected_cves_are_not_in_the_corpus(frozen_required):
    if not frozen_required:
        pytest.skip("corpus not frozen and TRACE_REQUIRE_FULL_CORPUS not set")
    corpus = json.loads(CORPUS_PATH.read_text())
    selected = {e["cve_id"] for e in corpus["entries"] if not e.get("is_example")}
    rejected = {doc["cve_id"] for _, doc in _iter_lines(REJECTIONS_PATH)}
    conflict = selected & rejected
    assert not conflict, (
        f"cve_ids both rejected and selected: {sorted(conflict)}"
    )
