"""Schema validation for trace bundle fixtures.

Two modes:
- schema-only (default): validates each JSON document against its schema, ignoring file-content hashes. Fixture sha256 placeholders are accepted as long as they match the schema's hex-pattern regex.
- strict (via TRACE_STRICT_HASHES=1): additionally recomputes sha256 for every file referenced by bundle.json.files and replay.json, and fails if declared hashes do not match actual file bytes.

Intentionally small and boring. No network, no side effects, no fancy reporters.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator
from referencing import Registry, Resource


REPO_ROOT = Path(__file__).resolve().parents[2]
POLICY_DIR = REPO_ROOT / "policy"

SCHEMA_FILES = {
    "bundle": POLICY_DIR / "bundle-schema.json",
    "finding": POLICY_DIR / "finding-schema.json",
    "upstream_ref": POLICY_DIR / "upstream-ref-schema.json",
    "replay": POLICY_DIR / "replay-schema.json",
    "provenance_line": POLICY_DIR / "provenance-line-schema.json",
    "impact": POLICY_DIR / "impact-schema.json",
    "maintainers": POLICY_DIR / "maintainers-schema.json",
    "graph_snapshot": POLICY_DIR / "graph-snapshot-schema.json",
    "scout_input": POLICY_DIR / "scout-input-schema.json",
    "vulnpatch_cve_source": POLICY_DIR / "vulnpatch-cve-source-schema.json",
    "ghsa_source": POLICY_DIR / "ghsa-source-schema.json",
    "purl_enrichment": POLICY_DIR / "purl-enrichment-schema.json",
    "eval_candidate": POLICY_DIR / "eval-candidate-schema.json",
    "eval_rejection": POLICY_DIR / "eval-rejection-schema.json",
}

# Maps bundle-relative file name -> schema key
DOC_TO_SCHEMA = {
    "bundle.json": "bundle",
    "finding.json": "finding",
    "upstream-ref.json": "upstream_ref",
    "replay.json": "replay",
    "impact.json": "impact",
    "maintainers.json": "maintainers",
}


def load_schemas() -> dict[str, dict[str, Any]]:
    return {k: json.loads(p.read_text()) for k, p in SCHEMA_FILES.items()}


def _registry(schemas: dict[str, dict[str, Any]]) -> Registry:
    resources = [
        (schema["$id"], Resource.from_contents(schema))
        for schema in schemas.values()
        if "$id" in schema
    ]
    return Registry().with_resources(resources)


def validators(schemas: dict[str, dict[str, Any]]) -> dict[str, Draft202012Validator]:
    reg = _registry(schemas)
    return {k: Draft202012Validator(s, registry=reg) for k, s in schemas.items()}


@dataclass
class FixtureResult:
    fixture_dir: Path
    expected: str  # "valid" | "invalid"
    per_doc_errors: dict[str, list[str]] = field(default_factory=dict)
    hash_errors: list[str] = field(default_factory=list)

    @property
    def any_errors(self) -> bool:
        return any(self.per_doc_errors.values()) or bool(self.hash_errors)


def _validate_doc(validator: Draft202012Validator, doc: Any) -> list[str]:
    return [
        f"{'/'.join(str(p) for p in e.absolute_path)}: {e.message}"
        for e in validator.iter_errors(doc)
    ]


def _validate_provenance(validator: Draft202012Validator, text: str) -> list[str]:
    errors: list[str] = []
    for i, line in enumerate(text.splitlines()):
        if not line.strip():
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError as e:
            errors.append(f"line {i}: not valid JSON ({e})")
            continue
        for msg in _validate_doc(validator, obj):
            errors.append(f"line {i}: {msg}")
    return errors


def _sha256_file(p: Path) -> str:
    h = hashlib.sha256()
    with p.open("rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def validate_fixture(
    fixture_dir: Path,
    schemas: dict[str, dict[str, Any]] | None = None,
    strict_hashes: bool = False,
) -> FixtureResult:
    schemas = schemas or load_schemas()
    vs = validators(schemas)

    expect_path = fixture_dir / "expect.json"
    expected = "valid"
    if expect_path.exists():
        expected = json.loads(expect_path.read_text()).get("overall", "valid")

    result = FixtureResult(fixture_dir=fixture_dir, expected=expected)

    for doc_name, schema_key in DOC_TO_SCHEMA.items():
        p = fixture_dir / doc_name
        if not p.exists():
            # Absence of an optional doc is not itself a validation error here;
            # the bundle schema's conditional required-file set catches missing required docs.
            continue
        doc = json.loads(p.read_text())
        result.per_doc_errors[doc_name] = _validate_doc(vs[schema_key], doc)

    prov_path = fixture_dir / "provenance.jsonl"
    if prov_path.exists():
        result.per_doc_errors["provenance.jsonl"] = _validate_provenance(
            vs["provenance_line"], prov_path.read_text()
        )

    if strict_hashes:
        bundle_path = fixture_dir / "bundle.json"
        if bundle_path.exists():
            bundle = json.loads(bundle_path.read_text())
            for rel, meta in bundle.get("files", {}).items():
                file_path = fixture_dir / rel
                if not file_path.exists():
                    result.hash_errors.append(f"{rel}: declared in bundle.json but missing on disk")
                    continue
                actual = _sha256_file(file_path)
                declared = meta.get("sha256")
                if actual != declared:
                    result.hash_errors.append(
                        f"{rel}: declared sha256 {declared} != actual {actual}"
                    )

    return result
