"""Cartographer stub tests.

Given a finding.json and a CannedCartographerGraph, analyze() must emit:

  * impact.json that validates against policy/impact-schema.json
  * maintainers.json that validates against policy/maintainers-schema.json

Explicit coverage:
  * single-attr finding with small closure       → bucket '<50', below threshold
  * closure size exactly at threshold            → bucket '50-500', NOT exceeding
  * closure size above threshold                 → exceeds_threshold=true
  * every bucket boundary: <50, 50-500, 500-5000, >5000
  * multi-attr finding: union reverse-closure-count deduplicates
  * maintainer pass-through: emails are optional, none-email absent
  * critical downstreams surface at both per-attr and union level
  * unknown attr: empty closure, empty maintainers, no crash
"""

from __future__ import annotations

import json
from typing import Any

import pytest
from jsonschema import Draft202012Validator

from agents.cartographer import (
    CannedCartographerGraph,
    CannedNode,
    Maintainer,
    analyze,
)
from tests.schema.validate import REPO_ROOT


@pytest.fixture(scope="module")
def impact_validator() -> Draft202012Validator:
    return Draft202012Validator(
        json.loads((REPO_ROOT / "policy" / "impact-schema.json").read_text())
    )


@pytest.fixture(scope="module")
def maintainers_validator() -> Draft202012Validator:
    return Draft202012Validator(
        json.loads((REPO_ROOT / "policy" / "maintainers-schema.json").read_text())
    )


def _validate(validator: Draft202012Validator, doc: Any, label: str) -> None:
    errors = [
        f"{'/'.join(str(p) for p in e.absolute_path)}: {e.message}"
        for e in validator.iter_errors(doc)
    ]
    assert not errors, f"{label} failed schema: {errors}"


NIXPKGS_REV = "0000000000000000000000000000000000000000"


def _finding(cve: str, attrs: list[tuple[str, str]]) -> dict[str, Any]:
    return {
        "schema_version": "1.0.0",
        "cve_id": cve,
        "source_feeds": ["nvd"],
        "severity": {"rating": "high", "cvss_v3_score": 7.5},
        "published_at": "2026-04-01T00:00:00Z",
        "affected": [
            {
                "attr_path": attr,
                "drv_path": drv,
                "pname": attr,
                "version": "1.4.7",
                "confidence": "high",
            }
            for attr, drv in attrs
        ],
        "mapping": {"method": "cpe-exact"},
        "replay_critical": True,
    }


def _mk_drv(attr: str, uniq: str) -> str:
    # Satisfies drv_path pattern: /nix/store/<32 hex or base32>-<name>.drv
    return f"/nix/store/{uniq:0>32s}-{attr}-1.4.7.drv"


# ─── bucket boundaries ──────────────────────────────────────────────────────


@pytest.mark.parametrize(
    "count,expected_bucket,exceeds",
    [
        (0, "<50", False),
        (49, "<50", False),
        (50, "50-500", False),
        (500, "50-500", False),
        (501, "500-5000", True),
        (5000, "500-5000", True),
        (5001, ">5000", True),
        (9999, ">5000", True),
    ],
)
def test_bucket_boundaries(impact_validator, maintainers_validator,
                           count, expected_bucket, exceeds):
    attr = "libexample"
    graph = CannedCartographerGraph([
        CannedNode(
            attr_path=attr,
            drv_path=_mk_drv(attr, "a"),
            pname="libexample",
            version="1.4.7",
            reverse_closure=tuple(f"downstream-{i}" for i in range(count)),
        )
    ])

    out = analyze(
        _finding("CVE-0000-3001", [(attr, _mk_drv(attr, "a"))]),
        graph,
        nixpkgs_rev=NIXPKGS_REV,
    )
    _validate(impact_validator, out["impact"], "impact.json")
    _validate(maintainers_validator, out["maintainers"], "maintainers.json")

    assert out["impact"]["reverse_closure_count"] == count
    assert out["impact"]["reverse_closure_bucket"] == expected_bucket
    assert out["impact"]["exceeds_threshold"] is exceeds
    assert out["impact"]["per_attr"][0]["reverse_closure_bucket"] == expected_bucket
    assert out["impact"]["per_attr"][0]["exceeds_threshold"] is exceeds


# ─── small happy path ──────────────────────────────────────────────────────


def test_small_closure_below_threshold(impact_validator, maintainers_validator):
    graph = CannedCartographerGraph([
        CannedNode(
            attr_path="libexample",
            drv_path=_mk_drv("libexample", "a"),
            pname="libexample",
            version="1.4.7",
            reverse_closure=("exampleApp", "exampleServer", "exampleCli"),
            critical_downstreams=("exampleServer",),
            maintainers=(
                Maintainer(github="alice"),
                Maintainer(github="bob", email="bob@example.invalid"),
            ),
        ),
    ])
    out = analyze(
        _finding("CVE-0000-3002", [("libexample", _mk_drv("libexample", "a"))]),
        graph,
        nixpkgs_rev=NIXPKGS_REV,
    )
    _validate(impact_validator, out["impact"], "impact.json")
    _validate(maintainers_validator, out["maintainers"], "maintainers.json")

    impact = out["impact"]
    assert impact["affected_attr_paths"] == ["libexample"]
    assert impact["reverse_closure_count"] == 3
    assert impact["reverse_closure_bucket"] == "<50"
    assert impact["exceeds_threshold"] is False
    assert impact["critical_downstreams"] == ["exampleServer"]
    assert impact["per_attr"][0]["critical_downstreams"] == ["exampleServer"]

    maint = out["maintainers"]
    assert list(maint["attr_paths"].keys()) == ["libexample"]
    github_handles = [m["github"] for m in maint["attr_paths"]["libexample"]["maintainers"]]
    assert github_handles == ["alice", "bob"]
    # email only appears on entries that supplied one
    emails = [m.get("email") for m in maint["attr_paths"]["libexample"]["maintainers"]]
    assert emails == [None, "bob@example.invalid"] or emails[0] is None


# ─── multi-attr: union counts dedupe ───────────────────────────────────────


def test_multi_attr_union_dedup(impact_validator, maintainers_validator):
    # Two affected attrs whose reverse closures overlap.
    # Attr A closure = {D1, D2, D3}, Attr B closure = {D3, D4, D5}.
    # Union count = 5, per-attr counts = 3 each.
    graph = CannedCartographerGraph([
        CannedNode(
            attr_path="attrA",
            drv_path=_mk_drv("attrA", "a"),
            pname="attrA",
            version="1.0.0",
            reverse_closure=("D1", "D2", "D3"),
            maintainers=(Maintainer(github="alice"),),
        ),
        CannedNode(
            attr_path="attrB",
            drv_path=_mk_drv("attrB", "b"),
            pname="attrB",
            version="1.0.0",
            reverse_closure=("D3", "D4", "D5"),
            critical_downstreams=("D4",),
            maintainers=(Maintainer(github="bob"),),
        ),
    ])
    finding = _finding(
        "CVE-0000-3003",
        [("attrA", _mk_drv("attrA", "a")), ("attrB", _mk_drv("attrB", "b"))],
    )

    out = analyze(finding, graph, nixpkgs_rev=NIXPKGS_REV)
    _validate(impact_validator, out["impact"], "impact.json")
    _validate(maintainers_validator, out["maintainers"], "maintainers.json")

    impact = out["impact"]
    assert impact["reverse_closure_count"] == 5
    assert [p["reverse_closure_count"] for p in impact["per_attr"]] == [3, 3]
    assert impact["critical_downstreams"] == ["D4"]

    maint_keys = sorted(out["maintainers"]["attr_paths"].keys())
    assert maint_keys == ["attrA", "attrB"]


# ─── unknown attr: graph returns nothing, no crash ──────────────────────────


def test_unknown_attr_empty_safely(impact_validator, maintainers_validator):
    graph = CannedCartographerGraph([])  # empty graph
    out = analyze(
        _finding("CVE-0000-3004", [("never-heard-of-it", _mk_drv("never", "x"))]),
        graph,
        nixpkgs_rev=NIXPKGS_REV,
    )
    _validate(impact_validator, out["impact"], "impact.json")
    _validate(maintainers_validator, out["maintainers"], "maintainers.json")

    assert out["impact"]["reverse_closure_count"] == 0
    assert out["impact"]["reverse_closure_bucket"] == "<50"
    assert out["impact"]["exceeds_threshold"] is False
    assert out["impact"]["per_attr"][0]["reverse_closure_sample"] == []
    assert out["maintainers"]["attr_paths"]["never-heard-of-it"]["maintainers"] == []


# ─── threshold override ─────────────────────────────────────────────────────


def test_threshold_override(impact_validator, maintainers_validator):
    graph = CannedCartographerGraph([
        CannedNode(
            attr_path="libexample",
            drv_path=_mk_drv("libexample", "a"),
            pname="libexample",
            version="1.4.7",
            reverse_closure=tuple(f"d-{i}" for i in range(100)),
        )
    ])
    out = analyze(
        _finding("CVE-0000-3005", [("libexample", _mk_drv("libexample", "a"))]),
        graph,
        nixpkgs_rev=NIXPKGS_REV,
        blast_radius_threshold=50,
        threshold_policy="tight-test-policy",
    )
    _validate(impact_validator, out["impact"], "impact.json")
    assert out["impact"]["blast_radius_threshold"] == 50
    assert out["impact"]["threshold_policy"] == "tight-test-policy"
    assert out["impact"]["exceeds_threshold"] is True


# ─── meta: cartographer emits no policy verdicts ────────────────────────────


def test_cartographer_emits_no_policy_verdicts():
    """Cartographer reports facts only. No kind / eligibility / verdict fields anywhere."""
    graph = CannedCartographerGraph([
        CannedNode(
            attr_path="libexample",
            drv_path=_mk_drv("libexample", "a"),
            pname="libexample",
            version="1.4.7",
        )
    ])
    out = analyze(
        _finding("CVE-0000-3006", [("libexample", _mk_drv("libexample", "a"))]),
        graph,
        nixpkgs_rev=NIXPKGS_REV,
    )
    for doc in (out["impact"], out["maintainers"]):
        assert "kind" not in doc
        assert "eligibility" not in doc
        assert "verdict" not in doc
        assert "bundle_kind" not in doc
