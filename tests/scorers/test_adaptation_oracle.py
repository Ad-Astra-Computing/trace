"""Tests for the adaptation-equivalence oracle registry.

The registry stores per-CVE ground-truth equivalence labels for the
Reviewer's adaptation lane (reviewer.v10+), keyed by CVE id. It never
carries the oracle patch bytes, only provenance for an auditor to
re-fetch and re-verify.
"""

from __future__ import annotations

import pytest

from agents.scorers.adaptation_oracle import (
    AdaptationOracle,
    OracleProvenance,
    get_oracle,
    registered_cve_ids,
)


def _provenance(**overrides) -> OracleProvenance:
    defaults = dict(
        source="nixpkgs",
        ref="0" * 8,
        path="pkgs/foo.patch",
        sha256="0" * 64,
        base_relation="same-base",
    )
    defaults.update(overrides)
    return OracleProvenance(**defaults)


def _oracle(**overrides) -> AdaptationOracle:
    defaults = dict(
        cve_id="CVE-0000-0000",
        ground_truth_equivalence="equivalent",
        adjudicated_patch_sha256="1" * 64,
        provenance=_provenance(),
        adjudicated_by="test-harness",
    )
    defaults.update(overrides)
    return AdaptationOracle(**defaults)


def test_get_oracle_returns_registered_maxima_cve() -> None:
    oracle = get_oracle("CVE-2024-34490")
    assert oracle is not None
    assert oracle.cve_id == "CVE-2024-34490"
    assert oracle.ground_truth_equivalence == "equivalent"


def test_maxima_oracle_has_pinned_adjudicated_patch_sha256() -> None:
    oracle = get_oracle("CVE-2024-34490")
    assert oracle is not None
    assert oracle.adjudicated_patch_sha256 == (
        "21acad11adabdf29ea2585b424e6ebb4bbcdccfa41d8ae2fb9b6b21c03ed9bed"
    )
    assert oracle.provenance.sha256 == (
        "a5da1348cf3d0837f58ea10e1377b9bb0740624c6ae13a5befe0da4337bc8880"
    )


def test_get_oracle_returns_none_for_unknown_cve() -> None:
    assert get_oracle("CVE-9999-99999") is None


def test_registered_cve_ids_includes_maxima_cve() -> None:
    assert "CVE-2024-34490" in registered_cve_ids()


def test_registered_cve_ids_is_sorted_tuple() -> None:
    ids = registered_cve_ids()
    assert isinstance(ids, tuple)
    assert list(ids) == sorted(ids)


def test_adaptation_oracle_rejects_bad_ground_truth_label() -> None:
    with pytest.raises(ValueError):
        _oracle(
            cve_id="CVE-0000-0001",
            ground_truth_equivalence="indeterminate",  # not a settled label
        )


def test_oracle_provenance_rejects_bad_sha256() -> None:
    with pytest.raises(ValueError):
        _provenance(sha256="not-a-sha256")
    with pytest.raises(ValueError):
        _provenance(sha256="a" * 63)  # one short of 64 hex chars


def test_adaptation_oracle_rejects_bad_base_relation() -> None:
    with pytest.raises(ValueError):
        _oracle(
            cve_id="CVE-0000-0002",
            provenance=_provenance(base_relation="different-base"),
        )


def test_adaptation_oracle_rejects_non_hex_adjudicated_patch_sha256() -> None:
    with pytest.raises(ValueError):
        _oracle(
            cve_id="CVE-0000-0003",
            adjudicated_patch_sha256="not-a-valid-sha256",
        )


def test_adaptation_oracle_rejects_wrong_length_adjudicated_patch_sha256() -> None:
    with pytest.raises(ValueError):
        _oracle(
            cve_id="CVE-0000-0004",
            adjudicated_patch_sha256="1" * 63,  # one short of 64 hex chars
        )


def test_oracle_to_dict_round_trips_fields() -> None:
    oracle = get_oracle("CVE-2024-34490")
    assert oracle is not None
    d = oracle.to_dict()
    assert d["cve_id"] == "CVE-2024-34490"
    assert d["ground_truth_equivalence"] == "equivalent"
    assert d["provenance"]["base_relation"] == "same-base"
