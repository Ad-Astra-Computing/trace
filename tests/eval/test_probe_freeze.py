"""The compound-guard probe is FROZEN: its bytes must match the freeze manifest.

Preregistration integrity depends on the probe not moving after measurement
begins. The peer review that authorized this experiment was explicit: "No row
exclusions for any reason post-freeze" — because the deterministic
`check_pc_omission_claim` diagnostic fires precisely on the false-reject shape,
so dropping rows it flags would mechanically flatter whichever arm produces more
of them (outcome-dependent exclusion).

A declaration in a doc cannot enforce that. This test can: any edit to the probe
file after the freeze — adding a row, removing one, or perturbing a byte — fails
loudly and forces an explicit, recorded re-freeze rather than a silent drift.

Growing the probe is still allowed; it just cannot happen quietly. Re-run the
freeze writer, commit the new manifest, and state in DECISIONS why the probe
changed and whether any measurement had already been taken against it.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
PROBE = REPO_ROOT / "data" / "probes" / "compound-guard-probe.jsonl"
FREEZE = REPO_ROOT / "data" / "probes" / "compound-guard-probe-freeze.json"


def _freeze() -> dict:
    return json.loads(FREEZE.read_text())


def test_probe_bytes_match_freeze():
    frozen = _freeze()
    actual = hashlib.sha256(PROBE.read_bytes()).hexdigest()
    assert actual == frozen["probe_sha256"], (
        "the frozen compound-guard probe changed.\n"
        f"  expected sha256 {frozen['probe_sha256']}\n"
        f"  actual   sha256 {actual}\n"
        "Post-freeze row changes are preregistration violations unless recorded. "
        "If the change is intended, regenerate the freeze manifest AND record in "
        "docs/DECISIONS.md why the probe changed and whether any arm had already "
        "been measured against the old rows."
    )


def test_freeze_inventory_matches_probe():
    frozen = _freeze()
    rows = [json.loads(l) for l in PROBE.read_text().splitlines() if l.strip()]
    assert len(rows) == frozen["row_count"]
    fams = {(r.get("provenance") or {}).get("attr_path") for r in rows}
    assert fams == set(frozen["families"]), (fams, set(frozen["families"]))


def test_every_family_has_exactly_one_paired_clean_positive():
    """The paired positive is what distinguishes real discrimination from
    'reject anything compound-shaped'. Losing it silently guts the design.

    libsynthguard is a deliberate, recorded exception (pre-measurement top-up,
    2026-08-03): it carries TWO clean positives -- the original awkward guard
    (mixed &&/||, casts, repeated subexpression) plus a second, deliberately
    PLAIN conventional guard -- so a future miss on this family can be
    attributed to a specific cause (external/synthetic artifact vs. awkward
    guard shape) rather than lumped together. No other family gets this
    exception without an equally explicit, recorded reason.
    """
    frozen = _freeze()
    for fam, meta in frozen["families"].items():
        if fam == "libsynthguard":
            assert meta["positives"] == 2, (
                f"libsynthguard has {meta['positives']} positives, expected exactly 2 "
                "(awkward + plain, per the 2026-08-03 pre-measurement top-up)"
            )
        else:
            assert meta["positives"] == 1, (
                f"{fam} has {meta['positives']} positives, need exactly 1"
            )
        assert meta["negatives"] >= 2, (
            f"{fam} has too few negatives: {meta['negatives']}"
        )


def test_recorded_gaps_are_declared_not_hidden():
    frozen = _freeze()
    gaps = frozen.get("recorded_gaps") or []
    assert gaps, "shape gaps must be declared in the freeze, not silently absent"
    for g in gaps:
        assert g.get("family") and g.get("missing_shape") and g.get("reason")


def test_external_control_is_marked_synthetic():
    frozen = _freeze()
    ext = frozen["external_control"]
    assert ext["synthetic"] is True
    assert ext["family"] in frozen["families"]
