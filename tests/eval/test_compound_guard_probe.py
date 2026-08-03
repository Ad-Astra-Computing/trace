"""Tests for the held-out compound-guard generalization probe.

Covers the two load-bearing properties of `traces/probes/compound-guard/` +
`scripts/build_compound_probe.py`:

1. Zero family leakage against the frozen corpus-v2
   (`data/reports/reviewer-corpus-2026-07-27-freeze.json`) -- the whole
   point of the probe is that `libwebp` / `ffmpeg_5` were never trained on.
2. The build script assembles well-formed gate-pilot-shaped rows (paired
   positive + negatives, correct labels/expected verdicts, unique
   (bundle_id, mutation_type) keys so `eval/score_gate_pilot.py`'s
   responses-matching does not collide).
"""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from tools.trace_cli.export import _normalize_attr  # noqa: E402

_spec = importlib.util.spec_from_file_location(
    "build_compound_probe", ROOT / "scripts" / "build_compound_probe.py"
)
bcp = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(bcp)

PROBE_ROOT = ROOT / "traces" / "probes" / "compound-guard"
FREEZE_PATH = ROOT / "data" / "reports" / "reviewer-corpus-2026-07-27-freeze.json"
# krb5 (CVE-2026-40356) added 2026-08-03 to widen the probe past 2 families.
# NOTE: `_normalize_attr` strips digit runs from every dot-component, so the
# krb5 attr_path collapses to split_family "krb" (NOT "krb5") -- this is the
# same normalization the frozen-corpus leakage check below uses, so the key
# must match exactly or the leakage check silently passes on the wrong key.
#
# jq was assessed as a THIRD candidate family (per traces/positives-reorg-
# reserved/README.md, which names krb5/jq/libarchive as "fresh compound-guard
# families that are not in the Reviewer train split") and rejected: the
# frozen corpus (data/reports/reviewer-corpus-2026-07-27-freeze.json)
# eligible_examples already contains THREE jq positives in the train split,
# including bundle_id a9dbef381f1d2d4e / CVE-2026-33948 -- the exact base
# bundle this task would have mutated. jq is family-level leaked; libarchive
# (bundle_id 1c4ef238c7b5bc98 / CVE-2026-15028) is leaked too. The README's
# claim is stale/incorrect for both. See the compound-guard-probe-families
# DECISIONS entry.
PROBE_FAMILIES = {"libwebp", "ffmpeg", "krb"}
# Every family must carry EXACTLY one clean positive (the paired-control
# design): more than one would let the model "average out" a false reject,
# fewer than one leaves no accept-side signal for that family at all.
EXPECTED_CLEAN_POSITIVES_PER_FAMILY = 1


def _frozen_families() -> set[str]:
    freeze = json.loads(FREEZE_PATH.read_text())
    return {_normalize_attr(e["attr_path"]) for e in freeze["eligible_examples"]}


def _run_build(out: Path) -> int:
    """Invoke build_compound_probe.main() with argv patched (it uses
    argparse against sys.argv, no programmatic entry point)."""
    saved_argv = sys.argv
    sys.argv = [
        "build_compound_probe.py",
        "--probes", str(PROBE_ROOT),
        "--prompt", str(ROOT / "prompts" / "reviewer.v9.md"),
        "--out", str(out),
    ]
    try:
        return bcp.main()
    finally:
        sys.argv = saved_argv


def test_probe_families_absent_from_frozen_corpus():
    """The whole point of the probe: every PROBE_FAMILIES entry must be unseen
    by corpus-v2 train/dev/test, or generalization can't be measured."""
    frozen = _frozen_families()
    leaked = PROBE_FAMILIES & frozen
    assert not leaked, f"probe families leak into frozen corpus-v2: {leaked}"


def test_jq_and_libarchive_are_leaked_not_fresh():
    """Documents why the probe was widened to krb5, not jq (2026-08-03).

    traces/positives-reorg-reserved/README.md claims krb5/jq/libarchive are
    "fresh compound-guard families that are not in the Reviewer train split".
    That is true for krb5 (asserted by test_probe_families_absent_from_frozen_
    corpus above, family key "krb") but FALSE for jq and libarchive: both
    already have positives in corpus-v2's train split, including the exact jq
    base bundle (CVE-2026-33948 / a9dbef381f1d2d4e) this task would have
    mutated. Promoting either into the probe would silently invalidate the
    held-out measurement it's meant to provide. This test pins the leak so a
    future README/corpus edit that makes it stale gets caught."""
    frozen = _frozen_families()
    assert "jq" in frozen, "jq no longer in frozen corpus-v2 -- README claim may now be correct"
    assert "libarchive" in frozen, "libarchive no longer in frozen corpus-v2 -- README claim may now be correct"


def test_probe_bundles_carry_probe_marker():
    """Every dir under traces/probes/compound-guard/ must be marked
    probe=true in its mutation.json (negative) or probe.json (positive) so
    it is unambiguously excluded-from-training, matching the zlib canary
    convention of an explicit 'excluded from training' note."""
    dirs = sorted(p for p in PROBE_ROOT.iterdir() if p.is_dir())
    assert dirs, "no probe bundles found"
    for d in dirs:
        mut = d / "mutation.json"
        pos = d / "probe.json"
        assert mut.is_file() or pos.is_file(), f"{d.name}: no mutation.json/probe.json"
        marker = json.loads((mut if mut.is_file() else pos).read_text())
        assert marker.get("probe") is True, f"{d.name}: marker missing probe: true"
        assert marker.get("expected_reviewer_verdict") in ("accept", "reject")


def test_build_compound_probe_rows_well_formed(tmp_path):
    out = tmp_path / "compound-guard-probe.jsonl"
    rc = _run_build(out)
    assert rc == 0
    rows = [json.loads(l) for l in out.read_text().splitlines() if l.strip()]

    assert rows, "build_compound_probe produced zero rows"
    positives = [r for r in rows if r["label"] == "positive"]
    negatives = [r for r in rows if r["label"] == "negative"]
    assert len(positives) >= len(PROBE_FAMILIES), "expected >=1 paired clean positive per family"
    assert len(negatives) >= 3, "expected multiple compound-guard negatives"

    families = {r["provenance"]["split_family"] for r in rows}
    assert families == PROBE_FAMILIES, f"unexpected families in probe: {families}"

    # Every family must have BOTH a positive and at least one negative (the
    # paired-control design: a probe that only ever rejects can't distinguish
    # real discrimination from reflexive reject), and EXACTLY one clean
    # positive (not zero, not more than one -- see EXPECTED_CLEAN_POSITIVES_
    # PER_FAMILY above).
    for fam in PROBE_FAMILIES:
        fam_rows = [r for r in rows if r["provenance"]["split_family"] == fam]
        fam_positives = [r for r in fam_rows if r["label"] == "positive"]
        assert fam_positives, f"{fam}: no paired positive"
        assert any(r["label"] == "negative" for r in fam_rows), f"{fam}: no negative"
        assert len(fam_positives) == EXPECTED_CLEAN_POSITIVES_PER_FAMILY, (
            f"{fam}: expected exactly {EXPECTED_CLEAN_POSITIVES_PER_FAMILY} clean positive, "
            f"got {len(fam_positives)}"
        )
        for r in fam_positives:
            assert r["provenance"]["positive_source"] == "clean"

    # (bundle_id, mutation_type) must be unique across all rows, or
    # eval/score_gate_pilot.py's responses dict silently drops collisions.
    keys = [(r["provenance"]["bundle_id"], r["provenance"].get("mutation_type") or "") for r in rows]
    assert len(keys) == len(set(keys)), f"duplicate (bundle_id, mutation_type) keys: {keys}"

    for r in rows:
        assert r["split"] == "canary"
        assert r["eligibility_for_training"] is False
        assert r["provenance"]["probe"] is True
        roles = [m["role"] for m in r["messages"]]
        assert roles == ["system", "user"], "gate-pilot rows must have no assistant turn"
