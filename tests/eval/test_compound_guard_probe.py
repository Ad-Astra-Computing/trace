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
PROBE_FAMILIES = {"libwebp", "ffmpeg"}


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
    """The whole point of the probe: libwebp/ffmpeg must be unseen by
    corpus-v2 train/dev/test, or generalization can't be measured."""
    frozen = _frozen_families()
    leaked = PROBE_FAMILIES & frozen
    assert not leaked, f"probe families leak into frozen corpus-v2: {leaked}"


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
    assert len(positives) >= 2, "expected >=1 paired clean positive per family"
    assert len(negatives) >= 3, "expected multiple compound-guard negatives"

    families = {r["provenance"]["split_family"] for r in rows}
    assert families == PROBE_FAMILIES, f"unexpected families in probe: {families}"

    # Every family must have BOTH a positive and at least one negative (the
    # paired-control design: a probe that only ever rejects can't distinguish
    # real discrimination from reflexive reject).
    for fam in PROBE_FAMILIES:
        fam_rows = [r for r in rows if r["provenance"]["split_family"] == fam]
        assert any(r["label"] == "positive" for r in fam_rows), f"{fam}: no paired positive"
        assert any(r["label"] == "negative" for r in fam_rows), f"{fam}: no negative"

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
