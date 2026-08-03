"""Structural guard on the train/probe family allocation.

We got this wrong twice in one session, both times by checking family
membership against `exports/reviewer-v1.10/reviewer.train.jsonl` instead of the
authoritative frozen corpus report, and once by hand-rolling a normalizer that
disagreed with the real one (`libxml2_13` -> `libxml_` vs `libxml`). Both
mistakes type-check, pass every other test, and silently corrupt a held-out
measurement — so they get an executable invariant instead of a convention.

The rule:
  * a hard positive under traces/positives-reorg/ is TRAIN data, so its family
    MUST already be in the frozen corpus (promoting it adds no new family, and
    therefore cannot consume a family the probe depends on);
  * a probe family under traces/probes/compound-guard/ is HELD OUT, so its
    family MUST NOT be in the frozen corpus.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT))

from tools.trace_cli.export import _normalize_attr  # noqa: E402

FREEZE = REPO_ROOT / "data" / "reports" / "reviewer-corpus-2026-07-27-freeze.json"
POSITIVES = REPO_ROOT / "traces" / "positives-reorg"
RESERVED = REPO_ROOT / "traces" / "positives-reorg-reserved"
PROBES = REPO_ROOT / "traces" / "probes" / "compound-guard"


def _frozen_families() -> set[str]:
    data = json.loads(FREEZE.read_text())
    return {
        _normalize_attr(e.get("attr_path") or "")
        for e in data.get("eligible_examples") or []
    }


def _family_of(bundle_dir: Path) -> str | None:
    """Family key exactly as the exporter computes it.

    `tools/trace_cli/export.py` splits by normalized `affected[0].attr_path`
    from finding.json (see its module docstring and line ~357). Nothing else is
    the split key: a bundle can carry a DIFFERENT `attr_path` in
    resolver-input.json (procps carries `procps-ng` there but `procps` in
    finding.json), and reading the wrong one reports a phantom fresh family.
    """
    finding = bundle_dir / "finding.json"
    if not finding.exists():
        return None
    try:
        blob = json.loads(finding.read_text())
    except (OSError, json.JSONDecodeError):
        return None
    affected = blob.get("affected") or [{}]
    attr = (affected[0] or {}).get("attr_path") or ""
    return _normalize_attr(attr) if attr else None


def test_train_eligible_positives_use_families_already_in_corpus():
    frozen = _frozen_families()
    offenders = []
    for d in sorted(POSITIVES.glob("CVE-*")):
        if not (d / "reorg.json").exists():
            continue
        fam = _family_of(d)
        if fam and fam not in frozen:
            offenders.append((d.name, fam))
    assert not offenders, (
        "hard positives are TRAIN data and must not introduce a family absent "
        "from the frozen corpus (it may be needed as a held-out probe family): "
        f"{offenders}"
    )


def test_probe_families_are_absent_from_corpus():
    frozen = _frozen_families()
    leaked = []
    for d in sorted(PROBES.glob("CVE-*")):
        fam = _family_of(d)
        if fam and fam in frozen:
            leaked.append((d.name, fam))
    assert not leaked, (
        "probe families must be HELD OUT of training; these are in the frozen "
        f"corpus: {leaked}"
    )


def test_reserved_positives_back_a_real_probe_family():
    """Anything quarantined must actually be probe-backing, else quarantine it wrongly."""
    frozen = _frozen_families()
    probe_fams = {f for f in (_family_of(d) for d in PROBES.glob("CVE-*")) if f}
    wrong = []
    for d in sorted(RESERVED.glob("CVE-*")):
        fam = _family_of(d)
        if fam is None:
            continue
        if fam in frozen or fam not in probe_fams:
            wrong.append((d.name, fam))
    assert not wrong, (
        "reserved positives must back an actual held-out probe family and must "
        f"not be corpus families; wrongly reserved: {wrong}"
    )
