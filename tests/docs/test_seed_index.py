"""Bind docs/SEED_INDEX.md to the real-CVE bundle corpus.

The seed index is the public-facing one-page map of every real-CVE bundle
under `traces/example/CVE-2*/`. If a new real-CVE bundle lands without a
matching index entry, external readers see a stale map. If a bundle is
removed without the index being pruned, the index points at nothing.

This test fails on either drift direction. It does NOT validate the index's
prose or table-cell accuracy; that remains a manual review concern.

Synthetic `CVE-0000-*` fixtures are intentionally excluded: they exercise
schema/Steward edges, not the public corpus, and are not catalogued in the
index.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

from tests.schema.validate import REPO_ROOT


SEED_INDEX = REPO_ROOT / "docs" / "SEED_INDEX.md"
FIXTURE_ROOT = REPO_ROOT / "traces" / "example"


def _real_cve_bundle_dirs() -> list[str]:
    return sorted(
        p.name for p in FIXTURE_ROOT.iterdir()
        if p.is_dir() and p.name.startswith("CVE-") and not p.name.startswith("CVE-0000-")
    )


def test_seed_index_exists():
    assert SEED_INDEX.is_file(), f"{SEED_INDEX} is missing"


def test_every_real_cve_bundle_appears_in_seed_index():
    body = SEED_INDEX.read_text()
    missing = [name for name in _real_cve_bundle_dirs() if name not in body]
    assert not missing, (
        "real-CVE bundles missing from docs/SEED_INDEX.md:\n  "
        + "\n  ".join(missing)
        + "\nAdd a row to the at-a-glance table and a per-bundle detail "
        "subsection, or remove the bundle if it was deleted intentionally."
    )


def test_seed_index_does_not_reference_removed_bundles():
    body = SEED_INDEX.read_text()
    real = set(_real_cve_bundle_dirs())
    referenced: set[str] = set()
    for line in body.splitlines():
        for token in line.split("`"):
            if token.startswith("CVE-") and "--" in token:
                head = token.split()[0].rstrip(".,)/")
                if head.startswith("CVE-") and "--" in head:
                    referenced.add(head)
    stale = sorted(name for name in referenced if name not in real and not name.startswith("CVE-0000-"))
    assert not stale, (
        "docs/SEED_INDEX.md references CVE bundles that no longer exist "
        "under traces/example/:\n  "
        + "\n  ".join(stale)
    )


# Match the at-a-glance table row for a given bundle, e.g.:
#   | [`CVE-2025-7207--mruby`](../traces/example/CVE-2025-7207--mruby/) | human-review-required | deterministic-no-model | ... |
_TABLE_ROW = re.compile(
    r"^\|\s*\[`(CVE-[^`]+)`\][^|]*\|\s*([^|]+?)\s*\|\s*([^|]+?)\s*\|",
    re.MULTILINE,
)


def _index_table_rows() -> dict[str, tuple[str, str]]:
    body = SEED_INDEX.read_text()
    rows: dict[str, tuple[str, str]] = {}
    for match in _TABLE_ROW.finditer(body):
        name, kind_cell, family_cell = match.group(1), match.group(2), match.group(3)
        rows[name] = (kind_cell, family_cell)
    return rows


def test_seed_index_kind_cell_matches_bundle_json():
    rows = _index_table_rows()
    mismatches: list[str] = []
    for name in _real_cve_bundle_dirs():
        if name not in rows:
            continue  # caught by the existence test above
        index_kind, _ = rows[name]
        bundle_path = FIXTURE_ROOT / name / "bundle.json"
        actual_kind = json.loads(bundle_path.read_text()).get("kind", "?")
        if index_kind != actual_kind:
            mismatches.append(
                f"  {name}: index says {index_kind!r}, bundle.json says {actual_kind!r}"
            )
    assert not mismatches, (
        "docs/SEED_INDEX.md table 'kind' column drifted from bundle.json:\n"
        + "\n".join(mismatches)
    )


def test_seed_index_family_cell_mentions_all_role_families():
    """Every model family declared in replay.json should appear in the
    index's family cell, modulo deterministic-no-model when paired with
    other families (the index typically writes 'model-attested (...)' in
    that case rather than listing 'deterministic-no-model' for the
    upstream-ref-resolver). The test only enforces the non-deterministic
    families, since 'model-attested' vs explicit family naming is an
    editorial choice we don't want to constrain mechanically.
    """
    rows = _index_table_rows()
    misses: list[str] = []
    for name in _real_cve_bundle_dirs():
        if name not in rows:
            continue
        _, family_cell = rows[name]
        replay = json.loads((FIXTURE_ROOT / name / "replay.json").read_text())
        non_det_families = {
            inv["model"]["family"]
            for role in replay.get("roles", [])
            for inv in role.get("invocations", [])
            if inv["model"]["family"] != "deterministic-no-model"
        }
        det_only = not non_det_families
        if det_only and "deterministic-no-model" not in family_cell:
            misses.append(
                f"  {name}: replay.json has only deterministic-no-model roles, "
                f"but index family cell {family_cell!r} omits it"
            )
        if non_det_families and "model-attested" not in family_cell and not any(
            f in family_cell for f in non_det_families
        ):
            misses.append(
                f"  {name}: replay.json declares families {sorted(non_det_families)!r}, "
                f"but index family cell {family_cell!r} mentions none"
            )
    assert not misses, (
        "docs/SEED_INDEX.md family cell drifted from replay.json:\n"
        + "\n".join(misses)
    )
