"""Validate every Authoring-LoRA training-example supplement under traces/example/*.

An *authoring supplement* is a `traces/example/CVE-*/` dir that carries an
`authoring-example.json` (a (vuln-only -> upstream-fix) training pair minted by
`trace export authoring`) but NO `bundle.json`. It is not a trace evidence bundle,
so it is deliberately excluded from the bundle expect.json / SEED_INDEX contract
(see tests/schema/test_fixtures.py and tests/docs/test_seed_index.py). This module
is where those dirs earn their keep: it asserts the training pair is well-shaped and,
critically, that the recorded `fix_diff` is *grounded* in the recorded pre-fix window.

Grounding is the load-bearing property (mirrors `export.py:_patch_grounded`): every
line the diff REMOVES must be present in `pre_fix_source`, and the diff must introduce
at least one genuinely new code line. If these hold, the pair is a valid supervised
example; if not, the label was authored against a different base than the window and
the pair would teach the model a hallucinated edit.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from tests.schema.validate import REPO_ROOT


FIXTURE_ROOT = REPO_ROOT / "traces" / "example"

# Canary CVE IDs seeded elsewhere in the corpus. None of them is a legitimate
# authoring-supplement subject; if one appears as an example's cve_id it means a
# canary leaked into the training corpus, which must fail loudly.
CANARY_CVE_IDS = {
    "CVE-2022-37434",
    "CVE-2026-42250",
    "CVE-2024-47081",
    "CVE-2026-48526",
}

REQUIRED_KEYS = {
    "cve_id",
    "attr_path",
    "vuln_raw",
    "file",
    "included_source_files",
    "input_window_truncated",
    "pre_fix_source",
    "fix_diff",
    "label_source",
    "fix_commit",
}


def _is_authoring_supplement(fixture_dir: Path) -> bool:
    """An authoring-supplement dir carries an `authoring-example.json` but is NOT an
    evidence bundle: it has neither a `bundle.json` nor an `expect.json`. Its only
    other file is `upstream-ref.json`.

    The classifier keys on the ABSENCE of BOTH positive bundle markers so nothing
    that the bundle contract already covers can be silently exempted:

    - a dir with `bundle.json` is a full evidence bundle (owes expect.json + SEED_INDEX);
    - a dir with `expect.json` but no bundle.json is a behavioral / reviewer-attested
      fixture that test_fixtures.py already validates via its expect.json;

    many real bundles ALSO ship an authoring-example.json alongside their bundle, so
    keying on authoring-example.json alone would wrongly pull them in here. Requiring
    the absence of both markers isolates exactly the thin training-only supplements.
    """
    return (
        (fixture_dir / "authoring-example.json").exists()
        and not (fixture_dir / "bundle.json").exists()
        and not (fixture_dir / "expect.json").exists()
    )


def _authoring_supplement_dirs() -> list[Path]:
    return sorted(p for p in FIXTURE_ROOT.iterdir() if p.is_dir() and _is_authoring_supplement(p))


def _load(fixture_dir: Path) -> dict:
    return json.loads((fixture_dir / "authoring-example.json").read_text())


def _diff_bodies(fix_diff: str, marker: str) -> list[str]:
    """Non-blank, whitespace-stripped bodies of `+`/`-` lines, excluding the
    `+++`/`---` file headers."""
    header = marker * 3  # "+++" or "---"
    out: list[str] = []
    for ln in fix_diff.splitlines():
        if ln.startswith(marker) and not ln.startswith(header) and ln[1:].strip():
            out.append(ln[1:].strip())
    return out


def _is_trivial(body: str) -> bool:
    """A structural line (lone brace / punctuation) that trivially recurs in most
    source and so carries no evidence that the diff introduces new logic."""
    return not any(c.isalnum() for c in body)


# Guard: the 6 (currently) supplement dirs must actually be discovered, so a
# refactor that silently empties the parametrization can't turn this suite into a
# no-op that reports green.
def test_authoring_supplements_are_discovered():
    dirs = _authoring_supplement_dirs()
    assert dirs, (
        "no authoring-supplement dirs found under traces/example/; expected dirs "
        "carrying authoring-example.json without bundle.json"
    )


@pytest.mark.parametrize(
    "fixture_dir", _authoring_supplement_dirs(), ids=lambda p: p.name
)
def test_authoring_example_shape(fixture_dir):
    ex = _load(fixture_dir)

    missing = sorted(REQUIRED_KEYS - set(ex))
    assert not missing, f"{fixture_dir.name}: authoring-example.json missing keys {missing}"

    assert isinstance(ex["cve_id"], str) and ex["cve_id"], f"{fixture_dir.name}: empty cve_id"
    assert isinstance(ex["attr_path"], str) and ex["attr_path"], f"{fixture_dir.name}: empty attr_path"
    assert isinstance(ex["vuln_raw"], str) and ex["vuln_raw"].strip(), f"{fixture_dir.name}: empty vuln_raw"
    assert isinstance(ex["file"], str) and ex["file"], f"{fixture_dir.name}: empty file"
    assert isinstance(ex["included_source_files"], list) and ex["included_source_files"], (
        f"{fixture_dir.name}: included_source_files must be a non-empty list"
    )
    assert isinstance(ex["input_window_truncated"], bool), (
        f"{fixture_dir.name}: input_window_truncated must be a bool"
    )
    assert isinstance(ex["pre_fix_source"], str) and ex["pre_fix_source"].strip(), (
        f"{fixture_dir.name}: empty pre_fix_source"
    )
    assert isinstance(ex["fix_diff"], str) and ex["fix_diff"].strip(), f"{fixture_dir.name}: empty fix_diff"
    assert isinstance(ex["label_source"], str) and ex["label_source"], f"{fixture_dir.name}: empty label_source"

    fc = ex["fix_commit"]
    assert isinstance(fc, dict), f"{fixture_dir.name}: fix_commit must be an object"
    repo_url = fc.get("repo_url")
    commit_sha = fc.get("commit_sha")
    assert isinstance(repo_url, str) and repo_url.startswith(("http://", "https://")), (
        f"{fixture_dir.name}: fix_commit.repo_url must be an http(s) URL, got {repo_url!r}"
    )
    assert isinstance(commit_sha, str) and len(commit_sha) == 40 and all(
        c in "0123456789abcdef" for c in commit_sha.lower()
    ), f"{fixture_dir.name}: fix_commit.commit_sha must be a 40-char hex sha, got {commit_sha!r}"


@pytest.mark.parametrize(
    "fixture_dir", _authoring_supplement_dirs(), ids=lambda p: p.name
)
def test_authoring_example_cve_matches_dir(fixture_dir):
    ex = _load(fixture_dir)
    cve_id = ex["cve_id"]
    assert fixture_dir.name.startswith(cve_id + "--") or fixture_dir.name == cve_id, (
        f"{fixture_dir.name}: dir name does not start with its cve_id {cve_id!r}"
    )


@pytest.mark.parametrize(
    "fixture_dir", _authoring_supplement_dirs(), ids=lambda p: p.name
)
def test_authoring_example_no_canary_leak(fixture_dir):
    ex = _load(fixture_dir)
    assert ex["cve_id"] not in CANARY_CVE_IDS, (
        f"{fixture_dir.name}: canary CVE {ex['cve_id']} leaked into the authoring "
        f"training corpus as an example subject"
    )


@pytest.mark.parametrize(
    "fixture_dir", _authoring_supplement_dirs(), ids=lambda p: p.name
)
def test_authoring_example_diff_grounded_in_window(fixture_dir):
    """The fix_diff must be grounded in pre_fix_source: every removed line body
    appears in the window, and the diff introduces at least one non-trivial new
    line. Whitespace-stripped comparison mirrors export.py:_patch_grounded — a
    curated label authored against a different base than the recorded window would
    desync here and fail loudly.
    """
    ex = _load(fixture_dir)
    fix_diff = ex["fix_diff"]
    pre_pool = {ln.strip() for ln in ex["pre_fix_source"].splitlines() if ln.strip()}

    removed = _diff_bodies(fix_diff, "-")
    added = _diff_bodies(fix_diff, "+")

    absent_removed = [r for r in removed if r not in pre_pool]
    assert not absent_removed, (
        f"{fixture_dir.name}: fix_diff removes lines not present in pre_fix_source "
        f"(label desynced from window): {absent_removed}"
    )

    # The diff must actually introduce new code, not just reshuffle existing lines.
    # Structural-only additions (lone braces/punctuation) re-appear in most source
    # and so do not evidence a real edit; require at least one non-trivial `+` line
    # that is genuinely new relative to the window.
    novel_added = [a for a in added if not _is_trivial(a) and a not in pre_pool]
    assert novel_added, (
        f"{fixture_dir.name}: fix_diff introduces no non-trivial new code line "
        f"absent from pre_fix_source; the pair teaches no edit. added={added}"
    )


@pytest.mark.parametrize(
    "fixture_dir", _authoring_supplement_dirs(), ids=lambda p: p.name
)
def test_authoring_supplement_has_upstream_ref(fixture_dir):
    ur_path = fixture_dir / "upstream-ref.json"
    assert ur_path.exists(), f"{fixture_dir.name}: authoring supplement missing upstream-ref.json"
    # Must parse; shape is validated by the upstream_ref schema elsewhere.
    json.loads(ur_path.read_text())
