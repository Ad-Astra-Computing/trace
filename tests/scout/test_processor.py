"""Scout inbox processor tests.

Slice 7 of Scout autonomy. Closes the loop after the cron poller:

  inbox/<CVE-ID>/scout-input.json     (written by poll_one)
       ↓
  scout.scan → finding.json | mapping-failure.json
       ↓ (when finding)
  build resolver-input.json from finding + scout-input refs
       ↓
  upstream_ref_resolver.resolve → upstream-ref.json

Per locked decision (b): auto-resolve immediately. We do not gate
processing on a human; the resolver records its own verdict
(eligible / requires-human-review / ineligible) and downstream
agents read that as given truth.

candidate_refs extraction is deterministic and conservative:
  * references[] with kind='upstream-commit' matching
    github.com/<owner>/<repo>/commit/<sha> or the gitlab.com
    equivalent become candidate `upstream_fix_commits` entries.
  * No changelog scraping; the resolver itself defers that.
  * No candidates → resolver returns ineligible-no-fix-available,
    which is a perfectly valid recorded outcome.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from agents.scout.graph_lookup import CannedGraphLookup, GraphMatch
from agents.scout.processor import ProcessOutcome, process_entry


_LIBTIFF = GraphMatch(
    attr_path="libtiff",
    drv_path="/nix/store/aaa-libtiff.drv",
    pname="libtiff",
    version="4.6.0",
    cpes=("cpe:2.3:a:libtiff:libtiff:*:*:*:*:*:*:*:*",),
)


def _seed_inbox(
    tmp_path: Path,
    *,
    cve_id: str = "CVE-2024-13978",
    cpe_matches: list[dict[str, Any]] | None = None,
    pname_hints: list[str] | None = None,
    references: list[dict[str, str]] | None = None,
) -> Path:
    """Write a minimal inbox entry for the processor to consume."""
    entry = tmp_path / cve_id
    entry.mkdir()
    scout_input: dict[str, Any] = {
        "feed": "nvd",
        "cve_id": cve_id,
        "published_at": "2025-08-01T21:32:07Z",
        "summary": "test",
        "severity": {"rating": "low", "cvss_v3_score": 3.3},
    }
    if cpe_matches is not None:
        scout_input["cpe_matches"] = cpe_matches
    if pname_hints is not None:
        scout_input["pname_hints"] = pname_hints
    if references is not None:
        scout_input["references"] = references
    (entry / "scout-input.json").write_text(json.dumps(scout_input))
    return entry


def test_finding_written_when_graph_hits(tmp_path: Path) -> None:
    entry = _seed_inbox(
        tmp_path,
        cpe_matches=[{"cpe": _LIBTIFF.cpes[0]}],
    )
    graph = CannedGraphLookup([_LIBTIFF])

    out = process_entry(entry, graph=graph)

    assert isinstance(out, ProcessOutcome)
    assert out.finding_status == "finding"
    finding = json.loads((entry / "finding.json").read_text())
    assert finding["cve_id"] == "CVE-2024-13978"
    assert finding["affected"][0]["attr_path"] == "libtiff"


def test_mapping_failure_written_when_no_match(tmp_path: Path) -> None:
    entry = _seed_inbox(
        tmp_path,
        cpe_matches=[{"cpe": "cpe:2.3:a:nope:nope:*:*:*:*:*:*:*:*"}],
    )
    graph = CannedGraphLookup([])

    out = process_entry(entry, graph=graph)

    assert out.finding_status == "mapping-failure"
    assert (entry / "mapping-failure.json").exists()
    assert not (entry / "finding.json").exists()
    assert out.resolver_status is None


def test_resolver_input_built_from_finding_and_references(tmp_path: Path) -> None:
    entry = _seed_inbox(
        tmp_path,
        cpe_matches=[{"cpe": _LIBTIFF.cpes[0]}],
        references=[
            {"url": "https://gitlab.com/libtiff/libtiff/-/commit/2ebfffb0e8836bfb1cd7d85c059cd285c59761a4",
             "kind": "upstream-commit"},
            {"url": "https://nvd.nist.gov/vuln/detail/CVE-2024-13978",
             "kind": "advisory"},
        ],
    )
    graph = CannedGraphLookup([_LIBTIFF])

    process_entry(entry, graph=graph)

    resolver_input = json.loads((entry / "resolver-input.json").read_text())
    assert resolver_input["cve_id"] == "CVE-2024-13978"
    assert resolver_input["current_version"] == "4.6.0"
    assert resolver_input["attr_path"] == "libtiff"
    refs = resolver_input["candidate_refs"]
    assert len(refs) == 1
    fix_commits = refs[0]["upstream_fix_commits"]
    assert fix_commits[0]["commit_sha"] == "2ebfffb0e8836bfb1cd7d85c059cd285c59761a4"
    assert "gitlab.com/libtiff/libtiff" in fix_commits[0]["repo_url"]
    assert "https://nvd.nist.gov/vuln/detail/CVE-2024-13978" in refs[0]["advisory_urls"]


def test_github_commit_url_recognised(tmp_path: Path) -> None:
    entry = _seed_inbox(
        tmp_path,
        cpe_matches=[{"cpe": _LIBTIFF.cpes[0]}],
        references=[
            {"url": "https://github.com/octocat/Hello-World/commit/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
             "kind": "upstream-commit"},
        ],
    )
    graph = CannedGraphLookup([_LIBTIFF])
    process_entry(entry, graph=graph)
    refs = json.loads((entry / "resolver-input.json").read_text())["candidate_refs"]
    assert refs[0]["upstream_fix_commits"][0]["repo_url"] == "https://github.com/octocat/Hello-World"


def test_upstream_ref_written_with_resolver_verdict(tmp_path: Path) -> None:
    entry = _seed_inbox(
        tmp_path,
        cpe_matches=[{"cpe": _LIBTIFF.cpes[0]}],
        references=[
            {"url": "https://github.com/x/y/commit/" + "a" * 40,
             "kind": "upstream-commit"},
        ],
    )
    graph = CannedGraphLookup([_LIBTIFF])

    out = process_entry(entry, graph=graph)

    upstream = json.loads((entry / "upstream-ref.json").read_text())
    assert upstream["cve_id"] == "CVE-2024-13978"
    assert upstream["eligibility"]["verdict"] in {
        "eligible",
        "eligible-requires-human-review",
        "ineligible-no-fix-available",
    }
    assert out.resolver_status == upstream["eligibility"]["verdict"]


def test_no_candidate_refs_yields_ineligible_verdict(tmp_path: Path) -> None:
    """No upstream-commit references → resolver gets empty candidates →
    ineligible-no-fix-available, which is a recorded outcome (not an
    error). Downstream agents see "no fix found in references"."""
    entry = _seed_inbox(
        tmp_path,
        cpe_matches=[{"cpe": _LIBTIFF.cpes[0]}],
        references=[
            {"url": "https://nvd.nist.gov/vuln/detail/CVE-2024-13978",
             "kind": "advisory"},
        ],
    )
    graph = CannedGraphLookup([_LIBTIFF])

    out = process_entry(entry, graph=graph)

    assert out.resolver_status == "ineligible-no-fix-available"
    upstream = json.loads((entry / "upstream-ref.json").read_text())
    assert upstream["eligibility"]["verdict"] == "ineligible-no-fix-available"


def test_idempotent_reprocess_overwrites_atomically(tmp_path: Path) -> None:
    """Re-processing the same entry must not leave stale files; a
    second run with the same input is byte-equivalent."""
    entry = _seed_inbox(
        tmp_path,
        cpe_matches=[{"cpe": _LIBTIFF.cpes[0]}],
    )
    graph = CannedGraphLookup([_LIBTIFF])

    process_entry(entry, graph=graph)
    first_finding = (entry / "finding.json").read_bytes()

    process_entry(entry, graph=graph)
    assert (entry / "finding.json").read_bytes() == first_finding


def test_missing_scout_input_raises(tmp_path: Path) -> None:
    empty = tmp_path / "CVE-9999-99999"
    empty.mkdir()
    with pytest.raises(FileNotFoundError):
        process_entry(empty, graph=CannedGraphLookup([]))


def test_outcome_records_entry_path_and_cve_id(tmp_path: Path) -> None:
    entry = _seed_inbox(tmp_path, cpe_matches=[{"cpe": _LIBTIFF.cpes[0]}])
    out = process_entry(entry, graph=CannedGraphLookup([_LIBTIFF]))
    assert out.entry_path == entry
    assert out.cve_id == "CVE-2024-13978"


def test_short_commit_sha_is_skipped(tmp_path: Path) -> None:
    """Commit-URL extraction requires 7-40 hex chars (resolver schema
    constraint). Anything shorter is dropped to avoid feeding the
    resolver an invalid candidate."""
    entry = _seed_inbox(
        tmp_path,
        cpe_matches=[{"cpe": _LIBTIFF.cpes[0]}],
        references=[
            {"url": "https://github.com/x/y/commit/abc12",
             "kind": "upstream-commit"},
        ],
    )
    graph = CannedGraphLookup([_LIBTIFF])
    process_entry(entry, graph=graph)
    refs = json.loads((entry / "resolver-input.json").read_text())["candidate_refs"]
    assert refs == []
