import json
from pathlib import Path

import pytest

from eval.beat_upstream_tier_audit import bucket_one, main


def _entry(tmp_path: Path, cve: str, *, refs, references=(), current="1.2.0") -> Path:
    d = tmp_path / cve
    d.mkdir()
    (d / "resolver-input.json").write_text(json.dumps({
        "attr_path": "foo", "current_version": current, "candidate_refs": refs}))
    (d / "scout-input.json").write_text(json.dumps({
        "references": [{"url": u, "kind": "other"} for u in references]}))
    return d


def _ref(version, tier="security-patch-release", reason=None):
    r = {"version": version, "tier_hint": tier,
         "upstream_fix_commits": [{"repo_url": "https://github.com/o/r", "commit_sha": "a" * 40}]}
    if reason:
        r["requires_review_reason"] = reason
    return r


def test_no_fix_commit_flags_regex_miss(tmp_path):
    d = _entry(tmp_path, "CVE-2026-1", refs=[],
               references=["https://git.example.org/proj/-/merge_requests/12"])
    row = bucket_one(d)
    assert row["bucket"] == "A-no-fix-commit"
    assert row["regex_miss"] is True


def test_no_fix_commit_without_fixlike_url(tmp_path):
    row = bucket_one(_entry(tmp_path, "CVE-2026-2", refs=[], references=["https://nvd.example/x"]))
    assert row["bucket"] == "A-no-fix-commit"
    assert row["regex_miss"] is False


def test_release_exists_nixpkgs_behind(tmp_path):
    row = bucket_one(_entry(tmp_path, "CVE-2026-3", refs=[_ref("1.2.1")], current="1.2.0"))
    assert row["bucket"] == "B-release-nixpkgs-behind"


def test_release_exists_nixpkgs_current(tmp_path):
    row = bucket_one(_entry(tmp_path, "CVE-2026-4", refs=[_ref("1.2.0")], current="1.2.0"))
    assert row["bucket"] == "C-release-nixpkgs-current"


def test_ambiguous_and_source_backport_and_unparseable(tmp_path):
    assert bucket_one(_entry(tmp_path, "CVE-2026-5",
                             refs=[_ref("1.2.0", reason="ambiguous-fixed-version")]))["bucket"] \
        == "D-ambiguous-fixed-version"
    assert bucket_one(_entry(tmp_path, "CVE-2026-6",
                             refs=[_ref("1.2.0", tier="source-backport",
                                        reason="placeholder-target-version")]))["bucket"] \
        == "E-source-backport"
    assert bucket_one(_entry(tmp_path, "CVE-2026-7", refs=[_ref("unstable-2026-01-01")]))["bucket"] \
        == "U-unparseable"


def test_main_counts_and_verdict_filter(tmp_path, capsys):
    _entry(tmp_path, "CVE-2026-3", refs=[_ref("1.2.1")], current="1.2.0")
    _entry(tmp_path, "CVE-2026-8", refs=[_ref("1.2.1")], current="1.2.0")
    verdicts = tmp_path / "v.json"
    verdicts.write_text(json.dumps({"verdicts": [
        {"cve_id": "CVE-2026-3", "reject": "not-source-backport-tier", "attr_path": "foo"},
        {"cve_id": "CVE-2026-8", "reject": "poll:skipped-irrelevant"},
    ]}))
    out = tmp_path / "audit.json"
    assert main(["--inbox", str(tmp_path), "--verdicts", str(verdicts), "--out", str(out)]) == 0
    summary = json.loads(out.read_text())["summary"]
    assert summary["audited"] == 1
    assert summary["window_candidates_B_plus_D"] == 1
    assert "B-release-nixpkgs-behind" in capsys.readouterr().out


class _FakeResp:
    def __init__(self, payload):
        self._p = payload

    def read(self):
        import json as _j
        return _j.dumps(self._p).encode()

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


def test_cross_check_reports_dropped_fix_commit():
    from eval.beat_upstream_tier_audit import cross_check_cve_list
    payload = {"containers": {"cna": {
        "references": [{"url": "https://github.com/o/r/commit/" + "b" * 40},
                       {"url": "https://example.org/advisory"}],
        "affected": [{"versions": [{"lessThan": "1.2.3"}]}]}}}
    got = cross_check_cve_list("CVE-2026-9", opener=lambda url: _FakeResp(payload))
    assert got["cve_list_refs"] == 2
    assert len(got["cve_list_fix_refs"]) == 1
    assert got["cve_list_has_bound"] is True


def test_cross_check_swallows_fetch_failure():
    from eval.beat_upstream_tier_audit import cross_check_cve_list

    def boom(url):
        raise OSError("network down")

    assert cross_check_cve_list("CVE-2026-10", opener=boom) == {}
