"""The advisory has to be about the package the pair claims."""
from __future__ import annotations

import pytest

from eval.cve_package_check import check_cve_names_package, package_tokens

COROSYNC = (
    "Corosync through 3.1.9, if encryption is disabled, has a stack-based buffer "
    "overflow in orf_token_endian_convert in exec/totemsrp.c via a large UDP packet."
)
NETTOOLS = (
    "net-tools is a collection of programs that form the base set of the NET-3 "
    "networking distribution. In versions up to and including 2.10, the Linux "
    "network utilities do not properly validate the structure of /proc files."
)


def _fetch(text):
    return lambda cve: text


def test_an_advisory_naming_the_package_passes():
    assert check_cve_names_package("CVE-2025-30472", "corosync", fetch=_fetch(COROSYNC)) is None


def test_an_advisory_about_another_package_is_rejected():
    reason = check_cve_names_package("CVE-2025-46836", "corosync", fetch=_fetch(NETTOOLS))
    assert reason and "corosync" in reason


def test_punctuation_and_case_do_not_decide_it():
    assert check_cve_names_package("CVE-2025-46836", "nettools", fetch=_fetch(NETTOOLS)) is None


def test_a_registry_attr_matches_on_its_module_name():
    text = "Perl module Spreadsheet::ParseExcel 0.65 allows arbitrary code execution."
    assert check_cve_names_package(
        "CVE-2023-7101", "perlPackages.SpreadsheetParseExcel", fetch=_fetch(text)
    ) is None


def test_a_reference_url_counts_as_naming_the_package():
    text = "A flaw in the daemon. See https://github.com/corosync/corosync/commit/7839990f"
    assert check_cve_names_package("CVE-2025-30472", "corosync", fetch=_fetch(text)) is None


def test_a_failed_lookup_is_reported_rather_than_swallowed():
    def boom(cve):
        raise RuntimeError("nvd said 503")

    reason = check_cve_names_package("CVE-2025-30472", "corosync", fetch=boom)
    assert reason and "503" in reason


def test_a_short_name_does_not_match_a_longer_word_that_starts_with_it():
    reason = check_cve_names_package("CVE-2020-0001", "jq", fetch=_fetch("a jquery flaw"))
    assert reason and "does not name jq" in reason


def test_package_tokens_drop_the_version_suffix():
    assert "grub" in package_tokens("grub2")


def test_a_digit_in_the_name_survives():
    text = "lz4 before 1.9.4 has an integer overflow in LZ4_write32."
    assert check_cve_names_package("CVE-2021-3520", "lz4", fetch=_fetch(text)) is None


def test_a_multi_word_module_name_matches():
    text = "Net::CIDR::Lite through 0.21 does not properly validate octets."
    assert check_cve_names_package(
        "CVE-2021-28918", "perlPackages.NetCIDRLite", fetch=_fetch(text)
    ) is None


def test_the_corpus_walk_reports_the_bundles_that_disagree(tmp_path):
    from eval.cve_package_check import audit_corpus

    good = tmp_path / "CVE-2025-30472--corosync-orf-token-backport"
    bad = tmp_path / "CVE-2025-46836--corosync-orf-token-backport"
    for d in (good, bad):
        d.mkdir()
        (d / "resolver-input.json").write_text('{"attr_path": "corosync"}')
    text = {"CVE-2025-30472": COROSYNC, "CVE-2025-46836": NETTOOLS}
    bad_rows = audit_corpus(tmp_path, fetch=lambda c: text[c], pause=lambda _: None)
    assert [r[0] for r in bad_rows] == [bad.name]


def test_a_bundle_naming_no_package_is_skipped(tmp_path):
    from eval.cve_package_check import audit_corpus

    (tmp_path / "CVE-2025-30472--nothing").mkdir()
    assert audit_corpus(tmp_path, fetch=_fetch(COROSYNC), pause=lambda _: None) == []


def test_a_withdrawn_candidate_is_called_out_as_withdrawn():
    text = ("Rejected reason: DO NOT USE THIS CANDIDATE NUMBER. ConsultIDs: none. "
            "Reason: This candidate was withdrawn by its CNA.")
    reason = check_cve_names_package("CVE-2022-47016", "tmux", fetch=_fetch(text))
    assert reason and "withdrawn" in reason


def test_lib_prefixed_upstream_name_matches_bare_nixpkgs_attr():
    """nixpkgs calls it `expat`; the advisory calls it `libexpat`."""
    advisory = "In libexpat before 2.8.1, attribute name collision checks allow a denial of service."
    assert check_cve_names_package("CVE-2026-45186", "expat", fetch=lambda c: advisory) is None


def test_two_letter_package_matches_the_cpe_product():
    advisory = "A flaw in the JSON processor. cpe:2.3:a:jqlang:jq:*:*:*:*:*:*:*:*"
    assert check_cve_names_package("CVE-2026-33948", "jq", fetch=lambda c: advisory) is None


def test_two_letter_package_still_rejects_an_unrelated_advisory():
    advisory = "In libexpat before 2.8.1, a denial of service. cpe:2.3:a:libexpat_project:libexpat:*"
    reason = check_cve_names_package("CVE-2026-45186", "jq", fetch=lambda c: advisory)
    assert reason and "does not name jq" in reason
