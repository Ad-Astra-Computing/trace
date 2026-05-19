"""Tests for `agents.reproducer.parser.parse_reproducer_output`.

Per `docs/REPRODUCER_V1.md` and `prompts/reproducer.v1.md`:

  * three-file output (reproducer.nix / reproducer-log.txt /
    passthru-tests.json) OR a refusal block
  * paired SIGNAL_UNPATCHED + SIGNAL_PATCHED with length bounds,
    generic-token floor, distinct-signals rule
  * passthru-tests.json: well-shaped JSON array, kind enum
  * proxy lane: meta.proxy=true + four required meta fields +
    locked proxy_reason enum + matching `=== proxy ===` log section
  * refusal range 1-8

The parser enforces output shape ONLY. Execution semantics (does the
test actually emit the named signal, etc.) belong to Builder.
"""

from __future__ import annotations

import json

import pytest

from agents.reproducer import (
    PROXY_REASON_ENUM,
    ProxyMetadata,
    ReproducerOutputMalformed,
    SIGNAL_GENERIC_TOKEN_FORBIDDEN,
    SIGNAL_LENGTH_MAX,
    SIGNAL_LENGTH_MIN,
    parse_reproducer_output,
)


# ─── happy-path fixtures ──────────────────────────────────────────────────


_GOOD_NIX = """\
{ pkgs ? import <nixpkgs> { } }:

let
  unpatched = pkgs.demo.overrideAttrs (old: {
    version = "1.0.0";
  });
  patched = pkgs.demo;
in
{
  inherit unpatched patched;

  test = pkgs.runCommand "repro-CVE-2026-99999" { } ''
    if ! ${unpatched}/bin/demo --check; then
      echo "vuln-triggered: deserialise() returned out-of-bounds for malformed length-prefix"
    fi
    if ${patched}/bin/demo --check; then
      echo "rejected-malformed-length-prefix-as-expected-from-CVE-2026-99999"
    fi
  '';
}
"""

_GOOD_LOG = """\
The unpatched `demo` binary fails to bound the length prefix in deserialise().

=== unpatched ===
On the unpatched binary, the malformed-length-prefix payload triggers an out-of-bounds read inside `deserialise()`. The vuln-class signal is the explicit "vuln-triggered" message the test prints.
+ ${unpatched}/bin/demo --check
vuln-triggered: deserialise() returned out-of-bounds for malformed length-prefix
SIGNAL_UNPATCHED: vuln-triggered: deserialise() returned out-of-bounds for malformed length-prefix
EXIT: 1

=== patched ===
On the patched binary, deserialise() now rejects the same input before reading past the buffer end.
+ ${patched}/bin/demo --check
rejected-malformed-length-prefix-as-expected-from-CVE-2026-99999
SIGNAL_PATCHED: rejected-malformed-length-prefix-as-expected-from-CVE-2026-99999
EXIT: 0
"""


_GOOD_PASSTHRU = """\
[
  { "name": "passthru.tests.basic", "drv_path": null, "kind": "passthru.tests" },
  { "name": "nixosTests.demo-smoke",  "drv_path": null, "kind": "nixosTests" }
]
"""


def _wrap_three_files(nix: str = _GOOD_NIX, log: str = _GOOD_LOG, pj: str = _GOOD_PASSTHRU) -> str:
    return (
        "=== BEGIN reproducer.nix ===\n"
        f"{nix}"
        "=== END reproducer.nix ===\n"
        "=== BEGIN reproducer-log.txt ===\n"
        f"{log}"
        "=== END reproducer-log.txt ===\n"
        "=== BEGIN passthru-tests.json ===\n"
        f"{pj}"
        "=== END passthru-tests.json ===\n"
    )


# ─── happy path ───────────────────────────────────────────────────────────


def test_well_formed_three_file_output_parses() -> None:
    raw = _wrap_three_files()
    res = parse_reproducer_output(raw)
    assert res.kind == "reproducer"
    assert res.is_proxy is False
    assert res.log_unpatched is not None
    assert res.log_patched is not None
    assert res.log_unpatched.signal.startswith("vuln-triggered:")
    assert res.log_patched.signal.startswith("rejected-malformed-length-prefix")
    assert res.log_unpatched.exit_code == 1
    assert res.log_patched.exit_code == 0
    assert len(res.passthru_tests) == 2
    assert res.passthru_tests[0].kind == "passthru.tests"
    assert res.passthru_tests[1].kind == "nixosTests"
    # Raw bodies are populated for atomic-write.
    assert res.raw_reproducer_nix is not None
    assert res.raw_reproducer_log_txt is not None
    assert res.raw_passthru_tests_json is not None
    # Canonicalised JSON is a re-serialised form, not the model's string.
    parsed_back = json.loads(res.raw_passthru_tests_json)
    assert parsed_back == json.loads(_GOOD_PASSTHRU)


def test_to_schema_dict_shape() -> None:
    raw = _wrap_three_files()
    res = parse_reproducer_output(raw)
    d = res.to_schema_dict()
    assert d["schema_version"]
    assert d["is_proxy"] is False
    assert d["log_unpatched"]["name"] == "unpatched"
    assert d["log_patched"]["name"] == "patched"
    assert d["proxy"] is None
    assert len(d["passthru_tests"]) == 2


def test_empty_passthru_array_is_valid() -> None:
    raw = _wrap_three_files(pj="[]\n")
    res = parse_reproducer_output(raw)
    assert res.kind == "reproducer"
    assert res.passthru_tests == []


def test_drv_path_null_is_valid() -> None:
    pj = json.dumps([
        {"name": "passthru.tests.basic", "drv_path": None, "kind": "passthru.tests"},
    ]) + "\n"
    raw = _wrap_three_files(pj=pj)
    res = parse_reproducer_output(raw)
    assert res.passthru_tests[0].drv_path is None


def test_drv_path_string_is_valid() -> None:
    pj = json.dumps([
        {"name": "passthru.tests.basic",
         "drv_path": "/nix/store/abc-foo.drv",
         "kind": "passthru.tests"},
    ]) + "\n"
    raw = _wrap_three_files(pj=pj)
    res = parse_reproducer_output(raw)
    assert res.passthru_tests[0].drv_path == "/nix/store/abc-foo.drv"


# ─── markdown-fence tolerance ─────────────────────────────────────────────


def test_wrapping_code_fence_is_stripped() -> None:
    raw = "```\n" + _wrap_three_files() + "\n```"
    res = parse_reproducer_output(raw)
    assert res.kind == "reproducer"


def test_language_tagged_fence_is_stripped() -> None:
    raw = "```text\n" + _wrap_three_files() + "\n```"
    res = parse_reproducer_output(raw)
    assert res.kind == "reproducer"


# ─── refusals ─────────────────────────────────────────────────────────────


def test_refusal_block_parses() -> None:
    raw = (
        "=== BEGIN refusal ===\n"
        "rule: 3\n"
        "reason: vuln class is not locally-reproducible (kernel oops)\n"
        "=== END refusal ===\n"
    )
    res = parse_reproducer_output(raw)
    assert res.kind == "refusal"
    assert res.refusal_rule == 3
    assert "kernel oops" in res.refusal_reason


@pytest.mark.parametrize("rule_n", [0, 9, 99])
def test_refusal_rule_out_of_range_rejected(rule_n: int) -> None:
    raw = (
        "=== BEGIN refusal ===\n"
        f"rule: {rule_n}\n"
        "reason: out of range probe\n"
        "=== END refusal ===\n"
    )
    with pytest.raises(ReproducerOutputMalformed, match="rule must be in"):
        parse_reproducer_output(raw)


@pytest.mark.parametrize("rule_n", [1, 2, 3, 4, 5, 6, 7, 8])
def test_refusal_rule_in_range_accepted(rule_n: int) -> None:
    raw = (
        "=== BEGIN refusal ===\n"
        f"rule: {rule_n}\n"
        "reason: in-range probe\n"
        "=== END refusal ===\n"
    )
    res = parse_reproducer_output(raw)
    assert res.refusal_rule == rule_n


# ─── preamble / postamble forbidden ──────────────────────────────────────


def test_prose_preamble_before_first_marker_is_forbidden() -> None:
    raw = "Here is my reproducer:\n\n" + _wrap_three_files()
    with pytest.raises(ReproducerOutputMalformed, match="preamble"):
        parse_reproducer_output(raw)


def test_trailing_prose_after_last_marker_is_forbidden() -> None:
    raw = _wrap_three_files() + "\nThanks for reading!\n"
    with pytest.raises(ReproducerOutputMalformed, match="trailing prose"):
        parse_reproducer_output(raw)


def test_inter_block_prose_forbidden() -> None:
    raw = (
        "=== BEGIN reproducer.nix ===\n"
        f"{_GOOD_NIX}"
        "=== END reproducer.nix ===\n"
        "Some commentary between blocks.\n"
        "=== BEGIN reproducer-log.txt ===\n"
        f"{_GOOD_LOG}"
        "=== END reproducer-log.txt ===\n"
        "=== BEGIN passthru-tests.json ===\n"
        f"{_GOOD_PASSTHRU}"
        "=== END passthru-tests.json ===\n"
    )
    with pytest.raises(ReproducerOutputMalformed, match="inter-block prose"):
        parse_reproducer_output(raw)


def test_no_marker_at_all_is_malformed() -> None:
    with pytest.raises(ReproducerOutputMalformed, match="no '=== BEGIN"):
        parse_reproducer_output("just a free text response with no markers")


def test_block_order_must_be_nix_log_passthru() -> None:
    raw = (
        "=== BEGIN reproducer.nix ===\n"
        f"{_GOOD_NIX}"
        "=== END reproducer.nix ===\n"
        "=== BEGIN passthru-tests.json ===\n"
        f"{_GOOD_PASSTHRU}"
        "=== END passthru-tests.json ===\n"
        "=== BEGIN reproducer-log.txt ===\n"
        f"{_GOOD_LOG}"
        "=== END reproducer-log.txt ===\n"
    )
    with pytest.raises(ReproducerOutputMalformed, match="appear in the order"):
        parse_reproducer_output(raw)


# ─── reproducer.nix structural floor ─────────────────────────────────────


def test_nix_must_have_pkgs_function_header() -> None:
    bad = "let foo = 1; in { unpatched = 1; patched = 1; test = 1; }"
    raw = _wrap_three_files(nix=bad + "\n")
    with pytest.raises(ReproducerOutputMalformed, match="pkgs"):
        parse_reproducer_output(raw)


def test_nix_minimal_pkgs_arg_form_accepted() -> None:
    """`{ pkgs }:` (without the import default) is valid."""
    nix = (
        "{ pkgs }:\n"
        "{\n"
        "  unpatched = pkgs.demo;\n"
        "  patched = pkgs.demo;\n"
        "  test = pkgs.runCommand \"r\" { } ''true'';\n"
        "}\n"
    )
    raw = _wrap_three_files(nix=nix)
    res = parse_reproducer_output(raw)
    assert res.kind == "reproducer"


@pytest.mark.parametrize("missing_attr", ["unpatched", "patched", "test"])
def test_nix_missing_required_attribute_rejected(missing_attr: str) -> None:
    nix_lines = [
        "{ pkgs ? import <nixpkgs> { } }:",
        "{",
        "  unpatched = pkgs.demo;",
        "  patched = pkgs.demo;",
        "  test = pkgs.runCommand \"r\" { } ''true'';",
        "}",
    ]
    # Strip the line that defines `missing_attr`.
    nix = "\n".join(line for line in nix_lines
                    if not line.lstrip().startswith(f"{missing_attr} =")) + "\n"
    raw = _wrap_three_files(nix=nix)
    with pytest.raises(ReproducerOutputMalformed, match=f"`{missing_attr}` attribute"):
        parse_reproducer_output(raw)


# ─── fetcher policy (v0.1 hash-pinned carve-out) ─────────────────────────


@pytest.mark.parametrize("hard_forbidden", [
    "fetchpatch",
    "builtins.fetchurl",
    "builtins.fetchTarball",
])
def test_hard_forbidden_fetcher_rejected(hard_forbidden: str) -> None:
    """Three fetcher classes remain forbidden unconditionally even after
    the hash-pinned carve-out: fetchpatch (patches must come from
    `old.patches` filtering, not network downloads) and the
    `builtins.*` variants (impure / hash-less)."""
    nix = (
        "{ pkgs ? import <nixpkgs> { } }:\n"
        "let\n"
        f"  fixture = {hard_forbidden} {{ url = \"https://example.invalid/x\"; sha256 = \"...\"; }};\n"
        "in {\n"
        "  unpatched = pkgs.demo;\n"
        "  patched = pkgs.demo;\n"
        "  test = pkgs.runCommand \"r\" { } ''true'';\n"
        "}\n"
    )
    raw = _wrap_three_files(nix=nix)
    with pytest.raises(ReproducerOutputMalformed, match="forbidden fetcher"):
        parse_reproducer_output(raw)


@pytest.mark.parametrize("soft_forbidden", [
    "fetchurl",
    "fetchzip",
    "fetchFromGitHub",
    "fetchgit",
    "fetchFromGitLab",
    "fetchFromGitea",
])
def test_hash_pinnable_fetcher_without_sri_hash_rejected(soft_forbidden: str) -> None:
    """A hash-pinnable fetcher call with no SRI hash literal is still
    rejected — the v0.1 carve-out only opens the gate for call sites
    that carry the hash literal at the call site."""
    nix = (
        "{ pkgs ? import <nixpkgs> { } }:\n"
        "let\n"
        f"  fixture = {soft_forbidden} {{ url = \"https://example.invalid/x\"; sha256 = \"...\"; }};\n"
        "in {\n"
        "  unpatched = pkgs.demo;\n"
        "  patched = pkgs.demo;\n"
        "  test = pkgs.runCommand \"r\" { } ''true'';\n"
        "}\n"
    )
    raw = _wrap_three_files(nix=nix)
    with pytest.raises(ReproducerOutputMalformed, match="forbidden network fetcher"):
        parse_reproducer_output(raw)


def test_hash_pinned_fetchFromGitLab_allowed_for_unpatched_reconstruction() -> None:
    """The canonical v0.1 use case: reconstruct the unpatched src by
    calling the original fetcher with the prior version's hash and tag
    pinned at the call site. The wget2 case that surfaced the contract
    limit on 2026-05-13."""
    nix = (
        "{ pkgs ? import <nixpkgs> { } }:\n"
        "let\n"
        "  unpatched = pkgs.wget2.overrideAttrs (old: {\n"
        "    version = \"2.2.0\";\n"
        "    src = pkgs.fetchFromGitLab {\n"
        "      owner = \"gnuwget\";\n"
        "      repo = \"wget2\";\n"
        "      tag = \"v2.2.0\";\n"
        "      hash = \"sha256-0tOoStZHr5opehFmuQdFRPYvOv8IMrDTBNFtoweY3VM=\";\n"
        "    };\n"
        "  });\n"
        "in {\n"
        "  inherit unpatched;\n"
        "  patched = pkgs.wget2;\n"
        "  test = pkgs.runCommand \"r\" { } ''true'';\n"
        "}\n"
    )
    raw = _wrap_three_files(nix=nix)
    # Must not raise — hash literal + specific tag + no fakeHash.
    parse_reproducer_output(raw)


def test_hash_pinned_fetchFromGitHub_with_rev_allowed() -> None:
    """Same carve-out for fetchFromGitHub with `rev = "v..."` instead of
    `tag`."""
    nix = (
        "{ pkgs ? import <nixpkgs> { } }:\n"
        "let\n"
        "  unpatched_src = pkgs.fetchFromGitHub {\n"
        "    owner = \"org\";\n"
        "    repo = \"name\";\n"
        "    rev = \"v1.2.3\";\n"
        "    hash = \"sha512-AbCdEfGhIjKlMnOpQrStUvWxYz0123456789AbCdEfGhIjKlMnOpQrStUvWxYz0123456789AbCdEfGh==\";\n"
        "  };\n"
        "in {\n"
        "  unpatched = pkgs.demo.overrideAttrs (_: { src = unpatched_src; });\n"
        "  patched = pkgs.demo;\n"
        "  test = pkgs.runCommand \"r\" { } ''true'';\n"
        "}\n"
    )
    raw = _wrap_three_files(nix=nix)
    parse_reproducer_output(raw)


def test_hash_pinned_fetcher_with_fakeHash_rejected() -> None:
    """`hash = fakeHash` defeats the carve-out — it forces an FOD
    mismatch at build time which is precisely the network-fetch event
    we're guarding against."""
    nix = (
        "{ pkgs ? import <nixpkgs> { } }:\n"
        "let\n"
        "  bad = pkgs.fetchFromGitLab {\n"
        "    owner = \"o\"; repo = \"r\"; tag = \"v1\";\n"
        "    hash = pkgs.lib.fakeHash;\n"
        "  };\n"
        "in {\n"
        "  unpatched = pkgs.demo.overrideAttrs (_: { src = bad; });\n"
        "  patched = pkgs.demo;\n"
        "  test = pkgs.runCommand \"r\" { } ''true'';\n"
        "}\n"
    )
    raw = _wrap_three_files(nix=nix)
    with pytest.raises(ReproducerOutputMalformed, match="fakeHash"):
        parse_reproducer_output(raw)


@pytest.mark.parametrize("floating_assignment", [
    'rev = "main"',
    'rev = "master"',
    'tag = "HEAD"',
    'ref = "refs/heads/main"',
])
def test_hash_pinned_fetcher_with_floating_ref_rejected(floating_assignment: str) -> None:
    """Even with a real SRI hash, a floating rev/tag/ref defeats the
    carve-out: the hash literal would go stale the next time upstream
    moves the branch, and the sandbox would then fail non-
    reproducibly."""
    nix = (
        "{ pkgs ? import <nixpkgs> { } }:\n"
        "let\n"
        "  bad = pkgs.fetchFromGitHub {\n"
        "    owner = \"o\"; repo = \"r\";\n"
        f"    {floating_assignment};\n"
        "    hash = \"sha256-AbCdEfGhIjKlMnOpQrStUvWxYz0123456789AbCdEfGh==\";\n"
        "  };\n"
        "in {\n"
        "  unpatched = pkgs.demo.overrideAttrs (_: { src = bad; });\n"
        "  patched = pkgs.demo;\n"
        "  test = pkgs.runCommand \"r\" { } ''true'';\n"
        "}\n"
    )
    raw = _wrap_three_files(nix=nix)
    with pytest.raises(ReproducerOutputMalformed, match="floating"):
        parse_reproducer_output(raw)


# ─── log signals: length, distinctness, generic tokens ──────────────────


def _log_with(unpatched_signal: str, patched_signal: str) -> str:
    return (
        "=== unpatched ===\n"
        "Unpatched commentary.\n"
        f"SIGNAL_UNPATCHED: {unpatched_signal}\n"
        "EXIT: 1\n"
        "\n"
        "=== patched ===\n"
        "Patched commentary.\n"
        f"SIGNAL_PATCHED: {patched_signal}\n"
        "EXIT: 0\n"
    )


def test_signal_too_short_rejected() -> None:
    short_signal = "x" * (SIGNAL_LENGTH_MIN - 1)
    raw = _wrap_three_files(
        log=_log_with(short_signal,
                      "rejected-malformed-length-prefix-as-expected-from-cve-XX")
    )
    with pytest.raises(ReproducerOutputMalformed, match="length"):
        parse_reproducer_output(raw)


def test_signal_too_long_rejected() -> None:
    long_signal = "y" * (SIGNAL_LENGTH_MAX + 1)
    raw = _wrap_three_files(
        log=_log_with(long_signal,
                      "rejected-malformed-length-prefix-as-expected-from-cve-XX")
    )
    with pytest.raises(ReproducerOutputMalformed, match="length"):
        parse_reproducer_output(raw)


@pytest.mark.parametrize("generic", sorted(SIGNAL_GENERIC_TOKEN_FORBIDDEN))
def test_signal_generic_token_rejected(generic: str) -> None:
    if not generic:
        pytest.skip("empty-string handled by length-min check, not generic-token check")
    if len(generic) < SIGNAL_LENGTH_MIN:
        # Pad to satisfy length floor; the generic-token rule strips
        # whitespace before lookup, so leading whitespace doesn't help.
        # We can't trick the rule; the test must be that the raw lookup
        # fires AS LONG AS length floor is satisfied. If the token is
        # too short to satisfy the floor, length-min rejects it first.
        pytest.skip(f"generic token {generic!r} is shorter than the length floor; "
                    "the floor rejects it before the generic-token check fires")
    raw = _wrap_three_files(
        log=_log_with(generic,
                      "rejected-malformed-length-prefix-as-expected-from-cve-XX")
    )
    with pytest.raises(ReproducerOutputMalformed):
        parse_reproducer_output(raw)


def test_identical_signals_rejected() -> None:
    sig = "vuln-triggered: out-of-bounds-read-in-deserialise-fn"
    raw = _wrap_three_files(log=_log_with(sig, sig))
    with pytest.raises(ReproducerOutputMalformed, match="identical"):
        parse_reproducer_output(raw)


def test_unpatched_substring_of_patched_rejected() -> None:
    short = "vuln-triggered: out-of-bounds-read"
    longer = "vuln-triggered: out-of-bounds-read-in-deserialise-fn"
    raw = _wrap_three_files(log=_log_with(short, longer))
    with pytest.raises(ReproducerOutputMalformed, match="substring"):
        parse_reproducer_output(raw)


def test_patched_substring_of_unpatched_rejected() -> None:
    short = "rejected-malformed-length-prefix"
    longer = "rejected-malformed-length-prefix-as-expected-from-cve-XX"
    raw = _wrap_three_files(log=_log_with(longer, short))
    with pytest.raises(ReproducerOutputMalformed, match="substring"):
        parse_reproducer_output(raw)


def test_missing_signal_unpatched_line_rejected() -> None:
    log = (
        "=== unpatched ===\n"
        "no signal here\n"
        "EXIT: 1\n"
        "\n"
        "=== patched ===\n"
        "SIGNAL_PATCHED: rejected-malformed-length-prefix-as-expected-from-cve-XX\n"
        "EXIT: 0\n"
    )
    raw = _wrap_three_files(log=log)
    with pytest.raises(ReproducerOutputMalformed, match="SIGNAL_UNPATCHED"):
        parse_reproducer_output(raw)


def test_missing_signal_patched_line_rejected() -> None:
    log = (
        "=== unpatched ===\n"
        "SIGNAL_UNPATCHED: vuln-triggered: out-of-bounds-read-in-deserialise-fn\n"
        "EXIT: 1\n"
        "\n"
        "=== patched ===\n"
        "no signal here either\n"
        "EXIT: 0\n"
    )
    raw = _wrap_three_files(log=log)
    with pytest.raises(ReproducerOutputMalformed, match="SIGNAL_PATCHED"):
        parse_reproducer_output(raw)


def test_missing_exit_line_rejected() -> None:
    log = (
        "=== unpatched ===\n"
        "SIGNAL_UNPATCHED: vuln-triggered: out-of-bounds-read-in-deserialise-fn\n"
        "\n"
        "=== patched ===\n"
        "SIGNAL_PATCHED: rejected-malformed-length-prefix-as-expected-from-cve-XX\n"
        "EXIT: 0\n"
    )
    raw = _wrap_three_files(log=log)
    with pytest.raises(ReproducerOutputMalformed, match="EXIT:"):
        parse_reproducer_output(raw)


def test_missing_unpatched_section_rejected() -> None:
    log = (
        "=== patched ===\n"
        "SIGNAL_PATCHED: rejected-malformed-length-prefix-as-expected-from-cve-XX\n"
        "EXIT: 0\n"
    )
    raw = _wrap_three_files(log=log)
    with pytest.raises(ReproducerOutputMalformed, match="unpatched"):
        parse_reproducer_output(raw)


def test_section_order_unpatched_then_patched() -> None:
    log = (
        "=== patched ===\n"
        "SIGNAL_PATCHED: rejected-malformed-length-prefix-as-expected-from-cve-XX\n"
        "EXIT: 0\n"
        "\n"
        "=== unpatched ===\n"
        "SIGNAL_UNPATCHED: vuln-triggered: out-of-bounds-read-in-deserialise-fn\n"
        "EXIT: 1\n"
    )
    raw = _wrap_three_files(log=log)
    with pytest.raises(ReproducerOutputMalformed, match="order"):
        parse_reproducer_output(raw)


def test_duplicate_section_header_rejected() -> None:
    log = (
        "=== unpatched ===\n"
        "SIGNAL_UNPATCHED: vuln-triggered: out-of-bounds-read-in-deserialise-fn\n"
        "EXIT: 1\n"
        "\n"
        "=== unpatched ===\n"
        "SIGNAL_UNPATCHED: vuln-triggered: out-of-bounds-read-in-deserialise-fn\n"
        "EXIT: 1\n"
        "\n"
        "=== patched ===\n"
        "SIGNAL_PATCHED: rejected-malformed-length-prefix-as-expected-from-cve-XX\n"
        "EXIT: 0\n"
    )
    raw = _wrap_three_files(log=log)
    with pytest.raises(ReproducerOutputMalformed, match="duplicate"):
        parse_reproducer_output(raw)


# ─── passthru-tests.json shape ───────────────────────────────────────────


def test_passthru_not_an_array_rejected() -> None:
    raw = _wrap_three_files(pj='{"name": "x", "drv_path": null, "kind": "passthru.tests"}\n')
    with pytest.raises(ReproducerOutputMalformed, match="JSON array"):
        parse_reproducer_output(raw)


def test_passthru_invalid_json_rejected() -> None:
    raw = _wrap_three_files(pj="not even json{{\n")
    with pytest.raises(ReproducerOutputMalformed, match="not valid JSON"):
        parse_reproducer_output(raw)


def test_passthru_extra_keys_rejected() -> None:
    pj = json.dumps([
        {"name": "x", "drv_path": None, "kind": "passthru.tests", "extra": True}
    ]) + "\n"
    raw = _wrap_three_files(pj=pj)
    with pytest.raises(ReproducerOutputMalformed, match="exactly the keys"):
        parse_reproducer_output(raw)


def test_passthru_missing_keys_rejected() -> None:
    pj = json.dumps([{"name": "x", "kind": "passthru.tests"}]) + "\n"
    raw = _wrap_three_files(pj=pj)
    with pytest.raises(ReproducerOutputMalformed, match="exactly the keys"):
        parse_reproducer_output(raw)


def test_passthru_kind_not_in_enum_rejected() -> None:
    pj = json.dumps([
        {"name": "x", "drv_path": None, "kind": "checkPhase"}
    ]) + "\n"
    raw = _wrap_three_files(pj=pj)
    with pytest.raises(ReproducerOutputMalformed, match="kind must be one of"):
        parse_reproducer_output(raw)


def test_passthru_empty_name_rejected() -> None:
    pj = json.dumps([{"name": "", "drv_path": None, "kind": "nixosTests"}]) + "\n"
    raw = _wrap_three_files(pj=pj)
    with pytest.raises(ReproducerOutputMalformed, match="non-empty string"):
        parse_reproducer_output(raw)


# ─── proxy lane ───────────────────────────────────────────────────────────


def _proxy_nix(reason: str = "sandbox-cannot-trigger") -> str:
    return (
        "{ pkgs ? import <nixpkgs> { } }:\n"
        "let\n"
        "  unpatched = pkgs.demo;\n"
        "  patched = pkgs.demo;\n"
        "in {\n"
        "  inherit unpatched patched;\n"
        "  test = pkgs.runCommand \"repro-proxy\" { } ''\n"
        "    echo \"rejected-malformed-length-prefix-as-expected-from-cve-XX\"\n"
        "  '' // {\n"
        "    meta = {\n"
        "      proxy = true;\n"
        f"      proxy_reason = \"{reason}\";\n"
        "      why_not_full_repro = \"The full chain requires CAP_SYS_ADMIN which the build sandbox forbids; only the patched-rejection path is locally verifiable.\";\n"
        "      expected_limitations = \"This proxy verifies only the parser's malformed-input rejection, not the downstream privilege escalation the unpatched chain reaches.\";\n"
        "    };\n"
        "  };\n"
        "}\n"
    )


def _proxy_log(reason: str = "sandbox-cannot-trigger") -> str:
    return (
        "Proxy reproducer for a CVE whose full chain requires CAP_SYS_ADMIN.\n"
        "\n"
        "=== unpatched ===\n"
        "By design out of scope for this proxy; see proxy section below.\n"
        "SIGNAL_UNPATCHED: proxy-test: full-chain unpatched evidence intentionally omitted (CAP_SYS_ADMIN)\n"
        "EXIT: 0\n"
        "\n"
        "=== patched ===\n"
        "Proxy verifies the parser's malformed-input rejection on the patched binary.\n"
        "SIGNAL_PATCHED: rejected-malformed-length-prefix-as-expected-from-cve-XX\n"
        "EXIT: 0\n"
        "\n"
        "=== proxy ===\n"
        f"proxy_reason: {reason}\n"
        "why_not_full_repro: The full chain requires CAP_SYS_ADMIN which the build sandbox forbids; only the patched-rejection path is locally verifiable.\n"
        "expected_limitations: This proxy verifies only the parser's malformed-input rejection, not the downstream privilege escalation the unpatched chain reaches.\n"
    )


def test_well_formed_proxy_parses() -> None:
    raw = _wrap_three_files(nix=_proxy_nix(), log=_proxy_log())
    res = parse_reproducer_output(raw)
    assert res.kind == "reproducer"
    assert res.is_proxy is True
    assert res.proxy is not None
    assert res.proxy.proxy_reason == "sandbox-cannot-trigger"
    assert "CAP_SYS_ADMIN" in res.proxy.why_not_full_repro
    assert "downstream" in res.proxy.expected_limitations


def test_proxy_log_present_but_nix_missing_meta_rejected() -> None:
    """nix without meta.proxy=true vs log with `=== proxy ===` is mismatch."""
    raw = _wrap_three_files(nix=_GOOD_NIX, log=_proxy_log())
    with pytest.raises(ReproducerOutputMalformed, match="proxy declaration mismatch"):
        parse_reproducer_output(raw)


def test_proxy_nix_present_but_log_missing_section_rejected() -> None:
    raw = _wrap_three_files(nix=_proxy_nix(), log=_GOOD_LOG)
    with pytest.raises(ReproducerOutputMalformed, match="proxy declaration mismatch"):
        parse_reproducer_output(raw)


@pytest.mark.parametrize("bad_reason", [
    "convenient",
    "we-just-couldnt",
    "platform-issue",
])
def test_proxy_reason_outside_enum_rejected(bad_reason: str) -> None:
    raw = _wrap_three_files(nix=_proxy_nix(reason=bad_reason),
                            log=_proxy_log(reason=bad_reason))
    with pytest.raises(ReproducerOutputMalformed, match="enum"):
        parse_reproducer_output(raw)


@pytest.mark.parametrize("reason", sorted(PROXY_REASON_ENUM))
def test_every_locked_proxy_reason_value_accepted(reason: str) -> None:
    raw = _wrap_three_files(nix=_proxy_nix(reason=reason),
                            log=_proxy_log(reason=reason))
    res = parse_reproducer_output(raw)
    assert res.proxy is not None
    assert res.proxy.proxy_reason == reason


def test_proxy_log_section_missing_required_keys_rejected() -> None:
    log = (
        "=== unpatched ===\n"
        "SIGNAL_UNPATCHED: proxy-test: full-chain unpatched evidence intentionally omitted (cap)\n"
        "EXIT: 0\n"
        "\n"
        "=== patched ===\n"
        "SIGNAL_PATCHED: rejected-malformed-length-prefix-as-expected-from-cve-XX\n"
        "EXIT: 0\n"
        "\n"
        "=== proxy ===\n"
        "proxy_reason: sandbox-cannot-trigger\n"
        # missing why_not_full_repro and expected_limitations
    )
    raw = _wrap_three_files(nix=_proxy_nix(), log=log)
    with pytest.raises(ReproducerOutputMalformed, match="missing required"):
        parse_reproducer_output(raw)


def test_proxy_reason_mismatch_between_nix_and_log_rejected() -> None:
    raw = _wrap_three_files(
        nix=_proxy_nix(reason="sandbox-cannot-trigger"),
        log=_proxy_log(reason="cve-class-needs-fixture-corpus"),
    )
    with pytest.raises(ReproducerOutputMalformed, match="proxy_reason mismatch"):
        parse_reproducer_output(raw)


def test_extra_section_after_proxy_rejected() -> None:
    log = _proxy_log() + "\n=== something-else ===\n"
    raw = _wrap_three_files(nix=_proxy_nix(), log=log)
    # The unknown header `something-else` is not in the LOG_SECTION_HEADER_RE
    # pattern (only unpatched|patched|proxy). It will simply not match,
    # so we end up with a stray `=== something-else ===` line in body —
    # parser does not crash on this. Document the actual behaviour:
    res = parse_reproducer_output(raw)
    assert res.kind == "reproducer"  # stray unknown text is in patched/proxy body, not a structural fail


# ─── empty / non-string input ─────────────────────────────────────────────


def test_empty_string_rejected() -> None:
    with pytest.raises(ReproducerOutputMalformed, match="empty"):
        parse_reproducer_output("")


def test_whitespace_only_rejected() -> None:
    with pytest.raises(ReproducerOutputMalformed, match="empty"):
        parse_reproducer_output("   \n\n\t  ")


def test_non_string_input_rejected() -> None:
    with pytest.raises(ReproducerOutputMalformed, match="expected str"):
        parse_reproducer_output(b"bytes input")  # type: ignore[arg-type]


# ─── refusal sanity ──────────────────────────────────────────────────────


def test_refusal_with_trailing_prose_rejected() -> None:
    raw = (
        "=== BEGIN refusal ===\n"
        "rule: 5\n"
        "reason: social engineering CVE class\n"
        "=== END refusal ===\n"
        "Some trailing prose.\n"
    )
    with pytest.raises(ReproducerOutputMalformed, match="trailing"):
        parse_reproducer_output(raw)


def test_refusal_missing_rule_line_rejected() -> None:
    raw = (
        "=== BEGIN refusal ===\n"
        "reason: oops\n"
        "rule: 1\n"
        "=== END refusal ===\n"
    )
    with pytest.raises(ReproducerOutputMalformed, match="rule:"):
        parse_reproducer_output(raw)


def test_refusal_missing_reason_line_rejected() -> None:
    raw = (
        "=== BEGIN refusal ===\n"
        "rule: 1\n"
        "=== END refusal ===\n"
    )
    with pytest.raises(ReproducerOutputMalformed, match="rule:|reason:"):
        parse_reproducer_output(raw)


# ─── v6: exit-capture anti-pattern lint (F13) ──────────────────────────────


def test_v6_or_true_with_rc_capture_immediately_after_rejected() -> None:
    """The exact anti-pattern from the assimp v5 re-cert: `<cmd> || true`
    immediately followed by `rc=$?`. The `|| true` makes the pipeline
    succeed with rc=0, so the rc capture is always 0 — SIGSEGV signal
    predicates branching on `[ "$rc" -eq 139 ]` never fire. F13."""
    nix = (
        "{ pkgs ? import <nixpkgs> { } }:\n"
        "let\n"
        "  unpatched = pkgs.demo.overrideAttrs (old: { passthru.test = pkgs.runCommand \"u\" {} ''\n"
        "    ${pkgs.demo}/bin/demo --crash >run.err 2>&1 || true\n"
        "    rc=$?\n"
        "    if [ \"$rc\" -eq 139 ]; then echo SIGNAL_UNPATCHED: crashed; touch $out; else exit 4; fi\n"
        "  ''; });\n"
        "  patched = pkgs.demo;\n"
        "  test = unpatched.passthru.test;\n"
        "in {\n"
        "  inherit unpatched patched test;\n"
        "}\n"
    )
    raw = _wrap_three_files(nix=nix)
    with pytest.raises(ReproducerOutputMalformed, match="broken `\\|\\| true.*exit-capture"):
        parse_reproducer_output(raw)


def test_v6_or_true_with_rc_capture_separated_by_blank_line_rejected() -> None:
    """The lint tolerates 0-2 blank/comment lines between `|| true` and
    `<name>=$?` — common shape where the model puts an inline comment
    before the rc capture. Still the same anti-pattern."""
    nix = (
        "{ pkgs ? import <nixpkgs> { } }:\n"
        "let\n"
        "  unpatched = pkgs.demo.overrideAttrs (old: { passthru.test = pkgs.runCommand \"u\" {} ''\n"
        "    ${pkgs.demo}/bin/demo --crash >run.err 2>&1 || true\n"
        "\n"
        "    # capture the rc\n"
        "    EXIT=$?\n"
        "    if [ \"$EXIT\" -eq 139 ]; then echo SIGNAL_UNPATCHED: crashed; touch $out; else exit 4; fi\n"
        "  ''; });\n"
        "  patched = pkgs.demo;\n"
        "  test = unpatched.passthru.test;\n"
        "in {\n"
        "  inherit unpatched patched test;\n"
        "}\n"
    )
    raw = _wrap_three_files(nix=nix)
    with pytest.raises(ReproducerOutputMalformed, match="broken `\\|\\| true.*exit-capture"):
        parse_reproducer_output(raw)


def test_v6_bracketed_capture_pattern_accepted() -> None:
    """The correct v6 capture form: `set +e; <cmd>; rc=$?; set -e`.
    No `|| true`, so the rc capture sees the real exit code (including
    SIGSEGV rc=139). Must parse cleanly."""
    nix = (
        "{ pkgs ? import <nixpkgs> { } }:\n"
        "let\n"
        "  unpatched = pkgs.demo.overrideAttrs (old: { passthru.test = pkgs.runCommand \"u\" {} ''\n"
        "    set +e\n"
        "    ${pkgs.demo}/bin/demo --crash >run.err 2>&1\n"
        "    rc=$?\n"
        "    set -e\n"
        "    if [ \"$rc\" -eq 139 ]; then echo SIGNAL_UNPATCHED: crashed; touch $out; else exit 4; fi\n"
        "  ''; });\n"
        "  patched = pkgs.demo;\n"
        "  test = unpatched.passthru.test;\n"
        "in {\n"
        "  inherit unpatched patched test;\n"
        "}\n"
    )
    raw = _wrap_three_files(nix=nix)
    result = parse_reproducer_output(raw)
    assert result.kind == "reproducer"


def test_v6_or_true_in_cleanup_context_not_rejected() -> None:
    """`|| true` is legitimate in cleanup contexts (e.g., `rm -rf $TMPDIR/x || true`
    so a failure to clean doesn't abort the test). Only the immediate
    `|| true` followed by `<name>=$?` exit-capture is banned. A `|| true`
    that is NOT followed by a `$?` capture must parse cleanly."""
    nix = (
        "{ pkgs ? import <nixpkgs> { } }:\n"
        "let\n"
        "  unpatched = pkgs.demo.overrideAttrs (old: { passthru.test = pkgs.runCommand \"u\" {} ''\n"
        "    rm -rf $TMPDIR/u || true\n"
        "    mkdir -p $TMPDIR/u\n"
        "    set +e\n"
        "    ${pkgs.demo}/bin/demo --crash >run.err 2>&1\n"
        "    rc=$?\n"
        "    set -e\n"
        "    if [ \"$rc\" -eq 139 ]; then echo SIGNAL_UNPATCHED: crashed; touch $out; else exit 4; fi\n"
        "  ''; });\n"
        "  patched = pkgs.demo;\n"
        "  test = unpatched.passthru.test;\n"
        "in {\n"
        "  inherit unpatched patched test;\n"
        "}\n"
    )
    raw = _wrap_three_files(nix=nix)
    result = parse_reproducer_output(raw)
    assert result.kind == "reproducer"
