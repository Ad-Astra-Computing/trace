"""Parse Reproducer model output into the contracted shape.

Per `prompts/reproducer.v1.md` and `docs/REPRODUCER_V1.md`, the only two
valid response shapes are:

  (a) a three-file reproducer block:

      === BEGIN reproducer.nix ===
      <Nix expression>
      === END reproducer.nix ===
      === BEGIN reproducer-log.txt ===
      === unpatched ===
      <commentary>
      <predicted output>
      SIGNAL_UNPATCHED: <substring>
      EXIT: <integer>

      === patched ===
      <commentary>
      <predicted output>
      SIGNAL_PATCHED: <substring>
      EXIT: <integer>

      [=== proxy ===
      proxy_reason: <enum>
      why_not_full_repro: <paragraph>
      expected_limitations: <paragraph>]
      [=== harness ===
      harness_class: <enum>
      target_files: <comma-separated repo-relative paths>
      stubbed: <comma-separated module/global names>
      effect: <one line>]
      === END reproducer-log.txt ===
      === BEGIN passthru-tests.json ===
      <JSON array>
      === END passthru-tests.json ===

  (b) a single refusal block (same shape as Patcher / Reviewer):

      === BEGIN refusal ===
      rule: <1-N>
      reason: <one-line reason>
      === END refusal ===

The `proxy` and `harness` sections are each optional and mutually
exclusive: a log carries at most one of them, never both.

The parser enforces output-shape ONLY. Execution-truth checks (does
the test actually emit the named signal? does the unpatched build
crash?) are Builder's territory, not the parser's.

Locked refusal rule range: 1-8 per `prompts/reproducer.v1.md`.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import Any


SCHEMA_VERSION = "1.0.0"


# Refusal rule range. Max 12: the reproducer prompt defines refusal rules through
# rule 11 (F17, silent OOB-read needs ASAN — reproducer.v7) and rule 12 (CWE-class
# crash-reliability — reproducer.v8); v12's fallback-fires-signal ban routes to rule
# 8/11/12. The bound was stale at 8 and rejected legitimate rule-11/12 refusals
# (mbedtls CVE-2024-49195, 2026-06-15). Keep in sync with the prompt's highest rule.
_REPRODUCER_REFUSAL_RULE_MIN = 1
_REPRODUCER_REFUSAL_RULE_MAX = 12


# Per `docs/REPRODUCER_V1.md` §3.2.
SIGNAL_LENGTH_MIN = 24
SIGNAL_LENGTH_MAX = 200


# Per `docs/REPRODUCER_V1.md` §3.2: forbidden generic tokens. Matched
# case-insensitively against the *entire* signal content (after strip).
# Anything in this set is too generic to discriminate vuln from non-vuln.
SIGNAL_GENERIC_TOKEN_FORBIDDEN: frozenset[str] = frozenset(
    {
        "error",
        "error:",
        "failed",
        "failure",
        "assertion failed",
        "aborted",
        "core dumped",
        "success",
        "ok",
        "passed",
        "done",
        "complete",
        "exit code 0",
        "exit code 1",
        "exit status 0",
        "exit status 1",
        "",
    }
)


# Per `docs/REPRODUCER_V1.md` §7. The contract does not allow proxies
# with reasons outside this set; out-of-enum reasons MUST refuse instead.
PROXY_REASON_ENUM: frozenset[str] = frozenset(
    {
        "sandbox-cannot-trigger",
        "chain-requires-public-poc",
        "pre-fix-build-uncrashable-in-sandbox",
        "attack-surface-not-locally-instrumentable",
        "cve-class-needs-fixture-corpus",
    }
)


# Per `docs/specs/stub-harness-fixtures.md`. One value for now; a stub
# harness that stands in for the ambient environment a live service or GUI
# would have supplied is the only class the contract allows.
HARNESS_CLASS_ENUM: frozenset[str] = frozenset(
    {
        "stub-ambient",
    }
)


# Per `docs/REPRODUCER_V1.md` §3.3.
PASSTHRU_KIND_ENUM: frozenset[str] = frozenset(
    {
        "passthru.tests",
        "nixosTests",
    }
)


class ReproducerOutputMalformed(Exception):
    """Raised when model output does not match the prompt contract.

    Carries optional `raw_response` / `raw_response_sha256` / `model_id` /
    `prompt_sha256` / `user_content_sha256` attributes, attached by
    `run_reproducer` so the executor can persist the failing artifact to
    `.reproducer-failures/<uuid>/` for debugging. Mirrors the Patcher
    failure-capture pattern (F19, 2026-05-25).
    """

    raw_response: str | None = None
    raw_response_sha256: str | None = None
    model_id: str | None = None
    prompt_sha256: str | None = None
    user_content_sha256: str | None = None


# ─── result types ─────────────────────────────────────────────────────────


@dataclass(frozen=True)
class LogSection:
    """Parsed contents of a single reproducer-log.txt section."""

    name: str  # "unpatched" | "patched"
    signal: str  # SIGNAL_UNPATCHED or SIGNAL_PATCHED value
    exit_code: int
    body: str  # full body text, including commentary

    def to_schema_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "signal": self.signal,
            "exit_code": self.exit_code,
        }


@dataclass(frozen=True)
class ProxyMetadata:
    """Parsed proxy-section content from reproducer-log.txt + Nix."""

    proxy_reason: str  # one of PROXY_REASON_ENUM
    why_not_full_repro: str
    expected_limitations: str

    def to_schema_dict(self) -> dict[str, Any]:
        return {
            "proxy_reason": self.proxy_reason,
            "why_not_full_repro": self.why_not_full_repro[:2048],
            "expected_limitations": self.expected_limitations[:2048],
        }


@dataclass(frozen=True)
class HarnessMetadata:
    """Parsed harness-section content from reproducer-log.txt.

    Per `docs/specs/stub-harness-fixtures.md`: a stub-harness fixture loads
    the patched code unit under its own interpreter with the ambient
    environment stubbed, when a live service or GUI is the only alternative.
    """

    harness_class: str  # one of HARNESS_CLASS_ENUM
    target_files: tuple[str, ...]  # repo-relative paths loaded unaltered
    stubbed: tuple[str, ...]  # module/global names the harness replaced
    effect: str  # the one-line observable SIGNAL_UNPATCHED reports

    def to_schema_dict(self) -> dict[str, Any]:
        return {
            "harness_class": self.harness_class,
            "target_files": list(self.target_files),
            "stubbed": list(self.stubbed),
            "effect": self.effect[:2048],
        }


@dataclass(frozen=True)
class PassthruEntry:
    """One entry in passthru-tests.json."""

    name: str
    drv_path: str | None
    kind: str  # "passthru.tests" | "nixosTests"

    def to_schema_dict(self) -> dict[str, Any]:
        return {"name": self.name, "drv_path": self.drv_path, "kind": self.kind}


@dataclass(frozen=True)
class ReproducerParseResult:
    """Structured result of a successful parse.

    Fields are populated based on `kind`:
      * kind="reproducer": all reproducer fields populated; refusal_* None.
      * kind="refusal":    refusal_rule + refusal_reason; reproducer fields None/empty.
    """

    kind: str  # "reproducer" | "refusal"

    # reproducer fields
    reproducer_nix: str | None = None
    log_unpatched: LogSection | None = None
    log_patched: LogSection | None = None
    proxy: ProxyMetadata | None = None  # set iff this is a proxy reproducer
    harness: HarnessMetadata | None = None  # set iff this is a stub-harness reproducer
    passthru_tests: list[PassthruEntry] = field(default_factory=list)
    raw_reproducer_nix: str | None = None  # for atomic-write to disk
    raw_reproducer_log_txt: str | None = None
    raw_passthru_tests_json: str | None = None  # canonicalised JSON for write

    # refusal fields
    refusal_rule: int | None = None
    refusal_reason: str | None = None

    @property
    def is_proxy(self) -> bool:
        return self.kind == "reproducer" and self.proxy is not None

    @property
    def is_stub_harness(self) -> bool:
        return self.kind == "reproducer" and self.harness is not None

    def to_schema_dict(self) -> dict[str, Any]:
        if self.kind != "reproducer":
            raise ValueError("to_schema_dict() only valid for kind=reproducer")
        return {
            "schema_version": SCHEMA_VERSION,
            "is_proxy": self.is_proxy,
            "is_stub_harness": self.is_stub_harness,
            "log_unpatched": self.log_unpatched.to_schema_dict()
            if self.log_unpatched
            else None,
            "log_patched": self.log_patched.to_schema_dict()
            if self.log_patched
            else None,
            "proxy": self.proxy.to_schema_dict() if self.proxy else None,
            "harness": self.harness.to_schema_dict() if self.harness else None,
            "passthru_tests": [e.to_schema_dict() for e in self.passthru_tests],
        }


# ─── top-level dispatch ───────────────────────────────────────────────────


_REPRODUCER_NIX_BLOCK_RE = re.compile(
    r"===\s*BEGIN reproducer\.nix\s*===\n(?P<body>.*?)\n===\s*END reproducer\.nix\s*===",
    re.DOTALL,
)
_REPRODUCER_LOG_BLOCK_RE = re.compile(
    r"===\s*BEGIN reproducer-log\.txt\s*===\n(?P<body>.*?)\n===\s*END reproducer-log\.txt\s*===",
    re.DOTALL,
)
_PASSTHRU_TESTS_BLOCK_RE = re.compile(
    r"===\s*BEGIN passthru-tests\.json\s*===\n(?P<body>.*?)\n===\s*END passthru-tests\.json\s*===",
    re.DOTALL,
)
_REFUSAL_BLOCK_RE = re.compile(
    r"===\s*BEGIN refusal\s*===\n(?P<body>.*?)\n===\s*END refusal\s*===",
    re.DOTALL,
)

_WRAPPING_FENCE_RE = re.compile(
    r"^```(?:[a-zA-Z0-9_-]*)?\s*\n(?P<body>.*?)\n```\s*$",
    re.DOTALL,
)


# A lead-in like "Here is the reproducer:" is tolerated; anything longer is
# genuine format breakdown (prose response with a marker buried inside it) and
# must still fail loudly.
_MAX_TOLERATED_PREAMBLE = 240


def _strip_wrapping_code_fence(text: str) -> str:
    """Remove a markdown code fence that wraps the entire response.

    Mirrors the reviewer-parser tolerance for sonnet's habit of wrapping
    its full response in ```...```. The fence is a formatting artifact,
    not contract content; tolerate but only if it wraps THE WHOLE thing.
    """
    m = _WRAPPING_FENCE_RE.match(text)
    if m is None:
        return text
    return m.group("body").strip()


def parse_reproducer_output(raw: str) -> ReproducerParseResult:
    """Parse the model's raw text output into a structured result.

    Args:
        raw: model response text, as returned by the adapter.

    Returns:
        ReproducerParseResult with kind="reproducer" or kind="refusal".

    Raises:
        ReproducerOutputMalformed: if the text violates the contract.
    """
    if not isinstance(raw, str):
        raise ReproducerOutputMalformed(f"expected str, got {type(raw).__name__}")
    text = raw.strip()
    if not text:
        raise ReproducerOutputMalformed("model returned empty output")
    text = _strip_wrapping_code_fence(text)

    first = re.search(
        r"^===\s*BEGIN (reproducer\.nix|refusal)\s*===$",
        text,
        re.MULTILINE,
    )
    if not first:
        raise ReproducerOutputMalformed(
            "no '=== BEGIN reproducer.nix ===' or '=== BEGIN refusal ===' marker found"
        )
    # A short preamble before the first marker ("Here is the reproducer:") is a
    # cosmetic artifact some models emit, in the same class as a wrapping code
    # fence, which is already tolerated above. Strip it rather than discarding
    # otherwise-valid output: the parser enforces output SHAPE, and the shape is
    # intact once we start from the first marker. Cap the tolerated preamble so a
    # response that is mostly prose with a marker buried in it still fails loudly
    # (that is genuine format breakdown, not a one-line lead-in).
    before = text[: first.start()].strip()
    if len(before) > _MAX_TOLERATED_PREAMBLE:
        raise ReproducerOutputMalformed(
            f"{len(before)} chars of content before the first '=== BEGIN' marker "
            f"(over the {_MAX_TOLERATED_PREAMBLE}-char tolerance); output shape is broken"
        )
    if before:
        text = text[first.start() :]

    if first.group(1) == "refusal":
        return _parse_refusal(text)
    return _parse_reproducer(text)


# ─── reproducer path ─────────────────────────────────────────────────────


def _parse_reproducer(text: str) -> ReproducerParseResult:
    nix_match = _REPRODUCER_NIX_BLOCK_RE.search(text)
    if not nix_match:
        raise ReproducerOutputMalformed(
            "reproducer output malformed: missing '=== BEGIN reproducer.nix ... === END reproducer.nix ===' block"
        )
    log_match = _REPRODUCER_LOG_BLOCK_RE.search(text)
    if not log_match:
        raise ReproducerOutputMalformed(
            "reproducer output malformed: missing '=== BEGIN reproducer-log.txt ... === END reproducer-log.txt ===' block"
        )
    json_match = _PASSTHRU_TESTS_BLOCK_RE.search(text)
    if not json_match:
        raise ReproducerOutputMalformed(
            "reproducer output malformed: missing '=== BEGIN passthru-tests.json ... === END passthru-tests.json ===' block"
        )

    # Order check: nix → log → passthru-tests, with no extraneous blocks.
    if not (nix_match.start() < log_match.start() < json_match.start()):
        raise ReproducerOutputMalformed(
            "reproducer output blocks must appear in the order: "
            "reproducer.nix, reproducer-log.txt, passthru-tests.json"
        )
    # Nothing after the last block.
    after = text[json_match.end() :].strip()
    if after:
        raise ReproducerOutputMalformed(
            "content after '=== END passthru-tests.json ===' is forbidden; "
            f"found {len(after)} chars of trailing prose"
        )
    # Nothing between the closing markers and the next opening marker.
    between_nix_log = text[nix_match.end() : log_match.start()].strip()
    if between_nix_log:
        raise ReproducerOutputMalformed(
            "content between '=== END reproducer.nix ===' and "
            f"'=== BEGIN reproducer-log.txt ===' is forbidden; found "
            f"{len(between_nix_log)} chars of inter-block prose"
        )
    between_log_json = text[log_match.end() : json_match.start()].strip()
    if between_log_json:
        raise ReproducerOutputMalformed(
            "content between '=== END reproducer-log.txt ===' and "
            f"'=== BEGIN passthru-tests.json ===' is forbidden; found "
            f"{len(between_log_json)} chars of inter-block prose"
        )

    nix_body = nix_match.group("body")
    log_body = log_match.group("body")
    json_body = json_match.group("body")

    _validate_reproducer_nix_shape(nix_body)
    nix_proxy_claim = _detect_meta_proxy_in_nix(nix_body)

    log_unpatched, log_patched, log_proxy, harness = parse_log_sections(log_body)
    nix_proxy_meta = (
        _extract_meta_proxy_fields_from_nix(nix_body) if nix_proxy_claim else None
    )

    proxy: ProxyMetadata | None = None
    log_has_proxy = log_proxy is not None
    nix_has_proxy = nix_proxy_claim
    if log_has_proxy != nix_has_proxy:
        raise ReproducerOutputMalformed(
            "proxy declaration mismatch: reproducer.nix has "
            f"`meta.proxy = true` = {nix_has_proxy}, but reproducer-log.txt "
            f"`=== proxy ===` section presence = {log_has_proxy}. Both must agree."
        )
    if log_has_proxy:
        # Cross-check the values from log vs Nix.
        assert log_proxy is not None
        if nix_proxy_meta is None:
            raise ReproducerOutputMalformed(
                "reproducer.nix declares `meta.proxy = true` but does not "
                "carry the required `proxy_reason` / `why_not_full_repro` / "
                "`expected_limitations` fields in the same `meta` attrset"
            )
        if nix_proxy_meta.proxy_reason != log_proxy.proxy_reason:
            raise ReproducerOutputMalformed(
                "proxy_reason mismatch between reproducer.nix "
                f"({nix_proxy_meta.proxy_reason!r}) and reproducer-log.txt "
                f"({log_proxy.proxy_reason!r}); both must agree"
            )
        proxy = log_proxy

    passthru = _parse_passthru_tests_json(json_body)
    canonicalised_json = (
        json.dumps([e.to_schema_dict() for e in passthru], indent=2) + "\n"
    )

    return ReproducerParseResult(
        kind="reproducer",
        reproducer_nix=nix_body,
        log_unpatched=log_unpatched,
        log_patched=log_patched,
        proxy=proxy,
        harness=harness,
        passthru_tests=passthru,
        raw_reproducer_nix=nix_body.rstrip() + "\n",
        raw_reproducer_log_txt=log_body.rstrip() + "\n",
        raw_passthru_tests_json=canonicalised_json,
    )


# ─── reproducer.nix structural checks ────────────────────────────────────


# Fetcher classes that NEVER carry a hash literal at the call site, or
# whose intended use in a Reproducer would be network-at-runtime even when
# they do. These remain forbidden unconditionally.
#
# - `fetchpatch`        : downloads a patch file from a URL. Reproducer
#                         contract says patches come from filtering the
#                         bundle's existing `old.patches`, not new downloads.
# - `builtins.fetchurl` : impure builtin; no hash required, fetched at eval
#                         time, not by a derivation. Always network at
#                         eval/build time.
# - `builtins.fetchTarball` : same impurity concerns; the hash-taking form
#                             is awkward and the carve-out has clearer
#                             coverage via `fetchzip` instead.
_NIX_HARD_FORBIDDEN_FETCHERS_RE = re.compile(
    r"\b(?:fetchpatch|builtins\.fetchurl|builtins\.fetchTarball)\b"
)

# Fetcher classes whose call sites ALWAYS take a `hash = "sha(256|512)-..."`
# argument and a specific rev/tag in modern nixpkgs. Allowed in reproducer.nix
# only under the v0.1 hash-pinned carve-out (docs/REPRODUCER_V1.md §4.3,
# DECISIONS 2026-05-14): the call site must carry a literal SRI hash AND
# any rev/tag/ref must be a specific value, not a branch name. This unlocks
# unpatched-src reconstruction for version-bump-shaped patches (the wget2
# case that surfaced the contract limit on 2026-05-13) without loosening
# the "no network at runtime" guarantee — the FOD content is pinned by
# hash at expression time and the Nix builder rejects mismatches.
_NIX_HASH_PINNABLE_FETCHERS_RE = re.compile(
    r"\b(?P<fetcher>fetchurl|fetchzip|fetchFromGitHub|fetchFromGitLab|fetchFromGitea|fetchgit)\b"
)

# A real SRI hash literal: `hash = "sha256-<base64>"` or `hash = "sha512-..."`.
# The base64 alphabet excludes whitespace and ellipsis-style placeholders;
# requiring at least 32 base64 chars rules out `"..."` / `""` / truncated
# values. Equals-padding is optional (Nix accepts both forms).
_SRI_HASH_LITERAL_RE = re.compile(
    r'\bhash\s*=\s*"sha(?:256|512)-[A-Za-z0-9+/]{32,}={0,2}"'
)

# `hash = fakeHash` / `hash = lib.fakeHash` / `hash = pkgs.lib.fakeHash`
# defeats the carve-out: it triggers an FOD mismatch error AT BUILD TIME,
# which requires Nix to attempt a network fetch with the wrong hash. Always
# forbidden when used inside a fetcher's `hash` argument.
_FAKE_HASH_IN_HASH_FIELD_RE = re.compile(
    r"\bhash\s*=\s*(?:pkgs\.)?(?:lib\.)?fakeHash\b"
)

# `rev = "main"` / `tag = "HEAD"` / `ref = "refs/heads/master"` etc. A
# floating ref pins the hash to a moving target — the hash literal will
# go stale on any upstream movement, and the sandbox would then fail in
# a non-reproducible way. Specific tag/rev values only.
_FLOATING_REF_RE = re.compile(
    r'\b(?P<key>rev|tag|ref)\s*=\s*"(?P<value>master|main|HEAD|refs/heads/[A-Za-z0-9._/-]+)"'
)

_META_PROXY_TRUE_RE = re.compile(r"\bproxy\s*=\s*true\b")


def _extract_function_header(nix_body: str) -> str | None:
    """Return the function-header text (everything up to and including the
    `:` that closes the function-arg attrset), or None if `nix_body` does
    not start with a brace-balanced attrset followed by `:`.

    Brace-balancing is required because the canonical header
    `{ pkgs ? import <nixpkgs> { } }:` contains a nested `{ }` for the
    default value of `pkgs`, which a non-recursive regex cannot span.
    """
    s = nix_body.lstrip()
    if not s.startswith("{"):
        return None
    depth = 0
    i = 0
    n = len(s)
    while i < n:
        c = s[i]
        if c == "{":
            depth += 1
        elif c == "}":
            depth -= 1
            if depth == 0:
                j = i + 1
                while j < n and s[j].isspace():
                    j += 1
                if j < n and s[j] == ":":
                    return s[: j + 1]
                return None
        i += 1
    return None


def _validate_reproducer_nix_shape(nix_body: str) -> None:
    """Lexical structure checks on reproducer.nix.

    The parser does NOT evaluate Nix; Builder does. The parser checks
    only the contract floor: function-shape header, presence of
    unpatched/patched/test attribute bindings, and absence of network
    fetchers (per `docs/REPRODUCER_V1.md` §3.1's no-network rule).
    """
    header = _extract_function_header(nix_body)
    if header is None or not re.search(r"\bpkgs\b", header):
        raise ReproducerOutputMalformed(
            "reproducer.nix must begin with `{ pkgs ? import <nixpkgs> { } }: ...` "
            "or equivalent (the function takes a `pkgs` argument and returns "
            "an attrset). The exact form `{ pkgs }:` is also accepted."
        )
    # Required attributes: unpatched, patched, test must all be bound at
    # some level in the body. We scan for `<name> =` lexically.
    for required in ("unpatched", "patched", "test"):
        if not re.search(rf"\b{required}\s*=", nix_body):
            raise ReproducerOutputMalformed(
                f"reproducer.nix must define a `{required}` attribute "
                "(seen as `{required} = ...`)".replace("{required}", required)
            )
    # Fetcher rules: hard-forbidden classes always rejected; hash-pinnable
    # classes allowed only when the call site carries a real SRI hash
    # literal AND no floating ref. v0.1 carve-out for unpatched-src
    # reconstruction; see docs/REPRODUCER_V1.md §4.3.
    _validate_fetcher_usage(nix_body)

    # v6: narrow lint against the `|| true ... rc=$?` exit-capture anti-
    # pattern. `|| true` makes the pipeline succeed with rc=0, so the
    # subsequent `rc=$?` is ALWAYS 0 — SIGSEGV-class signal predicates
    # (`[ "$rc" -eq 139 ]`) then never fire. The correct form is the
    # bracketed `set +e; <cmd>; rc=$?; set -e`. Surfaced as F13 / assimp
    # v5 re-cert run 26085849172. We DO NOT ban all `|| true` usage —
    # only the immediate `|| true` followed by `rc=$?` capture form.
    _validate_exit_capture_pattern(nix_body)


_EXIT_CAPTURE_ANTI_PATTERN_RE = re.compile(
    # Match `... >run.err 2>&1 || true` (or any `|| true` line ending) followed,
    # within a few lines of whitespace/comments, by a bash exit-code capture
    # `rc=$?` or `EXIT=$?` or similar identifier=$?.
    # We allow trailing whitespace + up to two blank/comment lines between.
    r"\|\|\s*true\s*\n"  # `|| true` line ends
    r"(?:[ \t]*#[^\n]*\n|[ \t]*\n){0,2}"  # 0-2 blank/comment lines
    r"[ \t]*[A-Za-z_][A-Za-z0-9_]*\s*=\s*\$\?",  # `<name>=$?`
    re.MULTILINE,
)


def _validate_exit_capture_pattern(nix_body: str) -> None:
    """Reject the v4/v5 broken exit-capture pattern (v6, F13).

    `<cmd> >run.err 2>&1 || true` followed immediately by `rc=$?` is the
    anti-pattern: `|| true` makes the pipeline succeed with rc=0, so the
    rc capture is always 0 regardless of what `<cmd>` did. SIGSEGV-class
    predicates branching on `[ "$rc" -eq 139 ]` then never fire.

    The correct form is the bracketed `set +e; <cmd>; rc=$?; set -e`.
    See prompts/reproducer.v6.md § Sandbox model § 4 and the assimp v5
    re-cert (DECISIONS 2026-05-19 Reproducer v5 + assimp re-cert entry).

    Other uses of `|| true` (cleanup, optional probes that don't gate
    the predicate) remain allowed — only the immediate `|| true` →
    `<name>=$?` capture family is banned.
    """
    m = _EXIT_CAPTURE_ANTI_PATTERN_RE.search(nix_body)
    if m:
        # Find the line number for the offending `|| true` for diagnostic.
        line_no = nix_body[: m.start()].count("\n") + 1
        raise ReproducerOutputMalformed(
            f"reproducer.nix uses the broken `|| true; <name>=$?` exit-capture "
            f"pattern at line {line_no}. `|| true` makes the pipeline succeed "
            f"with rc=0, so the subsequent `<name>=$?` is ALWAYS 0 regardless "
            f"of what the command did (including SIGSEGV, which would normally "
            f"be rc=139). Use the bracketed form instead:\n\n"
            f"    set +e\n"
            f"    <command> >run.err 2>&1\n"
            f"    rc=$?\n"
            f"    set -e\n\n"
            f"This is v6 capture discipline; see prompts/reproducer.v6.md § Sandbox model § 4."
        )


def _validate_fetcher_usage(nix_body: str) -> None:
    """Enforce the Reproducer's fetcher policy.

    Two tiers:

    1. **Hard-forbidden** (`fetchpatch`, `builtins.fetchurl`,
       `builtins.fetchTarball`): rejected unconditionally. None of these
       can satisfy the hash-pinned carve-out — fetchpatch fetches a patch
       file at build time (patches must come from filtering
       `old.patches`), and the `builtins.*` variants are impure or
       hash-less.

    2. **Hash-pinnable** (`fetchurl`, `fetchzip`, `fetchFromGitHub`,
       `fetchFromGitLab`, `fetchFromGitea`, `fetchgit`): allowed iff
       every call site carries a literal `hash = "sha256-..."` or
       `hash = "sha512-..."` (SRI form) inside its argument block AND
       does NOT use a floating rev/tag (`master` / `main` / `HEAD` /
       `refs/heads/...`). This unlocks unpatched-src reconstruction for
       version-bump-shaped patches without giving up the no-network-at-
       runtime guarantee: the FOD content is pinned at expression time
       and the Nix builder rejects mismatches before any phase runs.
    """
    hard = _NIX_HARD_FORBIDDEN_FETCHERS_RE.search(nix_body)
    if hard:
        raise ReproducerOutputMalformed(
            f"reproducer.nix uses forbidden fetcher {hard.group(0)!r}. "
            "Patches must come from filtering `old.patches`; the impure "
            "`builtins.fetchurl` / `builtins.fetchTarball` forms are never "
            "allowed."
        )

    for m in _NIX_HASH_PINNABLE_FETCHERS_RE.finditer(nix_body):
        fetcher = m.group("fetcher")
        arg_block = _extract_brace_block(nix_body, m.end())
        if arg_block is None:
            # Not a call site (e.g. a bare identifier reference, or the
            # symbol appears inside a string literal we don't bother
            # parsing). The carve-out's job is to gate ARGUMENT shapes;
            # references without arguments are uninteresting.
            continue

        if _FAKE_HASH_IN_HASH_FIELD_RE.search(arg_block):
            raise ReproducerOutputMalformed(
                f"reproducer.nix: {fetcher!r} call uses `hash = fakeHash`. "
                "The v0.1 hash-pinned carve-out requires a real SRI hash "
                "literal at the call site, not fakeHash (which would "
                "trigger a network fetch at build time to recover the "
                "real hash)."
            )

        if not _SRI_HASH_LITERAL_RE.search(arg_block):
            raise ReproducerOutputMalformed(
                f"reproducer.nix uses forbidden network fetcher {fetcher!r}. "
                "The v0.1 hash-pinned carve-out (docs/REPRODUCER_V1.md §4.3) "
                "allows fetcher calls ONLY when a literal "
                '`hash = "sha256-..."` or `hash = "sha512-..."` is present '
                "at the call site (SRI form, base64-encoded). Found no such "
                "literal in this fetcher's argument block. For inline "
                "fixtures use `pkgs.writeText` / `pkgs.writeScript`; for "
                "unpatched-src reconstruction supply the prior version's "
                "hash explicitly."
            )

        floating = _FLOATING_REF_RE.search(arg_block)
        if floating:
            raise ReproducerOutputMalformed(
                f"reproducer.nix: {fetcher!r} uses floating "
                f"{floating.group('key')}={floating.group('value')!r}. The "
                "hash-pinned carve-out requires a specific tag/rev/commit, "
                "not a branch name — a floating ref would let the hash go "
                "stale on any upstream movement."
            )


def _extract_brace_block(s: str, start: int) -> str | None:
    """Skip whitespace from index `start`; if the next non-whitespace
    character is `{`, return the brace-balanced block (inclusive of the
    outer braces). Return None if the next non-whitespace character
    isn't `{`, or if the braces don't balance within the remainder of
    `s`. Used by `_validate_fetcher_usage` to extract a fetcher's
    argument block for inspection."""
    i = start
    n = len(s)
    while i < n and s[i].isspace():
        i += 1
    if i >= n or s[i] != "{":
        return None
    depth = 0
    j = i
    while j < n:
        c = s[j]
        if c == "{":
            depth += 1
        elif c == "}":
            depth -= 1
            if depth == 0:
                return s[i : j + 1]
        j += 1
    return None


def _detect_meta_proxy_in_nix(nix_body: str) -> bool:
    """True iff reproducer.nix declares `meta.proxy = true` somewhere."""
    return bool(_META_PROXY_TRUE_RE.search(nix_body))


_META_PROXY_REASON_RE = re.compile(r"\bproxy_reason\s*=\s*\"(?P<value>[^\"]+)\"")
_META_WHY_NOT_FULL_REPRO_RE = re.compile(
    r"\bwhy_not_full_repro\s*=\s*\"(?P<value>(?:[^\"\\]|\\.)*)\"",
    re.DOTALL,
)
_META_EXPECTED_LIMITATIONS_RE = re.compile(
    r"\bexpected_limitations\s*=\s*\"(?P<value>(?:[^\"\\]|\\.)*)\"",
    re.DOTALL,
)


def _extract_meta_proxy_fields_from_nix(nix_body: str) -> ProxyMetadata | None:
    reason_m = _META_PROXY_REASON_RE.search(nix_body)
    why_m = _META_WHY_NOT_FULL_REPRO_RE.search(nix_body)
    lim_m = _META_EXPECTED_LIMITATIONS_RE.search(nix_body)
    if reason_m is None or why_m is None or lim_m is None:
        return None
    reason = reason_m.group("value").strip()
    why = why_m.group("value").strip()
    lim = lim_m.group("value").strip()
    if reason not in PROXY_REASON_ENUM:
        raise ReproducerOutputMalformed(
            f"reproducer.nix proxy_reason={reason!r} is not in the locked enum "
            f"{sorted(PROXY_REASON_ENUM)}. Refuse under rule 8 instead "
            "of using a non-enum reason."
        )
    if not why or not lim:
        raise ReproducerOutputMalformed(
            "reproducer.nix proxy meta requires non-empty `why_not_full_repro` "
            "AND `expected_limitations` strings"
        )
    return ProxyMetadata(
        proxy_reason=reason,
        why_not_full_repro=why,
        expected_limitations=lim,
    )


# ─── reproducer-log.txt parsing ──────────────────────────────────────────


_LOG_SECTION_HEADER_RE = re.compile(
    r"^===\s*(?P<name>unpatched|patched|proxy|harness)\s*===\s*$",
    re.MULTILINE,
)
_SIGNAL_UNPATCHED_LINE_RE = re.compile(
    r"^SIGNAL_UNPATCHED:\s*(?P<value>.+?)\s*$",
    re.MULTILINE,
)
_SIGNAL_PATCHED_LINE_RE = re.compile(
    r"^SIGNAL_PATCHED:\s*(?P<value>.+?)\s*$",
    re.MULTILINE,
)
_EXIT_LINE_RE = re.compile(r"^EXIT:\s*(?P<value>-?\d+)\s*$", re.MULTILINE)


def parse_log_sections(
    log_body: str,
) -> tuple[LogSection, LogSection, ProxyMetadata | None, HarnessMetadata | None]:
    """Split the log body into unpatched / patched / optional proxy or
    harness sections.

    Returns a 4-tuple (unpatched, patched, proxy_or_None,
    harness_or_None). `proxy` and `harness` are mutually exclusive: a log
    with both is rejected. Raises ReproducerOutputMalformed if any
    required section is missing or malformed.

    Public so callers outside the parser (finalize's tautology guard,
    `trace report`) can read the harness declaration without
    reimplementing the section split.
    """
    headers = list(_LOG_SECTION_HEADER_RE.finditer(log_body))
    if not headers:
        raise ReproducerOutputMalformed(
            "reproducer-log.txt has no '=== unpatched ===' / '=== patched ===' "
            "section markers"
        )
    by_name: dict[str, tuple[int, int]] = {}
    for i, h in enumerate(headers):
        name = h.group("name")
        if name in by_name:
            raise ReproducerOutputMalformed(
                f"reproducer-log.txt has duplicate '=== {name} ===' header"
            )
        section_start = h.end()
        section_end = headers[i + 1].start() if i + 1 < len(headers) else len(log_body)
        by_name[name] = (section_start, section_end)
    if "unpatched" not in by_name:
        raise ReproducerOutputMalformed(
            "reproducer-log.txt missing '=== unpatched ===' section"
        )
    if "patched" not in by_name:
        raise ReproducerOutputMalformed(
            "reproducer-log.txt missing '=== patched ===' section"
        )
    # Order: unpatched MUST come before patched; proxy or harness MUST come
    # after both, and never both at once.
    name_order = [h.group("name") for h in headers]
    expected_prefix = ["unpatched", "patched"]
    if name_order[:2] != expected_prefix:
        raise ReproducerOutputMalformed(
            "reproducer-log.txt section order must be unpatched, patched, "
            f"[proxy|harness]; got {name_order}"
        )
    if len(name_order) > 2 and name_order[2] not in ("proxy", "harness"):
        raise ReproducerOutputMalformed(
            f"unexpected reproducer-log.txt section after patched: "
            f"'{name_order[2]}' (only 'proxy' or 'harness' is permitted)"
        )
    if "proxy" in by_name and "harness" in by_name:
        raise ReproducerOutputMalformed(
            "reproducer-log.txt carries both '=== harness ===' and "
            "'=== proxy ===' sections; a stub-harness fixture proves both "
            "arms and is not a proxy, so the two are mutually exclusive"
        )
    if len(name_order) > 3:
        raise ReproducerOutputMalformed(
            f"reproducer-log.txt has too many sections: {name_order}"
        )

    def _section(name: str) -> str:
        s, e = by_name[name]
        return log_body[s:e]

    unpatched = _build_log_section(
        name="unpatched",
        body=_section("unpatched"),
        signal_re=_SIGNAL_UNPATCHED_LINE_RE,
        signal_field="SIGNAL_UNPATCHED",
    )
    patched = _build_log_section(
        name="patched",
        body=_section("patched"),
        signal_re=_SIGNAL_PATCHED_LINE_RE,
        signal_field="SIGNAL_PATCHED",
    )
    _validate_signal_pair(unpatched.signal, patched.signal)

    proxy: ProxyMetadata | None = None
    if "proxy" in by_name:
        proxy = _parse_proxy_section(_section("proxy"))

    harness: HarnessMetadata | None = None
    if "harness" in by_name:
        harness = _parse_harness_section(_section("harness"))

    return unpatched, patched, proxy, harness


def _build_log_section(
    *,
    name: str,
    body: str,
    signal_re: re.Pattern[str],
    signal_field: str,
) -> LogSection:
    sig_m = signal_re.search(body)
    if not sig_m:
        raise ReproducerOutputMalformed(
            f"reproducer-log.txt '=== {name} ===' section missing required "
            f"'{signal_field}: <substring>' line"
        )
    signal = sig_m.group("value")
    _validate_signal(signal, field_name=signal_field)

    # EXIT line: must come after SIGNAL line, anywhere in the section.
    exit_m = _EXIT_LINE_RE.search(body, sig_m.end())
    if exit_m is None:
        # Try anywhere in the section, but require its presence.
        exit_m = _EXIT_LINE_RE.search(body)
    if exit_m is None:
        raise ReproducerOutputMalformed(
            f"reproducer-log.txt '=== {name} ===' section missing required "
            f"'EXIT: <integer>' line"
        )
    try:
        exit_code = int(exit_m.group("value"))
    except ValueError:
        raise ReproducerOutputMalformed(
            f"reproducer-log.txt '=== {name} ===' EXIT line is not an integer: "
            f"{exit_m.group('value')!r}"
        )

    return LogSection(
        name=name,
        signal=signal,
        exit_code=exit_code,
        body=body.strip("\n"),
    )


def _validate_signal(signal: str, *, field_name: str) -> None:
    """Apply the §3.2 floor checks to a single signal substring."""
    n = len(signal)
    if n < SIGNAL_LENGTH_MIN:
        raise ReproducerOutputMalformed(
            f"{field_name} length {n} < {SIGNAL_LENGTH_MIN}; signals shorter "
            f"than {SIGNAL_LENGTH_MIN} chars are gameable noise"
        )
    if n > SIGNAL_LENGTH_MAX:
        raise ReproducerOutputMalformed(
            f"{field_name} length {n} > {SIGNAL_LENGTH_MAX}; signals longer "
            f"than {SIGNAL_LENGTH_MAX} chars are brittle (whitespace/locale drift)"
        )
    normalised = signal.strip().lower()
    if normalised in SIGNAL_GENERIC_TOKEN_FORBIDDEN:
        raise ReproducerOutputMalformed(
            f"{field_name}={signal!r} matches forbidden generic-token pattern; "
            "the signal must be specifically tied to the CVE-class outcome, "
            "not a generic build/runtime token"
        )
    if not normalised:
        raise ReproducerOutputMalformed(
            f"{field_name} is whitespace-only; signal must carry CVE-specific text"
        )


def _validate_signal_pair(unpatched: str, patched: str) -> None:
    """§3.2 distinct-signals rule: neither may be a substring of the other."""
    if unpatched == patched:
        raise ReproducerOutputMalformed(
            "SIGNAL_UNPATCHED and SIGNAL_PATCHED are identical; the test "
            "cannot discriminate pre-fix from post-fix"
        )
    if unpatched in patched:
        raise ReproducerOutputMalformed(
            "SIGNAL_UNPATCHED is a substring of SIGNAL_PATCHED; the contract "
            "forbids substring-prefix relationships between the two signals"
        )
    if patched in unpatched:
        raise ReproducerOutputMalformed(
            "SIGNAL_PATCHED is a substring of SIGNAL_UNPATCHED; the contract "
            "forbids substring-prefix relationships between the two signals"
        )


_PROXY_KEY_LINE_RE = re.compile(
    r"^(?P<key>proxy_reason|why_not_full_repro|expected_limitations)\s*:\s*(?P<value>.+?)\s*$",
    re.MULTILINE,
)


def _parse_proxy_section(body: str) -> ProxyMetadata:
    """Parse the `=== proxy ===` section into structured ProxyMetadata."""
    fields: dict[str, str] = {}
    for m in _PROXY_KEY_LINE_RE.finditer(body):
        fields[m.group("key")] = m.group("value").strip()
    missing = [
        k
        for k in ("proxy_reason", "why_not_full_repro", "expected_limitations")
        if k not in fields or not fields[k]
    ]
    if missing:
        raise ReproducerOutputMalformed(
            f"reproducer-log.txt '=== proxy ===' section missing required "
            f"keys: {missing}"
        )
    if fields["proxy_reason"] not in PROXY_REASON_ENUM:
        raise ReproducerOutputMalformed(
            f"reproducer-log.txt proxy_reason={fields['proxy_reason']!r} is "
            f"not in the locked enum {sorted(PROXY_REASON_ENUM)}. Refuse "
            "under rule 8 instead of using a non-enum reason."
        )
    return ProxyMetadata(
        proxy_reason=fields["proxy_reason"],
        why_not_full_repro=fields["why_not_full_repro"],
        expected_limitations=fields["expected_limitations"],
    )


_HARNESS_KEY_LINE_RE = re.compile(
    r"^(?P<key>harness_class|target_files|stubbed|effect)\s*:\s*(?P<value>.+?)\s*$",
    re.MULTILINE,
)


def _split_comma_list(value: str) -> tuple[str, ...]:
    return tuple(p.strip() for p in value.split(",") if p.strip())


def _parse_harness_section(body: str) -> HarnessMetadata:
    """Parse the `=== harness ===` section into structured HarnessMetadata.

    Per `docs/specs/stub-harness-fixtures.md`: all four keys are required,
    `harness_class` must be in the locked enum, and `target_files` /
    `stubbed` must each name at least one entry.
    """
    fields: dict[str, str] = {}
    for m in _HARNESS_KEY_LINE_RE.finditer(body):
        fields[m.group("key")] = m.group("value").strip()
    missing = [
        k
        for k in ("harness_class", "target_files", "stubbed", "effect")
        if k not in fields or not fields[k]
    ]
    if missing:
        raise ReproducerOutputMalformed(
            f"reproducer-log.txt '=== harness ===' section missing required "
            f"keys: {missing}"
        )
    harness_class = fields["harness_class"]
    if harness_class not in HARNESS_CLASS_ENUM:
        raise ReproducerOutputMalformed(
            f"reproducer-log.txt harness_class={harness_class!r} is not in "
            f"the locked enum {sorted(HARNESS_CLASS_ENUM)}"
        )
    target_files = _split_comma_list(fields["target_files"])
    if not target_files:
        raise ReproducerOutputMalformed(
            "reproducer-log.txt '=== harness ===' target_files must name at "
            "least one repository-relative file"
        )
    stubbed = _split_comma_list(fields["stubbed"])
    if not stubbed:
        raise ReproducerOutputMalformed(
            "reproducer-log.txt '=== harness ===' stubbed must name at least "
            "one module or global"
        )
    return HarnessMetadata(
        harness_class=harness_class,
        target_files=target_files,
        stubbed=stubbed,
        effect=fields["effect"],
    )


# ─── passthru-tests.json parsing ─────────────────────────────────────────


def _parse_passthru_tests_json(body: str) -> list[PassthruEntry]:
    """Parse passthru-tests.json body. Empty array is valid."""
    try:
        parsed = json.loads(body)
    except json.JSONDecodeError as exc:
        raise ReproducerOutputMalformed(f"passthru-tests.json is not valid JSON: {exc}")
    if not isinstance(parsed, list):
        raise ReproducerOutputMalformed(
            f"passthru-tests.json must be a JSON array; got {type(parsed).__name__}"
        )
    entries: list[PassthruEntry] = []
    for i, raw in enumerate(parsed):
        if not isinstance(raw, dict):
            raise ReproducerOutputMalformed(
                f"passthru-tests.json[{i}] must be an object; got {type(raw).__name__}"
            )
        keys = set(raw.keys())
        if keys != {"name", "drv_path", "kind"}:
            raise ReproducerOutputMalformed(
                f"passthru-tests.json[{i}] must have exactly the keys "
                f"name, drv_path, kind; got {sorted(keys)}"
            )
        name = raw["name"]
        drv_path = raw["drv_path"]
        kind = raw["kind"]
        if not isinstance(name, str) or not name:
            raise ReproducerOutputMalformed(
                f"passthru-tests.json[{i}].name must be a non-empty string"
            )
        if drv_path is not None and not isinstance(drv_path, str):
            raise ReproducerOutputMalformed(
                f"passthru-tests.json[{i}].drv_path must be a string or null"
            )
        if not isinstance(kind, str) or kind not in PASSTHRU_KIND_ENUM:
            raise ReproducerOutputMalformed(
                f"passthru-tests.json[{i}].kind must be one of "
                f"{sorted(PASSTHRU_KIND_ENUM)}; got {kind!r}"
            )
        entries.append(PassthruEntry(name=name, drv_path=drv_path, kind=kind))
    return entries


# ─── refusal path ────────────────────────────────────────────────────────


_RULE_LINE_RE = re.compile(r"^rule:\s*(\d+)\s*$")
_REASON_LINE_RE = re.compile(r"^reason:\s*(\S.*)$")


def _parse_refusal(text: str) -> ReproducerParseResult:
    stripped = text.lstrip()
    if not stripped.startswith("=== BEGIN refusal ==="):
        raise ReproducerOutputMalformed(
            "refusal path requires '=== BEGIN refusal ===' as the first non-whitespace line"
        )
    match = _REFUSAL_BLOCK_RE.match(stripped)
    if not match:
        raise ReproducerOutputMalformed(
            "refusal output malformed: expected '=== BEGIN refusal === ... === END refusal ==='"
        )
    after = stripped[match.end() :].strip()
    if after:
        raise ReproducerOutputMalformed(
            f"content after '=== END refusal ===' is forbidden; "
            f"found {len(after)} chars of trailing prose"
        )
    body_lines = [ln for ln in match.group("body").strip().splitlines() if ln.strip()]
    if len(body_lines) < 2:
        raise ReproducerOutputMalformed(
            "refusal body must contain a 'rule:' line and a 'reason:' line"
        )
    rule_match = _RULE_LINE_RE.match(body_lines[0])
    if not rule_match:
        raise ReproducerOutputMalformed(
            "refusal body's first line must be 'rule: <integer>'"
        )
    rule = int(rule_match.group(1))
    if rule < _REPRODUCER_REFUSAL_RULE_MIN or rule > _REPRODUCER_REFUSAL_RULE_MAX:
        raise ReproducerOutputMalformed(
            f"refusal rule must be in [{_REPRODUCER_REFUSAL_RULE_MIN}, "
            f"{_REPRODUCER_REFUSAL_RULE_MAX}]; got {rule}"
        )
    reason_match = _REASON_LINE_RE.match(body_lines[1])
    if not reason_match:
        raise ReproducerOutputMalformed(
            "refusal body's second line must be 'reason: <one-line reason>'"
        )
    return ReproducerParseResult(
        kind="refusal",
        refusal_rule=rule,
        refusal_reason=reason_match.group(1).strip(),
    )


__all__ = [
    "HARNESS_CLASS_ENUM",
    "HarnessMetadata",
    "LogSection",
    "PROXY_REASON_ENUM",
    "PASSTHRU_KIND_ENUM",
    "PassthruEntry",
    "ProxyMetadata",
    "ReproducerOutputMalformed",
    "ReproducerParseResult",
    "SCHEMA_VERSION",
    "SIGNAL_GENERIC_TOKEN_FORBIDDEN",
    "SIGNAL_LENGTH_MAX",
    "SIGNAL_LENGTH_MIN",
    "parse_log_sections",
    "parse_reproducer_output",
]
