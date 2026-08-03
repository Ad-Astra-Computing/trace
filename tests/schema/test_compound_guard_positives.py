"""Equivalence proofs for the hard compound-guard POSITIVES under traces/positives-reorg/.

A `guard-*` reorg positive rewrites a model-authored compound guard into a form
that a string-level reader mistakes for a dropped conjunct / flipped operator,
while denoting the identical predicate. That claim is the whole point of the
example: a positive whose rewrite is subtly NON-equivalent trains the Reviewer to
accept a broken patch, which is strictly worse than the negative skew it is there
to correct.

So each shipped positive is proven here, not asserted:

* structural — the variant's patch.diff differs from its base ONLY in the guard
  block plus the enclosing hunk-header line counts, and the base's (sometimes
  already-inconsistent) header offsets are preserved rather than silently
  recomputed;
* semantic — the original and rewritten guards are enumerated exhaustively over
  the operand space, comparing BOTH the resulting branch decision AND the
  evaluation trace. Comparing the trace is what rules out the short-circuit trap:
  a rewrite that reorders `p && p->x`, or hoists a faulting/impure operand out of
  a guard that used to protect it, produces a different trace and fails here even
  when the truth table matches.
"""

from __future__ import annotations

import itertools
import json
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
POSITIVES_ROOT = REPO_ROOT / "traces" / "positives-reorg"
EXAMPLE_ROOT = REPO_ROOT / "traces" / "example"

GUARD_REORG_TYPES = {"guard-demorgan", "guard-hoist", "guard-split", "guard-reorder"}


def _guard_positive_dirs() -> list[Path]:
    out = []
    for marker in sorted(POSITIVES_ROOT.glob("CVE-*/reorg.json")):
        if json.loads(marker.read_text()).get("reorg_type") in GUARD_REORG_TYPES:
            out.append(marker.parent)
    return out


GUARD_DIRS = _guard_positive_dirs()


# --------------------------------------------------------------------------- #
# Evaluation-trace machinery: every operand read is logged, so two expressions
# are compared on (value, order-and-count-of-operand-evaluations), not on value
# alone.
# --------------------------------------------------------------------------- #

class Ops:
    """Side-effect-free operand supplier that records each read, in order."""

    def __init__(self, **values: object) -> None:
        self._values = values
        self.log: list[str] = []

    def __getattr__(self, name: str) -> object:
        values = object.__getattribute__(self, "_values")
        if name not in values:
            raise AttributeError(name)

        def read() -> object:
            object.__getattribute__(self, "log").append(name)
            return values[name]

        return read


def _run(fn, values: dict[str, object]) -> tuple[object, tuple[str, ...]]:
    ops = Ops(**values)
    result = fn(ops)
    return bool(result), tuple(ops.log)


def assert_equivalent(orig, rewrite, space: dict[str, list]) -> None:
    """Exhaustively enumerate `space` and assert the two guards agree on both the
    branch decision and the operand-evaluation trace."""
    names = sorted(space)
    combos = list(itertools.product(*(space[n] for n in names)))
    assert combos, "empty operand space"
    for combo in combos:
        values = dict(zip(names, combo))
        got_o = _run(orig, values)
        got_r = _run(rewrite, values)
        assert got_o == got_r, f"guard mismatch at {values}: orig={got_o} rewrite={got_r}"


# --------------------------------------------------------------------------- #
# One model per shipped positive. `guard` / `rewrite` are transliterations of the
# exact C text; `pins` re-asserts that text against reorg.json so a re-mint with a
# different rewrite fails here instead of passing against a stale model.
# --------------------------------------------------------------------------- #

def _procps_orig(o):
    # if (!ret && size && nelems)
    return (not o.ret()) and o.size() and o.nelems()


def _procps_demorgan(o):
    # if (!(ret || !size || !nelems))
    return not (o.ret() or (not o.size()) or (not o.nelems()))


def _procps_split_orig(o):
    # if (!ret && size && nelems) xerrx(...);
    ran = []
    if (not o.ret()) and o.size() and o.nelems():
        ran.append("xerrx")
    return ran


def _procps_split_rewrite(o):
    # if (!ret && size) { if (nelems) xerrx(...); }
    ran = []
    if (not o.ret()) and o.size():
        if o.nelems():
            ran.append("xerrx")
    return ran


def _proxychains_orig(o):
    # if(ul > 255 || pl > 255)
    return o.ul() > 255 or o.pl() > 255


def _proxychains_demorgan(o):
    # if(!(ul <= 255 && pl <= 255))
    return not (o.ul() <= 255 and o.pl() <= 255)


def _libarchive_orig(o):
    # if (l > limit || (l == limit && digit >= last_digit_limit))
    return o.l() > o.limit() or (o.l() == o.limit() and o.digit() >= o.last_digit_limit())


def _libarchive_hoist(o):
    # const int at_digit_limit = (l == limit && digit >= last_digit_limit);
    # if (l > limit || at_digit_limit)
    at_digit_limit = o.l() == o.limit() and o.digit() >= o.last_digit_limit()
    return o.l() > o.limit() or at_digit_limit


def _krb5_orig(o):
    # if (in->status || msg_len > token_remaining ||
    #     header_len < (size_t)(in->ptr - msg_base) || header_len > msg_len)
    return (
        o.status()
        or o.msg_len() > o.token_remaining()
        or o.header_len() < o.consumed()
        or o.header_len() > o.msg_len()
    )


def _krb5_demorgan(o):
    # if (!(!in->status && msg_len <= token_remaining &&
    #       header_len >= (size_t)(in->ptr - msg_base) && header_len <= msg_len))
    return not (
        (not o.status())
        and o.msg_len() <= o.token_remaining()
        and o.header_len() >= o.consumed()
        and o.header_len() <= o.msg_len()
    )


def _jq_orig(o):
    # if (p == NULL && feof(state->current_input))
    return o.p() is None and o.feof()


def _jq_demorgan(o):
    # if (!(p != NULL || !feof(state->current_input)))
    return not ((o.p() is not None) or (not o.feof()))


_SENTINEL = object()
_BOOL = [0, 1]
_LEN = [0, 1, 254, 255, 256, 1_000_000_000]
_SMALL = [-2, -1, 0, 1, 2]

MODELS: dict[str, dict] = {
    "CVE-2023-4016--procps-ng-xxcalloc--guard-demorgan": dict(
        orig=_procps_orig,
        rewrite=_procps_demorgan,
        # ret is a pointer (NULL/non-NULL); size and nelems are size_t
        space={"ret": [None, _SENTINEL], "size": [0, 1, 4096], "nelems": [0, 1, 7]},
        pins=("!ret && size && nelems", "!(ret || !size || !nelems)"),
        trace_sensitive=True,
    ),
    "CVE-2023-4016--procps-ng-xxcalloc--guard-split": dict(
        orig=_procps_split_orig,
        rewrite=_procps_split_rewrite,
        space={"ret": [None, _SENTINEL], "size": [0, 1, 4096], "nelems": [0, 1, 7]},
        pins=("if (!ret && size && nelems)", "if (!ret && size) {"),
        trace_sensitive=True,
    ),
    "CVE-2025-34451--proxychains-ng-backport--guard-demorgan": dict(
        orig=_proxychains_orig,
        rewrite=_proxychains_demorgan,
        space={"ul": _LEN, "pl": _LEN},
        pins=("if(ul > 255 || pl > 255)", "if(!(ul <= 255 && pl <= 255))"),
        trace_sensitive=True,
    ),
    "CVE-2026-15028--libarchive-tar-atol-oob-backport--guard-hoist": dict(
        orig=_libarchive_orig,
        rewrite=_libarchive_hoist,
        space={"l": _SMALL, "limit": _SMALL, "digit": _SMALL, "last_digit_limit": _SMALL},
        pins=(
            "if (l > limit || (l == limit && digit >= last_digit_limit)) {",
            "if (l > limit || at_digit_limit) {",
        ),
        # A hoist DELIBERATELY changes the evaluation trace (the subexpression is
        # evaluated unconditionally). Sound only because every operand is a
        # side-effect-free, non-faulting scalar local — argued in reorg.json.
        trace_sensitive=False,
    ),
    "CVE-2026-40356--krb5-negoex-underflow-backport--guard-demorgan": dict(
        orig=_krb5_orig,
        rewrite=_krb5_demorgan,
        space={
            "status": [0, 1, 5],
            "msg_len": [0, 4, 16],
            "token_remaining": [0, 4, 16],
            "header_len": [0, 4, 16],
            "consumed": [0, 4, 16],
        },
        pins=(
            "if (in->status || msg_len > token_remaining ||",
            "if (!(!in->status && msg_len <= token_remaining &&",
        ),
        trace_sensitive=True,
    ),
    "CVE-2026-33948--jq-nul-backport--guard-demorgan": dict(
        orig=_jq_orig,
        rewrite=_jq_demorgan,
        space={"p": [None, _SENTINEL], "feof": _BOOL},
        pins=(
            "if (p == NULL && feof(state->current_input)) {",
            "if (!(p != NULL || !feof(state->current_input))) {",
        ),
        trace_sensitive=True,
    ),
}


def test_guard_positives_present():
    """The v1.11 balance move ships at least four hard compound-guard positives."""
    assert len(GUARD_DIRS) >= 4, f"expected >=4 guard-* positives, found {len(GUARD_DIRS)}"


@pytest.mark.parametrize("bundle_dir", GUARD_DIRS, ids=lambda p: p.name)
def test_guard_positive_marker_is_complete(bundle_dir: Path):
    marker = json.loads((bundle_dir / "reorg.json").read_text())
    assert marker["positive_source"] == "reorg"
    assert marker["expected_reviewer_verdict"] == "accept"
    # The written proof is mandatory: an unproven "equivalent" rewrite is a
    # corpus poison, not a positive.
    assert len(marker.get("equivalence_argument", "")) >= 200
    assert len(marker.get("hardness_rationale", "")) >= 80
    base = EXAMPLE_ROOT / marker["base_bundle_dir"]
    assert base.is_dir(), f"base bundle missing: {base}"
    details = marker["reorg_details"]
    assert details["guard"] and details["rewritten_to"]
    assert details["guard"] != details["rewritten_to"]


@pytest.mark.parametrize("bundle_dir", GUARD_DIRS, ids=lambda p: p.name)
def test_guard_rewrite_is_the_only_content_change(bundle_dir: Path):
    """The variant's patch.diff differs from its base only in the guard block and
    the enclosing hunk-header counts — no other hunk, file or line moved."""
    marker = json.loads((bundle_dir / "reorg.json").read_text())
    details = marker["reorg_details"]
    depth = details["depth"]
    prefix = "+" * depth
    base_lines = (EXAMPLE_ROOT / marker["base_bundle_dir"] / "patch.diff").read_text().splitlines()
    var_lines = (bundle_dir / "patch.diff").read_text().splitlines()

    removed = [l for l in base_lines if l not in var_lines]
    added = [l for l in var_lines if l not in base_lines]
    guard_lines = [prefix + l for l in details["guard"]]
    rewrite_lines = [prefix + l for l in details["rewritten_to"]]

    def is_header(line: str) -> bool:
        return line.lstrip("+").startswith("@@ ")

    for line in removed:
        assert line in guard_lines or is_header(line), f"unexpected removal: {line!r}"
    for line in added:
        assert line in rewrite_lines or is_header(line), f"unexpected addition: {line!r}"
    # the original guard is gone, the rewrite is present
    for line in guard_lines:
        assert line not in var_lines
    for line in rewrite_lines:
        assert line in var_lines


@pytest.mark.parametrize("bundle_dir", GUARD_DIRS, ids=lambda p: p.name)
def test_hunk_header_offsets_are_preserved(bundle_dir: Path):
    """Header counts are DELTA-BUMPED, never recounted: several corpus bundles
    carry headers that already disagree with a strict recount, and a positive
    variant must not quietly rewrite bytes outside the guard it varies."""
    import re

    marker = json.loads((bundle_dir / "reorg.json").read_text())
    delta = marker["reorg_details"]["line_delta"]
    base_lines = (EXAMPLE_ROOT / marker["base_bundle_dir"] / "patch.diff").read_text().splitlines()
    var_lines = (bundle_dir / "patch.diff").read_text().splitlines()

    hdr = re.compile(r"^(\++)?@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@")

    def headers(lines: list[str]) -> list[tuple]:
        out = []
        for line in lines:
            m = hdr.match(line)
            if m:
                out.append((m.group(1) or "", int(m.group(2)), m.group(3), int(m.group(4)), m.group(5)))
        return out

    base_h, var_h = headers(base_lines), headers(var_lines)
    assert len(base_h) == len(var_h), "hunk count changed"
    bumped = 0
    for b, v in zip(base_h, var_h):
        assert b[0] == v[0] and b[1] == v[1] and b[3] == v[3], "hunk start lines changed"
        assert b[2] == v[2], "old-side count changed"
        b_new = int(b[4]) if b[4] is not None else 1
        v_new = int(v[4]) if v[4] is not None else 1
        assert v_new - b_new in (0, delta), f"unexpected new-count change: {b} -> {v}"
        if v_new != b_new:
            bumped += 1
    if delta:
        # depth-2 guards sit inside an added file: the embedded AND the outer
        # header each count the added lines.
        assert bumped == marker["reorg_details"]["depth"]
    else:
        assert bumped == 0


@pytest.mark.parametrize("name", sorted(MODELS), ids=lambda n: n)
def test_guard_rewrite_is_semantically_equivalent(name: str):
    """Exhaustive enumeration: the rewritten guard denotes the same predicate as
    the original, with the same operand-evaluation trace (except where a hoist
    deliberately changes it and the operands are proven pure)."""
    model = MODELS[name]
    bundle_dir = POSITIVES_ROOT / name
    assert bundle_dir.is_dir(), f"modelled positive is missing on disk: {name}"
    details = json.loads((bundle_dir / "reorg.json").read_text())["reorg_details"]
    guard_text = "\n".join(details["guard"])
    rewrite_text = "\n".join(details["rewritten_to"])
    pin_guard, pin_rewrite = model["pins"]
    # Pin the transliteration to the on-disk C text: a re-mint that changes the
    # rewrite must re-prove it, not inherit this proof.
    assert pin_guard in guard_text
    assert pin_rewrite in rewrite_text

    if model["trace_sensitive"]:
        assert_equivalent(model["orig"], model["rewrite"], model["space"])
    else:
        # value-only comparison (the hoist case)
        names = sorted(model["space"])
        for combo in itertools.product(*(model["space"][n] for n in names)):
            values = dict(zip(names, combo))
            assert bool(model["orig"](Ops(**values))) == bool(model["rewrite"](Ops(**values))), values


def test_trace_comparison_catches_the_short_circuit_trap():
    """Guard rail on the proof machinery itself: reordering `p && p->x` keeps the
    truth table but changes the evaluation trace, and MUST fail assert_equivalent.
    (This is the discard rule that kept several candidate guards out of the corpus.)"""
    def orig(o):
        return o.p() is not None and o.p_x()

    def reordered(o):
        return o.p_x() and o.p() is not None

    space = {"p": [None, _SENTINEL], "p_x": _BOOL}
    with pytest.raises(AssertionError):
        assert_equivalent(orig, reordered, space)
