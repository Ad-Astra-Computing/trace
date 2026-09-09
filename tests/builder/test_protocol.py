"""Tests for `agents.builder.protocol`.

Covers:
  * FakeBuildRunner single-response and per-call-queue modes
  * truncate_to_inline_cap behaviour at the 64 KiB boundary
  * BuildOutcome.succeeded property
"""

from __future__ import annotations

from pathlib import Path

import pytest

from agents.builder.protocol import (
    BuildOutcome,
    FakeBuildRunner,
    INLINE_STDOUT_STDERR_CAP_BYTES,
    truncate_to_inline_cap,
)


# ─── BuildOutcome ─────────────────────────────────────────────────────────


def test_build_outcome_succeeded_when_exit_zero_and_not_timeout() -> None:
    o = BuildOutcome(
        exit_code=0,
        drv_path="/nix/store/x.drv",
        out_path="/nix/store/x",
        stdout_stderr="",
        elapsed_seconds=1.0,
    )
    assert o.succeeded is True


def test_build_outcome_succeeded_false_on_nonzero_exit() -> None:
    o = BuildOutcome(
        exit_code=1,
        drv_path=None,
        out_path=None,
        stdout_stderr="failure",
        elapsed_seconds=0.5,
    )
    assert o.succeeded is False


def test_build_outcome_succeeded_false_on_timeout_even_with_zero_exit() -> None:
    o = BuildOutcome(
        exit_code=0,
        drv_path=None,
        out_path=None,
        stdout_stderr="",
        elapsed_seconds=999.0,
        timed_out=True,
    )
    assert o.succeeded is False


# ─── FakeBuildRunner ──────────────────────────────────────────────────────


def test_fake_single_response_returns_same_outcome_each_time() -> None:
    canned = BuildOutcome(
        exit_code=0,
        drv_path="/nix/store/x.drv",
        out_path="/nix/store/x",
        stdout_stderr="ok",
        elapsed_seconds=1.0,
    )
    runner = FakeBuildRunner(response=canned)
    a = runner.run(attr="foo", cwd=Path("/tmp"))
    b = runner.run(attr="bar", cwd=Path("/tmp"))
    assert a is canned
    assert b is canned
    assert len(runner.calls) == 2
    assert runner.calls[0]["attr"] == "foo"
    assert runner.calls[1]["attr"] == "bar"


def test_fake_per_call_queue_consumes_in_order() -> None:
    o1 = BuildOutcome(
        exit_code=0,
        drv_path=None,
        out_path=None,
        stdout_stderr="first",
        elapsed_seconds=1.0,
    )
    o2 = BuildOutcome(
        exit_code=1,
        drv_path=None,
        out_path=None,
        stdout_stderr="second",
        elapsed_seconds=2.0,
    )
    runner = FakeBuildRunner(responses=[o1, o2])
    r1 = runner.run(attr="a", cwd=Path("/tmp"))
    r2 = runner.run(attr="b", cwd=Path("/tmp"))
    assert r1.stdout_stderr == "first"
    assert r2.stdout_stderr == "second"


def test_fake_queue_exhausted_raises() -> None:
    o = BuildOutcome(
        exit_code=0, drv_path=None, out_path=None, stdout_stderr="", elapsed_seconds=0.0
    )
    runner = FakeBuildRunner(responses=[o])
    runner.run(attr="x", cwd=Path("/tmp"))
    with pytest.raises(IndexError, match="queue exhausted"):
        runner.run(attr="y", cwd=Path("/tmp"))


def test_fake_must_supply_exactly_one_of_response_or_responses() -> None:
    with pytest.raises(ValueError, match="exactly one of"):
        FakeBuildRunner()  # type: ignore[call-arg]
    with pytest.raises(ValueError, match="exactly one of"):
        FakeBuildRunner(
            response=BuildOutcome(0, None, None, "", 0.0),
            responses=[BuildOutcome(0, None, None, "", 0.0)],
        )


def test_fake_run_requires_exactly_one_of_expression_or_attr() -> None:
    runner = FakeBuildRunner(response=BuildOutcome(0, None, None, "", 0.0))
    with pytest.raises(ValueError, match="exactly one of"):
        runner.run(cwd=Path("/tmp"))
    with pytest.raises(ValueError, match="exactly one of"):
        runner.run(nix_expression="let x = 1; in x", attr="y", cwd=Path("/tmp"))


def test_fake_records_full_call_args() -> None:
    runner = FakeBuildRunner(response=BuildOutcome(0, None, None, "", 0.0))
    runner.run(
        nix_expression="let x = 1; in x", cwd=Path("/some/dir"), timeout_seconds=42
    )
    assert len(runner.calls) == 1
    c = runner.calls[0]
    assert c["nix_expression"] == "let x = 1; in x"
    assert c["attr"] is None
    assert c["cwd"] == "/some/dir"
    assert c["timeout_seconds"] == 42
    # instrumentation defaults to None when the caller doesn't pass it.
    assert c["instrumentation"] is None


def test_fake_records_instrumentation_when_supplied() -> None:
    runner = FakeBuildRunner(response=BuildOutcome(0, None, None, "", 0.0))
    runner.run(attr="x", cwd=Path("/tmp"), instrumentation="asan")
    assert runner.calls[0]["instrumentation"] == "asan"


# ─── truncate_to_inline_cap ──────────────────────────────────────────────


def test_truncate_short_input_passes_through() -> None:
    text = "short text"
    out, was = truncate_to_inline_cap(text)
    assert out == text
    assert was is False


def test_truncate_at_cap_boundary_passes_through() -> None:
    text = "x" * INLINE_STDOUT_STDERR_CAP_BYTES
    out, was = truncate_to_inline_cap(text)
    assert out == text
    assert was is False


def test_truncate_just_over_cap_takes_tail() -> None:
    text = "header-prefix-text-" + ("y" * INLINE_STDOUT_STDERR_CAP_BYTES)
    out, was = truncate_to_inline_cap(text)
    assert was is True
    assert len(out.encode("utf-8")) <= INLINE_STDOUT_STDERR_CAP_BYTES
    assert out.endswith("y" * 100)
    # Header characters MUST NOT survive in the truncated tail.
    assert "header-prefix-text-" not in out


def test_truncate_handles_utf8_boundary_safely() -> None:
    """The cap can fall in the middle of a multi-byte UTF-8 sequence;
    the helper must strip leading partial bytes so the output decodes
    cleanly without UnicodeDecodeError."""
    # Build a string whose byte representation ends with 'é' (2 bytes
    # in UTF-8) right at the cap boundary, with significant prefix.
    prefix = "x" * (INLINE_STDOUT_STDERR_CAP_BYTES - 1)
    text = prefix + "éTAIL"
    # Verify the input is encoded longer than the cap (so the cap forces
    # a slice that lands inside the multi-byte 'é').
    assert len(text.encode("utf-8")) > INLINE_STDOUT_STDERR_CAP_BYTES
    out, was = truncate_to_inline_cap(text)
    assert was is True
    # Output decodes cleanly (no replacement chars at the leading edge).
    assert "TAIL" in out
