"""Tests for `agents.patcher.adapter.AnthropicAdapter` sampling-knob rules.

The Anthropic Messages API has model-family-specific constraints on the
`temperature` + `top_p` knobs:

  * Opus 4.7 deprecates BOTH knobs; sending either returns HTTP 400.
  * Sonnet 4.6 + Haiku 4.5 reject sending BOTH at once; one is required
    (we send `temperature` and drop `top_p`).
  * Older models accept both freely.

These tests pin the adapter's prefix-based dispatch table so a future
model-id rename or a new model addition fails loudly here rather than
at the first live invocation. The tests do NOT make real API calls;
they exercise the predicate methods directly.

Surfaced by:
  * 2026-04-27: first sonnet reviewer run on traefik (HTTP 400 on
    temperature+top_p) — added `claude-sonnet-4-6` to
    `_MODELS_THAT_REJECT_BOTH_SAMPLING_KNOBS`.
  * 2026-04-29: first haiku reproducer probe on bind (same HTTP 400) —
    added `claude-haiku-4-5` to the same list.
"""

from __future__ import annotations

import os

import pytest


def _make_adapter(model_id: str):
    """Build an AnthropicAdapter without an API key so the predicate
    methods are reachable. The constructor refuses without a key, so
    set a placeholder for the duration of construction; the predicate
    tests never actually call .invoke()."""
    from agents.patcher.adapter import AnthropicAdapter

    prev = os.environ.get("ANTHROPIC_API_KEY")
    os.environ["ANTHROPIC_API_KEY"] = "test-placeholder-not-real"
    try:
        return AnthropicAdapter(model_id)
    finally:
        if prev is None:
            os.environ.pop("ANTHROPIC_API_KEY", None)
        else:
            os.environ["ANTHROPIC_API_KEY"] = prev


@pytest.mark.parametrize(
    "model_id",
    [
        "claude-opus-4-7",
        "claude-opus-4-7-20260301",  # dated suffix
    ],
)
def test_opus_drops_both_sampling_knobs(model_id: str) -> None:
    """Opus 4.7 family deprecated both temperature and top_p. Adapter
    must omit both in the API call."""
    a = _make_adapter(model_id)
    assert a._model_drops_sampling() is True
    assert a._model_accepts_only_temperature() is False


@pytest.mark.parametrize(
    "model_id",
    [
        "claude-sonnet-4-6",
        "claude-sonnet-4-6-20260301",  # dated suffix
        "claude-haiku-4-5",
        "claude-haiku-4-5-20251001",  # dated suffix
    ],
)
def test_sonnet_and_haiku_reject_both_knobs(model_id: str) -> None:
    """Sonnet 4.6 and Haiku 4.5 reject sending both temperature and
    top_p; adapter sends temperature only."""
    a = _make_adapter(model_id)
    assert a._model_drops_sampling() is False
    assert a._model_accepts_only_temperature() is True


@pytest.mark.parametrize(
    "model_id",
    [
        "claude-3-5-sonnet-20241022",  # older, hypothetical
        "claude-3-haiku-20240307",  # older, hypothetical
    ],
)
def test_older_models_accept_both_knobs(model_id: str) -> None:
    """Older Claude models accept both knobs without complaint. The
    adapter's default branch sends both."""
    a = _make_adapter(model_id)
    assert a._model_drops_sampling() is False
    assert a._model_accepts_only_temperature() is False


def test_haiku_4_5_in_reject_both_set() -> None:
    """Direct check: claude-haiku-4-5 was added to the constraint list
    in commit landing alongside the 2026-04-29 reproducer probe finding.
    Pin the membership here so a regression is caught instantly."""
    from agents.patcher.adapter import AnthropicAdapter

    assert (
        "claude-haiku-4-5" in AnthropicAdapter._MODELS_THAT_REJECT_BOTH_SAMPLING_KNOBS
    )
