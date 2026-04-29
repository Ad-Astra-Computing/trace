"""Live Anthropic API smoke test.

Gated on `TRACE_REAL_ANTHROPIC=1` AND `ANTHROPIC_API_KEY` presence; skips
on every regular CI push. Run via the `live-anthropic-smoke.yml` workflow
on manual dispatch, or locally with both env vars set.

The test sends one tiny prompt to claude-haiku-4-5-20251001 (the cheapest
locked model) with max_tokens=16, and asserts the response is non-empty.
This proves the live API path works end-to-end:

  1. ANTHROPIC_API_KEY is wired through the runner
  2. The `anthropic` Python SDK is installed
  3. AnthropicAdapter constructs a valid request
  4. The API accepts the request and returns text
  5. Response parsing extracts text from the content blocks

It does NOT exercise prompt assembly, the parser stack, or the replay
writer; those run on every push via FakeAdapter in test_full_chain. This
test exists only to verify the API transport layer that FakeAdapter
substitutes.

Cost: account-wide budget on the Anthropic side, no per-workspace cap.
A single run is ~16 output tokens at haiku-4-5 pricing, comfortably
under one cent. Manual dispatch keeps the cumulative cost predictable;
running on every push would otherwise mint several cents of charges per
PR cycle for development churn.
"""

from __future__ import annotations

import os

import pytest

from agents.patcher.adapter import AnthropicAdapter


_GATE = os.environ.get("TRACE_REAL_ANTHROPIC") == "1"
_HAS_KEY = bool(os.environ.get("ANTHROPIC_API_KEY"))

pytestmark = pytest.mark.skipif(
    not (_GATE and _HAS_KEY),
    reason="live Anthropic test; set TRACE_REAL_ANTHROPIC=1 + ANTHROPIC_API_KEY to enable",
)


# claude-haiku-4-5-20251001 is the cheapest locked model in routing-config.
# Smoke-only: any successful response proves the transport works.
_SMOKE_MODEL = "claude-haiku-4-5-20251001"


def test_anthropic_adapter_round_trip() -> None:
    """One real API call. Asserts response is non-empty, model echoed back."""
    adapter = AnthropicAdapter(_SMOKE_MODEL)
    response = adapter.invoke(
        system_prompt="You are a smoke test. Reply with the single word OK.",
        user_content="Are you reachable?",
        sampling={"max_tokens": 16, "temperature": 0.0},
    )
    assert response.text, "live API returned empty text"
    assert response.model_id == _SMOKE_MODEL
    # Optional but useful: the API should report token counts.
    # If either is None, we still pass; some adapter paths drop usage.
    if response.input_tokens is not None:
        assert response.input_tokens > 0
    if response.output_tokens is not None:
        assert response.output_tokens > 0
