"""Tests for agents.cost — the shared pricing helper.

Pins three behaviors that the cost/throughput rollup depends on:

  1. Backwards-compatible signature: existing callers that pass only
     input_tokens + output_tokens get the same number as before any
     prompt caching was wired up.

  2. Cache-aware pricing. The traefik smoke surfaced that the Anthropic
     adapter reports input_tokens=6 on cache hits because the bulk of
     the system prompt is served from cache. Without pricing the
     cache_creation_input_tokens and cache_read_input_tokens fields,
     the headline cost is under-reported by 30-40%.

  3. Missing token data returns None so the report's three-section
     split surfaces 'unobserved' rather than a misleading $0.00.
"""

from __future__ import annotations

import pytest

from agents.cost import (
    MODEL_PRICES_PER_MTOK,
    actual_cost_usd,
    prices_for,
)


def test_prices_for_known_model_returns_table_entry() -> None:
    p = prices_for("claude-opus-4-7")
    assert p == MODEL_PRICES_PER_MTOK["claude-opus-4-7"]
    assert p["input"] == 15.0
    assert p["cached_input"] == 1.50
    assert p["output"] == 75.0


def test_prices_for_versioned_id_prefix_matches() -> None:
    """Anthropic appends date suffixes (e.g. claude-sonnet-4-5-20250929).
    Pricing must still resolve via prefix match."""
    p = prices_for("claude-sonnet-4-5-20250929")
    assert p == MODEL_PRICES_PER_MTOK["claude-sonnet-4-5"]


def test_prices_for_unknown_model_falls_back_to_opus() -> None:
    """Conservative default: unknown ids are treated as expensive so
    cost reports never silently under-count a brand-new model."""
    p = prices_for("claude-future-model-9000")
    assert p["input"] == 15.0  # Opus rate


def test_actual_cost_usd_no_cache_path_unchanged() -> None:
    """Callers that don't pass cache fields get the same answer as
    before the prompt-cache work. 1M input + 1M output on Opus."""
    cost = actual_cost_usd(
        model_id="claude-opus-4-7",
        input_tokens=1_000_000,
        output_tokens=1_000_000,
    )
    # 1M × $15 + 1M × $75 = $15 + $75 = $90.
    assert cost == 90.0


def test_actual_cost_usd_with_cache_creation() -> None:
    """cache_creation_input_tokens charged at 1.25 × standard input.
    Anthropic 5-min TTL rate. Verifies the multiplier is applied."""
    cost = actual_cost_usd(
        model_id="claude-opus-4-7",
        input_tokens=0,
        output_tokens=0,
        cache_creation_input_tokens=1_000_000,
        cache_read_input_tokens=0,
    )
    # 1M × $15 × 1.25 = $18.75.
    assert cost == 18.75


def test_actual_cost_usd_with_cache_read() -> None:
    """cache_read_input_tokens charged at the `cached_input` price.
    Verifies the per-million-token cached rate (Opus: $1.50)."""
    cost = actual_cost_usd(
        model_id="claude-opus-4-7",
        input_tokens=0,
        output_tokens=0,
        cache_creation_input_tokens=0,
        cache_read_input_tokens=1_000_000,
    )
    assert cost == 1.50


def test_actual_cost_usd_all_four_fields_sum_correctly() -> None:
    """Realistic invocation shape: small uncached delta + large cache
    creation + no reads (first run) + meaningful output."""
    cost = actual_cost_usd(
        model_id="claude-opus-4-7",
        input_tokens=100,  # 100 × $15 / 1M = $0.0015
        output_tokens=1000,  # 1000 × $75 / 1M = $0.075
        cache_creation_input_tokens=8000,  # 8000 × $15 × 1.25 / 1M = $0.15
        cache_read_input_tokens=0,
    )
    assert cost == pytest.approx(0.0015 + 0.075 + 0.15, rel=1e-9)


def test_actual_cost_usd_cache_read_subsequent_call() -> None:
    """Cache-hit case: small uncached delta + cache reads (no creation
    on subsequent calls within TTL) + output. Cost should be markedly
    lower than the cache-creation case."""
    cost = actual_cost_usd(
        model_id="claude-opus-4-7",
        input_tokens=100,
        output_tokens=1000,
        cache_creation_input_tokens=0,
        cache_read_input_tokens=8000,  # 8000 × $1.50 / 1M = $0.012
    )
    assert cost == pytest.approx(0.0015 + 0.075 + 0.012, rel=1e-9)


def test_actual_cost_usd_none_input_tokens_returns_none() -> None:
    """Missing usage data must surface as None so the report's
    unobserved section reports it honestly, not as $0."""
    assert (
        actual_cost_usd(
            model_id="claude-opus-4-7",
            input_tokens=None,
            output_tokens=1000,
        )
        is None
    )


def test_actual_cost_usd_none_cache_fields_default_to_zero() -> None:
    """Adapters that don't surface cache fields (OpenAI, FakeAdapter)
    must still produce a non-None cost when input + output are known.
    Cache=None is treated as zero, not as 'cost unknown'."""
    cost = actual_cost_usd(
        model_id="claude-opus-4-7",
        input_tokens=100,
        output_tokens=1000,
        cache_creation_input_tokens=None,
        cache_read_input_tokens=None,
    )
    assert cost is not None
    # Same as the no-cache path: 100×15/M + 1000×75/M = $0.0765.
    assert cost == pytest.approx(0.0765, rel=1e-9)


# ── rollup_usage: per-call usage records -> a report cost block ─────────────

from agents.cost import rollup_usage


def test_rollup_usage_sums_observed_calls_and_cost() -> None:
    block = rollup_usage(
        [
            {"model": "claude-opus-4-7", "input_tokens": 1000, "output_tokens": 500},
            {"model": "claude-opus-4-7", "input_tokens": 2000, "output_tokens": 100},
        ]
    )
    assert block["calls"] == 2
    assert block["observed_calls"] == 2
    assert block["unobserved_calls"] == 0
    assert block["input_tokens"] == 3000
    assert block["output_tokens"] == 600
    # (1000+2000)*15 + (500+100)*75 per Mtok
    assert block["total_usd"] == round((3000 * 15 + 600 * 75) / 1_000_000, 6)
    assert block["by_model"]["claude-opus-4-7"]["observed_calls"] == 2


def test_rollup_usage_missing_tokens_count_unobserved_not_zero() -> None:
    """A call with no token counts must not dilute the total to a false $0;
    it is counted but its dollars stay out of the sum (honest-or-null)."""
    block = rollup_usage(
        [
            {"model": "claude-opus-4-7", "input_tokens": 1000, "output_tokens": 500},
            {"model": "claude-opus-4-7", "input_tokens": None, "output_tokens": None},
        ]
    )
    assert block["calls"] == 2
    assert block["observed_calls"] == 1
    assert block["unobserved_calls"] == 1
    assert block["total_usd"] == round((1000 * 15 + 500 * 75) / 1_000_000, 6)
    m = block["by_model"]["claude-opus-4-7"]
    assert m["calls"] == 2 and m["observed_calls"] == 1


def test_rollup_usage_splits_by_model() -> None:
    block = rollup_usage(
        [
            {"model": "claude-opus-4-7", "input_tokens": 100, "output_tokens": 10},
            {
                "model": "claude-sonnet-4-5-20250929",
                "input_tokens": 100,
                "output_tokens": 10,
            },
        ]
    )
    assert set(block["by_model"]) == {"claude-opus-4-7", "claude-sonnet-4-5-20250929"}
    opus = block["by_model"]["claude-opus-4-7"]["total_usd"]
    sonnet = block["by_model"]["claude-sonnet-4-5-20250929"]["total_usd"]
    assert opus > sonnet  # opus prices dominate for identical tokens


def test_rollup_usage_empty_is_all_zero() -> None:
    block = rollup_usage([])
    assert block == {
        "calls": 0,
        "observed_calls": 0,
        "unobserved_calls": 0,
        "input_tokens": 0,
        "output_tokens": 0,
        "total_usd": 0.0,
        "by_model": {},
    }
