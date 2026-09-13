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


def test_the_5_line_models_are_priced_from_the_table_not_the_fallback() -> None:
    """A model missing from the table prices through the Opus fallback, which
    is deliberately the most expensive rate available. That is the right
    default for an unknown model and the wrong answer for a model we chose
    BECAUSE it is cheap, so the 5 line has to be present by name."""
    from agents.cost import _DEFAULT_PRICES, prices_for

    for model_id, expected_in, expected_out in [
        ("claude-sonnet-5", 2.0, 10.0),
        ("claude-opus-5", 5.0, 25.0),
        ("claude-fable-5-1", 10.0, 50.0),
        ("claude-haiku-4-5", 1.0, 5.0),
    ]:
        prices = prices_for(model_id)
        assert prices["input"] == expected_in, model_id
        assert prices["output"] == expected_out, model_id
        assert prices is not _DEFAULT_PRICES, model_id


def test_fable_5_1_does_not_price_as_fable_5_by_prefix() -> None:
    """prices_for matches by prefix over a dict, so the more specific id has
    to win. The two share an input and output rate, so the cache-read rate is
    what actually discriminates them: Fable 5.1 publishes 0.25/MTok where
    Fable 5 follows the usual 10 percent. Asserting only on `input` here would
    pass even if the rows were ordered so that `claude-fable-5` swallowed
    `claude-fable-5-1`."""
    from agents.cost import prices_for

    assert prices_for("claude-fable-5-1")["input"] == 10.0
    assert prices_for("claude-fable-5")["input"] == 10.0
    assert prices_for("claude-fable-5-1")["cached_input"] == 0.25
    assert prices_for("claude-fable-5")["cached_input"] == 1.00


def test_sonnet_5_is_not_priced_as_sonnet_4_5() -> None:
    """`claude-sonnet-5` and `claude-sonnet-4-5` are different models at
    different prices; neither prefix may swallow the other."""
    from agents.cost import prices_for

    assert prices_for("claude-sonnet-5")["input"] == 2.0
    assert prices_for("claude-sonnet-4-5-20250929")["input"] == 3.0


def test_a_sonnet_5_patcher_call_is_not_billed_at_opus_rates() -> None:
    """Regression pin for the observed case: the first live sonnet-5 Patcher
    run recorded 0.811987 USD because the id was absent from the table and
    priced at 15/75. The same usage at the sonnet-5 rate is about 0.111 USD."""
    from agents.cost import actual_cost_usd

    cost = actual_cost_usd(
        model_id="claude-sonnet-5",
        input_tokens=4645,
        output_tokens=7878,
        cache_creation_input_tokens=8078,
        cache_read_input_tokens=0,
    )
    assert cost is not None
    assert 0.10 < cost < 0.13, cost
    assert cost < 0.811987
