"""Shared cost/pricing helpers for model-backed roles.

Single source of truth for token prices and cost computation. Used by:

  * agents/patcher/cli.py        — pre-flight estimate + post-run actual.
  * tools/trace_cli/execute.py   — post-run actual for Reviewer +
                                   Reproducer sidecar invocation files.
  * tools/trace_cli/report.py    — read-back to roll up cost across
                                   sidecars (via the same prices for
                                   any back-fill calculation).

Errs on the high side: an unknown model_id falls back to Opus pricing
so cost reports treat unknowns as expensive. Cached-input rate is the
5-minute prompt-cache discount price; agents don't currently report
cache hits, so cost computations use the full input rate.

Update prices from official vendor pricing pages when models change.
This is the only place to touch; downstream consumers import the
constants and helpers.
"""

from __future__ import annotations


# Per-million-token prices in USD. Errs on the high side to avoid
# silently undercounting. The cached_input field is informational for
# the moment — runners don't surface cache hits from adapter usage
# blocks yet.
MODEL_PRICES_PER_MTOK: dict[str, dict[str, float]] = {
    "claude-opus-4-7":   {"input": 15.0, "cached_input": 1.50, "output": 75.0},
    "claude-opus-4-6":   {"input": 15.0, "cached_input": 1.50, "output": 75.0},
    "claude-opus-4-5":   {"input": 15.0, "cached_input": 1.50, "output": 75.0},
    "claude-sonnet-4-6": {"input":  3.0, "cached_input": 0.30, "output": 15.0},
    "claude-sonnet-4-5": {"input":  3.0, "cached_input": 0.30, "output": 15.0},
    "claude-haiku-4-5":  {"input":  0.80, "cached_input": 0.08, "output":  4.0},
}


# Defensive default if a brand-new model id isn't in the table yet:
# match Opus pricing so the budget treats unknowns as expensive.
_DEFAULT_PRICES = {"input": 15.0, "cached_input": 1.50, "output": 75.0}


def prices_for(model_id: str) -> dict[str, float]:
    """Look up per-million-token prices for a model_id. Prefix match so
    versioned variants (e.g. claude-sonnet-4-5-20250929) hit the right
    family. Unknown ids fall back to Opus pricing (conservative)."""
    for prefix, prices in MODEL_PRICES_PER_MTOK.items():
        if model_id.startswith(prefix):
            return prices
    return _DEFAULT_PRICES


# Anthropic ephemeral (5-min TTL) cache write rate: 1.25 × standard
# input price. Default cache TTL for all current trace usage. Update
# to 2.0 when/if we start using `ttl=1h` cache_control blocks.
_CACHE_WRITE_MULTIPLIER = 1.25


def actual_cost_usd(
    *,
    model_id: str,
    input_tokens: int | None,
    output_tokens: int | None,
    cache_creation_input_tokens: int | None = None,
    cache_read_input_tokens: int | None = None,
) -> float | None:
    """Compute realized cost from response usage, including prompt-cache.

    Returns None when input_tokens or output_tokens is missing (the
    FakeAdapter and OpenAI adapters don't report usage). Cache fields
    default to 0 when None so adapters that don't surface them still
    produce a valid cost figure.

    Anthropic prompt caching changes the cost math:
      * input_tokens     = *uncached* new input, charged at standard rate
      * cache_creation_  = tokens written to ephemeral cache,
        input_tokens      charged at 1.25 × standard input (5-min TTL)
      * cache_read_      = tokens served from cache, charged at the
        input_tokens      `cached_input` price (typically 0.1 × input)

    Returning None remains load-bearing for the report's three-section
    split: a missing cost must show as 'unobserved', not as 0.
    """
    if input_tokens is None or output_tokens is None:
        return None
    cache_creation = cache_creation_input_tokens or 0
    cache_read = cache_read_input_tokens or 0
    prices = prices_for(model_id)
    cost = (
        input_tokens * prices["input"] / 1_000_000.0
        + cache_creation * prices["input"] * _CACHE_WRITE_MULTIPLIER / 1_000_000.0
        + cache_read * prices["cached_input"] / 1_000_000.0
        + output_tokens * prices["output"] / 1_000_000.0
    )
    return round(cost, 6)
