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


def actual_cost_usd(
    *,
    model_id: str,
    input_tokens: int | None,
    output_tokens: int | None,
) -> float | None:
    """Compute realized cost from response usage.

    Returns None if either token count is missing (the FakeAdapter does
    not report usage; live adapter populates both). Returning None is
    load-bearing for the report's three-section split: a missing cost
    must show as 'unobserved', not as 0.
    """
    if input_tokens is None or output_tokens is None:
        return None
    prices = prices_for(model_id)
    cost = (
        input_tokens * prices["input"] / 1_000_000.0
        + output_tokens * prices["output"] / 1_000_000.0
    )
    return round(cost, 6)
