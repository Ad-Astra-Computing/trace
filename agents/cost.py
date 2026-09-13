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

from collections.abc import Iterable, Mapping


# Per-million-token prices in USD. Errs on the high side to avoid
# silently undercounting. The cached_input field is informational for
# the moment — runners don't surface cache hits from adapter usage
# blocks yet.
MODEL_PRICES_PER_MTOK: dict[str, dict[str, float]] = {
    # Absent rows price through the expensive-unknown fallback below.
    # Fable 5.1 publishes 0.25/MTok cache reads, not the usual 10 percent.
    "claude-fable-5-1": {"input": 10.0, "cached_input": 0.25, "output": 50.0},
    "claude-fable-5": {"input": 10.0, "cached_input": 1.00, "output": 50.0},
    "claude-opus-5": {"input": 5.0, "cached_input": 0.50, "output": 25.0},
    "claude-sonnet-5": {"input": 2.0, "cached_input": 0.20, "output": 10.0},
    "claude-opus-4-8": {"input": 5.0, "cached_input": 0.50, "output": 25.0},
    # 4.7 and 4.6 are stale on purpose: both are now 5/25. The
    # cost-per-merge-ready baseline was measured through these rows.
    # See DECISIONS 2026-09-13.
    "claude-opus-4-7": {"input": 15.0, "cached_input": 1.50, "output": 75.0},
    "claude-opus-4-6": {"input": 15.0, "cached_input": 1.50, "output": 75.0},
    "claude-opus-4-5": {"input": 15.0, "cached_input": 1.50, "output": 75.0},
    "claude-sonnet-4-6": {"input": 3.0, "cached_input": 0.30, "output": 15.0},
    "claude-sonnet-4-5": {"input": 3.0, "cached_input": 0.30, "output": 15.0},
    "claude-haiku-4-5": {"input": 1.0, "cached_input": 0.10, "output": 5.0},
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


def rollup_usage(records: Iterable[Mapping[str, object]]) -> dict:
    """Aggregate per-call usage records into a cost block for an eval report.

    Each record is a mapping with a ``model`` id and the token counts from
    an adapter usage block: ``input_tokens``, ``output_tokens`` and the
    optional ``cache_creation_input_tokens`` / ``cache_read_input_tokens``.
    A record whose cost cannot be computed (missing token counts) is counted
    as an unobserved call, never as a zero-dollar one, matching the
    honest-or-null rule the throughput report already applies to sidecars.

    Returns a block shaped for direct inclusion in an eval report's ``cost``
    field: total and per-model call counts, token sums and realized USD.
    """
    calls = observed = 0
    total_in = total_out = 0
    total_usd = 0.0
    by_model: dict[str, dict] = {}
    for rec in records:
        calls += 1
        model = str(rec.get("model") or "unknown")
        in_tok = rec.get("input_tokens")
        out_tok = rec.get("output_tokens")
        cost = actual_cost_usd(
            model_id=model,
            input_tokens=in_tok if isinstance(in_tok, int) else None,
            output_tokens=out_tok if isinstance(out_tok, int) else None,
            cache_creation_input_tokens=rec.get("cache_creation_input_tokens"),  # type: ignore[arg-type]
            cache_read_input_tokens=rec.get("cache_read_input_tokens"),  # type: ignore[arg-type]
        )
        m = by_model.setdefault(
            model,
            {
                "calls": 0,
                "observed_calls": 0,
                "input_tokens": 0,
                "output_tokens": 0,
                "total_usd": 0.0,
            },
        )
        m["calls"] += 1
        if cost is None:
            continue
        observed += 1
        total_in += in_tok  # type: ignore[operator]
        total_out += out_tok  # type: ignore[operator]
        total_usd += cost
        m["observed_calls"] += 1
        m["input_tokens"] += in_tok  # type: ignore[operator]
        m["output_tokens"] += out_tok  # type: ignore[operator]
        m["total_usd"] = round(m["total_usd"] + cost, 6)
    return {
        "calls": calls,
        "observed_calls": observed,
        "unobserved_calls": calls - observed,
        "input_tokens": total_in,
        "output_tokens": total_out,
        "total_usd": round(total_usd, 6),
        "by_model": by_model,
    }
