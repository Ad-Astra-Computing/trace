"""Patcher CLI: spend tokens to produce a patch from an inbox entry.

  python -m agents.patcher.cli inbox/CVE-2026-42615 \\
      --nixpkgs-root /nix/store/.../nixpkgs \\
      --nixpkgs-rev abc123

This is the first slice that issues real model calls. It composes:

  Steward decision (must be auto-merge-eligible)
    -> assemble_inputs_from_inbox (Cartographer + path resolver)
    -> run_patcher (model invocation)
    -> atomic write of patch.diff + patch-rationale.md
       (or refusal.json), plus patcher-invocation.json

Live-call gating is explicit and layered:

  * TRACE_REAL_PATCHER=1 must be set in the environment.
  * The model adapter must construct successfully (e.g. claude-* needs
    ANTHROPIC_API_KEY).
  * A pre-flight estimate against the per-CVE budget must clear; the
    soft cap warns and requires --force-budget, the hard cap refuses.

Budget enforcement is a circuit breaker, not a meter. The pre-flight
clamps based on input length and max_tokens. After the call, actual
usage is recorded in patcher-invocation.json so an auditor can compare
estimate vs reality.

Tests inject a FakeAdapter via `adapter_factory` to exercise the CLI
without real spend. The TRACE_REAL_PATCHER gate is bypassed when an
adapter_factory is supplied (test path) or when --dry-run is passed.

Exit codes:
  0   patch (or refusal) written
  10  budget exceeded (soft without --force-budget, or hard)
  11  live-call gating failed (env / API key)
  12  Steward state not auto-merge-eligible
  13  inbox bundle not ready (missing artefact / package source)
  14  patcher output malformed (no files written)
  64  usage error
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import tempfile
import uuid
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

from agents.cartographer.graph import CartographerGraph
from agents.cartographer.snapshot_graph import SnapshotMinimalCartographerGraph
from agents.patcher.adapter import ModelAdapter
from agents.patcher.inbox_bridge import (
    BridgeRefused,
    InboxBundleNotReady,
    assemble_inputs_from_inbox,
)
from agents.patcher.parser import PatcherOutputMalformed
from agents.patcher.runner import DEFAULT_SAMPLING, run_patcher
from agents.scout.graph_lookup import GraphMatch


_EXIT_OK = 0
_EXIT_BUDGET = 10
_EXIT_GATING = 11
_EXIT_REFUSED_BY_STEWARD = 12
_EXIT_BUNDLE_NOT_READY = 13
_EXIT_MALFORMED = 14
_EXIT_USAGE = 64


# Per-million-token prices in USD. Errs on the high side to avoid
# silently undercounting. Update from official pricing pages when models
# change. Cached-input rate is the 5-minute prompt-cache discount price.
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


# Conservative chars-per-token heuristic for English-ish text + JSON.
# Anthropic and OpenAI both publish ~4 chars/token for English; we
# round down to 3.5 so the estimate is biased high.
_CHARS_PER_TOKEN = 3.5


@dataclass(frozen=True)
class BudgetEstimate:
    """Pre-flight estimate vs configured caps."""
    input_tokens_est: int
    max_output_tokens: int
    input_cost_est: float
    max_output_cost_est: float
    total_cost_est: float
    soft_cap_usd: float
    hard_cap_usd: float
    within_soft: bool
    within_hard: bool


def _prices_for(model_id: str) -> dict[str, float]:
    for prefix, prices in MODEL_PRICES_PER_MTOK.items():
        if model_id.startswith(prefix):
            return prices
    return _DEFAULT_PRICES


def _estimate_tokens_from_chars(s: str) -> int:
    return max(1, int(len(s) / _CHARS_PER_TOKEN))


def estimate_budget(
    *,
    model_id: str,
    system_prompt: str,
    user_content: str,
    max_tokens: int,
    soft_cap_usd: float,
    hard_cap_usd: float,
) -> BudgetEstimate:
    prices = _prices_for(model_id)
    input_tokens = _estimate_tokens_from_chars(system_prompt) + _estimate_tokens_from_chars(user_content)
    input_cost = input_tokens * prices["input"] / 1_000_000.0
    max_output_cost = max_tokens * prices["output"] / 1_000_000.0
    total = input_cost + max_output_cost
    return BudgetEstimate(
        input_tokens_est=input_tokens,
        max_output_tokens=max_tokens,
        input_cost_est=round(input_cost, 4),
        max_output_cost_est=round(max_output_cost, 4),
        total_cost_est=round(total, 4),
        soft_cap_usd=soft_cap_usd,
        hard_cap_usd=hard_cap_usd,
        within_soft=total <= soft_cap_usd,
        within_hard=total <= hard_cap_usd,
    )


def actual_cost_usd(
    *,
    model_id: str,
    input_tokens: int | None,
    output_tokens: int | None,
) -> float | None:
    """Compute realized cost from response usage. Returns None if either
    token count is missing (the FakeAdapter does not report usage)."""
    if input_tokens is None or output_tokens is None:
        return None
    prices = _prices_for(model_id)
    cost = (
        input_tokens * prices["input"] / 1_000_000.0
        + output_tokens * prices["output"] / 1_000_000.0
    )
    return round(cost, 4)


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _atomic_write_bytes(target: Path, data: bytes) -> None:
    target.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix=target.name + ".", dir=str(target.parent))
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, target)
    except Exception:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def _atomic_write_json(path: Path, data: Any) -> None:
    payload = json.dumps(data, indent=2, sort_keys=True).encode("utf-8") + b"\n"
    _atomic_write_bytes(path, payload)


def _build_default_adapter(model_id: str) -> ModelAdapter:
    """Mirror tools/trace_cli/execute._build_adapter_from_model_id but
    keep the import local so the CLI can run without those modules
    being on the path during isolated tests."""
    from agents.patcher.adapter import AnthropicAdapter, OpenAIAdapter
    if model_id.startswith("claude-"):
        return AnthropicAdapter(model_id)
    if model_id.startswith(("gpt-", "o1-", "o3-")):
        return OpenAIAdapter(model_id)
    raise RuntimeError(
        f"no adapter wired for model id {model_id!r}. "
        f"Pass a claude-* / gpt-* / o1-* / o3-* model id."
    )


def _make_v0_graph(_attr_paths: list[str]) -> CartographerGraph:
    """v0: empty snapshot. The bridge calls Cartographer.analyze with
    analysis_status='skipped-v0' so impact carries the unanalyzed flag."""
    return SnapshotMinimalCartographerGraph(records=())


def main(
    argv: list[str] | None = None,
    *,
    adapter_factory: Callable[[str], ModelAdapter] | None = None,
    graph_factory: Callable[[list[str]], CartographerGraph] | None = None,
    prompt_path: Path | None = None,
    skip_env_gate: bool = False,
) -> int:
    """Entry point. Tests pass adapter_factory + skip_env_gate=True."""
    parser = argparse.ArgumentParser(prog="trace-patcher")
    parser.add_argument("entry", type=Path,
                        help="Path to an inbox/<CVE-ID> directory.")
    parser.add_argument("--nixpkgs-root", type=Path, required=True,
                        help="Path to the nixpkgs checkout containing package.nix.")
    parser.add_argument("--nixpkgs-rev", required=True,
                        help="nixpkgs rev hash; recorded in invocation.")
    parser.add_argument("--model", default="claude-opus-4-7",
                        help="Model id (default: claude-opus-4-7).")
    parser.add_argument("--soft-budget", type=float, default=1.00,
                        help="USD soft cap per CVE (warn + require --force-budget).")
    parser.add_argument("--hard-budget", type=float, default=3.00,
                        help="USD hard cap per CVE (refuse).")
    parser.add_argument("--force-budget", action="store_true",
                        help="Allow exceeding the soft cap up to the hard cap.")
    parser.add_argument("--use-nix-eval", action="store_true",
                        help="Allow path resolver to fall back to `nix eval`.")
    parser.add_argument("--analysis-status", default="skipped-v0",
                        choices=("complete", "skipped-v0"),
                        help="Cartographer analysis_status. v0 default is "
                             "'skipped-v0' to match the snapshot graph adapter.")
    parser.add_argument("--analysis-reason", default="snapshot-backend-unimplemented",
                        help="Cartographer analysis_reason.")
    parser.add_argument("--max-tokens", type=int,
                        default=DEFAULT_SAMPLING["max_tokens"],
                        help="max_tokens passed to the model adapter.")
    parser.add_argument("--dry-run", action="store_true",
                        help="Estimate budget and exit without invoking the model.")
    args = parser.parse_args(argv)

    if not args.entry.is_dir():
        print(f"error: not a directory: {args.entry}", file=sys.stderr)
        return _EXIT_USAGE
    if not args.nixpkgs_root.is_dir():
        print(f"error: --nixpkgs-root not a directory: {args.nixpkgs_root}",
              file=sys.stderr)
        return _EXIT_USAGE
    if args.hard_budget < args.soft_budget:
        print(f"error: --hard-budget ({args.hard_budget}) must be >= "
              f"--soft-budget ({args.soft_budget})", file=sys.stderr)
        return _EXIT_USAGE

    # Live-call env gate. Bypassed when an adapter_factory is injected
    # (test path) or when --dry-run skips invocation.
    if not (skip_env_gate or adapter_factory is not None or args.dry_run):
        if os.environ.get("TRACE_REAL_PATCHER") != "1":
            print(
                "error: TRACE_REAL_PATCHER=1 not set; refusing to issue "
                "real model calls. Set it explicitly to authorize spend.",
                file=sys.stderr,
            )
            return _EXIT_GATING

    # Step 1: assemble inputs (Steward dispatch refusal happens here).
    try:
        graph_builder = graph_factory or _make_v0_graph
        graph = graph_builder([])  # attr paths not used by the v0 snapshot graph
        assembled = assemble_inputs_from_inbox(
            args.entry,
            nixpkgs_root=args.nixpkgs_root,
            graph=graph,
            nixpkgs_rev=args.nixpkgs_rev,
            use_nix_eval=args.use_nix_eval,
            write_to_inbox=False,
            analysis_status=args.analysis_status,
            analysis_reason=args.analysis_reason,
        )
    except BridgeRefused as e:
        print(f"refused: {e}", file=sys.stderr)
        return _EXIT_REFUSED_BY_STEWARD
    except InboxBundleNotReady as e:
        print(f"not-ready: {e}", file=sys.stderr)
        return _EXIT_BUNDLE_NOT_READY

    # Step 2: build adapter (may raise on missing API key).
    try:
        if adapter_factory is not None:
            adapter = adapter_factory(args.model)
        else:
            adapter = _build_default_adapter(args.model)
    except RuntimeError as e:
        print(f"error: {e}", file=sys.stderr)
        return _EXIT_GATING

    # Step 3: pre-flight budget. We need the assembled prompt to estimate
    # input tokens, so render it the same way the runner will.
    from agents.patcher.runner import assemble_user_content
    prompt_path_resolved = (
        prompt_path
        or Path(__file__).resolve().parents[2] / "prompts" / "patcher.v1.md"
    )
    if not prompt_path_resolved.is_file():
        print(f"error: prompt not at {prompt_path_resolved}", file=sys.stderr)
        return _EXIT_USAGE

    system_prompt = prompt_path_resolved.read_text(encoding="utf-8")
    user_content = assemble_user_content(assembled.inputs)
    estimate = estimate_budget(
        model_id=args.model,
        system_prompt=system_prompt,
        user_content=user_content,
        max_tokens=args.max_tokens,
        soft_cap_usd=args.soft_budget,
        hard_cap_usd=args.hard_budget,
    )

    if not estimate.within_hard:
        print(
            f"refused: estimated cost ${estimate.total_cost_est} exceeds "
            f"hard cap ${args.hard_budget}. Increase --hard-budget or "
            f"shrink --max-tokens.",
            file=sys.stderr,
        )
        return _EXIT_BUDGET
    if not estimate.within_soft and not args.force_budget:
        print(
            f"refused: estimated cost ${estimate.total_cost_est} exceeds "
            f"soft cap ${args.soft_budget}. Re-run with --force-budget "
            f"to authorize, or shrink --max-tokens.",
            file=sys.stderr,
        )
        return _EXIT_BUDGET

    if args.dry_run:
        print(json.dumps({
            "kind": "dry-run",
            "estimate": asdict(estimate),
            "model": args.model,
            "entry": args.entry.name,
        }, indent=2))
        return _EXIT_OK

    # Step 4: invoke the patcher.
    started_at = _utc_now_iso()
    try:
        result = run_patcher(
            inputs=assembled.inputs,
            adapter=adapter,
            sampling={"max_tokens": args.max_tokens},
            prompt_path=prompt_path_resolved,
        )
    except PatcherOutputMalformed as e:
        # Loud failure. Nothing written.
        print(f"error: patcher output malformed: {e}", file=sys.stderr)
        return _EXIT_MALFORMED
    ended_at = _utc_now_iso()

    # Step 5: write outputs into the inbox entry.
    if result.kind == "patch":
        diff_bytes = (result.parsed.patch_diff or "").encode("utf-8")
        rat_bytes = (result.parsed.patch_rationale_md or "").encode("utf-8")
        if diff_bytes and not diff_bytes.endswith(b"\n"):
            diff_bytes += b"\n"
        if rat_bytes and not rat_bytes.endswith(b"\n"):
            rat_bytes += b"\n"
        _atomic_write_bytes(args.entry / "patch.diff", diff_bytes)
        _atomic_write_bytes(args.entry / "patch-rationale.md", rat_bytes)
    else:  # refusal
        refusal_body = json.dumps(
            {
                "rule": result.parsed.refusal_rule,
                "reason": result.parsed.refusal_reason,
            },
            indent=2,
            sort_keys=True,
        ).encode("utf-8") + b"\n"
        _atomic_write_bytes(args.entry / "refusal.json", refusal_body)

    # Step 6: invocation record.
    actual = actual_cost_usd(
        model_id=args.model,
        input_tokens=result.model_response.input_tokens,
        output_tokens=result.model_response.output_tokens,
    )
    invocation = {
        "schema_version": "1.0.0",
        "invocation_id": str(uuid.uuid4()),
        "cve_id": args.entry.name,
        "started_at": started_at,
        "ended_at": ended_at,
        "model_id": args.model,
        "adapter": result.model_response.extras.get("adapter"),
        "kind": result.kind,
        "sampling": result.sampling,
        "prompt_sha256": result.prompt_sha256,
        "user_content_sha256": result.user_content_sha256,
        "raw_response_sha256": result.raw_response_sha256,
        "usage": {
            "input_tokens": result.model_response.input_tokens,
            "output_tokens": result.model_response.output_tokens,
        },
        "budget": {
            "soft_cap_usd": args.soft_budget,
            "hard_cap_usd": args.hard_budget,
            "force_budget": args.force_budget,
            "estimate": asdict(estimate),
            "actual_cost_usd": actual,
            "actual_exceeded_hard": (
                actual is not None and actual > args.hard_budget
            ),
            "actual_exceeded_soft": (
                actual is not None and actual > args.soft_budget
            ),
        },
        "nixpkgs_rev": args.nixpkgs_rev,
        "package_source_path": assembled.inputs.get("package_source_path"),
        "steward_state": assembled.steward_state,
    }
    _atomic_write_json(args.entry / "patcher-invocation.json", invocation)

    print(json.dumps({
        "kind": result.kind,
        "entry": args.entry.name,
        "model": args.model,
        "actual_cost_usd": actual,
        "estimate_cost_usd": estimate.total_cost_est,
    }))
    return _EXIT_OK


if __name__ == "__main__":
    sys.exit(main())
