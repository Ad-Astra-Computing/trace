"""Model-call adapter for the Patcher role.

A thin Protocol + two concrete implementations:

  * `AnthropicAdapter` — calls the Anthropic SDK. Used for real runs.
  * `FakeAdapter` — returns a caller-supplied canned string. Used for
    tests, for dry-runs, and for offline validation of the runner.

Keeping the adapter behind a Protocol from day one makes later work
easier: the Sonnet 4.6 A/B comparison, open-weight experiments against
`gpt-oss-120b` / `Qwen3-Coder-480B-A35B-Instruct` / `Kimi-K2.6` per
MODEL_EVAL_PLAN.md, and any future routing config all just swap the
adapter instance — nothing in the runner, the parser, or the replay
writer changes.

Network policy: AnthropicAdapter is the ONLY place in the Patcher
path that is permitted to make a network call. Everything else runs
strictly locally.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import Any, Protocol


@dataclass(frozen=True)
class ModelResponse:
    text: str
    model_id: str
    input_tokens: int | None = None
    output_tokens: int | None = None
    stop_reason: str | None = None
    extras: dict[str, Any] = field(default_factory=dict)


class ModelAdapter(Protocol):
    """Protocol every Patcher model adapter satisfies.

    invoke() takes a system prompt and a user content string, returns
    the raw text response plus metadata. Nothing more.
    """

    model_id: str

    def invoke(
        self,
        *,
        system_prompt: str,
        user_content: str,
        sampling: dict[str, Any],
    ) -> ModelResponse: ...


# ─── Fake adapter for tests / dry-runs ─────────────────────────────────────


class FakeAdapter:
    """Returns a pre-canned response string. Records every invocation."""

    def __init__(self, model_id: str, response_text: str):
        self.model_id = model_id
        self._response_text = response_text
        self.calls: list[dict[str, Any]] = []

    def invoke(
        self,
        *,
        system_prompt: str,
        user_content: str,
        sampling: dict[str, Any],
    ) -> ModelResponse:
        # Record UTF-8 byte lengths so the numbers line up with the runner's
        # prompt_bytes / user_content_bytes (both encoded, not char length).
        self.calls.append(
            {
                "system_prompt_len": len(system_prompt.encode("utf-8")),
                "user_content_len": len(user_content.encode("utf-8")),
                "sampling": dict(sampling),
            }
        )
        return ModelResponse(
            text=self._response_text,
            model_id=self.model_id,
            input_tokens=None,
            output_tokens=None,
            stop_reason="end_turn",
            extras={"adapter": "fake"},
        )


# ─── Anthropic adapter (real API calls) ────────────────────────────────────


class AnthropicAdapter:
    """Patcher adapter for Anthropic API.

    Constructor reads `ANTHROPIC_API_KEY` from the env. Imports the
    `anthropic` SDK lazily so that installing the SDK is only a
    requirement when real API calls happen.
    """

    def __init__(self, model_id: str):
        if not os.environ.get("ANTHROPIC_API_KEY"):
            raise RuntimeError(
                "AnthropicAdapter requires ANTHROPIC_API_KEY in the environment. "
                "Set it, or use FakeAdapter for offline work."
            )
        self.model_id = model_id
        self._client = None  # constructed lazily in invoke()

    def _ensure_client(self) -> Any:
        if self._client is not None:
            return self._client
        try:
            import anthropic  # type: ignore
        except ImportError as exc:
            raise RuntimeError(
                "AnthropicAdapter needs the `anthropic` Python SDK. "
                "Add `ps.anthropic` to pythonEnv in flake.nix or install "
                "via pip. Underlying ImportError: " + str(exc)
            ) from exc
        self._client = anthropic.Anthropic()
        return self._client

    # Anthropic models that have deprecated BOTH `temperature` and
    # `top_p`. Sending either returns HTTP 400. Opus 4.7 was the first;
    # match by prefix so dated suffixes (e.g. `claude-opus-4-7-20260301`)
    # are covered.
    _MODELS_THAT_DEPRECATED_SAMPLING: tuple[str, ...] = (
        "claude-opus-4-7",
    )

    # Anthropic models that accept ONLY ONE of `temperature` or `top_p`,
    # not both. Sending both returns HTTP 400. Sonnet 4.6 is the first
    # in this bucket; we send `temperature` (the more common knob) and
    # drop `top_p`. Surfaced by the first live reviewer run on traefik
    # 2026-04-27.
    _MODELS_THAT_REJECT_BOTH_SAMPLING_KNOBS: tuple[str, ...] = (
        "claude-sonnet-4-6",
    )

    def _model_drops_sampling(self) -> bool:
        return any(
            self.model_id.startswith(prefix)
            for prefix in self._MODELS_THAT_DEPRECATED_SAMPLING
        )

    def _model_accepts_only_temperature(self) -> bool:
        return any(
            self.model_id.startswith(prefix)
            for prefix in self._MODELS_THAT_REJECT_BOTH_SAMPLING_KNOBS
        )

    def invoke(
        self,
        *,
        system_prompt: str,
        user_content: str,
        sampling: dict[str, Any],
    ) -> ModelResponse:
        client = self._ensure_client()
        kwargs: dict[str, Any] = {
            "model": self.model_id,
            "max_tokens": int(sampling.get("max_tokens", 8192)),
            "system": system_prompt,
            "messages": [{"role": "user", "content": user_content}],
        }
        if self._model_drops_sampling():
            pass  # Send neither temperature nor top_p (Opus 4.7).
        elif self._model_accepts_only_temperature():
            # Sonnet 4.6 path: send temperature only. The default 0.0
            # is the deterministic-evidence-friendly choice we use for
            # every model-call in this project.
            kwargs["temperature"] = float(sampling.get("temperature", 0.0))
        else:
            kwargs["temperature"] = float(sampling.get("temperature", 0.0))
            kwargs["top_p"] = float(sampling.get("top_p", 1.0))
        msg = client.messages.create(**kwargs)
        # Claude returns a list of content blocks; Patcher expects text-only.
        text_parts: list[str] = []
        for block in getattr(msg, "content", []) or []:
            btype = getattr(block, "type", None)
            if btype == "text":
                text_parts.append(getattr(block, "text", ""))
        usage = getattr(msg, "usage", None)
        return ModelResponse(
            text="".join(text_parts),
            model_id=self.model_id,
            input_tokens=getattr(usage, "input_tokens", None) if usage else None,
            output_tokens=getattr(usage, "output_tokens", None) if usage else None,
            stop_reason=getattr(msg, "stop_reason", None),
            extras={"adapter": "anthropic"},
        )
