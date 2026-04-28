"""Tests for `agents.patcher.adapter.OpenAIAdapter`.

The adapter has three behaviours worth pinning that don't require a
live API call:

  1. Constructor refuses without OPENAI_API_KEY in the env.
  2. _ensure_client honours OPENAI_BASE_URL when set (so the same
     adapter drives vLLM / OpenRouter / any OpenAI-compatible server).
  3. The ModelAdapter Protocol surface is satisfied (the runner code
     calls adapter.invoke(system_prompt=..., user_content=...,
     sampling=...) and reads back a ModelResponse).

A fourth set of tests pins the executor's _build_adapter_from_model_id
dispatch helper across claude-*, gpt-*, o1-*, o3-*, and the unknown
case.
"""

from __future__ import annotations

import os
from unittest.mock import MagicMock, patch

import pytest


# ─── constructor / env handling ───────────────────────────────────────────


def test_constructor_refuses_without_api_key() -> None:
    from agents.patcher.adapter import OpenAIAdapter

    prev = os.environ.pop("OPENAI_API_KEY", None)
    try:
        with pytest.raises(RuntimeError, match="OPENAI_API_KEY"):
            OpenAIAdapter("gpt-4o")
    finally:
        if prev is not None:
            os.environ["OPENAI_API_KEY"] = prev


def test_constructor_accepts_api_key() -> None:
    from agents.patcher.adapter import OpenAIAdapter

    prev = os.environ.get("OPENAI_API_KEY")
    os.environ["OPENAI_API_KEY"] = "test-placeholder-not-real"
    try:
        a = OpenAIAdapter("gpt-4o")
        assert a.model_id == "gpt-4o"
        # Client constructed lazily; no network call yet.
        assert a._client is None
    finally:
        if prev is None:
            os.environ.pop("OPENAI_API_KEY", None)
        else:
            os.environ["OPENAI_API_KEY"] = prev


# ─── base_url override ────────────────────────────────────────────────────


def test_ensure_client_honours_openai_base_url(monkeypatch) -> None:
    """OPENAI_BASE_URL in env should be passed to openai.OpenAI(base_url=...)
    so the adapter drives vLLM / OpenRouter / any OpenAI-compatible server."""
    from agents.patcher.adapter import OpenAIAdapter

    monkeypatch.setenv("OPENAI_API_KEY", "test-placeholder-not-real")
    monkeypatch.setenv("OPENAI_BASE_URL", "https://openrouter.ai/api/v1")
    a = OpenAIAdapter("gpt-oss-120b")

    fake_openai = MagicMock()
    with patch.dict("sys.modules", {"openai": fake_openai}):
        a._ensure_client()
    fake_openai.OpenAI.assert_called_once()
    call = fake_openai.OpenAI.call_args
    assert call.kwargs.get("base_url") == "https://openrouter.ai/api/v1"


def test_ensure_client_omits_base_url_when_unset(monkeypatch) -> None:
    """No OPENAI_BASE_URL → use the SDK's default endpoint (the OpenAI API)."""
    from agents.patcher.adapter import OpenAIAdapter

    monkeypatch.setenv("OPENAI_API_KEY", "test-placeholder-not-real")
    monkeypatch.delenv("OPENAI_BASE_URL", raising=False)
    a = OpenAIAdapter("gpt-4o")

    fake_openai = MagicMock()
    with patch.dict("sys.modules", {"openai": fake_openai}):
        a._ensure_client()
    call = fake_openai.OpenAI.call_args
    # base_url should not be present when env var is unset.
    assert "base_url" not in call.kwargs


# ─── invoke() shape ───────────────────────────────────────────────────────


def test_invoke_returns_model_response_with_text(monkeypatch) -> None:
    """invoke() reads choices[0].message.content + usage.{prompt,completion}_tokens
    + finish_reason, packs into a ModelResponse with extras={"adapter":"openai"}."""
    from agents.patcher.adapter import OpenAIAdapter, ModelResponse

    monkeypatch.setenv("OPENAI_API_KEY", "test-placeholder-not-real")
    a = OpenAIAdapter("gpt-4o")

    fake_msg = MagicMock(content="canned response text")
    fake_choice = MagicMock(message=fake_msg, finish_reason="stop")
    fake_usage = MagicMock(prompt_tokens=42, completion_tokens=17)
    fake_completion = MagicMock(choices=[fake_choice], usage=fake_usage)
    fake_client = MagicMock()
    fake_client.chat.completions.create.return_value = fake_completion
    a._client = fake_client

    result = a.invoke(
        system_prompt="sys", user_content="user",
        sampling={"temperature": 0.0, "top_p": 1.0, "max_tokens": 8192},
    )
    assert isinstance(result, ModelResponse)
    assert result.text == "canned response text"
    assert result.model_id == "gpt-4o"
    assert result.input_tokens == 42
    assert result.output_tokens == 17
    assert result.stop_reason == "stop"
    assert result.extras == {"adapter": "openai"}

    # Verify what was sent to the SDK.
    call_kwargs = fake_client.chat.completions.create.call_args.kwargs
    assert call_kwargs["model"] == "gpt-4o"
    assert call_kwargs["temperature"] == 0.0
    assert call_kwargs["top_p"] == 1.0
    assert call_kwargs["max_tokens"] == 8192
    assert call_kwargs["messages"] == [
        {"role": "system", "content": "sys"},
        {"role": "user", "content": "user"},
    ]


def test_invoke_handles_empty_choices_gracefully(monkeypatch) -> None:
    """If the API returns no choices (rare but documented), the adapter
    must not crash; return an empty-text ModelResponse so the parser
    raises its own malformed-output error downstream."""
    from agents.patcher.adapter import OpenAIAdapter

    monkeypatch.setenv("OPENAI_API_KEY", "test-placeholder-not-real")
    a = OpenAIAdapter("gpt-4o")
    a._client = MagicMock()
    a._client.chat.completions.create.return_value = MagicMock(
        choices=[], usage=None,
    )
    result = a.invoke(
        system_prompt="sys", user_content="user", sampling={},
    )
    assert result.text == ""
    assert result.input_tokens is None


# ─── executor dispatch helper ─────────────────────────────────────────────


def test_dispatch_helper_routes_claude_to_anthropic(monkeypatch) -> None:
    """Executor's _build_adapter_from_model_id picks AnthropicAdapter for
    claude-* model ids."""
    from tools.trace_cli.execute import _build_adapter_from_model_id
    from agents.patcher.adapter import AnthropicAdapter

    monkeypatch.setenv("ANTHROPIC_API_KEY", "test-placeholder-not-real")
    a = _build_adapter_from_model_id("claude-opus-4-7", role_label="patcher")
    assert isinstance(a, AnthropicAdapter)


@pytest.mark.parametrize("model_id", [
    "gpt-4o",
    "gpt-4-turbo",
    "gpt-oss-120b",          # OpenRouter / vLLM-served gpt-oss
    "o1-preview",            # OpenAI o1 family
    "o3-mini",               # OpenAI o3 family
])
def test_dispatch_helper_routes_openai_family(model_id: str, monkeypatch) -> None:
    """gpt-* / o1-* / o3-* model ids route to OpenAIAdapter."""
    from tools.trace_cli.execute import _build_adapter_from_model_id
    from agents.patcher.adapter import OpenAIAdapter

    monkeypatch.setenv("OPENAI_API_KEY", "test-placeholder-not-real")
    a = _build_adapter_from_model_id(model_id, role_label="reproducer")
    assert isinstance(a, OpenAIAdapter)


def test_dispatch_helper_rejects_unknown_model_family(monkeypatch) -> None:
    """An unknown prefix raises ExecutionError with the role_label
    embedded so the operator can tell which dispatch site refused."""
    from tools.trace_cli.execute import (
        _build_adapter_from_model_id,
        ExecutionError,
    )

    with pytest.raises(ExecutionError, match="reproducer model id 'mistral-7b'"):
        _build_adapter_from_model_id("mistral-7b", role_label="reproducer")


# ─── _model_id_family extension for openai-gpt ────────────────────────────


def test_model_id_family_recognises_openai_models() -> None:
    """The executor's family-resolution helper must classify gpt-* / o1-*
    / o3-* into 'openai-gpt' so the cross-family rule can compare them
    against an anthropic-* patcher recorded in replay.json."""
    from tools.trace_cli.execute import _model_id_family

    assert _model_id_family("gpt-4o") == "openai-gpt"
    assert _model_id_family("gpt-oss-120b") == "openai-gpt"
    assert _model_id_family("o1-preview") == "openai-gpt"
    assert _model_id_family("o3-mini") == "openai-gpt"
    assert _model_id_family("claude-opus-4-7") == "anthropic-opus"
