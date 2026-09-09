"""Tests for AnthropicAdapter prompt-caching behaviour.

Anthropic Messages API supports `cache_control: {type: "ephemeral"}` on
content blocks; the marked block (and everything before it in the
prompt) becomes a cache prefix. Repeat calls within ~5 minutes hit the
cached prefix at ~90% input-token discount.

For trace's Patcher / Reviewer / Reproducer roles, the system prompt is
the obvious cache candidate: large, role-stable, identical across every
invocation in a corpus run. The user content (finding.json + per-bundle
artifacts) is the variable suffix that legitimately differs.

These tests pin two invariants:

  1. The system prompt is sent as a CONTENT-BLOCK ARRAY with
     `cache_control: {type: "ephemeral"}` on the (last) block, not as a
     bare string. The Anthropic SDK accepts both forms; trace MUST use
     the cached form.
  2. The user content is sent as a bare string (uncached), since user
     content varies per invocation and caching it would waste cache
     slots and pin the wrong prefix.

Cost-of-failure: if a regression drops cache_control, every Patcher
invocation pays full input-token price for the system prompt. At
corpus scale (50+ bundles × 5+ retries × ~3000-token system prompts)
that's measurable.
"""

from __future__ import annotations

import os
from typing import Any
from unittest import mock

import pytest


def _make_adapter(model_id: str):
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


class _FakeUsage:
    input_tokens = 10
    output_tokens = 4


class _FakeBlock:
    def __init__(self, text: str) -> None:
        self.type = "text"
        self.text = text


class _FakeMsg:
    def __init__(self, text: str) -> None:
        self.content = [_FakeBlock(text)]
        self.usage = _FakeUsage()
        self.stop_reason = "end_turn"


def _capture_invoke(
    model_id: str, system_prompt: str, user_content: str
) -> dict[str, Any]:
    """Invoke adapter against a mocked Anthropic client; return the kwargs
    the SDK saw."""
    adapter = _make_adapter(model_id)
    captured: dict[str, Any] = {}

    class _FakeMessages:
        @staticmethod
        def create(**kwargs: Any) -> _FakeMsg:
            captured.update(kwargs)
            return _FakeMsg("ok")

    class _FakeClient:
        messages = _FakeMessages()

    with mock.patch.object(adapter, "_ensure_client", return_value=_FakeClient()):
        adapter.invoke(
            system_prompt=system_prompt,
            user_content=user_content,
            sampling={"max_tokens": 16, "temperature": 0.0},
        )
    return captured


@pytest.mark.parametrize(
    "model_id",
    [
        "claude-opus-4-7",
        "claude-sonnet-4-6",
        "claude-haiku-4-5-20251001",
    ],
)
def test_system_prompt_marked_for_caching(model_id: str) -> None:
    """The system prompt MUST be sent as a content-block array with
    `cache_control: {type: "ephemeral"}` on the marked block. A bare
    string system prompt fails this test because the API would not cache
    it."""
    kwargs = _capture_invoke(
        model_id,
        system_prompt="You are a Patcher. Follow the strict-output contract.",
        user_content="Some bundle inputs here.",
    )
    system = kwargs.get("system")
    assert isinstance(system, list), (
        f"system prompt must be a content-block array for caching, got {type(system).__name__}"
    )
    assert system, "system content-block array must be non-empty"
    # Find the cached block (the design caches the entire system prompt as
    # one ephemeral block, so the last block is the natural marker).
    cached_blocks = [
        b for b in system if isinstance(b, dict) and b.get("cache_control")
    ]
    assert cached_blocks, "at least one system block must carry cache_control"
    # Ephemeral type is the only one Anthropic supports today.
    for b in cached_blocks:
        assert b["cache_control"] == {"type": "ephemeral"}, (
            f"cache_control must be ephemeral, got {b['cache_control']!r}"
        )
        assert b.get("type") == "text"
        assert b.get("text"), "cached system block must carry the actual prompt text"


def test_user_content_remains_bare_string() -> None:
    """User content varies per invocation; caching it would waste cache
    slots. It must remain a bare string in the messages payload."""
    kwargs = _capture_invoke(
        "claude-opus-4-7",
        system_prompt="role prompt",
        user_content="bundle-specific inputs",
    )
    messages = kwargs.get("messages")
    assert isinstance(messages, list) and len(messages) == 1
    assert messages[0]["role"] == "user"
    assert messages[0]["content"] == "bundle-specific inputs"


def test_cached_block_carries_full_system_text() -> None:
    """The text in the cached block must equal the system prompt the
    runner passed in. A truncation regression would silently degrade
    Patcher behaviour without breaking the cache test above."""
    sentinel = "ROLE-PROMPT-SENTINEL-d2c4e6f8a1b3"
    kwargs = _capture_invoke(
        "claude-opus-4-7",
        system_prompt=sentinel,
        user_content="x",
    )
    cached_text = "".join(
        b.get("text", "") for b in kwargs["system"] if isinstance(b, dict)
    )
    assert sentinel in cached_text
