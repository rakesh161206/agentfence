"""Dependency-free adapters used by tests, demos, and custom providers."""

from __future__ import annotations

from collections import deque
from collections.abc import Callable, Iterable, Mapping, Sequence
from typing import Any

from .base import AdapterError, LLMTurn, Message, ToolCall, ToolSpec


def _coerce_turn(value: LLMTurn | Mapping[str, Any]) -> LLMTurn:
    if isinstance(value, LLMTurn):
        return value
    calls: list[ToolCall] = []
    for raw in value.get("tool_calls", ()):
        if isinstance(raw, ToolCall):
            calls.append(raw)
            continue
        calls.append(
            ToolCall(
                name=str(raw["name"]),
                arguments=dict(raw.get("arguments") or {}),
                call_id=str(raw.get("call_id", "")),
            )
        )
    return LLMTurn(content=str(value.get("content", "")), tool_calls=tuple(calls))


class ScriptedAdapter:
    """Replay a fixed sequence of assistant turns.

    This adapter makes agent behavior deterministic while still exercising the
    real gateway, policy engine, tool runtime, and audit chain.
    """

    def __init__(self, turns: Iterable[LLMTurn | Mapping[str, Any]]) -> None:
        self._turns = deque(_coerce_turn(turn) for turn in turns)
        self.calls = 0

    @property
    def remaining(self) -> int:
        return len(self._turns)

    def complete(self, messages: Sequence[Message], tools: Sequence[ToolSpec]) -> LLMTurn:
        if not self._turns:
            raise AdapterError("scripted adapter has no turns left")
        self.calls += 1
        return self._turns.popleft()


class CallableAdapter:
    """Wrap a function as an adapter for tests or a custom provider bridge."""

    def __init__(self, fn: Callable[[Sequence[Message], Sequence[ToolSpec]], LLMTurn]) -> None:
        self._fn = fn
        self.calls = 0

    def complete(self, messages: Sequence[Message], tools: Sequence[ToolSpec]) -> LLMTurn:
        self.calls += 1
        turn = self._fn(messages, tools)
        if not isinstance(turn, LLMTurn):
            raise AdapterError("adapter function must return LLMTurn")
        return turn


def tool_call(name: str, arguments: dict[str, Any] | None = None, *, call_id: str = "") -> ToolCall:
    """Build a readable scripted tool call."""
    return ToolCall(name=name, arguments=dict(arguments or {}), call_id=call_id or f"call-{name}")
