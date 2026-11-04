"""Provider-neutral interfaces for the model side of AgentFence.

The gateway never imports a vendor SDK. An adapter turns a conversation into a
single assistant turn. The runtime loop, not the adapter, submits every
requested tool call to the policy enforcement point.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass, field
from typing import Any, Literal, Protocol, runtime_checkable

Role = Literal["system", "user", "assistant", "tool"]


class AdapterError(RuntimeError):
    """Raised when an adapter cannot produce a turn."""


@dataclass(frozen=True)
class ToolSpec:
    """A tool declaration exposed to the model."""

    name: str
    description: str
    parameters: dict[str, Any] = field(default_factory=dict)

    def as_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "description": self.description,
            "parameters": self.parameters,
        }


@dataclass(frozen=True)
class ToolCall:
    """A model request to invoke a tool.

    The call is only a proposal. It becomes a ``ToolAction`` when the runtime
    loop hands it to ``AgentFenceService.submit``.
    """

    name: str
    arguments: dict[str, Any] = field(default_factory=dict)
    call_id: str = ""

    def __post_init__(self) -> None:
        if not self.name.strip():
            raise ValueError("tool call name must not be empty")


@dataclass(frozen=True)
class Message:
    role: Role
    content: str = ""
    tool_calls: tuple[ToolCall, ...] = ()
    tool_call_id: str = ""
    name: str = ""

    @classmethod
    def system(cls, content: str) -> Message:
        return cls(role="system", content=content)

    @classmethod
    def user(cls, content: str) -> Message:
        return cls(role="user", content=content)

    @classmethod
    def assistant(cls, content: str = "", tool_calls: Sequence[ToolCall] = ()) -> Message:
        return cls(role="assistant", content=content, tool_calls=tuple(tool_calls))

    @classmethod
    def tool_result(cls, call: ToolCall, content: str) -> Message:
        return cls(role="tool", content=content, tool_call_id=call.call_id, name=call.name)


@dataclass(frozen=True)
class LLMTurn:
    """One assistant turn: either a final answer or one or more tool calls."""

    content: str = ""
    tool_calls: tuple[ToolCall, ...] = ()

    @property
    def wants_tools(self) -> bool:
        return bool(self.tool_calls)


@runtime_checkable
class LLMAdapter(Protocol):
    """Minimal interface implemented by every model provider adapter."""

    def complete(self, messages: Sequence[Message], tools: Sequence[ToolSpec]) -> LLMTurn:
        """Return the next assistant turn for the conversation."""
