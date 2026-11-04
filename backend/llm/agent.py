"""Conversation state and the model-facing agent facade."""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass, field

from .base import LLMAdapter, LLMTurn, Message, ToolCall, ToolSpec

DEFAULT_SYSTEM_PROMPT = (
    "You are a tool-using assistant. Request a tool only when it is necessary. "
    "Every tool request is reviewed by AgentFence and may be blocked or require "
    "human approval. If a call is blocked, explain the outcome or choose a "
    "permitted alternative. Never claim that a blocked action succeeded."
)


@dataclass
class Agent:
    """Own the conversation; leave enforcement to the runtime loop."""

    adapter: LLMAdapter
    tools: Sequence[ToolSpec] = ()
    system_prompt: str = DEFAULT_SYSTEM_PROMPT
    messages: list[Message] = field(default_factory=list)
    max_steps: int = 8

    def __post_init__(self) -> None:
        self.tools = tuple(self.tools)
        if self.max_steps < 1:
            raise ValueError("max_steps must be at least 1")
        if not self.messages and self.system_prompt:
            self.messages.append(Message.system(self.system_prompt))

    def reset(self) -> None:
        self.messages.clear()
        if self.system_prompt:
            self.messages.append(Message.system(self.system_prompt))

    def add_user(self, content: str) -> None:
        self.messages.append(Message.user(content))

    def next_turn(self) -> LLMTurn:
        turn = self.adapter.complete(tuple(self.messages), self.tools)
        self.messages.append(Message.assistant(turn.content, turn.tool_calls))
        return turn

    def add_tool_result(self, call: ToolCall, content: str) -> None:
        self.messages.append(Message.tool_result(call, content))
