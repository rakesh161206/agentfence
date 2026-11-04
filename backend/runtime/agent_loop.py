"""Run a model conversation through the AgentFence enforcement point.

The loop is deliberately small: the adapter proposes, the gateway decides, and
the result is returned to the model. There is no path from the adapter to a
tool implementation that bypasses ``AgentFenceService.submit``.
"""

from __future__ import annotations

import json
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from ..core.models import ActionResponse, ApprovalToken, Decision, PendingApproval, ToolAction
from ..llm.agent import Agent
from ..llm.base import ToolCall
from ..security.approval import ApprovalError
from .interceptor import AgentFenceService

ApprovalHandler = Callable[[PendingApproval], ApprovalToken | None]


@dataclass
class ToolEvent:
    """One proposed call and the gateway's decision on it."""

    call: ToolCall
    action: ToolAction
    response: ActionResponse
    approval: PendingApproval | None = None


@dataclass
class AgentRun:
    """The visible outcome of one agent invocation."""

    answer: str
    events: list[ToolEvent] = field(default_factory=list)
    stopped_reason: str = "complete"
    steps: int = 0

    @property
    def blocked(self) -> int:
        return sum(1 for event in self.events if event.response.decision is Decision.BLOCK)

    @property
    def executed(self) -> int:
        return sum(1 for event in self.events if event.response.executed)


class AgentLoop:
    """Drive an ``Agent`` while enforcing every requested tool call."""

    def __init__(
        self,
        service: AgentFenceService,
        agent: Agent,
        token: str,
        *,
        approval_handler: ApprovalHandler | None = None,
        max_steps: int | None = None,
        result_chars: int = 4000,
    ) -> None:
        if max_steps is not None and max_steps < 1:
            raise ValueError("max_steps must be at least 1")
        self.service = service
        self.agent = agent
        self.token = token
        self.approval_handler = approval_handler
        self.max_steps = max_steps or agent.max_steps
        self.result_chars = result_chars

    def run(self, user_message: str) -> AgentRun:
        self.agent.add_user(user_message)
        events: list[ToolEvent] = []
        last_content = ""

        for step in range(1, self.max_steps + 1):
            turn = self.agent.next_turn()
            last_content = turn.content
            if not turn.tool_calls:
                return AgentRun(
                    answer=turn.content,
                    events=events,
                    stopped_reason="complete",
                    steps=step,
                )

            for call in turn.tool_calls:
                event, terminal = self._run_call(call)
                events.append(event)
                self.agent.add_tool_result(call, self._render(event.response))
                if terminal:
                    return AgentRun(
                        answer="",
                        events=events,
                        stopped_reason=terminal,
                        steps=step,
                    )

        return AgentRun(
            answer=last_content,
            events=events,
            stopped_reason="max_steps",
            steps=self.max_steps,
        )

    # ------------------------------------------------------------------ calls
    def _run_call(self, call: ToolCall) -> tuple[ToolEvent, str]:
        action = ToolAction(tool=call.name, args=dict(call.arguments))
        response = self.service.submit(token=self.token, action=action)
        approval: PendingApproval | None = None

        if response.decision is Decision.REQUIRE_APPROVAL and response.pending_approval is not None:
            approval = response.pending_approval
            if self.approval_handler is None:
                return ToolEvent(call, action, response, approval), "approval_required"

            token = self.approval_handler(approval)
            if token is None:
                self._deny_if_pending(approval)
                return ToolEvent(call, action, response, approval), "approval_denied"

            response = self.service.submit(
                token=self.token,
                action=action,
                approval_token=token.token,
            )

        return ToolEvent(call, action, response, approval), ""

    def _deny_if_pending(self, approval: PendingApproval) -> None:
        try:
            self.service.deny(approval.approval_id)
        except ApprovalError:
            # The handler may already have denied it.
            pass

    # --------------------------------------------------------------- rendering
    def _render(self, response: ActionResponse) -> str:
        if response.decision is Decision.ALLOW:
            payload: dict[str, Any] = {
                "decision": response.decision.value,
                "tool": response.tool,
                "executed": response.executed,
                "handle": response.handle,
                "content": self._content(response),
            }
        elif response.decision is Decision.REQUIRE_APPROVAL:
            payload = {
                "decision": response.decision.value,
                "tool": response.tool,
                "executed": False,
                "approval_id": response.pending_approval.approval_id
                if response.pending_approval
                else "",
                "preview": response.pending_approval.preview.content_preview
                if response.pending_approval
                else "",
            }
        else:
            payload = {
                "decision": response.decision.value,
                "tool": response.tool,
                "executed": False,
                "reasons": [
                    {"rule": hit.rule_id, "reason": hit.reason} for hit in response.reasons
                ],
            }
        return json.dumps(payload, ensure_ascii=False)

    def _content(self, response: ActionResponse) -> str:
        if not response.result:
            return ""
        content = response.result.get("content", "")
        if not isinstance(content, str):
            content = str(content)
        return content[: self.result_chars]
