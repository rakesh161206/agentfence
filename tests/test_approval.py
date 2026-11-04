"""Behavioral tests for the human-approval path."""

from __future__ import annotations

from backend.core.models import Capability, Decision, ToolAction
from backend.llm import Agent, ScriptedAdapter, tool_call
from backend.llm.base import LLMTurn
from backend.runtime.agent_loop import AgentLoop
from backend.runtime.interceptor import AgentFenceService


def _approval_task(service: AgentFenceService):
    return service.create_task(
        agent_id="agent",
        description="Send the status note",
        capabilities=[
            Capability(
                tool="email.send",
                allow_domains=["myuni.edu"],
                require_approval=True,
            )
        ],
        ttl_seconds=600,
    )


def _email(to: str = "analyst@myuni.edu") -> ToolAction:
    return ToolAction(
        tool="email.send",
        args={"to": [to], "subject": "Status", "body": "The review is on schedule."},
    )


def test_approval_is_required_then_executes(service: AgentFenceService) -> None:
    _, token = _approval_task(service)
    action = _email()

    pending = service.submit(token=token, action=action)
    assert pending.decision is Decision.REQUIRE_APPROVAL
    assert pending.executed is False
    assert pending.pending_approval is not None

    approval = service.approve(pending.pending_approval.approval_id)
    allowed = service.submit(token=token, action=action, approval_token=approval.token)

    assert allowed.decision is Decision.ALLOW
    assert allowed.executed is True
    assert allowed.approval_used is True
    assert [effect.tool for effect in service.list_effects()] == ["email.send"]


def test_approval_token_cannot_be_replayed_on_a_changed_action(
    service: AgentFenceService,
) -> None:
    _, token = _approval_task(service)
    pending = service.submit(token=token, action=_email())
    assert pending.pending_approval is not None
    approval = service.approve(pending.pending_approval.approval_id)

    changed = service.submit(
        token=token,
        action=_email(to="someone-else@myuni.edu"),
        approval_token=approval.token,
    )

    assert changed.decision is Decision.BLOCK
    assert "R9" in {hit.rule_id for hit in changed.reasons}
    assert not service.list_effects()


def test_agent_loop_can_approve_a_sensitive_call(service: AgentFenceService) -> None:
    _, token = _approval_task(service)
    agent = Agent(
        adapter=ScriptedAdapter(
            [
                LLMTurn(
                    tool_calls=(
                        tool_call(
                            "email.send",
                            {
                                "to": ["analyst@myuni.edu"],
                                "subject": "Status",
                                "body": "The review is on schedule.",
                            },
                            call_id="call-email",
                        ),
                    )
                ),
                LLMTurn(content="The status note was sent after approval."),
            ]
        )
    )

    run = AgentLoop(
        service,
        agent,
        token,
        approval_handler=lambda pending: service.approve(pending.approval_id),
    ).run("Send the status note.")

    assert run.stopped_reason == "complete"
    assert run.executed == 1
    assert run.blocked == 0
    event = run.events[0]
    assert event.approval is not None
    assert event.response.decision is Decision.ALLOW
    assert event.response.approval_used is True


def test_agent_loop_stops_when_approval_is_denied(service: AgentFenceService) -> None:
    _, token = _approval_task(service)
    agent = Agent(
        adapter=ScriptedAdapter(
            [
                LLMTurn(
                    tool_calls=(
                        tool_call(
                            "email.send",
                            {
                                "to": ["analyst@myuni.edu"],
                                "subject": "Status",
                                "body": "The review is on schedule.",
                            },
                            call_id="call-email",
                        ),
                    )
                ),
                LLMTurn(content="This turn should not be reached."),
            ]
        )
    )

    run = AgentLoop(
        service,
        agent,
        token,
        approval_handler=lambda pending: None,
    ).run("Send the status note.")

    assert run.stopped_reason == "approval_denied"
    assert run.executed == 0
    assert not service.list_effects()
    assert service.list_approvals("denied")
