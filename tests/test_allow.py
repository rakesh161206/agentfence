"""Behavioral tests for permitted work."""

from __future__ import annotations

from backend.core.models import Capability, Decision, ToolAction
from backend.llm import Agent, ScriptedAdapter, tool_call
from backend.llm.base import LLMTurn
from backend.runtime.agent_loop import AgentLoop
from backend.runtime.interceptor import AgentFenceService


def _read_write_task(service: AgentFenceService):
    return service.create_task(
        agent_id="agent",
        description="Read the project overview and write a summary",
        capabilities=[
            Capability(tool="file.read", allow_paths=["/project/**"]),
            Capability(tool="file.write", allow_paths=["/project/out/**"], allow_write=True),
        ],
        ttl_seconds=600,
    )


def test_read_then_write_is_allowed(service: AgentFenceService) -> None:
    _, token = _read_write_task(service)

    read = service.submit(
        token=token,
        action=ToolAction(tool="file.read", args={"path": "/project/docs/overview.md"}),
    )
    assert read.decision is Decision.ALLOW
    assert read.executed is True
    assert read.handle
    assert not read.reasons

    write = service.submit(
        token=token,
        action=ToolAction(
            tool="file.write",
            args={
                "path": "/project/out/overview_summary.md",
                "content_refs": [read.handle],
            },
        ),
    )
    assert write.decision is Decision.ALLOW
    assert write.executed is True
    assert [effect.tool for effect in service.list_effects()] == ["file.read", "file.write"]


def test_agent_loop_allows_a_benign_tool_call(service: AgentFenceService) -> None:
    _, token = _read_write_task(service)
    agent = Agent(
        adapter=ScriptedAdapter(
            [
                LLMTurn(
                    tool_calls=(
                        tool_call(
                            "file.read",
                            {"path": "/project/docs/overview.md"},
                            call_id="call-read",
                        ),
                    )
                ),
                LLMTurn(content="The overview is available."),
            ]
        )
    )

    run = AgentLoop(service, agent, token).run("Read the overview.")

    assert run.stopped_reason == "complete"
    assert run.answer == "The overview is available."
    assert run.steps == 2
    assert len(run.events) == 1
    assert run.events[0].response.decision is Decision.ALLOW
    assert run.executed == 1
    assert run.blocked == 0
    assert service.list_effects()[0].tool == "file.read"


def test_benign_email_to_an_allowed_domain_is_not_blocked(service: AgentFenceService) -> None:
    _, token = service.create_task(
        agent_id="agent",
        description="Send a status note to the project analyst",
        capabilities=[
            Capability(
                tool="email.send",
                allow_domains=["myuni.edu"],
                rate_per_minute=10,
                max_calls=20,
            )
        ],
        ttl_seconds=600,
    )

    response = service.submit(
        token=token,
        action=ToolAction(
            tool="email.send",
            args={
                "to": ["analyst@myuni.edu"],
                "subject": "Status",
                "body": "The review is on schedule.",
            },
        ),
    )

    assert response.decision is Decision.ALLOW
    assert response.executed is True
    assert [effect.tool for effect in service.list_effects()] == ["email.send"]
