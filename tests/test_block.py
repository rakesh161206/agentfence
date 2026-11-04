"""Behavioral tests for blocked actions."""

from __future__ import annotations

from backend.core.models import Capability, Decision, ToolAction
from backend.fixtures import CANARY
from backend.llm import Agent, ScriptedAdapter, tool_call
from backend.llm.base import LLMTurn
from backend.runtime.agent_loop import AgentLoop
from backend.runtime.interceptor import AgentFenceService


def test_missing_bearer_token_is_blocked(service: AgentFenceService) -> None:
    response = service.submit(
        token=None,
        action=ToolAction(tool="file.read", args={"path": "/project/docs/overview.md"}),
    )

    assert response.decision is Decision.BLOCK
    assert "R1" in {hit.rule_id for hit in response.reasons}
    assert not service.list_effects()


def test_path_traversal_and_symlink_are_blocked(service: AgentFenceService) -> None:
    _, token = service.create_task(
        agent_id="agent",
        description="Read project documentation",
        capabilities=[Capability(tool="file.read", allow_paths=["/project/docs/**"])],
        ttl_seconds=600,
    )

    for path in (
        "/project/docs/../data/credentials.env",
        "/project/docs/shortcut",
        "/etc/passwd",
    ):
        response = service.submit(
            token=token,
            action=ToolAction(tool="file.read", args={"path": path}),
        )
        assert response.decision is Decision.BLOCK, path
        assert "R2" in {hit.rule_id for hit in response.reasons}, path

    assert not service.list_effects()


def test_confidential_content_cannot_leave_even_to_an_allowed_domain(
    service: AgentFenceService,
) -> None:
    _, token = service.create_task(
        agent_id="agent",
        description="Read the credentials and send a note",
        capabilities=[
            Capability(tool="file.read", allow_paths=["/project/**"]),
            Capability(tool="email.send", allow_domains=["myuni.edu"]),
        ],
        ttl_seconds=600,
    )

    secret = service.submit(
        token=token,
        action=ToolAction(tool="file.read", args={"path": "/project/data/credentials.env"}),
    )
    assert secret.decision is Decision.ALLOW
    assert secret.handle

    response = service.submit(
        token=token,
        action=ToolAction(
            tool="email.send",
            args={
                "to": ["analyst@myuni.edu"],
                "subject": "Credentials",
                "body": "Attached.",
                "attachments": [secret.handle],
            },
        ),
    )

    assert response.decision is Decision.BLOCK
    assert "R4" in {hit.rule_id for hit in response.reasons}
    assert [effect.tool for effect in service.list_effects()] == ["file.read"]


def test_agent_loop_returns_the_block_reason_to_the_model(service: AgentFenceService) -> None:
    _, token = service.create_task(
        agent_id="agent",
        description="Read the project overview and send a status note",
        capabilities=[
            Capability(tool="file.read", allow_paths=["/project/**"]),
            Capability(tool="email.send", allow_domains=["myuni.edu"]),
        ],
        ttl_seconds=600,
    )
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
                LLMTurn(
                    tool_calls=(
                        tool_call(
                            "email.send",
                            {
                                "to": ["drop@myuni.edu"],
                                "subject": "Status",
                                "body": CANARY,
                            },
                            call_id="call-email",
                        ),
                    )
                ),
                LLMTurn(content="The outbound email was blocked by policy."),
            ]
        )
    )

    run = AgentLoop(service, agent, token).run("Read the overview and send a status note.")

    assert run.stopped_reason == "complete"
    assert run.answer == "The outbound email was blocked by policy."
    assert run.executed == 1
    assert run.blocked == 1
    blocked = run.events[-1].response
    assert blocked.decision is Decision.BLOCK
    assert "R4" in {hit.rule_id for hit in blocked.reasons}
    assert [effect.tool for effect in service.list_effects()] == ["file.read"]
