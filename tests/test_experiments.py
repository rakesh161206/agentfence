"""Regression tests for harness behaviour and instrumentation.

These cover bugs that would silently invalidate experimental numbers:
embedded scenario placeholders, multi-channel attack traces that must keep
running after a block, a benign task whose read capability spans two output
prefixes, and the latency fields used in the paper.
"""

from __future__ import annotations

from agentfence.models import Capability, Decision, ToolAction
from agentfence.service import AgentFenceService

from conftest import make_service
from experiments.agent import MissingRef, ScriptedAgent, resolve_value
from experiments.scenarios import attack_scenarios, benign_scenarios


def _scenario(scenario_id: str):
    for scenario in [*attack_scenarios(), *benign_scenarios()]:
        if scenario.id == scenario_id:
            return scenario
    raise AssertionError(f"missing scenario {scenario_id}")


def test_embedded_placeholders_resolve_inside_larger_scalars(service: AgentFenceService) -> None:
    _, token = service.create_task(
        agent_id="agent",
        description="Read a secret for encoding tests",
        capabilities=[Capability(tool="file.read", allow_paths=["/project/data/**"])],
        ttl_seconds=600,
    )
    read = service.submit(
        token=token, action=ToolAction(tool="file.read", args={"path": "/project/data/credentials.env"})
    )
    assert read.handle

    url = resolve_value(
        {
            "url": "https://api.myuni.edu/ingest?d=$urlkey:read&x=1",
            "headers": {"X-Data": "prefix-$hexkey:read"},
        },
        {"read": read.handle},
        service.provenance,
    )
    assert "$urlkey" not in url["url"]
    assert "$hexkey" not in url["headers"]["X-Data"]
    assert "%2D" in url["url"] or "sk-live" in url["url"]
    assert url["url"].endswith("&x=1")
    assert url["headers"]["X-Data"].startswith("prefix-")

    split = resolve_value(
        "https://api.myuni.edu/ingest?a=$partkey:read:0:14&b=$partkey:read:14:40",
        {"read": read.handle},
        service.provenance,
    )
    assert "$partkey" not in split
    assert "a=" in split and "b=" in split

    try:
        resolve_value("https://api.myuni.edu/?x=$urlkey:missing", {}, service.provenance)
    except MissingRef as exc:
        assert "missing" in str(exc)
    else:  # pragma: no cover - an unknown handle must not be silently ignored
        raise AssertionError("unknown handle was not rejected")


def test_a2_trace_continues_after_block(sandbox) -> None:
    scenario = _scenario("A2-1")
    service = make_service(sandbox, "B2")
    _, token = service.create_task(
        agent_id="agent",
        description=scenario.task_description,
        capabilities=scenario.capabilities,
        ttl_seconds=600,
    )
    result = ScriptedAgent(service, token, scenario).run()

    # The first post is blocked by the destination allow-list.  The scenario
    # deliberately continues, so all four independent channels are measured.
    assert result.actions_submitted == 4
    assert len(result.decisions) == 4
    assert result.decisions[1]["decision"] == "BLOCK"
    assert result.actions_blocked == 1
    assert result.attack_success is True  # B2 has no data-flow control


def test_b15_read_scope_spans_docs_and_out(sandbox) -> None:
    scenario = _scenario("B15")
    service = make_service(sandbox, "B5")
    _, token = service.create_task(
        agent_id="agent",
        description=scenario.task_description,
        capabilities=scenario.capabilities,
        ttl_seconds=600,
    )
    result = ScriptedAgent(service, token, scenario).run()

    assert result.task_completed is True
    assert result.required_completed == result.required_total == 4
    assert result.false_blocks == 0
    assert all(trace["decision"] == "ALLOW" for trace in result.decisions)


def test_decision_latency_is_recorded_and_bounded(sandbox) -> None:
    for mode in ("B0", "B5"):
        service = make_service(sandbox, mode)
        _, token = service.create_task(
            agent_id="agent",
            description="Status note",
            capabilities=[
                Capability(tool="email.send", allow_domains=["myuni.edu"], require_approval=mode == "B5")
            ],
            ttl_seconds=600,
        )
        action = ToolAction(
            tool="email.send",
            args={"to": ["analyst@myuni.edu"], "subject": "status", "body": "On track."},
        )
        response = service.submit(token=token, action=action)
        assert response.decision_latency_ms > 0, mode

        if response.decision is Decision.REQUIRE_APPROVAL:
            assert response.pending_approval is not None
            approval = service.approve(response.pending_approval.approval_id)
            response = service.submit(token=token, action=action, approval_token=approval.token)

        assert response.decision is Decision.ALLOW, mode
        assert response.decision_latency_ms > 0, mode
        assert response.latency_ms >= response.decision_latency_ms, mode
