from __future__ import annotations

import pytest

from agentfence.demo import get_scenario, list_scenarios, run_scenario, seed_live
from agentfence.service import AgentFenceService


def test_scenario_catalogue_is_presentation_ready() -> None:
    scenarios = list_scenarios()
    assert len(scenarios) == 10
    ids = {scenario["id"] for scenario in scenarios}
    assert {"a1-injection", "a5-split", "a5-paraphrase", "a7-approval"} <= ids
    for scenario in scenarios:
        assert scenario["title"]
        assert scenario["summary"]
        assert scenario["expectation"]
        assert scenario["defense"]
        assert scenario["family"]
        assert scenario["kind"] in {"attack", "benign"}
        assert scenario["actions"] >= 1
        assert scenario["capabilities"]


def test_unknown_scenario_is_rejected() -> None:
    with pytest.raises(KeyError):
        get_scenario("does-not-exist")
    with pytest.raises(KeyError):
        run_scenario("does-not-exist")


def test_unknown_mode_is_rejected() -> None:
    with pytest.raises(ValueError):
        run_scenario("a1-injection", mode="B99")


def test_a1_is_blocked_under_b5() -> None:
    result = run_scenario("a1-injection", mode="B5", approval_policy="approve")
    assert result["verdict"] == "blocked"
    assert result["summary"]["leak_bytes"] == 0
    assert result["summary"]["audit_ok"] is True
    final = result["steps"][-1]
    assert final["decision"] == "BLOCK"
    assert final["executed"] is False
    assert "R4" in {reason["rule_id"] for reason in final["reasons"]}


def test_a1_leaks_under_b0() -> None:
    result = run_scenario("a1-injection", mode="B0", approval_policy="approve")
    assert result["verdict"] == "leaked"
    assert result["summary"]["leak_bytes"] == 124
    assert result["steps"][-1]["executed"] is True


def test_fragment_reassembly_leaks_only_the_prefix() -> None:
    result = run_scenario("a5-split", mode="B5", approval_policy="approve")
    assert result["verdict"] == "leaked"
    assert result["summary"]["leak_bytes"] == 14
    final = result["steps"][-1]
    assert final["decision"] == "BLOCK"
    assert "R4b" in {reason["rule_id"] for reason in final["reasons"]}


def test_semantic_paraphrase_is_the_residual_leak() -> None:
    result = run_scenario("a5-paraphrase", mode="B5", approval_policy="approve")
    assert result["verdict"] == "leaked"
    assert result["summary"]["leak_bytes"] == 148
    assert result["steps"][-1]["executed"] is True


def test_approval_token_cannot_be_replayed_on_a_mutated_action() -> None:
    result = run_scenario("a7-approval", mode="B5", approval_policy="approve")
    original, replay = result["steps"]
    assert original["approval"]["status"] == "approved"
    assert original["approval"]["token_used"] is True
    assert original["executed"] is True
    assert replay["decision"] == "BLOCK"
    assert replay["executed"] is False
    assert "R9" in {reason["rule_id"] for reason in replay["reasons"]}
    assert result["verdict"] == "blocked"


def test_denied_approval_is_reported_as_blocked_not_pending() -> None:
    result = run_scenario("a7-approval", mode="B5", approval_policy="deny")
    assert result["verdict"] == "blocked"
    assert result["summary"]["approvals_denied"] == 2
    assert result["summary"]["approvals_pending"] == 0
    assert all(step["approval"]["status"] == "denied" for step in result["steps"])


def test_left_approval_is_reported_as_pending() -> None:
    result = run_scenario("a7-approval", mode="B5", approval_policy="leave")
    assert result["verdict"] == "pending"
    assert result["summary"]["approvals_pending"] == 2
    assert all(step["approval"]["status"] == "pending" for step in result["steps"])


def test_benign_task_completes_without_a_false_block() -> None:
    result = run_scenario("b03-benign-email", mode="B5", approval_policy="approve")
    assert result["verdict"] == "completed"
    assert result["summary"]["leak_bytes"] == 0
    assert result["summary"]["unsafe_executed"] == 0
    assert result["summary"]["blocked"] == 0
    assert all(step["executed"] for step in result["steps"])


def test_seed_live_populates_the_console(service: AgentFenceService) -> None:
    seeded = seed_live(service)
    assert len(seeded["runs"]) == 5
    assert seeded["pending_approvals"] >= 1
    assert seeded["audit_entries"] > 0
    assert seeded["effects"] > 0
    assert service.audit.verify()["ok"]
