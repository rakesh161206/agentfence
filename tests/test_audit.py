from __future__ import annotations

from agentfence.models import Capability, ToolAction


def test_audit_chain_detects_tampering(service) -> None:
    _, token = service.create_task(
        agent_id="agent",
        description="Read docs",
        capabilities=[Capability(tool="file.read", allow_paths=["/project/**"])],
        ttl_seconds=600,
    )
    service.submit(token=token, action=ToolAction(tool="file.read", args={"path": "/project/docs/overview.md"}))
    assert service.audit.verify()["ok"]
    assert len(service.audit.entries) >= 2

    entry = service.audit.entries[1]
    entry.reasons.append("tampered after the fact")
    verification = service.audit.verify()
    assert not verification["ok"]
    assert "hash mismatch" in verification["error"]


def test_audit_chain_detects_reordering(service) -> None:
    _, token = service.create_task(
        agent_id="agent",
        description="Read docs",
        capabilities=[Capability(tool="file.read", allow_paths=["/project/**"])],
        ttl_seconds=600,
    )
    for path in ("/project/docs/overview.md", "/project/docs/meeting_notes.md"):
        service.submit(token=token, action=ToolAction(tool="file.read", args={"path": path}))
    assert service.audit.verify()["ok"]
    service.audit.entries[0], service.audit.entries[1] = service.audit.entries[1], service.audit.entries[0]
    verification = service.audit.verify()
    assert not verification["ok"]
