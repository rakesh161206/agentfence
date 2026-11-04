from __future__ import annotations

import time

from backend.core.models import Capability
from backend.security.capabilities import CapabilityError


def test_token_round_trip(service) -> None:
    grant, token = service.create_task(
        agent_id="agent",
        description="test",
        capabilities=[Capability(tool="file.read", allow_paths=["/project/**"])],
        ttl_seconds=60,
    )
    claims, verified = service.capabilities.verify_token(token)
    assert claims.task_id == grant.task_id
    assert verified.description == "test"


def test_forged_signature_rejected(service) -> None:
    _, token = service.create_task(
        agent_id="agent",
        description="test",
        capabilities=[Capability(tool="file.read", allow_paths=["/project/**"])],
        ttl_seconds=60,
    )
    body, signature = token.split(".")
    tampered = body + "." + ("0" * len(signature))
    try:
        service.capabilities.verify_token(tampered)
    except CapabilityError as exc:
        assert "signature" in str(exc)
    else:  # pragma: no cover
        raise AssertionError("forged token accepted")


def test_expired_token_rejected(service) -> None:
    _, token = service.create_task(
        agent_id="agent",
        description="test",
        capabilities=[Capability(tool="file.read")],
        ttl_seconds=1,
    )
    time.sleep(1.1)
    try:
        service.capabilities.verify_token(token)
    except CapabilityError as exc:
        assert "expired" in str(exc)
    else:  # pragma: no cover
        raise AssertionError("expired token accepted")


def test_grant_hash_detects_mutation(service) -> None:
    grant, token = service.create_task(
        agent_id="agent",
        description="test",
        capabilities=[Capability(tool="file.read", allow_paths=["/project/docs/**"])],
        ttl_seconds=60,
    )
    grant.capabilities[0].allow_paths.append("/project/data/**")
    try:
        service.capabilities.verify_token(token)
    except CapabilityError as exc:
        assert "grant changed" in str(exc)
    else:  # pragma: no cover
        raise AssertionError("mutated grant accepted")
