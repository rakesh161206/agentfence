"""Task-scoped capability grants and signed bearer tokens."""

from __future__ import annotations

import base64
import json
import secrets
import time
from datetime import UTC, datetime, timedelta

from ..core.canonical import canonical_json, constant_time_equal, hmac_sha256_hex, sha256_hex
from ..core.models import Capability, TaskGrant, TokenClaims, utcnow


class CapabilityError(Exception):
    pass


def _b64encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64decode(data: str) -> bytes:
    return base64.urlsafe_b64decode(data + "=" * (-len(data) % 4))


def grant_hash(grant: TaskGrant) -> str:
    payload = grant.model_dump(mode="json")
    return sha256_hex(canonical_json(payload))


class CapabilityManager:
    def __init__(self, secret: str) -> None:
        self.secret = secret
        self.grants: dict[str, TaskGrant] = {}

    def create_task(
        self,
        *,
        agent_id: str,
        description: str,
        capabilities: list[Capability],
        ttl_seconds: int = 600,
        task_id: str | None = None,
    ) -> tuple[TaskGrant, str]:
        now = utcnow()
        grant = TaskGrant(
            task_id=task_id or f"t-{secrets.token_hex(6)}",
            agent_id=agent_id,
            description=description,
            capabilities=capabilities,
            created_at=now,
            expires_at=now + timedelta(seconds=ttl_seconds),
        )
        self.grants[grant.task_id] = grant
        token = self.issue_token(grant)
        return grant, token

    def register(self, grant: TaskGrant) -> str:
        self.grants[grant.task_id] = grant
        return self.issue_token(grant)

    def issue_token(self, grant: TaskGrant) -> str:
        claims = TokenClaims(
            task_id=grant.task_id,
            agent_id=grant.agent_id,
            exp=int(grant.expires_at.timestamp()),
            grant_hash=grant_hash(grant),
            jti=f"j-{secrets.token_hex(8)}",
        )
        payload = canonical_json(claims.model_dump(mode="json")).encode("utf-8")
        body = _b64encode(payload)
        signature = hmac_sha256_hex(self.secret, body)
        return f"{body}.{signature}"

    def verify_token(self, token: str, *, now: float | None = None) -> tuple[TokenClaims, TaskGrant]:
        try:
            body, signature = token.split(".", 1)
        except ValueError as exc:
            raise CapabilityError("malformed token") from exc

        expected = hmac_sha256_hex(self.secret, body)
        if not constant_time_equal(signature, expected):
            raise CapabilityError("bad token signature")

        try:
            claims = TokenClaims.model_validate(json.loads(_b64decode(body)))
        except Exception as exc:  # noqa: BLE001 - malformed claims are untrusted input
            raise CapabilityError("malformed token claims") from exc

        current = time.time() if now is None else now
        if claims.exp <= current:
            raise CapabilityError("token expired")

        grant = self.grants.get(claims.task_id)
        if grant is None:
            raise CapabilityError("unknown task")
        if grant.expires_at.timestamp() <= current:
            raise CapabilityError("task grant expired")
        if not constant_time_equal(grant_hash(grant), claims.grant_hash):
            raise CapabilityError("grant changed after issuance")
        if grant.agent_id != claims.agent_id:
            raise CapabilityError("agent mismatch")
        return claims, grant

    def get(self, task_id: str) -> TaskGrant | None:
        return self.grants.get(task_id)


def now_iso() -> str:
    return datetime.now(UTC).isoformat()
