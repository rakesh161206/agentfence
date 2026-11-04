"""Transaction-aware approvals bound to an exact action hash."""

from __future__ import annotations

import base64
import json
import secrets
import time
from datetime import timedelta

from ..core.canonical import canonical_json, constant_time_equal, hmac_sha256_hex
from ..core.models import ApprovalToken, PendingApproval, Preview, utcnow


class ApprovalError(Exception):
    pass


def _b64encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64decode(data: str) -> bytes:
    return base64.urlsafe_b64decode(data + "=" * (-len(data) % 4))


class ApprovalStore:
    def __init__(self, secret: str, ttl_seconds: int = 900) -> None:
        self.secret = secret
        self.ttl_seconds = ttl_seconds
        self.pending: dict[str, PendingApproval] = {}
        self.consumed: set[str] = set()

    def request(self, preview: Preview) -> PendingApproval:
        approval = PendingApproval(
            approval_id=f"ap-{secrets.token_hex(8)}",
            task_id=preview.task_id,
            action_hash=preview.action_hash,
            preview=preview,
            expires_at=utcnow() + timedelta(seconds=self.ttl_seconds),
        )
        self.pending[approval.approval_id] = approval
        return approval

    def get(self, approval_id: str) -> PendingApproval:
        self._expire()
        try:
            return self.pending[approval_id]
        except KeyError as exc:
            raise ApprovalError("unknown approval") from exc

    def list(self, status: str | None = None) -> list[PendingApproval]:
        self._expire()
        values = list(self.pending.values())
        if status:
            values = [item for item in values if item.status == status]
        return sorted(values, key=lambda item: item.created_at)

    def approve(self, approval_id: str) -> ApprovalToken:
        self._expire()
        approval = self.get(approval_id)
        if approval.status != "pending":
            raise ApprovalError(f"approval is {approval.status}")
        approval.status = "approved"
        claims = {
            "approval_id": approval.approval_id,
            "action_hash": approval.action_hash,
            "preview_hash": approval.preview.preview_hash,
            "exp": int(approval.expires_at.timestamp()),
            "jti": f"aj-{secrets.token_hex(8)}",
        }
        body = _b64encode(canonical_json(claims).encode("utf-8"))
        signature = hmac_sha256_hex(self.secret, body)
        return ApprovalToken(
            approval_id=approval.approval_id,
            action_hash=approval.action_hash,
            token=f"{body}.{signature}",
            expires_at=approval.expires_at,
        )

    def deny(self, approval_id: str) -> PendingApproval:
        approval = self.get(approval_id)
        if approval.status != "pending":
            raise ApprovalError(f"approval is {approval.status}")
        approval.status = "denied"
        return approval

    def verify(
        self, token: str, *, action_hash: str, preview_hash: str | None = None
    ) -> PendingApproval:
        self._expire()
        try:
            body, signature = token.split(".", 1)
        except ValueError as exc:
            raise ApprovalError("malformed approval token") from exc

        expected = hmac_sha256_hex(self.secret, body)
        if not constant_time_equal(signature, expected):
            raise ApprovalError("bad approval signature")

        try:
            claims = json.loads(_b64decode(body))
        except Exception as exc:  # noqa: BLE001 - token payload is untrusted
            raise ApprovalError("malformed approval claims") from exc

        if claims.get("exp", 0) <= time.time():
            raise ApprovalError("approval expired")
        if not constant_time_equal(str(claims.get("action_hash", "")), action_hash):
            raise ApprovalError("approval is bound to a different action")
        approval = self.get(str(claims.get("approval_id", "")))
        expected_preview = preview_hash or approval.preview.preview_hash
        if not constant_time_equal(str(claims.get("preview_hash", "")), expected_preview):
            raise ApprovalError("approval preview changed")
        if approval.status != "approved":
            raise ApprovalError(f"approval is {approval.status}")
        if approval.approval_id in self.consumed:
            raise ApprovalError("approval token already used")
        if approval.action_hash != action_hash:
            raise ApprovalError("stored approval does not match action")
        return approval

    def consume(self, approval_id: str) -> None:
        self.consumed.add(approval_id)
        approval = self.pending.get(approval_id)
        if approval is not None:
            approval.status = "consumed"

    def _expire(self) -> None:
        now = utcnow()
        for approval in self.pending.values():
            if approval.status == "pending" and approval.expires_at <= now:
                approval.status = "expired"
