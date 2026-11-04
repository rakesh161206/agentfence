"""Typed data model shared by the gateway, policy engine, and harness."""

from __future__ import annotations

from datetime import UTC, datetime
from enum import StrEnum
from typing import Any, Literal

from pydantic import BaseModel, Field, field_validator


def utcnow() -> datetime:
    return datetime.now(UTC)


class Trust(StrEnum):
    TRUSTED = "trusted"
    UNTRUSTED = "untrusted"


class Sensitivity(StrEnum):
    PUBLIC = "public"
    INTERNAL = "internal"
    CONFIDENTIAL = "confidential"

    @property
    def rank(self) -> int:
        return {self.PUBLIC: 0, self.INTERNAL: 1, self.CONFIDENTIAL: 2}[self]


class Decision(StrEnum):
    ALLOW = "ALLOW"
    BLOCK = "BLOCK"
    REQUIRE_APPROVAL = "REQUIRE_APPROVAL"


HIGH_RISK_TOOLS = frozenset({"http.post", "email.send", "file.write"})
EGRESS_TOOLS = frozenset({"http.post", "email.send"})


class Capability(BaseModel):
    """A single task-scoped permission.

    The grant is intentionally explicit: a tool is denied unless enumerated.
    Optional fields narrow the permission further.
    """

    tool: str
    allow_paths: list[str] = Field(default_factory=list)
    allow_domains: list[str] = Field(default_factory=list)
    allow_recipients: list[str] = Field(default_factory=list)
    allow_tables: list[str] = Field(default_factory=list)
    allow_write: bool = False
    require_approval: bool = False
    allow_confidential_egress: bool = False
    confidential_recipients: list[str] = Field(default_factory=list)
    rate_per_minute: int | None = None
    max_calls: int | None = None

    @field_validator("tool")
    @classmethod
    def _tool_nonempty(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("tool must not be empty")
        return value.strip()


class TaskGrant(BaseModel):
    task_id: str
    agent_id: str
    description: str
    capabilities: list[Capability]
    created_at: datetime = Field(default_factory=utcnow)
    expires_at: datetime

    def capability_for(self, tool: str) -> Capability | None:
        for cap in self.capabilities:
            if cap.tool == tool:
                return cap
        return None


class TokenClaims(BaseModel):
    task_id: str
    agent_id: str
    exp: int
    grant_hash: str
    jti: str


class DataLabel(BaseModel):
    trust: Trust = Trust.TRUSTED
    sensitivity: Sensitivity = Sensitivity.PUBLIC
    taint_sources: list[str] = Field(default_factory=list)
    sources: list[str] = Field(default_factory=list)
    content_hash: str = ""
    bytes: int = 0
    media_type: str = "text/plain"

    def merged(self, other: DataLabel) -> DataLabel:
        sensitivity = (
            self.sensitivity if self.sensitivity.rank >= other.sensitivity.rank else other.sensitivity
        )
        trust = (
            Trust.UNTRUSTED
            if Trust.UNTRUSTED in (self.trust, other.trust)
            else Trust.TRUSTED
        )
        return DataLabel(
            trust=trust,
            sensitivity=sensitivity,
            taint_sources=sorted(set(self.taint_sources) | set(other.taint_sources)),
            sources=sorted(set(self.sources) | set(other.sources)),
            content_hash=self.content_hash or other.content_hash,
            bytes=max(self.bytes, other.bytes),
            media_type=self.media_type if self.media_type != "text/plain" else other.media_type,
        )


class HandleRecord(BaseModel):
    handle: str
    content: str
    label: DataLabel


class ToolAction(BaseModel):
    tool: str
    args: dict[str, Any] = Field(default_factory=dict)
    purpose: str | None = None
    approval_token: str | None = None

    @field_validator("tool")
    @classmethod
    def _tool_nonempty(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("tool must not be empty")
        return value.strip()


class RuleHit(BaseModel):
    rule_id: str
    decision: Decision
    reason: str
    details: dict[str, Any] = Field(default_factory=dict)


class RiskFactor(BaseModel):
    name: str
    value: float
    weight: float
    detail: str = ""


class RiskBreakdown(BaseModel):
    score: float = 0.0
    factors: list[RiskFactor] = Field(default_factory=list)
    reasons: list[str] = Field(default_factory=list)


class Destination(BaseModel):
    kind: Literal["none", "http", "email", "path", "table"] = "none"
    value: str = ""
    host: str = ""
    recipients: list[str] = Field(default_factory=list)
    allowed: bool = False
    trusted: bool = False
    reason: str = ""


class Preview(BaseModel):
    task_id: str
    agent_id: str
    task_description: str
    tool: str
    action_hash: str
    destination: Destination
    content: str = ""
    content_preview: str = ""
    decoded_preview: str = ""
    attachments: list[dict[str, Any]] = Field(default_factory=list)
    labels: list[dict[str, Any]] = Field(default_factory=list)
    bytes_out: int = 0
    risk: RiskBreakdown = Field(default_factory=RiskBreakdown)
    reasons: list[str] = Field(default_factory=list)
    created_at: datetime = Field(default_factory=utcnow)
    preview_hash: str = ""


class PendingApproval(BaseModel):
    approval_id: str
    task_id: str
    action_hash: str
    preview: Preview
    status: Literal["pending", "approved", "denied", "expired", "consumed"] = "pending"
    created_at: datetime = Field(default_factory=utcnow)
    expires_at: datetime


class ApprovalToken(BaseModel):
    approval_id: str
    action_hash: str
    token: str
    expires_at: datetime


class ActionResponse(BaseModel):
    decision: Decision
    executed: bool
    task_id: str
    tool: str
    action_hash: str
    reasons: list[RuleHit] = Field(default_factory=list)
    risk: RiskBreakdown = Field(default_factory=RiskBreakdown)
    result: dict[str, Any] | None = None
    handle: str | None = None
    labels: DataLabel | None = None
    pending_approval: PendingApproval | None = None
    approval_requested: bool = False
    approval_used: bool = False
    error: str | None = None
    latency_ms: float = 0.0
    decision_latency_ms: float = 0.0
    effect_id: str | None = None


class TaskResponse(BaseModel):
    task_id: str
    agent_id: str
    token: str
    expires_at: datetime


class AuditEntry(BaseModel):
    seq: int
    timestamp: datetime
    event: str
    task_id: str
    agent_id: str = ""
    tool: str = ""
    action_hash: str = ""
    decision: str = ""
    rule_ids: list[str] = Field(default_factory=list)
    reasons: list[str] = Field(default_factory=list)
    risk_score: float = 0.0
    preview_hash: str = ""
    approval_id: str = ""
    executed: bool = False
    result_summary: str = ""
    prev_hash: str
    hash: str = ""
    hmac: str = ""
