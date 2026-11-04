"""Deterministic policy decision point.

Layer 1 rules are total and fail closed.  The risk layer (Layer 2) is applied
afterwards and may only tighten the outcome: a BLOCK from Layer 1 can never be
downgraded.  The code implements that by computing the final decision from the
set of rule hits with a fixed precedence.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime

from ..core.config import ModeConfig
from ..core.destinations import DestInfo, path_allowed, sql_tables
from ..core.models import (
    EGRESS_TOOLS,
    HIGH_RISK_TOOLS,
    Capability,
    DataLabel,
    Decision,
    RiskBreakdown,
    RuleHit,
    Sensitivity,
    TaskGrant,
    Trust,
)
from .risk_engine import CallTracker


@dataclass
class PolicyContext:
    mode: ModeConfig
    task: TaskGrant | None
    capability: Capability | None
    tool: str
    action_hash: str
    destination: DestInfo
    resolved_path: str | None = None
    labels: list[DataLabel] = field(default_factory=list)
    risk: RiskBreakdown = field(default_factory=RiskBreakdown)
    tracker: CallTracker | None = None
    auth_ok: bool = True
    auth_reason: str = ""
    prompt_score: float = 0.0
    approval_valid: bool = False
    cross_call_leak: bool = False


@dataclass
class PolicyResult:
    decision: Decision
    hits: list[RuleHit] = field(default_factory=list)

    @property
    def reasons(self) -> list[str]:
        return [hit.reason for hit in self.hits]

    @property
    def rule_ids(self) -> list[str]:
        return [hit.rule_id for hit in self.hits]

    @property
    def requires_approval(self) -> bool:
        return self.decision is Decision.REQUIRE_APPROVAL


def _hit(rule_id: str, decision: Decision, reason: str, **details) -> RuleHit:
    return RuleHit(rule_id=rule_id, decision=decision, reason=reason, details=details)


def _confidential_egress_allowed(cap: Capability | None, tool: str, dest: DestInfo) -> bool:
    if cap is None or not cap.allow_confidential_egress:
        return False
    if tool == "email.send":
        allowed_recipients = {r.lower() for r in cap.confidential_recipients}
        return bool(allowed_recipients) and all(r.lower() in allowed_recipients for r in dest.recipients)
    if tool == "http.post":
        return dest.host in {d.lower() for d in cap.allow_domains}
    return False


def evaluate(ctx: PolicyContext) -> PolicyResult:
    hits: list[RuleHit] = []

    if not ctx.mode.enforcement:
        return PolicyResult(decision=Decision.ALLOW, hits=[])

    if not ctx.auth_ok:
        hits.append(_hit("R1", Decision.BLOCK, f"authentication failed: {ctx.auth_reason}"))

    cap = ctx.capability
    if ctx.mode.capability_mode:
        if cap is None:
            hits.append(_hit("R1", Decision.BLOCK, "tool is not in the task's capability grant"))
        elif ctx.mode.expiry and ctx.task is not None:
            if ctx.task.expires_at <= datetime.now(UTC):
                hits.append(_hit("R1", Decision.BLOCK, "capability grant expired"))

    if ctx.mode.path_scope and ctx.tool in {"file.read", "file.write"}:
        path = ctx.resolved_path or ""
        if cap is None or not cap.allow_paths or not path_allowed(path, cap.allow_paths):
            hits.append(
                _hit(
                    "R2",
                    Decision.BLOCK,
                    "path is outside the task's allowed scope",
                    path=path,
                    allowed=cap.allow_paths if cap else [],
                )
            )
        if ctx.tool == "file.write" and (cap is None or not cap.allow_write):
            hits.append(_hit("R2", Decision.BLOCK, "write permission was not granted"))

    if ctx.mode.egress_allowlist:
        if ctx.tool in {"http.get", "http.post"} and not ctx.destination.allowed:
            hits.append(
                _hit(
                    "R3",
                    Decision.BLOCK,
                    f"destination not allow-listed: {ctx.destination.reason}",
                    host=ctx.destination.host,
                )
            )
        if ctx.tool == "email.send" and not ctx.destination.allowed:
            hits.append(
                _hit(
                    "R3",
                    Decision.BLOCK,
                    f"recipient not allow-listed: {ctx.destination.reason}",
                    recipients=ctx.destination.recipients,
                )
            )
        if ctx.tool == "db.query":
            tables = sql_tables(str(ctx.destination.value or ""))
            allowed_tables = {t.lower() for t in (cap.allow_tables if cap else [])}
            if not tables or not set(t.lower() for t in tables).issubset(allowed_tables):
                hits.append(
                    _hit(
                        "R3",
                        Decision.BLOCK,
                        "database table is outside the task's allowed scope",
                        tables=tables,
                        allowed=sorted(allowed_tables),
                    )
                )

    if ctx.mode.dlp and ctx.tool in EGRESS_TOOLS:
        confidential = [label for label in ctx.labels if label.sensitivity is Sensitivity.CONFIDENTIAL]
        if confidential and not _confidential_egress_allowed(cap, ctx.tool, ctx.destination):
            hits.append(
                _hit(
                    "R4",
                    Decision.BLOCK,
                    "confidential data cannot leave to this destination",
                    bytes=sum(label.bytes for label in confidential),
                )
            )

    if ctx.mode.taint and ctx.tool in HIGH_RISK_TOOLS:
        untrusted = [label for label in ctx.labels if label.trust is Trust.UNTRUSTED]
        if untrusted and not any(hit.rule_id == "R4" for hit in hits):
            decision = Decision.REQUIRE_APPROVAL if ctx.mode.approvals else Decision.BLOCK
            hits.append(
                _hit(
                    "R5",
                    decision,
                    "untrusted-provenance data is used in a high-risk action",
                    sources=sorted({source for label in untrusted for source in label.taint_sources})[:8],
                )
            )

    if ctx.mode.rate_limit and cap is not None and ctx.tracker is not None:
        recent = ctx.tracker.recent_count(ctx.task.task_id if ctx.task else "")
        total = ctx.tracker.total_count(ctx.task.task_id if ctx.task else "")
        if cap.rate_per_minute is not None and recent >= cap.rate_per_minute:
            hits.append(
                _hit(
                    "R6",
                    Decision.BLOCK,
                    "task rate limit exceeded",
                    recent=recent,
                    limit=cap.rate_per_minute,
                )
            )
        if cap.max_calls is not None and total >= cap.max_calls:
            hits.append(
                _hit(
                    "R6",
                    Decision.BLOCK,
                    "task call budget exhausted",
                    total=total,
                    limit=cap.max_calls,
                )
            )
        repeats = ctx.tracker.repeat_count(ctx.task.task_id if ctx.task else "", ctx.action_hash)
        if repeats >= 4:
            hits.append(
                _hit("R6b", Decision.BLOCK, "repeated identical action (loop protection)", repeats=repeats)
            )

    if ctx.mode.prompt_filter and ctx.prompt_score >= ctx.mode.detector_threshold:
        hits.append(
            _hit(
                "PF1",
                Decision.BLOCK,
                "prompt-injection filter flagged action content",
                score=ctx.prompt_score,
            )
        )

    if ctx.mode.capability_mode and cap is not None and cap.require_approval:
        hits.append(_hit("R8", Decision.REQUIRE_APPROVAL, "capability requires human approval"))

    if ctx.mode.risk:
        threshold = (
            ctx.mode.risk_block_threshold if ctx.mode.risk_action == "block" else ctx.mode.risk_threshold
        )
        if ctx.risk.score >= threshold:
            decision = Decision.BLOCK if ctx.mode.risk_action == "block" else Decision.REQUIRE_APPROVAL
            hits.append(
                _hit(
                    "R7",
                    decision,
                    f"risk score {ctx.risk.score:.2f} exceeds threshold {threshold:.2f}",
                    score=ctx.risk.score,
                )
            )

    decision = Decision.ALLOW
    if any(hit.decision is Decision.BLOCK for hit in hits):
        decision = Decision.BLOCK
    elif any(hit.decision is Decision.REQUIRE_APPROVAL for hit in hits):
        decision = Decision.REQUIRE_APPROVAL

    if decision is Decision.REQUIRE_APPROVAL and not ctx.mode.approvals and not ctx.approval_valid:
        decision = Decision.BLOCK
        hits.append(_hit("R9", Decision.BLOCK, "approval required but approval channel is disabled"))

    return PolicyResult(decision=decision, hits=hits)
