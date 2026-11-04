"""Adaptive risk scoring.

Risk is advisory.  It can escalate an ALLOW to REQUIRE_APPROVAL, or (in the
risk-only baseline) block, but it can never override a deterministic BLOCK.
That monotonicity is enforced by the policy engine, not by this module.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime

from ..core.detector import InjectionDetector
from ..core.dlp import DLP
from ..core.models import DataLabel, RiskBreakdown, RiskFactor, Sensitivity


@dataclass
class RiskWeights:
    injection: float = 0.35
    sensitivity: float = 0.35
    anomaly: float = 0.15
    destination: float = 0.15


class CallTracker:
    """Per-task sliding window of tool calls."""

    def __init__(self, window_seconds: int = 60) -> None:
        self.window_seconds = window_seconds
        self.events: dict[str, list[tuple[float, str]]] = {}
        self.total: dict[str, int] = {}

    def _prune(self, task_id: str, now: float) -> list[tuple[float, str]]:
        events = self.events.get(task_id, [])
        cutoff = now - self.window_seconds
        pruned = [item for item in events if item[0] >= cutoff]
        self.events[task_id] = pruned
        return pruned

    def record(self, task_id: str, action_hash: str, now: float | None = None) -> None:
        timestamp = now or datetime.now(UTC).timestamp()
        self.events.setdefault(task_id, []).append((timestamp, action_hash))
        self.total[task_id] = self.total.get(task_id, 0) + 1

    def recent_count(self, task_id: str, now: float | None = None) -> int:
        timestamp = now or datetime.now(UTC).timestamp()
        return len(self._prune(task_id, timestamp))

    def repeat_count(self, task_id: str, action_hash: str, now: float | None = None) -> int:
        timestamp = now or datetime.now(UTC).timestamp()
        return sum(1 for _, item_hash in self._prune(task_id, timestamp) if item_hash == action_hash)

    def total_count(self, task_id: str) -> int:
        return self.total.get(task_id, 0)


class RiskEngine:
    def __init__(
        self,
        detector: InjectionDetector,
        dlp: DLP,
        *,
        trusted_domains: set[str] | None = None,
        weights: RiskWeights | None = None,
    ) -> None:
        self.detector = detector
        self.dlp = dlp
        self.trusted_domains = trusted_domains or {"myuni.edu", "api.myuni.edu", "partner.example"}
        self.weights = weights or RiskWeights()

    def assess(
        self,
        *,
        task_id: str,
        tool: str,
        text: str,
        labels: list[DataLabel],
        destination_trusted: bool,
        destination_allowed: bool,
        tracker: CallTracker,
        action_hash: str,
        capability_rate: int | None = None,
        capability_max: int | None = None,
    ) -> RiskBreakdown:
        factors: list[RiskFactor] = []
        reasons: list[str] = []

        injection = self.detector.scan(text)
        factors.append(
            RiskFactor(
                name="injection",
                value=injection.score,
                weight=self.weights.injection,
                detail=", ".join(injection.labels) or "no injection markers",
            )
        )
        if injection.score >= 0.5:
            reasons.append("prompt-injection markers in action content")

        sensitivity_rank = max([label.sensitivity.rank for label in labels], default=0)
        dlp_result = self.dlp.scan(text)
        sensitivity_rank = max(sensitivity_rank, dlp_result.sensitivity.rank)
        sensitivity_value = {0: 0.0, 1: 0.5, 2: 1.0}[sensitivity_rank]
        factors.append(
            RiskFactor(
                name="sensitivity",
                value=sensitivity_value,
                weight=self.weights.sensitivity,
                detail=Sensitivity(
                    ["public", "internal", "confidential"][sensitivity_rank]
                ).value,
            )
        )
        if sensitivity_rank == 2:
            reasons.append("confidential data in action")

        recent = tracker.recent_count(task_id)
        repeats = tracker.repeat_count(task_id, action_hash)
        total = tracker.total_count(task_id)
        anomaly = 0.0
        if capability_rate:
            anomaly = max(anomaly, min(1.0, recent / max(1, capability_rate)))
        else:
            anomaly = max(anomaly, min(1.0, recent / 40.0))
        anomaly = max(anomaly, min(1.0, repeats / 4.0))
        if capability_max:
            anomaly = max(anomaly, min(1.0, total / max(1, capability_max)))
        factors.append(
            RiskFactor(
                name="anomaly",
                value=round(anomaly, 4),
                weight=self.weights.anomaly,
                detail=f"recent={recent} repeats={repeats} total={total}",
            )
        )
        if anomaly >= 0.8:
            reasons.append("unusual call rate or repeated action")

        destination_value = 0.1 if destination_trusted else (0.45 if destination_allowed else 0.9)
        factors.append(
            RiskFactor(
                name="destination",
                value=destination_value,
                weight=self.weights.destination,
                detail="trusted" if destination_trusted else ("allowed" if destination_allowed else "unknown"),
            )
        )
        if not destination_trusted:
            reasons.append("destination is not a trusted allow-list entry")

        score = sum(f.value * f.weight for f in factors)
        if sensitivity_rank == 2 and tool in {"http.post", "email.send"}:
            score = max(score, 0.86)
        if injection.score >= 0.8:
            score = max(score, 0.9)
        score = round(min(1.0, score), 4)

        return RiskBreakdown(score=score, factors=factors, reasons=reasons)
