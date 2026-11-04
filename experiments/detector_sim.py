"""Simulated prompt-injection detectors for the recall / false-positive sweeps.

The point of the sweep is not to claim that a particular classifier has these
error rates.  It is to vary detector quality while holding the rest of the
gateway fixed, so the experiment can show which decisions depend on the
detector and which are enforced by data-flow and authorization policy.
"""

from __future__ import annotations

import hashlib
import re
from typing import Any

from agentfence.detector import DetectorMatch, DetectorResult, InjectionDetector
from agentfence.fixtures import DEFAULT_INJECTIONS


def _normalize(text: str) -> str:
    return re.sub(r"[^a-z0-9]", "", text.lower())


class SimulatedDetector:
    """A calibrated-by-construction detector with controllable error rates.

    ``recall`` is the probability of returning a high score for content that
    contains one of the known injection payloads.  ``fpr`` is the probability
    of returning a high score for other content.  A deterministic hash of the
    content, seed and channel makes repeated scans of the same action stable,
    which is important because approval retries rescan the same content.
    """

    name = "simulated"

    def __init__(
        self,
        *,
        recall: float = 1.0,
        fpr: float = 0.0,
        seed: int = 0,
        markers: list[str] | None = None,
    ) -> None:
        self.recall = max(0.0, min(1.0, recall))
        self.fpr = max(0.0, min(1.0, fpr))
        self.seed = seed
        self.base = InjectionDetector()
        self.markers = [_normalize(marker) for marker in (markers or DEFAULT_INJECTIONS)]

    def _uniform(self, text: str, channel: str) -> float:
        digest = hashlib.sha256(f"{self.seed}|{channel}|{text}".encode("utf-8")).digest()
        return int.from_bytes(digest[:8], "big") / float(2**64)

    def _hit(self, label: str, excerpt: str) -> DetectorResult:
        return DetectorResult(
            score=0.90,
            matches=[DetectorMatch(label=label, weight=0.90, excerpt=excerpt[:180])],
        )

    def scan(self, text: str) -> DetectorResult:
        if not text:
            return DetectorResult(0.0)
        normalized = _normalize(text)
        injection = any(marker and marker in normalized for marker in self.markers)
        if injection:
            if self._uniform(text, "recall") < self.recall:
                return self._hit("simulated_injection", text)
            return DetectorResult(0.0)
        if self.fpr and self._uniform(text, "fpr") < self.fpr:
            return self._hit("simulated_false_positive", text)
        return self.base.scan(text)


def detector_factory(recall: float, fpr: float = 0.0):
    def make(scenario: Any, seed: int, repeat: int) -> SimulatedDetector:
        scenario_hash = int.from_bytes(
            hashlib.sha256(scenario.id.encode("utf-8")).digest()[:4], "big"
        )
        return SimulatedDetector(
            recall=recall,
            fpr=fpr,
            seed=seed * 1_000_003 + repeat * 97 + scenario_hash % 10_000,
        )

    return make
