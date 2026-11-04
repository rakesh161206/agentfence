"""Data-loss-prevention and sensitivity labelling.

The DLP layer is deliberately multi-representation: attackers routinely
base64, percent-encode or hex-encode a secret, so every outgoing string is
scanned raw and after bounded decoding.  Cross-call reassembly lives in the
gateway service; this module handles single-string evidence.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from .encoding import decode_layers
from .models import Sensitivity


@dataclass(frozen=True)
class DLPHit:
    kind: str
    value: str
    layer: str = "raw"


@dataclass
class DLPResult:
    sensitivity: Sensitivity = Sensitivity.PUBLIC
    hits: list[DLPHit] = field(default_factory=list)
    decoded: list[tuple[str, str]] = field(default_factory=list)

    @property
    def is_confidential(self) -> bool:
        return self.sensitivity is Sensitivity.CONFIDENTIAL

    @property
    def labels(self) -> list[str]:
        return sorted({hit.kind for hit in self.hits})


_SECRET_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("openai_key", re.compile(r"\bsk-(?:live|test|proj)-[A-Za-z0-9_-]{8,}\b")),
    ("aws_key", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
    ("github_token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{20,}\b")),
    ("slack_token", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b")),
    ("private_key", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----")),
    ("jwt", re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b")),
    ("password_assignment", re.compile(r"(?i)\b(?:password|passwd|secret|api[_-]?key|token)\s*[:=]\s*[^\s]{6,}")),
]

_PII_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("email", re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")),
    ("ssn", re.compile(r"\b\d{3}-\d{2}-\d{4}\b")),
    ("phone", re.compile(r"\b(?:\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b")),
]


def normalize_for_match(text: str) -> str:
    return re.sub(r"[^a-z0-9]", "", text.lower())


class DLP:
    def __init__(self, canaries: list[str] | None = None) -> None:
        self.canaries = [c for c in (canaries or []) if c]
        self._normalized_canaries = [normalize_for_match(c) for c in self.canaries]

    def scan(self, text: str, baseline: Sensitivity = Sensitivity.PUBLIC) -> DLPResult:
        if not text:
            return DLPResult(sensitivity=baseline)

        result = DLPResult(sensitivity=baseline)
        normalized = normalize_for_match(text)

        for canary, norm in zip(self.canaries, self._normalized_canaries, strict=False):
            if norm and norm in normalized:
                result.hits.append(DLPHit(kind="canary", value=canary, layer="raw"))
                result.sensitivity = Sensitivity.CONFIDENTIAL

        for kind, pattern in _SECRET_PATTERNS:
            for match in pattern.finditer(text):
                result.hits.append(DLPHit(kind=kind, value=match.group(0)[:80], layer="raw"))
                result.sensitivity = Sensitivity.CONFIDENTIAL

        for layer, decoded in decode_layers(text, max_depth=2):
            decoded_norm = normalize_for_match(decoded)
            matched = False
            for canary, norm in zip(self.canaries, self._normalized_canaries, strict=False):
                if norm and norm in decoded_norm:
                    result.hits.append(DLPHit(kind="canary", value=canary, layer=layer))
                    result.sensitivity = Sensitivity.CONFIDENTIAL
                    matched = True
            for kind, pattern in _SECRET_PATTERNS:
                for match in pattern.finditer(decoded):
                    result.hits.append(DLPHit(kind=kind, value=match.group(0)[:80], layer=layer))
                    result.sensitivity = Sensitivity.CONFIDENTIAL
                    matched = True
            if matched:
                result.decoded.append((layer, decoded))

        if result.sensitivity is Sensitivity.PUBLIC:
            for kind, pattern in _PII_PATTERNS:
                if pattern.search(text):
                    result.hits.append(DLPHit(kind=kind, value="[redacted]"))
                    result.sensitivity = Sensitivity.INTERNAL
                    break

        return result

    def contains_secret(self, text: str) -> bool:
        return self.scan(text).is_confidential

    def decoded_preview(self, text: str, limit: int = 4000) -> str:
        """Human-readable decoded content for an approval preview."""
        chunks: list[str] = []
        for layer, decoded in decode_layers(text, max_depth=2):
            if not self.contains_secret(decoded):
                continue
            chunks.append(f"--- decoded via {layer} ---\n{decoded[:limit]}")
        return "\n\n".join(chunks)[: limit * 2]

    def summarize_hits(self, text: str) -> list[str]:
        return [f"{hit.kind} ({hit.layer})" for hit in self.scan(text).hits]
