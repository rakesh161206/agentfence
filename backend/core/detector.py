"""Prompt-injection detector.

This is a deterministic, dependency-free baseline.  It is intentionally
imperfect: the evaluation includes paraphrased payloads that it does not
detect, which is precisely why AgentFence does not rely on it for
authorisation decisions.  A production deployment can replace it with a
trained classifier behind the same ``scan`` interface.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from .encoding import decode_layers


@dataclass(frozen=True)
class DetectorMatch:
    label: str
    weight: float
    excerpt: str


@dataclass
class DetectorResult:
    score: float
    matches: list[DetectorMatch] = field(default_factory=list)

    @property
    def labels(self) -> list[str]:
        return sorted({m.label for m in self.matches})


_PATTERNS: list[tuple[str, str, float]] = [
    (
        "override",
        r"\b(ignore|disregard|forget|override)\b.{0,40}\b(previous|prior|above|earlier|system|developer)\b.{0,30}\b(instruction|prompt|message|rule|direction)s?\b",
        0.88,
    ),
    (
        "new_instructions",
        r"\b(new|updated|real|hidden)\s+(instruction|task|system prompt|directive)s?\b",
        0.55,
    ),
    (
        "role_hijack",
        r"\b(you are now|from now on you|act as|pretend to be)\b.{0,40}\b(admin|system|developer|unrestricted|root)\b",
        0.65,
    ),
    (
        "exfiltrate",
        r"\b(send|upload|forward|email|post|transmit|exfiltrate|leak|share)\b.{0,60}\b(all|every|the|this|these|any)\b.{0,40}\b(file|files|data|document|documents|secret|secrets|credential|credentials|key|keys|folder|database|records)\b",
        0.62,
    ),
    (
        "send_to_address",
        r"\b(send|upload|forward|email|post|transmit)\b.{0,50}\b(to|at)\b.{0,20}[\w.+-]+@[\w.-]+\.[A-Za-z]{2,}",
        0.45,
    ),
    (
        "send_to_url",
        r"\b(send|upload|forward|post|transmit)\b.{0,50}https?://",
        0.45,
    ),
    (
        "secrecy",
        r"\b(do not|don't|without)\b.{0,30}\b(tell|notify|inform|ask|alert|mention)\b.{0,20}\b(user|human|owner|anyone)\b",
        0.58,
    ),
    (
        "destructive",
        r"\b(delete|remove|erase|wipe|destroy)\b.{0,30}\b(all|every|the)\b.{0,30}\b(file|files|data|logs|records|database)\b",
        0.65,
    ),
    (
        "chained_tools",
        r"\b(first|then|after that|before you)\b.{0,60}\b(read|open|fetch|retrieve)\b.{0,60}\b(then|and)\b.{0,40}\b(send|email|post|upload)\b",
        0.50,
    ),
    (
        "encoded_payload",
        r"\b(base64|rot13|url.?encode|hex.?encode|obfuscat|encode)\b",
        0.40,
    ),
    (
        "fake_tags",
        r"<\s*(system|assistant|tool|developer|admin)\s*>",
        0.55,
    ),
    (
        "authority",
        r"\b(compliance|security|legal|it)\s+(team|department|officer)\b.{0,50}\b(require|instruct|demand|order)s?\b",
        0.32,
    ),
    (
        "urgency",
        r"\b(urgent|immediately|right away|asap|without delay)\b.{0,40}\b(send|upload|forward|delete|transfer|email)\b",
        0.35,
    ),
    (
        "credential_words",
        r"\b(api[_ -]?key|password|passwd|access[_ -]?token|private[_ -]?key|credential)s?\b",
        0.22,
    ),
    (
        "system_prompt",
        r"\b(system prompt|developer message|hidden prompt|internal instruction)s?\b",
        0.40,
    ),
    (
        "tool_syntax",
        r"\b(tool_call|function_call|assistant to=|recipient=)\b",
        0.45,
    ),
]

_COMPILED = [(label, re.compile(pattern, re.IGNORECASE | re.DOTALL), weight) for label, pattern, weight in _PATTERNS]


class InjectionDetector:
    name = "heuristic-v1"

    def scan(self, text: str) -> DetectorResult:
        if not text:
            return DetectorResult(0.0)

        matches: list[DetectorMatch] = []
        for label, pattern, weight in _COMPILED:
            match = pattern.search(text)
            if match:
                excerpt = text[max(0, match.start() - 20) : match.end() + 40].replace("\n", " ")
                matches.append(DetectorMatch(label=label, weight=weight, excerpt=excerpt[:180]))

        # Encoded instruction channels: scan decoded variants, discounting the
        # score slightly because decoding increases false-positive risk.
        for layer, decoded in decode_layers(text, max_depth=2):
            for label, pattern, weight in _COMPILED:
                match = pattern.search(decoded)
                if match and not any(m.label == label for m in matches):
                    matches.append(
                        DetectorMatch(
                            label=f"decoded:{label}",
                            weight=weight * 0.85,
                            excerpt=f"[{layer}] " + match.group(0)[:160],
                        )
                    )

        score = 1.0
        for item in matches:
            score *= 1.0 - item.weight
        score = min(1.0, 1.0 - score)
        return DetectorResult(score=round(score, 4), matches=matches)


DEFAULT_DETECTOR = InjectionDetector()
