"""Encoding-aware text utilities used by the detector and DLP scanner."""

from __future__ import annotations

import base64
import binascii
import re
import urllib.parse
from typing import Any

_B64_RE = re.compile(r"[A-Za-z0-9+/]{20,}={0,2}")
_B64URL_RE = re.compile(r"[A-Za-z0-9_-]{24,}")
_HEX_RE = re.compile(r"(?:[0-9a-fA-F]{2}){16,}")
_URL_RE = re.compile(r"(?:%[0-9A-Fa-f]{2}){4,}")


def _printable_ratio(text: str) -> float:
    if not text:
        return 0.0
    good = sum(1 for ch in text if ch.isprintable() or ch in "\n\r\t")
    return good / len(text)


def flatten_text(value: Any, *, include_keys: bool = True) -> str:
    """Flatten nested JSON-ish values into one searchable string."""

    parts: list[str] = []

    def walk(node: Any) -> None:
        if node is None:
            return
        if isinstance(node, str):
            parts.append(node)
        elif isinstance(node, (int, float, bool)):
            parts.append(str(node))
        elif isinstance(node, dict):
            for key, item in node.items():
                if include_keys:
                    parts.append(str(key))
                walk(item)
        elif isinstance(node, (list, tuple, set)):
            for item in node:
                walk(item)
        else:
            parts.append(str(node))

    walk(value)
    return "\n".join(parts)


def decode_layers(text: str, *, max_depth: int = 2) -> list[tuple[str, str]]:
    """Return printable decoded variants of a string.

    Supports base64, base64url, hex and percent-encoding.  Decoding is
    deliberately conservative to keep benign text from exploding into noise.
    """

    found: list[tuple[str, str]] = []
    seen: set[str] = {text}
    frontier: list[tuple[str, str]] = [("raw", text)]

    for _ in range(max_depth):
        next_frontier: list[tuple[str, str]] = []
        for layer, candidate in frontier:
            for encoding, decoded in _decode_once(candidate):
                if decoded in seen or len(decoded) < 8:
                    continue
                seen.add(decoded)
                item = (f"{layer}>{encoding}", decoded)
                found.append(item)
                next_frontier.append(item)
        frontier = next_frontier
        if not frontier:
            break
    return found


def _decode_once(text: str) -> list[tuple[str, str]]:
    out: list[tuple[str, str]] = []

    if _URL_RE.search(text):
        decoded = urllib.parse.unquote(text)
        if decoded != text and _printable_ratio(decoded) > 0.85:
            out.append(("url", decoded))

    for match in _B64_RE.findall(text):
        try:
            raw = base64.b64decode(match, validate=True)
        except (binascii.Error, ValueError):
            continue
        decoded = raw.decode("utf-8", errors="replace")
        if _printable_ratio(decoded) > 0.85 and _contains_wordish(decoded):
            out.append(("base64", decoded))

    for match in _B64URL_RE.findall(text):
        if "=" in match:
            continue
        padded = match + "=" * (-len(match) % 4)
        try:
            raw = base64.urlsafe_b64decode(padded)
        except (binascii.Error, ValueError):
            continue
        decoded = raw.decode("utf-8", errors="replace")
        if _printable_ratio(decoded) > 0.85 and _contains_wordish(decoded):
            out.append(("base64url", decoded))

    for match in _HEX_RE.findall(text):
        try:
            raw = bytes.fromhex(match)
        except ValueError:
            continue
        decoded = raw.decode("utf-8", errors="replace")
        if _printable_ratio(decoded) > 0.85 and _contains_wordish(decoded):
            out.append(("hex", decoded))

    return out


def _contains_wordish(text: str) -> bool:
    return bool(re.search(r"[A-Za-z]{3}", text))


def redact(text: str, *, keep: int = 6) -> str:
    if len(text) <= keep * 2:
        return "***"
    return f"{text[:keep]}...{text[-keep:]}"
