"""Canonical serialisation and hashing helpers.

Every security-relevant binding in AgentFence (capability tokens, approval
tokens, action hashes, audit entries) is computed over a canonical JSON
encoding so that two components cannot disagree about what was signed.
"""

from __future__ import annotations

import hashlib
import hmac
import json
from typing import Any


def canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=str)


def sha256_hex(value: str | bytes) -> str:
    data = value.encode("utf-8") if isinstance(value, str) else value
    return hashlib.sha256(data).hexdigest()


def hmac_sha256_hex(secret: str | bytes, value: str | bytes) -> str:
    key = secret.encode("utf-8") if isinstance(secret, str) else secret
    data = value.encode("utf-8") if isinstance(value, str) else value
    return hmac.new(key, data, hashlib.sha256).hexdigest()


def constant_time_equal(a: str, b: str) -> bool:
    return hmac.compare_digest(a.encode("utf-8"), b.encode("utf-8"))
