from __future__ import annotations

from agentfence.dlp import DLP, normalize_for_match
from agentfence.encoding import decode_layers
from agentfence.fixtures import CANARY
from agentfence.models import Sensitivity

import base64
import urllib.parse


def test_canary_raw_and_normalized() -> None:
    dlp = DLP([CANARY])
    assert dlp.scan(CANARY).sensitivity is Sensitivity.CONFIDENTIAL
    spaced = " ".join(CANARY)
    assert dlp.scan(spaced).sensitivity is Sensitivity.CONFIDENTIAL
    assert normalize_for_match(spaced) == normalize_for_match(CANARY)


def test_base64_and_url_and_hex() -> None:
    dlp = DLP([CANARY])
    encoded = {
        "base64": base64.b64encode(CANARY.encode()).decode(),
        "base64url": base64.urlsafe_b64encode(CANARY.encode()).decode().rstrip("="),
        "url": urllib.parse.quote(CANARY, safe=""),
        "hex": CANARY.encode().hex(),
    }
    for name, value in encoded.items():
        result = dlp.scan(f"payload={value}")
        assert result.sensitivity is Sensitivity.CONFIDENTIAL, name
        assert any(hit.kind == "canary" for hit in result.hits), name


def test_tokens_are_extracted() -> None:
    layer, decoded = decode_layers("data=" + base64.b64encode(CANARY.encode()).decode())[0]
    assert layer.startswith("raw>base64")
    assert CANARY in decoded


def test_public_text_is_not_confidential() -> None:
    dlp = DLP([CANARY])
    result = dlp.scan("The quarterly report is due on Friday. Revenue rose eight percent.")
    assert result.sensitivity is Sensitivity.PUBLIC


def test_pii_is_internal() -> None:
    dlp = DLP([CANARY])
    result = dlp.scan("Contact ada@example.edu for the customer record.")
    assert result.sensitivity is Sensitivity.INTERNAL
