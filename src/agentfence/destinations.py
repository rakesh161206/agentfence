"""Destination parsing, allow-list matching and DB table extraction."""

from __future__ import annotations

import ipaddress
import posixpath
import re
import urllib.parse
from dataclasses import dataclass, field

from .models import Destination

EMAIL_RE = re.compile(r"^[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}$")


@dataclass
class DestInfo:
    kind: str = "none"
    value: str = ""
    host: str = ""
    recipients: list[str] = field(default_factory=list)
    allowed: bool = True
    trusted: bool = False
    reason: str = ""

    def to_model(self) -> Destination:
        return Destination(
            kind=self.kind,  # type: ignore[arg-type]
            value=self.value,
            host=self.host,
            recipients=self.recipients,
            allowed=self.allowed,
            trusted=self.trusted,
            reason=self.reason,
        )


def host_matches(host: str, patterns: list[str]) -> bool:
    host = host.lower().strip(".")
    for pattern in patterns:
        pattern = pattern.lower().strip().strip(".")
        if not pattern:
            continue
        if pattern.startswith("*."):
            suffix = pattern[2:]
            if host.endswith("." + suffix) or host == suffix:
                return True
        elif host == pattern:
            return True
    return False


def is_private_host(host: str) -> bool:
    lowered = host.lower().strip(".")
    if lowered in {"localhost", "localhost.localdomain"} or lowered.endswith((".local", ".internal")):
        return True
    try:
        address = ipaddress.ip_address(lowered)
    except ValueError:
        return False
    return address.is_private or address.is_loopback or address.is_link_local or address.is_reserved


def http_destination(url: str, allow_domains: list[str] | None = None) -> DestInfo:
    try:
        parsed = urllib.parse.urlsplit(url)
    except ValueError as exc:
        return DestInfo(kind="http", value=url, allowed=False, reason=f"invalid URL: {exc}")

    host = (parsed.hostname or "").lower().strip(".")
    if parsed.scheme != "https":
        return DestInfo(kind="http", value=url, host=host, allowed=False, reason="HTTPS required")
    if not host:
        return DestInfo(kind="http", value=url, allowed=False, reason="missing host")
    if parsed.username or parsed.password:
        return DestInfo(kind="http", value=url, host=host, allowed=False, reason="userinfo not allowed")
    if is_private_host(host):
        return DestInfo(kind="http", value=url, host=host, allowed=False, reason="private address")
    try:
        port = parsed.port
    except ValueError:
        return DestInfo(kind="http", value=url, host=host, allowed=False, reason="invalid port")
    if port not in (None, 443):
        return DestInfo(kind="http", value=url, host=host, allowed=False, reason="non-standard port")

    patterns = allow_domains or []
    allowed = host_matches(host, patterns)
    return DestInfo(
        kind="http",
        value=url,
        host=host,
        allowed=allowed,
        trusted=allowed,
        reason="host allow-listed" if allowed else "host not allow-listed",
    )


def normalize_email(value: str) -> str | None:
    candidate = value.strip()
    if "<" in candidate and candidate.endswith(">"):
        candidate = candidate.rsplit("<", 1)[1].rstrip(">").strip()
    if not EMAIL_RE.match(candidate):
        return None
    return candidate.lower()


def email_destination(recipients: list[str], allow_domains: list[str] | None = None) -> DestInfo:
    normalized: list[str] = []
    for recipient in recipients:
        parsed = normalize_email(str(recipient))
        if parsed is None:
            return DestInfo(kind="email", value=",".join(recipients), allowed=False, reason="invalid recipient")
        normalized.append(parsed)

    patterns = allow_domains or []
    domains = [r.split("@", 1)[1] for r in normalized]
    allowed = bool(normalized) and all(host_matches(domain, patterns) for domain in domains)
    return DestInfo(
        kind="email",
        value=",".join(normalized),
        host=domains[0] if len(set(domains)) == 1 else ",".join(sorted(set(domains))),
        recipients=normalized,
        allowed=allowed,
        trusted=allowed,
        reason="recipient domain allow-listed" if allowed else "recipient domain not allow-listed",
    )


def path_destination(path: str) -> DestInfo:
    normalized = posixpath.normpath(path)
    return DestInfo(
        kind="path",
        value=normalized,
        host="",
        allowed=True,
        trusted=False,
        reason="",
    )


def path_allowed(path: str, patterns: list[str]) -> bool:
    normalized = posixpath.normpath(path)
    for pattern in patterns:
        candidate = posixpath.normpath(pattern)
        if candidate.endswith("/**"):
            prefix = candidate[:-3].rstrip("/")
            if normalized == prefix or normalized.startswith(prefix + "/"):
                return True
        elif "*" in candidate:
            import fnmatch

            if fnmatch.fnmatchcase(normalized, candidate):
                return True
        elif normalized == candidate:
            return True
    return False


def sql_tables(sql: str) -> list[str]:
    return sorted(set(re.findall(r"\b(?:from|join)\s+([A-Za-z_][A-Za-z0-9_]*)", sql, re.IGNORECASE)))


KNOWN_GOOD_DOMAINS = {"myuni.edu", "api.myuni.edu", "partner.example"}
