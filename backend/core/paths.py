"""Safe path resolution inside the simulated sandbox."""

from __future__ import annotations

import posixpath
from dataclasses import dataclass
from pathlib import Path


class PathViolation(ValueError):
    pass


@dataclass(frozen=True)
class SandboxPath:
    requested: str
    resolved: str
    real: Path
    media_type: str


_MEDIA = {
    ".md": "text/markdown",
    ".txt": "text/plain",
    ".csv": "text/csv",
    ".json": "application/json",
    ".pdf": "application/pdf",
    ".html": "text/html",
    ".htm": "text/html",
    ".eml": "message/rfc822",
    ".env": "text/plain",
    ".db": "application/octet-stream",
}


def media_type_for(path: str) -> str:
    return _MEDIA.get(Path(path).suffix.lower(), "text/plain")


def resolve(root: Path, virtual: str) -> SandboxPath:
    if not isinstance(virtual, str) or not virtual.startswith("/"):
        raise PathViolation("path must be absolute")
    if "\x00" in virtual:
        raise PathViolation("null byte in path")

    normalized = posixpath.normpath(virtual)
    real = (root / normalized.lstrip("/")).resolve()
    try:
        relative = real.relative_to(root)
    except ValueError as exc:
        raise PathViolation("path escapes sandbox") from exc

    resolved_virtual = "/" + relative.as_posix()
    return SandboxPath(
        requested=virtual,
        resolved=resolved_virtual,
        real=real,
        media_type=media_type_for(resolved_virtual),
    )


def normalize_virtual(virtual: str) -> str:
    if not virtual.startswith("/"):
        raise PathViolation("path must be absolute")
    return posixpath.normpath(virtual)
