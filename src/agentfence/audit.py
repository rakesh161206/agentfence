"""Tamper-evident audit log.

Each entry commits to the previous entry's hash and is authenticated with
HMAC-SHA256.  A hash chain alone detects edits; the HMAC also prevents an
attacker who can write the log file from recomputing a valid chain without the
gateway's key.
"""

from __future__ import annotations

import json
import threading
from datetime import datetime
from pathlib import Path
from typing import Any

from .canonical import canonical_json, constant_time_equal, hmac_sha256_hex, sha256_hex
from .models import AuditEntry, utcnow

GENESIS = "0" * 64


class AuditLog:
    def __init__(self, secret: str, path: Path | None = None) -> None:
        self.secret = secret
        self.path = path
        self.entries: list[AuditEntry] = []
        self._lock = threading.Lock()
        if self.path is not None:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            if not self.path.exists():
                self.path.touch()

    def append(self, **fields: Any) -> AuditEntry:
        with self._lock:
            previous = self.entries[-1].hash if self.entries else GENESIS
            entry = AuditEntry(
                seq=len(self.entries) + 1,
                timestamp=fields.pop("timestamp", utcnow()),
                prev_hash=previous,
                **fields,
            )
            payload = canonical_json(entry.model_dump(mode="json", exclude={"hash", "hmac"}))
            entry.hash = sha256_hex(payload)
            entry.hmac = hmac_sha256_hex(self.secret, entry.hash)
            self.entries.append(entry)
            if self.path is not None:
                with self.path.open("a", encoding="utf-8") as handle:
                    handle.write(entry.model_dump_json() + "\n")
            return entry

    def verify(self) -> dict[str, Any]:
        with self._lock:
            previous = GENESIS
            for index, entry in enumerate(self.entries, start=1):
                if entry.seq != index:
                    return {"ok": False, "error": f"sequence mismatch at entry {index}", "checked": index}
                if entry.prev_hash != previous:
                    return {"ok": False, "error": f"broken link at entry {index}", "checked": index}
                payload = canonical_json(entry.model_dump(mode="json", exclude={"hash", "hmac"}))
                expected_hash = sha256_hex(payload)
                if not constant_time_equal(entry.hash, expected_hash):
                    return {"ok": False, "error": f"hash mismatch at entry {index}", "checked": index}
                expected_hmac = hmac_sha256_hex(self.secret, entry.hash)
                if not constant_time_equal(entry.hmac, expected_hmac):
                    return {"ok": False, "error": f"hmac mismatch at entry {index}", "checked": index}
                previous = entry.hash
            return {"ok": True, "entries": len(self.entries), "head": previous}

    def recent(self, limit: int = 100) -> list[AuditEntry]:
        return self.entries[-limit:]

    def export_jsonl(self, path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("w", encoding="utf-8") as handle:
            for entry in self.entries:
                handle.write(entry.model_dump_json() + "\n")

    @staticmethod
    def load_jsonl(path: Path, secret: str) -> AuditLog:
        log = AuditLog(secret)
        for line in path.read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            log.entries.append(AuditEntry.model_validate(json.loads(line)))
        return log
