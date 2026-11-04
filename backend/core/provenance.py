"""Provenance store: labels survive reads, writes, transforms and round-trips.

A handle is an opaque reference to content the gateway has already seen.  The
agent never supplies authoritative labels; it supplies handles, and the
gateway resolves them.  Content hashes act as a second index so that writing
a secret to disk and reading it back does not launder its label.
"""

from __future__ import annotations

import secrets
from dataclasses import dataclass

from .canonical import sha256_hex
from .dlp import DLP
from .models import DataLabel, HandleRecord, Sensitivity, Trust


@dataclass(frozen=True)
class SourcePolicy:
    trust: Trust
    sensitivity: Sensitivity


def source_policy(source: str, media_type: str = "text/plain") -> SourcePolicy:
    if source.startswith("file:"):
        path = source[5:]
        if path.startswith("/project/data/"):
            if path.endswith("quarterly.csv") or path.endswith("customers.db"):
                return SourcePolicy(Trust.TRUSTED, Sensitivity.INTERNAL)
            return SourcePolicy(Trust.TRUSTED, Sensitivity.CONFIDENTIAL)
        if path.startswith("/project/docs/"):
            if media_type in {"application/pdf", "text/html"} or path.endswith((".pdf", ".html", ".htm")):
                return SourcePolicy(Trust.UNTRUSTED, Sensitivity.PUBLIC)
            return SourcePolicy(Trust.TRUSTED, Sensitivity.PUBLIC)
        if path.startswith("/project/inbox/"):
            return SourcePolicy(Trust.UNTRUSTED, Sensitivity.INTERNAL)
        if path.startswith("/project/out/"):
            return SourcePolicy(Trust.TRUSTED, Sensitivity.PUBLIC)
        return SourcePolicy(Trust.TRUSTED, Sensitivity.INTERNAL)

    if source.startswith(("web:", "http:", "https:")):
        return SourcePolicy(Trust.UNTRUSTED, Sensitivity.PUBLIC)
    if source.startswith(("email:", "inbox:")):
        return SourcePolicy(Trust.UNTRUSTED, Sensitivity.INTERNAL)
    if source.startswith("db:"):
        table = source.split(":", 1)[1]
        if "secret" in table or "credential" in table:
            return SourcePolicy(Trust.TRUSTED, Sensitivity.CONFIDENTIAL)
        return SourcePolicy(Trust.TRUSTED, Sensitivity.INTERNAL)
    if source.startswith("tool:"):
        return SourcePolicy(Trust.TRUSTED, Sensitivity.PUBLIC)
    return SourcePolicy(Trust.TRUSTED, Sensitivity.INTERNAL)


class ProvenanceStore:
    def __init__(self, dlp: DLP) -> None:
        self.dlp = dlp
        self.handles: dict[str, HandleRecord] = {}
        self.hash_registry: dict[str, DataLabel] = {}
        self.task_reads: dict[str, list[str]] = {}

    def add(
        self,
        content: str,
        *,
        source: str,
        media_type: str = "text/plain",
        task_id: str = "",
        trust: Trust | None = None,
        sensitivity: Sensitivity | None = None,
        extra_sources: list[str] | None = None,
    ) -> HandleRecord:
        policy = source_policy(source, media_type)
        content_hash = sha256_hex(content)
        dlp_result = self.dlp.scan(content, baseline=sensitivity or policy.sensitivity)

        label = DataLabel(
            trust=trust or policy.trust,
            sensitivity=max(
                [sensitivity or policy.sensitivity, dlp_result.sensitivity],
                key=lambda s: s.rank,
            ),
            taint_sources=[],
            sources=[source, *(extra_sources or [])],
            content_hash=content_hash,
            bytes=len(content.encode("utf-8")),
            media_type=media_type,
        )
        if label.trust is Trust.UNTRUSTED:
            label.taint_sources = sorted(set(label.sources))

        prior = self.hash_registry.get(content_hash)
        if prior is not None:
            label = label.merged(prior)

        handle = f"dh_{secrets.token_hex(6)}"
        record = HandleRecord(handle=handle, content=content, label=label)
        self.handles[handle] = record
        self.hash_registry[content_hash] = label
        if task_id:
            self.task_reads.setdefault(task_id, []).append(handle)
        return record

    def register_label(self, content: str, label: DataLabel) -> DataLabel:
        content_hash = sha256_hex(content)
        prior = self.hash_registry.get(content_hash)
        merged = label.merged(prior) if prior else label
        merged.content_hash = content_hash
        merged.bytes = len(content.encode("utf-8"))
        self.hash_registry[content_hash] = merged
        return merged

    def get(self, handle: str) -> HandleRecord:
        try:
            return self.handles[handle]
        except KeyError as exc:
            raise KeyError(f"unknown data handle {handle!r}") from exc

    def get_many(self, handles: list[str]) -> list[HandleRecord]:
        return [self.get(h) for h in handles]

    def label_for_text(
        self,
        text: str,
        *,
        source: str = "tool:literal",
        base_trust: Trust = Trust.TRUSTED,
        base_sensitivity: Sensitivity = Sensitivity.PUBLIC,
    ) -> DataLabel:
        content_hash = sha256_hex(text)
        dlp_result = self.dlp.scan(text, baseline=base_sensitivity)
        label = DataLabel(
            trust=base_trust,
            sensitivity=max([base_sensitivity, dlp_result.sensitivity], key=lambda s: s.rank),
            taint_sources=[source] if base_trust is Trust.UNTRUSTED else [],
            sources=[source],
            content_hash=content_hash,
            bytes=len(text.encode("utf-8")),
        )
        prior = self.hash_registry.get(content_hash)
        return label.merged(prior) if prior else label

    def task_handles(self, task_id: str) -> list[HandleRecord]:
        return [self.handles[h] for h in self.task_reads.get(task_id, []) if h in self.handles]

    def session_confidential(self, task_id: str) -> bool:
        return any(h.label.sensitivity is Sensitivity.CONFIDENTIAL for h in self.task_handles(task_id))
