"""Gateway orchestration: authentication, policy, approval, execution, audit."""

from __future__ import annotations

import json
import time
from datetime import timedelta
from pathlib import Path
from typing import Any

from .approvals import ApprovalError, ApprovalStore
from .audit import AuditLog
from .canonical import canonical_json, sha256_hex
from .capabilities import CapabilityError, CapabilityManager
from .config import GatewayConfig, ModeConfig
from .destinations import (
    KNOWN_GOOD_DOMAINS,
    DestInfo,
    email_destination,
    http_destination,
    path_destination,
    sql_tables,
)
from .detector import InjectionDetector
from .dlp import DLP
from .encoding import flatten_text
from .models import (
    ActionResponse,
    Capability,
    DataLabel,
    Decision,
    HandleRecord,
    PendingApproval,
    Preview,
    RuleHit,
    Sensitivity,
    TaskGrant,
    ToolAction,
    Trust,
    utcnow,
)
from .paths import PathViolation
from .policy import PolicyContext, evaluate
from .provenance import ProvenanceStore, source_policy
from .risk import CallTracker, RiskEngine
from .tools import Effect, ToolRuntime, ToolResult

MAX_ATTACHMENT_BYTES = 2_000_000


class AgentFenceService:
    def __init__(self, config: GatewayConfig, *, root: Path | None = None) -> None:
        self.config = config
        self.mode = config.mode
        self.root = Path(root or config.root).resolve()
        self.dlp = DLP(config.canaries)
        self.detector = InjectionDetector()
        self.capabilities = CapabilityManager(config.secret)
        self.approvals = ApprovalStore(config.secret, config.approval_ttl_seconds)
        self.audit = AuditLog(config.secret, config.audit_path)
        self.provenance = ProvenanceStore(self.dlp)
        self.tools = ToolRuntime(self.root)
        self.tracker = CallTracker()
        self.risk = RiskEngine(self.detector, self.dlp)
        self.egress_history: dict[str, list[str]] = {}
        self.static_grant = self._build_static_grant()
        if self.mode.static_rbac:
            self.capabilities.grants[self.static_grant.task_id] = self.static_grant

    # ------------------------------------------------------------------ tasks
    def _build_static_grant(self) -> TaskGrant:
        caps = [
            Capability(tool="file.read", allow_paths=["/project/**"]),
            Capability(tool="file.write", allow_paths=["/project/out/**"], allow_write=True),
            Capability(tool="email.send", allow_domains=["myuni.edu"]),
            Capability(tool="http.get", allow_domains=["api.myuni.edu", "partner.example"]),
            Capability(tool="http.post", allow_domains=["api.myuni.edu"]),
            Capability(tool="db.query", allow_tables=["customers", "orders"]),
            Capability(tool="data.derive"),
        ]
        return TaskGrant(
            task_id=self.config.static_task_id,
            agent_id="static-role",
            description="Static assistant role",
            capabilities=caps,
            expires_at=utcnow() + timedelta(days=3650),
        )

    def create_task(
        self,
        *,
        agent_id: str,
        description: str,
        capabilities: list[Capability],
        ttl_seconds: int | None = None,
    ) -> tuple[TaskGrant, str]:
        grant, token = self.capabilities.create_task(
            agent_id=agent_id,
            description=description,
            capabilities=capabilities,
            ttl_seconds=ttl_seconds or self.config.default_task_ttl_seconds,
        )
        self.audit.append(
            event="TASK_CREATED",
            task_id=grant.task_id,
            agent_id=agent_id,
            decision="ALLOW",
            reasons=[description],
            result_summary=f"{len(capabilities)} capabilities",
        )
        return grant, token

    # ----------------------------------------------------------------- submit
    def submit(
        self,
        *,
        token: str | None,
        action: ToolAction,
        approval_token: str | None = None,
    ) -> ActionResponse:
        started = time.perf_counter()
        task, capability, auth_ok, auth_reason, _ = self._authenticate(token, action.tool)
        count_call = approval_token is None

        if task is None:
            response = self._blocked(
                started,
                task_id="unknown",
                tool=action.tool,
                action_hash="",
                reasons=[RuleHit(rule_id="R1", decision=Decision.BLOCK, reason=auth_reason)],
            )
            self.audit.append(
                event="ACTION",
                task_id="unknown",
                tool=action.tool,
                decision="BLOCK",
                reasons=[auth_reason],
                executed=False,
            )
            return response

        try:
            prepared = self._prepare(task, capability, action)
        except (PathViolation, KeyError, ValueError, FileNotFoundError, IsADirectoryError) as exc:
            response = self._blocked(
                started,
                task_id=task.task_id,
                tool=action.tool,
                action_hash="",
                reasons=[RuleHit(rule_id="R1", decision=Decision.BLOCK, reason=f"invalid action: {exc}")],
            )
            self.audit.append(
                event="ACTION",
                task_id=task.task_id,
                agent_id=task.agent_id,
                tool=action.tool,
                decision="BLOCK",
                reasons=[f"invalid action: {exc}"],
                executed=False,
            )
            if count_call:
                self.tracker.record(task.task_id, "")
            return response

        action_hash = prepared["action_hash"]
        destination: DestInfo = prepared["destination"]
        labels: list[DataLabel] = prepared["labels"]
        text: str = prepared["text"]
        prompt_score = self.detector.scan(text).score if self.mode.prompt_filter else 0.0

        risk = self.risk.assess(
            task_id=task.task_id,
            tool=action.tool,
            text=text,
            labels=labels,
            destination_trusted=destination.trusted or destination.host in KNOWN_GOOD_DOMAINS,
            destination_allowed=destination.allowed,
            tracker=self.tracker,
            action_hash=action_hash,
            capability_rate=capability.rate_per_minute if capability else None,
            capability_max=capability.max_calls if capability else None,
        ) if self.mode.risk else self._empty_risk()

        cross_call, cross_reason = self._cross_call_leak(
            task.task_id,
            prepared.get("content", "") if action.tool == "http.post" else prepared.get("text", ""),
        )
        ctx = PolicyContext(
            mode=self.mode,
            task=task,
            capability=capability,
            tool=action.tool,
            action_hash=action_hash,
            destination=destination,
            resolved_path=prepared.get("resolved_path"),
            labels=labels,
            risk=risk,
            tracker=self.tracker,
            auth_ok=auth_ok,
            auth_reason=auth_reason,
            prompt_score=prompt_score,
            cross_call_leak=cross_call,
        )
        result = evaluate(ctx)
        if cross_call:
            result.hits.append(
                RuleHit(
                    rule_id="R4b",
                    decision=Decision.BLOCK,
                    reason=cross_reason,
                )
            )
            result.decision = Decision.BLOCK

        preview: Preview | None = None
        if result.decision is Decision.REQUIRE_APPROVAL:
            preview = self._build_preview(task, action, prepared, risk, result.reasons)
            action_hash = preview.action_hash
            # The action hash includes the preview's resolved content, so the
            # context used by the policy is still valid; binding is recomputed
            # deterministically below.
            prepared["action_hash"] = action_hash

        approval_valid = False
        approval_id = ""
        approval_hit: RuleHit | None = None
        if result.decision is Decision.REQUIRE_APPROVAL and approval_token:
            try:
                approval = self.approvals.verify(approval_token, action_hash=action_hash)
                approval_valid = True
                approval_id = approval.approval_id
            except ApprovalError as exc:
                approval_hit = RuleHit(
                    rule_id="R9", decision=Decision.BLOCK, reason=f"approval rejected: {exc}"
                )

        if approval_hit is not None:
            result.hits.append(approval_hit)
            result.decision = Decision.BLOCK

        if result.decision is Decision.BLOCK:
            if count_call:
                self.tracker.record(task.task_id, action_hash)
            self.audit.append(
                event="ACTION",
                task_id=task.task_id,
                agent_id=task.agent_id,
                tool=action.tool,
                action_hash=action_hash,
                decision="BLOCK",
                rule_ids=result.rule_ids,
                reasons=result.reasons,
                risk_score=risk.score,
                executed=False,
                result_summary="blocked before execution",
            )
            return self._blocked(
                started,
                task_id=task.task_id,
                tool=action.tool,
                action_hash=action_hash,
                reasons=result.hits,
                risk=risk,
            )

        if result.decision is Decision.REQUIRE_APPROVAL and not approval_valid:
            preview = preview or self._build_preview(task, action, prepared, risk, result.reasons)
            pending = self.approvals.request(preview)
            if count_call:
                self.tracker.record(task.task_id, action_hash)
            self.audit.append(
                event="APPROVAL_REQUESTED",
                task_id=task.task_id,
                agent_id=task.agent_id,
                tool=action.tool,
                action_hash=action_hash,
                decision="REQUIRE_APPROVAL",
                rule_ids=result.rule_ids,
                reasons=result.reasons,
                risk_score=risk.score,
                preview_hash=preview.preview_hash,
                approval_id=pending.approval_id,
                executed=False,
                result_summary=pending.approval_id,
            )
            return ActionResponse(
                decision=Decision.REQUIRE_APPROVAL,
                executed=False,
                task_id=task.task_id,
                tool=action.tool,
                action_hash=action_hash,
                reasons=result.hits,
                risk=risk,
                pending_approval=pending,
                approval_requested=True,
                latency_ms=(time.perf_counter() - started) * 1000,
                decision_latency_ms=(time.perf_counter() - started) * 1000,
            )

        if approval_valid:
            self.approvals.consume(approval_id)

        decision_latency_ms = (time.perf_counter() - started) * 1000
        try:
            tool_result, handle, labels_out = self._execute(task, action, prepared, labels)
        except Exception as exc:  # noqa: BLE001 - tool failure must not crash the gateway
            if count_call:
                self.tracker.record(task.task_id, action_hash)
            self.audit.append(
                event="ACTION",
                task_id=task.task_id,
                agent_id=task.agent_id,
                tool=action.tool,
                action_hash=action_hash,
                decision="BLOCK",
                rule_ids=["R1"],
                reasons=[f"tool execution failed: {exc}"],
                risk_score=risk.score,
                executed=False,
                result_summary="tool error",
            )
            response = self._blocked(
                started,
                task_id=task.task_id,
                tool=action.tool,
                action_hash=action_hash,
                reasons=[
                    RuleHit(rule_id="R1", decision=Decision.BLOCK, reason=f"tool execution failed: {exc}")
                ],
                risk=risk,
            )
            response.error = str(exc)
            return response

        if count_call:
            self.tracker.record(task.task_id, action_hash)
        if action.tool in {"http.post", "email.send"}:
            payload = prepared.get("content", "") if action.tool == "http.post" else prepared.get("text", "")
            self._remember_egress(task.task_id, payload)

        execution_error = tool_result.metadata.get("error") if tool_result else None

        self.audit.append(
            event="ACTION",
            task_id=task.task_id,
            agent_id=task.agent_id,
            tool=action.tool,
            action_hash=action_hash,
            decision="ALLOW",
            rule_ids=result.rule_ids,
            reasons=result.reasons,
            risk_score=risk.score,
            preview_hash=preview.preview_hash if preview else "",
            approval_id=approval_id,
            executed=True,
            result_summary=tool_result.metadata.get("message_id", "")
            or tool_result.destination
            or tool_result.source,
        )

        return ActionResponse(
            decision=Decision.ALLOW,
            executed=True,
            task_id=task.task_id,
            tool=action.tool,
            action_hash=action_hash,
            reasons=result.hits,
            risk=risk,
            result={
                "content": tool_result.content[: self.config.max_content_chars],
                "source": tool_result.source,
                "destination": tool_result.destination,
                "metadata": tool_result.metadata,
            },
            handle=handle,
            labels=labels_out,
            approval_used=approval_valid,
            latency_ms=(time.perf_counter() - started) * 1000,
            decision_latency_ms=decision_latency_ms,
            effect_id=tool_result.effect_id,
        )

    # ------------------------------------------------------------- preparation
    def _authenticate(
        self, token: str | None, tool: str
    ) -> tuple[TaskGrant | None, Capability | None, bool, str, bool]:
        grant: TaskGrant | None = None
        if self.mode.capability_mode:
            if not token:
                return None, None, False, "missing bearer token", True
            try:
                _, grant = self.capabilities.verify_token(token)
            except CapabilityError as exc:
                return None, None, False, str(exc), True
            if self.mode.static_rbac:
                capability = self.static_grant.capability_for(tool)
            else:
                capability = grant.capability_for(tool)
            return grant, capability, True, "", True

        if token:
            try:
                _, grant = self.capabilities.verify_token(token)
            except CapabilityError:
                grant = None
        if grant is None:
            grant = TaskGrant(
                task_id=f"anon-{sha256_hex(str(time.time_ns()))[:8]}",
                agent_id="anonymous",
                description="unscoped task",
                capabilities=[],
                expires_at=utcnow() + timedelta(seconds=self.config.default_task_ttl_seconds),
            )
        return grant, grant.capability_for(tool), True, "", True

    def _prepare(self, task: TaskGrant, capability: Capability | None, action: ToolAction) -> dict[str, Any]:
        tool = action.tool
        if tool not in {"file.read", "file.write", "http.get", "http.post", "email.send", "db.query", "data.derive"}:
            raise ValueError(f"unsupported tool {tool!r}")

        prepared: dict[str, Any] = {
            "tool": tool,
            "args": action.args,
            "refs": [],
            "attachments": [],
            "content": "",
            "labels": [],
            "text": "",
            "destination": DestInfo(kind="none"),
            "resolved_path": None,
        }

        if tool in {"file.read", "file.write"}:
            path = action.args.get("path")
            if not isinstance(path, str):
                raise ValueError("path is required")
            sandbox_path = self.tools.resolve_path(path)
            prepared["resolved_path"] = sandbox_path.resolved
            prepared["destination"] = path_destination(sandbox_path.resolved)
            prepared["path_requested"] = path

            content = ""
            if tool == "file.read":
                peeked, media_type, _ = self.tools.peek_file(path)
                content = peeked
                prepared["media_type"] = media_type
                policy = source_policy(f"file:{sandbox_path.resolved}", media_type)
                label = self.provenance.label_for_text(
                    content,
                    source=f"file:{sandbox_path.resolved}",
                    base_trust=policy.trust,
                    base_sensitivity=policy.sensitivity,
                )
                prepared["labels"] = [label]
                prepared["text"] = content
                prepared["content"] = content
            else:
                refs = self._resolve_refs(action.args, keys=("content_refs", "refs"))
                content = self._literal(action.args, keys=("content", "text")) + "".join(
                    r.content for r in refs
                )
                prepared["content"] = content
                prepared["refs"] = refs
                labels = [r.label for r in refs]
                literal_label = self.provenance.label_for_text(content, source="tool:literal")
                labels.append(literal_label)
                prepared["labels"] = self._merge_label_list(labels)
                prepared["text"] = content

        elif tool in {"http.get", "http.post"}:
            url = action.args.get("url")
            if not isinstance(url, str):
                raise ValueError("url is required")
            destination = http_destination(
                url, capability.allow_domains if (self.mode.egress_allowlist and capability) else []
            )
            prepared["destination"] = destination
            prepared["url"] = url
            headers = action.args.get("headers") or {}
            if not isinstance(headers, dict):
                raise ValueError("headers must be an object")
            prepared["headers"] = {str(k): str(v) for k, v in headers.items()}
            if tool == "http.get":
                prepared["text"] = url
            else:
                refs = self._resolve_refs(action.args, keys=("body_refs", "refs"))
                body = self._literal(action.args, keys=("body", "json", "text"))
                body = body + "".join(r.content for r in refs)
                prepared["refs"] = refs
                prepared["content"] = body
                prepared["text"] = "\n".join([url, body, flatten_text(headers)])
                labels = [r.label for r in refs]
                labels.append(self.provenance.label_for_text(prepared["text"], source="tool:literal"))
                prepared["labels"] = self._merge_label_list(labels)

        elif tool == "email.send":
            recipients_raw = action.args.get("to") or action.args.get("recipients") or []
            if isinstance(recipients_raw, str):
                recipients_raw = [recipients_raw]
            if not isinstance(recipients_raw, list):
                raise ValueError("to must be a string or list")
            destination = email_destination(
                [str(r) for r in recipients_raw],
                capability.allow_domains if (self.mode.egress_allowlist and capability) else [],
            )
            prepared["destination"] = destination
            prepared["recipients"] = destination.recipients or [str(r) for r in recipients_raw]
            refs = self._resolve_refs(action.args, keys=("body_refs", "refs"))
            body = self._literal(action.args, keys=("body", "text")) + "".join(r.content for r in refs)
            attachments = self._resolve_attachments(action.args.get("attachments") or [])
            prepared["refs"] = refs
            prepared["attachments"] = attachments
            prepared["subject"] = str(action.args.get("subject", ""))
            prepared["content"] = body
            attachment_text = "\n".join(a["content"] for a in attachments)
            prepared["text"] = "\n".join([prepared["subject"], body, attachment_text])
            labels = [r.label for r in refs]
            labels.extend(a["label"] for a in attachments)
            labels.append(self.provenance.label_for_text(prepared["text"], source="tool:literal"))
            prepared["labels"] = self._merge_label_list(labels)

        elif tool == "db.query":
            sql = action.args.get("sql")
            if not isinstance(sql, str):
                raise ValueError("sql is required")
            prepared["sql"] = sql
            tables = sql_tables(sql)
            prepared["tables"] = tables
            prepared["destination"] = DestInfo(
                kind="table",
                value=sql,
                host=",".join(tables),
                allowed=True,
                trusted=False,
                reason="",
            )
            prepared["text"] = sql
            prepared["content"] = sql

        elif tool == "data.derive":
            refs = self._resolve_refs(action.args, keys=("refs", "input_refs"))
            if not refs:
                raise ValueError("at least one data reference is required")
            operation = str(action.args.get("operation", "concat"))
            content = "\n\n".join(r.content for r in refs)
            prepared["refs"] = refs
            prepared["content"] = content
            prepared["operation"] = operation
            prepared["labels"] = self._merge_label_list([r.label for r in refs])
            prepared["text"] = content

        else:  # pragma: no cover - guarded above
            raise ValueError("unsupported tool")

        prepared["action_hash"] = self._action_hash(task, action, prepared)
        return prepared

    def _action_hash(self, task: TaskGrant, action: ToolAction, prepared: dict[str, Any]) -> str:
        refs = prepared.get("refs", [])
        attachments = prepared.get("attachments", [])
        binding = {
            "task_id": task.task_id,
            "tool": action.tool,
            "args": action.args,
            "path": prepared.get("resolved_path"),
            "destination": prepared["destination"].value,
            "content_hash": sha256_hex(prepared.get("content", "")) if prepared.get("content") else "",
            "ref_hashes": [sha256_hex(r.content) for r in refs],
            "attachment_hashes": [
                {"filename": a["filename"], "hash": sha256_hex(a["content"])} for a in attachments
            ],
        }
        return sha256_hex(canonical_json(binding))

    def _build_preview(
        self,
        task: TaskGrant,
        action: ToolAction,
        prepared: dict[str, Any],
        risk: Any,
        reasons: list[str],
    ) -> Preview:
        content = prepared.get("content", "")
        decoded = self.dlp.decoded_preview(prepared.get("text", content)) if self.mode.dlp else ""
        preview = Preview(
            task_id=task.task_id,
            agent_id=task.agent_id,
            task_description=task.description,
            tool=action.tool,
            action_hash=prepared["action_hash"],
            destination=prepared["destination"].to_model(),
            content=content[: self.config.max_content_chars],
            content_preview=content[:2000],
            decoded_preview=decoded[:8000],
            attachments=[
                {
                    "filename": a["filename"],
                    "bytes": len(a["content"].encode("utf-8")),
                    "content_hash": sha256_hex(a["content"]),
                    "content_preview": a["content"][:2000],
                    "labels": a["label"].model_dump(mode="json"),
                }
                for a in prepared.get("attachments", [])
            ],
            labels=[label.model_dump(mode="json") for label in prepared.get("labels", [])],
            bytes_out=len(content.encode("utf-8"))
            + sum(len(a["content"].encode("utf-8")) for a in prepared.get("attachments", [])),
            risk=risk,
            reasons=reasons,
        )
        core = preview.model_dump(mode="json", exclude={"preview_hash"})
        preview.preview_hash = sha256_hex(canonical_json(core))
        return preview

    # ---------------------------------------------------------------- execution
    def _execute(
        self,
        task: TaskGrant,
        action: ToolAction,
        prepared: dict[str, Any],
        labels: list[DataLabel],
    ) -> tuple[ToolResult, str | None, DataLabel | None]:
        tool = action.tool
        context = {"task_id": task.task_id, "tool": tool, "action_hash": prepared["action_hash"]}

        if tool == "file.read":
            result = self.tools.read_file(context, action.args["path"])
            policy = source_policy(result.source, result.media_type)
            record = self.provenance.add(
                result.content,
                source=result.source,
                media_type=result.media_type,
                task_id=task.task_id,
                trust=policy.trust,
                sensitivity=policy.sensitivity,
            )
            return result, record.handle, record.label

        if tool == "file.write":
            content = prepared["content"]
            result = self.tools.write_file(context, action.args["path"], content)
            merged = self._merge_labels(prepared.get("labels", []))
            merged.sources = sorted(set(merged.sources) | {result.source})
            self.provenance.register_label(content, merged)
            return result, None, merged

        if tool == "http.get":
            result = self.tools.http_get(context, action.args["url"])
            record = self.provenance.add(
                result.content,
                source=result.source,
                media_type=result.media_type,
                task_id=task.task_id,
                trust=Trust.UNTRUSTED,
                sensitivity=Sensitivity.PUBLIC,
            )
            return result, record.handle, record.label

        if tool == "http.post":
            result = self.tools.http_post(
                context,
                prepared["url"],
                prepared["content"],
                prepared["headers"],
            )
            return result, None, self._merge_labels(prepared.get("labels", []))

        if tool == "email.send":
            attachments = [
                {"filename": a["filename"], "content": a["content"]} for a in prepared.get("attachments", [])
            ]
            result = self.tools.send_email(
                context,
                prepared["recipients"],
                prepared["subject"],
                prepared["content"],
                attachments,
            )
            return result, None, self._merge_labels(prepared.get("labels", []))

        if tool == "db.query":
            result = self.tools.query_db(context, prepared["sql"])
            tables = prepared.get("tables", [])
            source = f"db:{','.join(tables) or 'unknown'}"
            policy = source_policy(source)
            record = self.provenance.add(
                result.content,
                source=source,
                media_type="application/json",
                task_id=task.task_id,
                trust=policy.trust,
                sensitivity=policy.sensitivity,
            )
            return result, record.handle, record.label

        if tool == "data.derive":
            content = prepared["content"]
            record = self.provenance.add(
                content,
                source="tool:derive",
                media_type="text/plain",
                task_id=task.task_id,
                trust=Trust.UNTRUSTED
                if any(label.trust is Trust.UNTRUSTED for label in prepared.get("labels", []))
                else Trust.TRUSTED,
                sensitivity=max(
                    [label.sensitivity for label in prepared.get("labels", [])],
                    key=lambda item: item.rank,
                    default=Sensitivity.PUBLIC,
                ),
                extra_sources=sorted(
                    {source for label in prepared.get("labels", []) for source in label.sources}
                ),
            )
            result = ToolResult(
                content=content[: self.config.max_content_chars],
                source="tool:derive",
                destination="",
                media_type="text/plain",
                metadata={"operation": prepared.get("operation", "concat"), "bytes": record.label.bytes},
            )
            return result, record.handle, record.label

        raise ValueError(f"unsupported tool {tool!r}")

    # ------------------------------------------------------------------ helpers
    def _resolve_refs(self, args: dict[str, Any], keys: tuple[str, ...]) -> list[HandleRecord]:
        raw: list[Any] = []
        for key in keys:
            value = args.get(key)
            if value is None:
                continue
            if isinstance(value, str):
                raw.append(value)
            elif isinstance(value, list):
                raw.extend(value)
            else:
                raise ValueError(f"{key} must be a handle or list of handles")
        records: list[HandleRecord] = []
        for item in raw:
            if not isinstance(item, str):
                raise ValueError("data handle must be a string")
            records.append(self.provenance.get(item))
        return records

    def _resolve_attachments(self, raw: list[Any]) -> list[dict[str, Any]]:
        attachments: list[dict[str, Any]] = []
        for item in raw:
            if isinstance(item, str):
                handle = self.provenance.get(item)
                filename = Path(handle.label.sources[0].replace("file:", "")).name if handle.label.sources else handle.handle
                attachments.append(
                    {"filename": filename, "content": handle.content, "label": handle.label, "handle": handle.handle}
                )
            elif isinstance(item, dict):
                handle = self.provenance.get(str(item.get("handle", "")))
                filename = str(item.get("filename") or Path(handle.label.sources[0].replace("file:", "")).name)
                attachments.append(
                    {"filename": filename, "content": handle.content, "label": handle.label, "handle": handle.handle}
                )
            else:
                raise ValueError("attachment must be a handle or object")
        total = sum(len(a["content"].encode("utf-8")) for a in attachments)
        if total > MAX_ATTACHMENT_BYTES:
            raise ValueError("attachments exceed size limit")
        return attachments

    def _literal(self, args: dict[str, Any], keys: tuple[str, ...]) -> str:
        for key in keys:
            if key in args and args[key] is not None:
                value = args[key]
                if isinstance(value, (dict, list)):
                    return json.dumps(value, ensure_ascii=False)
                return str(value)
        return ""

    @staticmethod
    def _merge_labels(labels: list[DataLabel]) -> DataLabel:
        if not labels:
            return DataLabel()
        merged = labels[0]
        for label in labels[1:]:
            merged = merged.merged(label)
        return merged

    def _merge_label_list(self, labels: list[DataLabel]) -> list[DataLabel]:
        if not labels:
            return [DataLabel()]
        merged = self._merge_labels(labels)
        return [merged]

    def _cross_call_leak(self, task_id: str, text: str) -> tuple[bool, str]:
        if not self.mode.dlp or not text:
            return False, ""
        history = self.egress_history.get(task_id, [])
        if not history:
            return False, ""
        combined = "\n".join([*history, text])
        if self.dlp.contains_secret(combined) and not self.dlp.contains_secret(text):
            return True, "cross-call reassembly exposed confidential data"
        return False, ""

    def _remember_egress(self, task_id: str, text: str) -> None:
        history = self.egress_history.setdefault(task_id, [])
        history.append(text[:20000])
        del history[: -self.config.max_egress_history]

    def _blocked(
        self,
        started: float,
        *,
        task_id: str,
        tool: str,
        action_hash: str,
        reasons: list[RuleHit],
        risk: Any | None = None,
    ) -> ActionResponse:
        return ActionResponse(
            decision=Decision.BLOCK,
            executed=False,
            task_id=task_id,
            tool=tool,
            action_hash=action_hash,
            reasons=reasons,
            risk=risk or self._empty_risk(),
            latency_ms=(time.perf_counter() - started) * 1000,
            decision_latency_ms=(time.perf_counter() - started) * 1000,
        )

    @staticmethod
    def _empty_risk():
        from .models import RiskBreakdown

        return RiskBreakdown()

    # ------------------------------------------------------------------ access
    def list_effects(self, task_id: str | None = None) -> list[Effect]:
        if task_id is None:
            return list(self.tools.effects)
        return [effect for effect in self.tools.effects if effect.task_id == task_id]

    def list_approvals(self, status: str | None = None) -> list[PendingApproval]:
        return self.approvals.list(status)

    def approve(self, approval_id: str) -> Any:
        token = self.approvals.approve(approval_id)
        approval = self.approvals.get(approval_id)
        self.audit.append(
            event="APPROVAL_APPROVED",
            task_id=approval.task_id,
            tool=approval.preview.tool,
            action_hash=approval.action_hash,
            decision="ALLOW",
            preview_hash=approval.preview.preview_hash,
            approval_id=approval_id,
            result_summary="approved",
        )
        return token

    def deny(self, approval_id: str) -> PendingApproval:
        approval = self.approvals.deny(approval_id)
        self.audit.append(
            event="APPROVAL_DENIED",
            task_id=approval.task_id,
            tool=approval.preview.tool,
            action_hash=approval.action_hash,
            decision="BLOCK",
            preview_hash=approval.preview.preview_hash,
            approval_id=approval_id,
            result_summary="denied",
        )
        return approval
