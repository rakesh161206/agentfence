"""FastAPI policy enforcement point."""

from __future__ import annotations

import secrets
from pathlib import Path
from typing import Any, Literal

from fastapi import Depends, FastAPI, Header, HTTPException, Query
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field

from .approvals import ApprovalError
from .config import GatewayConfig, get_mode
from .demo import list_scenarios, run_scenario, seed_live
from .fixtures import build_template
from .models import ActionResponse, ApprovalToken, Capability, PendingApproval, TaskResponse, ToolAction
from .results import load_results
from .service import AgentFenceService

STATIC_DIR = Path(__file__).parent / "static"


class CreateTaskRequest(BaseModel):
    agent_id: str = "demo-agent"
    description: str
    capabilities: list[Capability] = Field(default_factory=list)
    ttl_seconds: int = 600


class DenyResponse(BaseModel):
    approval_id: str
    status: str


class DemoRunRequest(BaseModel):
    scenario_id: str
    mode: str = "B5"
    approval_policy: Literal["approve", "deny", "leave"] = "approve"


def create_app(
    config: GatewayConfig,
    *,
    root: Path | None = None,
    build_fixtures: bool = True,
) -> FastAPI:
    root = Path(root or config.root).resolve()
    if build_fixtures:
        build_template(root)
    service = AgentFenceService(config, root=root)

    app = FastAPI(
        title="AgentFence",
        version="0.1.0",
        description="Adaptive, risk-aware runtime security firewall for autonomous agents",
    )
    app.state.service = service
    app.state.config = config

    def require_admin(x_admin_key: str = Header(default="")) -> None:
        if not secrets.compare_digest(x_admin_key, config.admin_key):
            raise HTTPException(status_code=401, detail="invalid admin key")

    def bearer_token(authorization: str = Header(default="")) -> str:
        if not authorization.lower().startswith("bearer "):
            raise HTTPException(status_code=401, detail="missing bearer token")
        return authorization.split(" ", 1)[1].strip()

    @app.get("/healthz")
    def healthz() -> dict[str, Any]:
        return {
            "ok": True,
            "mode": config.mode.name,
            "enforcement": config.mode.enforcement,
            "audit": service.audit.verify(),
        }

    @app.post("/v1/admin/tasks", response_model=TaskResponse)
    def create_task(payload: CreateTaskRequest, _: None = Depends(require_admin)) -> TaskResponse:
        grant, token = service.create_task(
            agent_id=payload.agent_id,
            description=payload.description,
            capabilities=payload.capabilities,
            ttl_seconds=payload.ttl_seconds,
        )
        return TaskResponse(
            task_id=grant.task_id,
            agent_id=grant.agent_id,
            token=token,
            expires_at=grant.expires_at,
        )

    @app.get("/v1/admin/tasks/{task_id}")
    def get_task(task_id: str, _: None = Depends(require_admin)) -> dict[str, Any]:
        grant = service.capabilities.get(task_id)
        if grant is None:
            raise HTTPException(status_code=404, detail="unknown task")
        return grant.model_dump(mode="json")

    @app.post("/v1/actions", response_model=ActionResponse)
    def submit_action(
        action: ToolAction,
        token: str = Depends(bearer_token),
    ) -> ActionResponse:
        return service.submit(token=token, action=action, approval_token=action.approval_token)

    @app.get("/v1/admin/approvals", response_model=list[PendingApproval])
    def list_approvals(
        status: str | None = Query(default=None),
        _: None = Depends(require_admin),
    ) -> list[PendingApproval]:
        return service.list_approvals(status)

    @app.get("/v1/admin/approvals/{approval_id}", response_model=PendingApproval)
    def get_approval(approval_id: str, _: None = Depends(require_admin)) -> PendingApproval:
        try:
            return service.approvals.get(approval_id)
        except ApprovalError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc

    @app.post("/v1/admin/approvals/{approval_id}/approve", response_model=ApprovalToken)
    def approve(approval_id: str, _: None = Depends(require_admin)) -> ApprovalToken:
        try:
            return service.approve(approval_id)
        except ApprovalError as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc

    @app.post("/v1/admin/approvals/{approval_id}/deny", response_model=DenyResponse)
    def deny(approval_id: str, _: None = Depends(require_admin)) -> DenyResponse:
        try:
            approval = service.deny(approval_id)
        except ApprovalError as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc
        return DenyResponse(approval_id=approval.approval_id, status=approval.status)

    @app.get("/v1/admin/audit")
    def audit(
        limit: int = Query(default=100, ge=1, le=1000),
        _: None = Depends(require_admin),
    ) -> dict[str, Any]:
        entries = service.audit.recent(limit)
        return {
            "entries": [entry.model_dump(mode="json") for entry in entries],
            "verification": service.audit.verify(),
        }

    @app.get("/v1/admin/audit/verify")
    def verify_audit(_: None = Depends(require_admin)) -> dict[str, Any]:
        return service.audit.verify()

    @app.get("/v1/admin/effects")
    def effects(
        task_id: str | None = Query(default=None),
        _: None = Depends(require_admin),
    ) -> list[dict[str, Any]]:
        return [
            {
                "effect_id": effect.effect_id,
                "task_id": effect.task_id,
                "tool": effect.tool,
                "destination": effect.destination,
                "source": effect.source,
                "bytes_out": effect.bytes_out,
                "content_hash": effect.content_hash,
                "metadata": effect.metadata,
                "timestamp": effect.timestamp.isoformat(),
                "delivered": effect.delivered,
            }
            for effect in service.list_effects(task_id)
        ]

    @app.get("/v1/admin/stats")
    def stats(_: None = Depends(require_admin)) -> dict[str, Any]:
        entries = service.audit.entries
        return {
            "mode": config.mode.name,
            "decisions": {
                "block": sum(1 for entry in entries if entry.decision == "BLOCK"),
                "allow": sum(1 for entry in entries if entry.decision == "ALLOW" and entry.executed),
                "approval_required": sum(
                    1 for entry in entries if entry.decision == "REQUIRE_APPROVAL"
                ),
            },
            "approvals_pending": len(service.list_approvals("pending")),
            "effects": len(service.list_effects()),
            "audit": service.audit.verify(),
        }

    # -------------------------------------------------------------------- demo
    @app.get("/v1/admin/demo/scenarios")
    def demo_scenarios(_: None = Depends(require_admin)) -> list[dict[str, Any]]:
        return list_scenarios()

    @app.post("/v1/admin/demo/run")
    def demo_run(payload: DemoRunRequest, _: None = Depends(require_admin)) -> dict[str, Any]:
        try:
            return run_scenario(
                payload.scenario_id,
                mode=payload.mode,
                approval_policy=payload.approval_policy,
            )
        except KeyError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        except Exception as exc:  # noqa: BLE001 - keep the dashboard responsive
            raise HTTPException(status_code=500, detail=f"demo failed: {exc}") from exc

    @app.post("/v1/admin/demo/seed")
    def demo_seed(_: None = Depends(require_admin)) -> dict[str, Any]:
        try:
            return seed_live(service)
        except Exception as exc:  # noqa: BLE001
            raise HTTPException(status_code=500, detail=f"seed failed: {exc}") from exc

    @app.get("/v1/admin/results")
    def experiment_results(_: None = Depends(require_admin)) -> dict[str, Any]:
        return load_results()

    # ---------------------------------------------------------------- dashboard
    @app.get("/", include_in_schema=False)
    def dashboard() -> FileResponse:
        return FileResponse(STATIC_DIR / "index.html")

    @app.get("/static/{filename}", include_in_schema=False)
    def static_file(filename: str) -> FileResponse:
        candidate = (STATIC_DIR / filename).resolve()
        if not candidate.is_relative_to(STATIC_DIR.resolve()) or not candidate.is_file():
            raise HTTPException(status_code=404, detail="not found")
        return FileResponse(candidate)

    return app


def app_from_env() -> FastAPI:
    import os

    mode = os.environ.get("AGENTFENCE_MODE", "B5")
    root = Path(os.environ.get("AGENTFENCE_ROOT", "./runtime"))
    config = GatewayConfig(
        mode=get_mode(mode),
        root=root,
        secret=os.environ.get("AGENTFENCE_SECRET", "agentfence-dev-secret-change-me"),
        admin_key=os.environ.get("AGENTFENCE_ADMIN_KEY", "agentfence-admin-key"),
    )
    return create_app(config)
