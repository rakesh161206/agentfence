from __future__ import annotations

import httpx
import pytest

from backend.core.config import GatewayConfig, get_mode
from backend.main import create_app


@pytest.mark.asyncio
async def test_gateway_end_to_end(sandbox) -> None:
    config = GatewayConfig(mode=get_mode("B5"), root=sandbox)
    app = create_app(config, root=sandbox, build_fixtures=False)
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        health = await client.get("/healthz")
        assert health.status_code == 200

        task = await client.post(
            "/v1/admin/tasks",
            headers={"X-Admin-Key": config.admin_key},
            json={
                "agent_id": "agent",
                "description": "Read a document",
                "ttl_seconds": 600,
                "capabilities": [{"tool": "file.read", "allow_paths": ["/project/docs/**"]}],
            },
        )
        assert task.status_code == 200
        token = task.json()["token"]

        response = await client.post(
            "/v1/actions",
            headers={"Authorization": f"Bearer {token}"},
            json={"tool": "file.read", "args": {"path": "/project/docs/overview.md"}},
        )
        assert response.status_code == 200
        assert response.json()["decision"] == "ALLOW"

        audit = await client.get("/v1/admin/audit", headers={"X-Admin-Key": config.admin_key})
        assert audit.status_code == 200
        assert audit.json()["verification"]["ok"]

        unauthorized = await client.get("/v1/admin/audit")
        assert unauthorized.status_code == 401


@pytest.mark.asyncio
async def test_gateway_blocks_traversal(sandbox) -> None:
    config = GatewayConfig(mode=get_mode("B5"), root=sandbox)
    app = create_app(config, root=sandbox, build_fixtures=False)
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        task = await client.post(
            "/v1/admin/tasks",
            headers={"X-Admin-Key": config.admin_key},
            json={
                "agent_id": "agent",
                "description": "Read docs",
                "ttl_seconds": 60,
                "capabilities": [{"tool": "file.read", "allow_paths": ["/project/docs/**"]}],
            },
        )
        token = task.json()["token"]
        response = await client.post(
            "/v1/actions",
            headers={"Authorization": f"Bearer {token}"},
            json={"tool": "file.read", "args": {"path": "/project/docs/../data/credentials.env"}},
        )
        body = response.json()
        assert body["decision"] == "BLOCK"
        assert "R2" in [hit["rule_id"] for hit in body["reasons"]]


@pytest.mark.asyncio
async def test_demo_catalogue_and_results_endpoints(sandbox) -> None:
    config = GatewayConfig(mode=get_mode("B5"), root=sandbox)
    app = create_app(config, root=sandbox, build_fixtures=False)
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        unauthorized = await client.get("/v1/admin/demo/scenarios")
        assert unauthorized.status_code == 401

        scenarios = await client.get(
            "/v1/admin/demo/scenarios",
            headers={"X-Admin-Key": config.admin_key},
        )
        assert scenarios.status_code == 200
        body = scenarios.json()
        assert len(body) == 10
        assert {item["id"] for item in body} >= {"a1-injection", "a7-approval"}

        results = await client.get(
            "/v1/admin/results",
            headers={"X-Admin-Key": config.admin_key},
        )
        assert results.status_code == 200
        payload = results.json()
        assert payload["available"] is True
        assert payload["main"]["by_mode"]["B5"]["attack"]["asr"] == pytest.approx(0.0323)
        assert payload["sweep"]["recall"]
        assert payload["deny_all"]["by_mode"]["B5"]


@pytest.mark.asyncio
async def test_demo_run_and_seed_endpoints(sandbox) -> None:
    config = GatewayConfig(mode=get_mode("B5"), root=sandbox)
    app = create_app(config, root=sandbox, build_fixtures=False)
    transport = httpx.ASGITransport(app=app)
    headers = {"X-Admin-Key": config.admin_key}
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        blocked = await client.post(
            "/v1/admin/demo/run",
            headers=headers,
            json={"scenario_id": "a1-injection", "mode": "B5", "approval_policy": "approve"},
        )
        assert blocked.status_code == 200
        body = blocked.json()
        assert body["verdict"] == "blocked"
        assert body["summary"]["audit_ok"] is True

        missing = await client.post(
            "/v1/admin/demo/run",
            headers=headers,
            json={"scenario_id": "nope", "mode": "B5", "approval_policy": "approve"},
        )
        assert missing.status_code == 404

        bad_mode = await client.post(
            "/v1/admin/demo/run",
            headers=headers,
            json={"scenario_id": "a1-injection", "mode": "B99", "approval_policy": "approve"},
        )
        assert bad_mode.status_code == 400

        seeded = await client.post("/v1/admin/demo/seed", headers=headers)
        assert seeded.status_code == 200
        seed_body = seeded.json()
        assert len(seed_body["runs"]) == 5
        assert seed_body["pending_approvals"] >= 1
        assert seed_body["audit_entries"] > 0

        stats = await client.get("/v1/admin/stats", headers=headers)
        assert stats.status_code == 200
        assert stats.json()["approvals_pending"] == seed_body["pending_approvals"]
        assert stats.json()["audit"]["ok"] is True
