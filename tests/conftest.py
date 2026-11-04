from __future__ import annotations

import shutil
from pathlib import Path

import pytest

from agentfence.config import GatewayConfig, get_mode
from agentfence.fixtures import build_template
from agentfence.models import Capability
from agentfence.service import AgentFenceService


@pytest.fixture(scope="session")
def template_root(tmp_path_factory: pytest.TempPathFactory) -> Path:
    path = tmp_path_factory.mktemp("agentfence-template")
    build_template(path)
    return path


@pytest.fixture()
def sandbox(tmp_path: Path, template_root: Path) -> Path:
    root = tmp_path / "runtime"
    shutil.copytree(template_root, root, symlinks=True)
    return root


def make_service(root: Path, mode: str = "B5") -> AgentFenceService:
    config = GatewayConfig(mode=get_mode(mode), root=root)
    return AgentFenceService(config, root=root)


def basic_capabilities() -> list[Capability]:
    return [
        Capability(tool="file.read", allow_paths=["/project/**"]),
        Capability(tool="file.write", allow_paths=["/project/out/**"], allow_write=True),
        Capability(tool="email.send", allow_domains=["myuni.edu"], rate_per_minute=30, max_calls=60),
        Capability(tool="http.post", allow_domains=["api.myuni.edu"], rate_per_minute=30, max_calls=60),
        Capability(tool="http.get", allow_domains=["api.myuni.edu"]),
        Capability(tool="db.query", allow_tables=["customers", "orders"]),
        Capability(tool="data.derive"),
    ]


@pytest.fixture()
def service(sandbox: Path) -> AgentFenceService:
    return make_service(sandbox)
