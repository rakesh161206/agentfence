"""Experiment configurations and gateway settings.

Modes B0--B5 are the comparison points in the paper.  The two ablation modes
(B4T, B4TR) isolate provenance and risk scoring on top of task-scoped
capabilities.  A mode is a declarative feature set; the policy engine never
branches on the mode name.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path


@dataclass(frozen=True)
class ModeConfig:
    name: str
    enforcement: bool = True
    capabilities: bool = False
    expiry: bool = False
    path_scope: bool = False
    egress_allowlist: bool = False
    static_rbac: bool = False
    prompt_filter: bool = False
    taint: bool = False
    dlp: bool = False
    risk: bool = False
    risk_action: str = "approve"  # "approve" | "block"
    approvals: bool = False
    rate_limit: bool = False
    audit: bool = True
    detector_threshold: float = 0.5
    risk_threshold: float = 0.70
    risk_block_threshold: float = 0.65
    description: str = ""

    @property
    def capability_mode(self) -> bool:
        return self.capabilities or self.static_rbac

    @property
    def blocks_instead_of_approval(self) -> bool:
        return not self.approvals


MODES: dict[str, ModeConfig] = {
    "B0": ModeConfig(
        name="B0",
        enforcement=False,
        description="No protection: every tool call is executed.",
    ),
    "B1": ModeConfig(
        name="B1",
        prompt_filter=True,
        description="Prompt-injection filter only; no capability or data controls.",
    ),
    "B2": ModeConfig(
        name="B2",
        static_rbac=True,
        path_scope=True,
        egress_allowlist=True,
        description="Static role-based permissions; one broad role for every task.",
    ),
    "B3": ModeConfig(
        name="B3",
        risk=True,
        risk_action="block",
        description="Adaptive risk scoring only; blocks at a tuned threshold.",
    ),
    "B4": ModeConfig(
        name="B4",
        capabilities=True,
        expiry=True,
        path_scope=True,
        egress_allowlist=True,
        rate_limit=True,
        description="Task-scoped, expiring capabilities with egress and rate limits.",
    ),
    "B5": ModeConfig(
        name="B5",
        capabilities=True,
        expiry=True,
        path_scope=True,
        egress_allowlist=True,
        prompt_filter=False,
        taint=True,
        dlp=True,
        risk=True,
        risk_action="approve",
        approvals=True,
        rate_limit=True,
        audit=True,
        description="Full AgentFence: deterministic policy + taint + risk escalation + approvals.",
    ),
    "B4T": ModeConfig(
        name="B4T",
        capabilities=True,
        expiry=True,
        path_scope=True,
        egress_allowlist=True,
        taint=True,
        dlp=True,
        rate_limit=True,
        description="Capabilities + provenance/DLP (no risk scoring, no approvals).",
    ),
    "B4TR": ModeConfig(
        name="B4TR",
        capabilities=True,
        expiry=True,
        path_scope=True,
        egress_allowlist=True,
        taint=True,
        dlp=True,
        risk=True,
        risk_action="block",
        approvals=False,
        rate_limit=True,
        description="Capabilities + provenance + risk scoring (no approval channel).",
    ),
}

BASELINE_MODES = ["B0", "B1", "B2", "B3", "B4", "B5"]
ABLATION_MODES = ["B4", "B4T", "B4TR", "B5"]


@dataclass
class GatewayConfig:
    mode: ModeConfig
    root: Path
    secret: str = "agentfence-dev-secret-change-me"
    admin_key: str = "agentfence-admin-key"
    canaries: list[str] = field(default_factory=list)
    approval_ttl_seconds: int = 900
    default_task_ttl_seconds: int = 600
    egress_window_seconds: int = 120
    max_egress_history: int = 12
    max_content_chars: int = 200_000
    audit_path: Path | None = None
    static_task_id: str = "static-role"

    def __post_init__(self) -> None:
        self.root = Path(self.root).resolve()
        if not self.canaries:
            self.canaries = ["sk-live-CANARY-9f3a2b7c4d5e"]


def get_mode(name: str) -> ModeConfig:
    try:
        return MODES[name]
    except KeyError as exc:
        raise ValueError(f"unknown mode {name!r}; choose from {sorted(MODES)}") from exc
