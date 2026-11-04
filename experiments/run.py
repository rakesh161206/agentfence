"""Reproducible experiment runner.

The runner creates an isolated fixture tree for every episode, builds a fresh
gateway in the requested configuration, executes a fixed agent trace, and
records both security outcomes and timing.  No network access is used: the
tool runtime is entirely simulated.

Examples
--------
    uv run python -m experiments.run --out results/main
    uv run python -m experiments.run --modes B0 B5 --repeats 2
"""

from __future__ import annotations

import argparse
import csv
import json
import shutil
import tempfile
import time
import traceback
from collections.abc import Iterable
from pathlib import Path
from typing import Any

from backend.core.config import ABLATION_MODES, BASELINE_MODES, GatewayConfig, get_mode
from backend.core.models import ToolAction
from backend.fixtures import build_template
from backend.runtime.interceptor import AgentFenceService

from .agent import ScriptedAgent
from .scenarios import Scenario, attack_scenarios, benign_scenarios


def _mode_list() -> list[str]:
    return list(dict.fromkeys([*BASELINE_MODES, *ABLATION_MODES]))


def _write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=False), encoding="utf-8")


def run_episode(
    scenario: Scenario,
    mode: str,
    template: Path,
    *,
    seed: int = 0,
    repeat: int = 0,
    detector_factory: Any = None,
    approval_mode: str = "always_approve",
) -> dict[str, Any]:
    """Run one scenario against one configuration in a fresh sandbox."""

    started_wall = time.time()
    parent = Path(tempfile.mkdtemp(prefix=f"af-{mode}-"))
    root = parent / "runtime"
    try:
        shutil.copytree(template, root, symlinks=True)
        service = AgentFenceService(GatewayConfig(mode=get_mode(mode), root=root), root=root)
        if detector_factory is not None:
            detector = detector_factory(scenario, seed, repeat)
            service.detector = detector
            service.risk.detector = detector
        _, token = service.create_task(
            agent_id="scripted-agent",
            description=scenario.task_description,
            capabilities=scenario.capabilities,
            ttl_seconds=600,
        )
        result = ScriptedAgent(
            service,
            token,
            scenario,
            approval_mode=approval_mode,
            seed=seed,
        ).run()
        record = result.to_dict()
        record.update(
            {
                "mode": mode,
                "variant": scenario.variant,
                "description": scenario.task_description,
                "repeat": repeat,
                "trial_seed": seed,
                "audit_ok": service.audit.verify()["ok"],
                "audit_entries": len(service.audit.entries),
                "wall_ms": round((time.time() - started_wall) * 1000, 3),
            }
        )
        return record
    except Exception as exc:  # noqa: BLE001 - an experiment failure must be recorded, not hidden
        return {
            "config": mode,
            "mode": mode,
            "scenario_id": scenario.id,
            "family": scenario.family,
            "kind": scenario.kind,
            "variant": scenario.variant,
            "seed": seed,
            "repeat": repeat,
            "trial_seed": seed,
            "description": scenario.task_description,
            "attack_success": False,
            "task_completed": False,
            "error": f"{type(exc).__name__}: {exc}",
            "traceback": traceback.format_exc()[-4000:],
            "audit_ok": False,
            "wall_ms": round((time.time() - started_wall) * 1000, 3),
        }
    finally:
        shutil.rmtree(parent, ignore_errors=True)


def iter_episodes(
    scenarios: Iterable[Scenario],
    modes: list[str],
    template: Path,
    *,
    repeats: int = 1,
    seed: int = 0,
    detector_factory: Any = None,
    approval_mode: str = "always_approve",
) -> Iterable[dict[str, Any]]:
    for mode in modes:
        for scenario in scenarios:
            for repeat in range(repeats):
                episode_seed = seed + repeat
                yield run_episode(
                    scenario,
                    mode,
                    template,
                    seed=episode_seed,
                    repeat=repeat,
                    detector_factory=detector_factory,
                    approval_mode=approval_mode,
                )


def _flatten_episode(record: dict[str, Any]) -> dict[str, Any]:
    row = {key: value for key, value in record.items() if key not in {"decisions", "effect_summary"}}
    decisions = record.get("decisions") or []
    row["n_decisions"] = len(decisions)
    row["decision_rule_ids"] = ";".join(
        sorted(
            {
                piece.split(":", 1)[0]
                for decision in decisions
                for piece in str(decision.get("reason", "")).split("; ")
                if piece
            }
        )
    )
    return row


def write_episode_csv(records: list[dict[str, Any]], path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    rows = [_flatten_episode(record) for record in records]
    fields: list[str] = []
    for row in rows:
        for key in row:
            if key not in fields:
                fields.append(key)
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        for row in rows:
            writer.writerow({key: row.get(key, "") for key in fields})


def run_experiment(
    *,
    out: Path,
    modes: list[str],
    repeats: int = 5,
    seed: int = 20261026,
    suites: str = "all",
    template: Path | None = None,
    warmup: bool = True,
    progress: bool = True,
    approval_mode: str = "always_approve",
) -> dict[str, Any]:
    out.mkdir(parents=True, exist_ok=True)
    scenarios: list[Scenario] = []
    if suites in {"all", "attack"}:
        scenarios.extend(attack_scenarios())
    if suites in {"all", "benign"}:
        scenarios.extend(benign_scenarios())

    if template is None:
        template = Path(tempfile.mkdtemp(prefix="af-template-"))
        build_template(template)

    if warmup:
        warmup_root = Path(tempfile.mkdtemp(prefix="af-warmup-")) / "runtime"
        try:
            shutil.copytree(template, warmup_root, symlinks=True)
            service = AgentFenceService(
                GatewayConfig(mode=get_mode(modes[0]), root=warmup_root), root=warmup_root
            )
            _, token = service.create_task(
                agent_id="warmup",
                description="warmup",
                capabilities=attack_scenarios()[0].capabilities,
                ttl_seconds=60,
            )
            service.submit(
                token=token,
                action=ToolAction(
                    tool="file.read", args={"path": "/project/docs/vendor_report.pdf"}
                ),
            )
        except Exception:
            pass
        finally:
            shutil.rmtree(warmup_root.parent, ignore_errors=True)

    raw_path = out / "episodes.jsonl"
    started = time.time()
    records: list[dict[str, Any]] = []
    with raw_path.open("w", encoding="utf-8") as handle:
        for index, record in enumerate(
            iter_episodes(
                scenarios,
                modes,
                template,
                repeats=repeats,
                seed=seed,
                approval_mode=approval_mode,
            ),
            start=1,
        ):
            records.append(record)
            handle.write(json.dumps(record, sort_keys=False) + "\n")
            handle.flush()
            if progress and (index % 50 == 0 or index == len(scenarios) * len(modes) * repeats):
                print(f"  {index}/{len(scenarios) * len(modes) * repeats} episodes", flush=True)

    write_episode_csv(records, out / "episodes.csv")
    manifest = {
        "created_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "modes": modes,
        "scenarios": len(scenarios),
        "attack_scenarios": len([s for s in scenarios if s.kind == "attack"]),
        "benign_scenarios": len([s for s in scenarios if s.kind == "benign"]),
        "repeats": repeats,
        "seed": seed,
        "suites": suites,
        "approval_mode": approval_mode,
        "elapsed_seconds": round(time.time() - started, 3),
        "raw": str(raw_path),
    }
    _write_json(out / "manifest.json", manifest)

    from . import plots, stats, tables

    summary = stats.summarize(records, out)
    tables.write_tables(summary, out / "tables")
    try:
        plots.write_figures(summary, out / "figures")
    except Exception as exc:  # pragma: no cover - figures are optional diagnostics
        print(f"figure generation failed: {exc}")
    print(f"\nResults written to {out}")
    print(stats.render_text_summary(summary))
    return summary


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Run AgentFence attack/benign matrix")
    parser.add_argument("--out", default="results/main", help="output directory")
    parser.add_argument("--modes", nargs="+", default=_mode_list(), choices=_mode_list())
    parser.add_argument("--repeats", type=int, default=5)
    parser.add_argument("--seed", type=int, default=20261026)
    parser.add_argument("--suites", choices=["all", "attack", "benign"], default="all")
    parser.add_argument("--template", default=None, help="reuse a prepared fixture tree")
    parser.add_argument("--no-warmup", action="store_true")
    parser.add_argument(
        "--approval-mode",
        choices=["always_approve", "deny_all"],
        default="always_approve",
        help="how the scripted agent responds to pending approvals",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    run_experiment(
        out=Path(args.out),
        modes=args.modes,
        repeats=args.repeats,
        seed=args.seed,
        suites=args.suites,
        template=Path(args.template) if args.template else None,
        warmup=not args.no_warmup,
        approval_mode=args.approval_mode,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
