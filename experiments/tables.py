"""Generate Markdown tables consumed by the paper build."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any


def _pct(value: float) -> str:
    return f"{100.0 * value:.1f}"


def _count(value: float) -> str:
    if abs(value - round(value)) < 1e-9:
        return str(int(round(value)))
    return f"{value:.1f}"


def _main_table(summary: dict[str, Any]) -> str:
    modes = summary["modes"]
    lines = [
        "| Mode | ASR (%) | TCR (%) | False-block tasks | Approvals / attack | Approvals / benign | Leak bytes | p50 (ms) | p95 (ms) | p99 (ms) |",
        "|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|",
    ]
    for mode in modes:
        item = summary["by_mode"][mode]
        a, b, latency = item["attack"], item["benign"], item["latency"]["end_to_end"]
        lines.append(
            f"| {mode} | {a['successes']:.0f}/{a['n_scenarios']} ({_pct(a['asr'])}) | "
            f"{b['completed']:.0f}/{b['n_scenarios']} ({_pct(b['tcr'])}) | "
            f"{_count(b['false_block_tasks'])} | {a['approvals_requested_mean']:.2f} | "
            f"{b['approvals_requested_mean']:.2f} | {a['leak_bytes_total']:.0f} | "
            f"{latency['p50']:.2f} | {latency['p95']:.2f} | {latency['p99']:.2f} |"
        )
    return "\n".join(lines)


def _family_table(summary: dict[str, Any]) -> str:
    modes = summary["modes"]
    families = sorted(
        {family for mode in modes for family in summary["by_mode"][mode]["attack"]["by_family"]}
    )
    lines = [
        "| Family | " + " | ".join(modes) + " |",
        "|---|" + "|".join("---:" for _ in modes) + "|",
    ]
    for family in families:
        cells = []
        for mode in modes:
            value = summary["by_mode"][mode]["attack"]["by_family"].get(family, {})
            cells.append(f"{value.get('successes', 0):.0f}/{value.get('n_scenarios', 0)}")
        lines.append(f"| {family} | " + " | ".join(cells) + " |")
    return "\n".join(lines)


def _ablation_table(summary: dict[str, Any]) -> str:
    modes = [m for m in ["B4", "B4T", "B4TR", "B5"] if m in summary["modes"]]
    lines = [
        "| Configuration | Added layer | ASR (%) | TCR (%) | False-block tasks | Approvals / benign |",
        "|---|---|---:|---:|---:|---:|",
    ]
    added = {
        "B4": "task-scoped capabilities",
        "B4T": "+ taint/DLP",
        "B4TR": "+ risk hard-block",
        "B5": "+ risk approval + approvals",
    }
    for mode in modes:
        item = summary["by_mode"][mode]
        lines.append(
            f"| {mode} | {added.get(mode, '')} | {_pct(item['attack']['asr'])} | "
            f"{_pct(item['benign']['tcr'])} | {_count(item['benign']['false_block_tasks'])} | "
            f"{item['benign']['approvals_requested_mean']:.2f} |"
        )
    return "\n".join(lines)


def _latency_table(summary: dict[str, Any]) -> str:
    lines = [
        "| Mode | Decision p50 | Decision p95 | End-to-end p50 | End-to-end p95 | End-to-end p99 |",
        "|---|---:|---:|---:|---:|---:|",
    ]
    for mode in summary["modes"]:
        latency = summary["by_mode"][mode]["latency"]
        d, e = latency["decision"], latency["end_to_end"]
        lines.append(
            f"| {mode} | {d['p50']:.2f} | {d['p95']:.2f} | {e['p50']:.2f} | "
            f"{e['p95']:.2f} | {e['p99']:.2f} |"
        )
    return "\n".join(lines)


def _rule_table(summary: dict[str, Any]) -> str:
    lines = [
        "| Rule | Decisions | Scenario variants |",
        "|---|---:|---:|",
    ]
    rules = summary["by_mode"].get("B5", {}).get("rules", {})
    for rule, count in rules.get("counts", {}).items():
        lines.append(f"| {rule} | {count} | {rules.get('scenario_counts', {}).get(rule, 0)} |")
    return "\n".join(lines)


def _benign_table(summary: dict[str, Any]) -> str:
    """Per-task completion matrix is written by stats as outcomes.csv; this
    table summarizes the ablation utility differences in prose-friendly form."""

    modes = summary["modes"]
    lines = [
        "| Mode | Benign tasks completed | Benign tasks with a false block | False-blocked actions |",
        "|---|---:|---:|---:|",
    ]
    for mode in modes:
        item = summary["by_mode"][mode]["benign"]
        lines.append(
            f"| {mode} | {item['completed']:.0f}/{item['n_scenarios']} | "
            f"{_count(item['false_block_tasks'])} | {_count(item['false_block_actions'])} |"
        )
    return "\n".join(lines)


def write_tables(summary: dict[str, Any], out: Path) -> dict[str, str]:
    out.mkdir(parents=True, exist_ok=True)
    tables = {
        "main": _main_table(summary),
        "family": _family_table(summary),
        "ablation": _ablation_table(summary),
        "latency": _latency_table(summary),
        "rules": _rule_table(summary),
        "benign": _benign_table(summary),
    }
    for name, content in tables.items():
        (out / f"{name}.md").write_text(content + "\n", encoding="utf-8")
    (out / "tables.json").write_text(json.dumps(tables, indent=2), encoding="utf-8")
    return tables


def main(argv: list[str] | None = None) -> int:
    import argparse

    parser = argparse.ArgumentParser(description="Generate AgentFence tables")
    parser.add_argument("summary", nargs="?", default="results/main/summary.json")
    parser.add_argument("--out", default="results/main/tables")
    args = parser.parse_args(argv)
    summary = json.loads(Path(args.summary).read_text(encoding="utf-8"))
    tables = write_tables(summary, Path(args.out))
    for name, content in tables.items():
        print(f"## {name}\n{content}\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
