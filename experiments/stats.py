"""Aggregate episode records into paper-ready statistics.

The security outcomes are deterministic for a fixed scenario suite, so the
headline rates are descriptive: they count security-relevant scenario variants,
not a random sample of real-world attacks.  Latency is the one quantity that is
genuinely sampled, and we report bootstrap intervals for its percentiles.
"""

from __future__ import annotations

import json
import math
import re
from collections import defaultdict
from pathlib import Path
from typing import Any, Iterable

import numpy as np

RULE_RE = re.compile(r"\b(?:R\d+[a-z]?|PF1)\b")


def _safe_mean(values: Iterable[float]) -> float:
    values = list(values)
    return float(sum(values) / len(values)) if values else 0.0


def _percentile(values: list[float], q: float) -> float:
    if not values:
        return 0.0
    return float(np.percentile(np.asarray(values, dtype=float), q))


def _latency_summary(values: list[float], *, bootstrap: int = 400, seed: int = 7) -> dict[str, Any]:
    if not values:
        return {"n": 0, "mean": 0.0, "p50": 0.0, "p95": 0.0, "p99": 0.0}
    array = np.asarray(values, dtype=float)
    result: dict[str, Any] = {
        "n": int(array.size),
        "mean": round(float(array.mean()), 3),
        "p50": round(float(np.percentile(array, 50)), 3),
        "p95": round(float(np.percentile(array, 95)), 3),
        "p99": round(float(np.percentile(array, 99)), 3),
    }
    rng = np.random.default_rng(seed)
    samples = {50: [], 95: [], 99: []}
    for _ in range(bootstrap):
        draw = rng.choice(array, size=array.size, replace=True)
        for q in samples:
            samples[q].append(float(np.percentile(draw, q)))
    result["ci95"] = {
        f"p{q}": [
            round(float(np.percentile(samples[q], 2.5)), 3),
            round(float(np.percentile(samples[q], 97.5)), 3),
        ]
        for q in samples
    }
    return result


def load_records(path: Path) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    with path.open(encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if line:
                records.append(json.loads(line))
    return records


def _scenario_means(records: list[dict[str, Any]], key: str, *, binary: bool = True) -> dict[str, float]:
    grouped: dict[str, list[float]] = defaultdict(list)
    for record in records:
        value = float(bool(record.get(key))) if binary else float(record.get(key, 0) or 0)
        grouped[record["scenario_id"]].append(value)
    return {scenario: _safe_mean(values) for scenario, values in grouped.items()}


def _mode_summary(records: list[dict[str, Any]]) -> dict[str, Any]:
    attacks = [r for r in records if r.get("kind") == "attack"]
    benign = [r for r in records if r.get("kind") == "benign"]

    attack_means = _scenario_means(attacks, "attack_success")
    benign_means = _scenario_means(benign, "task_completed")
    by_family: dict[str, dict[str, Any]] = {}
    families = sorted({r["family"] for r in attacks})
    for family in families:
        family_records = [r for r in attacks if r["family"] == family]
        means = _scenario_means(family_records, "attack_success")
        by_family[family] = {
            "n_scenarios": len(means),
            "successes": round(sum(means.values()), 3),
            "asr": round(_safe_mean(means.values()), 4),
        }

    false_block_tasks: dict[str, list[float]] = defaultdict(list)
    false_block_actions: dict[str, list[float]] = defaultdict(list)
    approval_requested_benign: dict[str, list[float]] = defaultdict(list)
    approval_used_benign: dict[str, list[float]] = defaultdict(list)
    for record in benign:
        false_block_tasks[record["scenario_id"]].append(
            float(int(record.get("false_blocks", 0)) > 0)
        )
        false_block_actions[record["scenario_id"]].append(float(record.get("false_blocks", 0)))
        approval_requested_benign[record["scenario_id"]].append(
            float(record.get("approvals_requested", 0))
        )
        approval_used_benign[record["scenario_id"]].append(float(record.get("approvals_used", 0)))

    leak_per_scenario = _scenario_means(attacks, "leak_bytes", binary=False)
    attack_approvals = _safe_mean(float(r.get("approvals_requested", 0)) for r in attacks)
    attack_approval_used = _safe_mean(float(r.get("approvals_used", 0)) for r in attacks)
    benign_approvals = _safe_mean(float(r.get("approvals_requested", 0)) for r in benign)
    benign_approval_used = _safe_mean(float(r.get("approvals_used", 0)) for r in benign)

    end_to_end: list[float] = []
    decision: list[float] = []
    by_tool: dict[str, list[float]] = defaultdict(list)
    for record in records:
        end_to_end.extend(float(x) for x in record.get("latency_ms", []) or [])
        decision.extend(float(x) for x in record.get("decision_latency_ms", []) or [])
        for item in record.get("decisions", []) or []:
            if item.get("latency_ms"):
                by_tool[str(item.get("tool", "unknown"))].append(float(item["latency_ms"]))

    rule_counts: dict[str, int] = defaultdict(int)
    rule_scenarios: dict[str, set[str]] = defaultdict(set)
    for record in attacks:
        for item in record.get("decisions", []) or []:
            for rule in RULE_RE.findall(str(item.get("reason", ""))):
                rule_counts[rule] += 1
                rule_scenarios[rule].add(record["scenario_id"])

    errors = [r for r in records if r.get("error")]
    audit_ok = _safe_mean(1.0 if r.get("audit_ok") else 0.0 for r in records)

    return {
        "attack": {
            "n_scenarios": len(attack_means),
            "successes": round(sum(attack_means.values()), 3),
            "asr": round(_safe_mean(attack_means.values()), 4),
            "by_family": by_family,
            "leak_bytes_total": round(sum(leak_per_scenario.values()), 3),
            "leak_bytes_per_attack": round(_safe_mean(leak_per_scenario.values()), 3),
            "leak_bytes_per_success": round(
                _safe_mean(
                    float(r.get("leak_bytes", 0))
                    for r in attacks
                    if r.get("attack_success")
                ),
                3,
            ),
            "approvals_requested_mean": round(attack_approvals, 3),
            "approvals_used_mean": round(attack_approval_used, 3),
        },
        "benign": {
            "n_scenarios": len(benign_means),
            "completed": round(sum(benign_means.values()), 3),
            "tcr": round(_safe_mean(benign_means.values()), 4),
            "false_block_tasks": round(sum(_safe_mean(v) for v in false_block_tasks.values()), 3),
            "false_block_task_rate": round(
                _safe_mean(_safe_mean(v) for v in false_block_tasks.values()), 4
            ),
            "false_block_actions": round(sum(_safe_mean(v) for v in false_block_actions.values()), 3),
            "false_block_action_rate": round(
                _safe_mean(_safe_mean(v) for v in false_block_actions.values()), 4
            ),
            "approvals_requested_mean": round(benign_approvals, 3),
            "approvals_used_mean": round(benign_approval_used, 3),
            "approvals_requested_total": round(sum(_safe_mean(v) for v in approval_requested_benign.values()), 3),
            "approvals_used_total": round(sum(_safe_mean(v) for v in approval_used_benign.values()), 3),
        },
        "latency": {
            "end_to_end": _latency_summary(end_to_end),
            "decision": _latency_summary(decision, seed=11),
            "by_tool": {
                tool: _latency_summary(values, seed=13 + index)
                for index, (tool, values) in enumerate(sorted(by_tool.items()))
            },
        },
        "rules": {
            "counts": dict(sorted(rule_counts.items())),
            "scenario_counts": {key: len(value) for key, value in sorted(rule_scenarios.items())},
        },
        "audit_ok_rate": round(audit_ok, 4),
        "errors": len(errors),
        "n_episodes": len(records),
    }


def _pairwise(records: list[dict[str, Any]], modes: list[str]) -> dict[str, Any]:
    outcomes: dict[str, dict[str, dict[str, bool]]] = {
        "attack": defaultdict(dict),
        "benign": defaultdict(dict),
    }
    for record in records:
        kind = "attack" if record.get("kind") == "attack" else "benign"
        key = "attack_success" if kind == "attack" else "task_completed"
        outcomes[kind][record["mode"]][record["scenario_id"]] = bool(record.get(key))
    result: dict[str, Any] = {}
    for kind, by_mode in outcomes.items():
        pairs: dict[str, Any] = {}
        for left in modes:
            for right in modes:
                if left >= right:
                    continue
                common = sorted(set(by_mode[left]) & set(by_mode[right]))
                changed = [sid for sid in common if by_mode[left][sid] != by_mode[right][sid]]
                pairs[f"{left}_vs_{right}"] = {
                    "n": len(common),
                    "changed": len(changed),
                    "left_only": [sid for sid in changed if by_mode[left][sid]],
                    "right_only": [sid for sid in changed if by_mode[right][sid]],
                }
        result[kind] = pairs
    return result


def summarize(records: list[dict[str, Any]], out: Path | None = None) -> dict[str, Any]:
    modes = list(dict.fromkeys(record["mode"] for record in records))
    summary: dict[str, Any] = {
        "modes": modes,
        "by_mode": {mode: _mode_summary([r for r in records if r["mode"] == mode]) for mode in modes},
        "pairwise": _pairwise(records, modes),
        "attacks": sorted({r["scenario_id"] for r in records if r.get("kind") == "attack"}),
        "benign": sorted({r["scenario_id"] for r in records if r.get("kind") == "benign"}),
    }
    if out is not None:
        out.mkdir(parents=True, exist_ok=True)
        (out / "summary.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")
        (out / "summary.md").write_text(render_markdown(summary), encoding="utf-8")
        _write_outcomes(records, out / "outcomes.csv")
    return summary


def _write_outcomes(records: list[dict[str, Any]], path: Path) -> None:
    modes = list(dict.fromkeys(record["mode"] for record in records))
    values: dict[str, dict[str, dict[str, float]]] = defaultdict(lambda: defaultdict(dict))
    for record in records:
        key = "attack_success" if record.get("kind") == "attack" else "task_completed"
        values[record["scenario_id"]].setdefault(record["mode"], {})[key] = float(
            bool(record.get(key))
        )
    lines = ["scenario,kind,family," + ",".join(modes)]
    for scenario_id in sorted(values):
        record = next(r for r in records if r["scenario_id"] == scenario_id)
        cells = [str(values[scenario_id].get(mode, {}).get(
            "attack_success" if record.get("kind") == "attack" else "task_completed", ""
        )) for mode in modes]
        lines.append(f"{scenario_id},{record.get('kind','')},{record.get('family','')}," + ",".join(cells))
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def _pct(value: float) -> str:
    return f"{100.0 * value:.1f}%"


def _num(value: float) -> str:
    return f"{value:.3f}".rstrip("0").rstrip(".")


def render_markdown(summary: dict[str, Any]) -> str:
    modes = summary["modes"]
    lines = [
        "# AgentFence experiment summary",
        "",
        "Security rates are descriptive proportions over the scripted scenario suite. "
        "Latency percentiles are over all submitted actions; brackets are bootstrap 95% intervals.",
        "",
        "## Main matrix",
        "",
        "| Mode | ASR | TCR | False-block tasks | Approval req. / attack | Approval req. / benign | p50 ms | p95 ms | p99 ms | Audit |",
        "|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|",
    ]
    for mode in modes:
        item = summary["by_mode"][mode]
        a, b, latency = item["attack"], item["benign"], item["latency"]
        lines.append(
            f"| {mode} | {a['successes']:.0f}/{a['n_scenarios']} ({_pct(a['asr'])}) | "
            f"{b['completed']:.0f}/{b['n_scenarios']} ({_pct(b['tcr'])}) | "
            f"{b['false_block_tasks']:.0f} | {a['approvals_requested_mean']:.2f} | "
            f"{b['approvals_requested_mean']:.2f} | {latency['end_to_end']['p50']:.2f} | "
            f"{latency['end_to_end']['p95']:.2f} | {latency['end_to_end']['p99']:.2f} | "
            f"{_pct(item['audit_ok_rate'])} |"
        )

    families = sorted({family for item in summary["by_mode"].values() for family in item["attack"]["by_family"]})
    lines += [
        "",
        "## Attack success by family",
        "",
        "| Family | " + " | ".join(modes) + " |",
        "|---|" + "|".join("---:" for _ in modes) + "|",
    ]
    for family in families:
        cells = []
        for mode in modes:
            value = summary["by_mode"][mode]["attack"]["by_family"].get(family, {})
            cells.append(f"{value.get('successes', 0):.0f}/{value.get('n_scenarios', 0)}")
        lines.append(f"| {family} | " + " | ".join(cells) + " |")

    lines += [
        "",
        "## Latency detail",
        "",
        "| Mode | Decision p50 | Decision p95 | End-to-end p50 | End-to-end p95 | End-to-end p99 |",
        "|---|---:|---:|---:|---:|---:|",
    ]
    for mode in modes:
        latency = summary["by_mode"][mode]["latency"]
        d, e = latency["decision"], latency["end_to_end"]
        lines.append(
            f"| {mode} | {d['p50']:.2f} | {d['p95']:.2f} | {e['p50']:.2f} | "
            f"{e['p95']:.2f} | {e['p99']:.2f} |"
        )

    lines += [
        "",
        "## Rule coverage in attack episodes",
        "",
        "| Rule | Decisions | Scenarios |",
        "|---|---:|---:|",
    ]
    for mode in modes:
        rules = summary["by_mode"][mode]["rules"]
        if not rules["counts"]:
            continue
        lines.append(f"| **{mode}** | | |")
        for rule, count in rules["counts"].items():
            lines.append(f"| {rule} | {count} | {rules['scenario_counts'].get(rule, 0)} |")

    for kind, title in [("attack", "Paired attack-scenario changes"), ("benign", "Paired benign-task changes")]:
        lines += [
            "",
            f"## {title}",
            "",
            "| Pair | Changed | Left only | Right only |",
            "|---|---:|---|---|",
        ]
        for pair, item in summary["pairwise"].get(kind, {}).items():
            lines.append(
                f"| {pair.replace('_vs_', ' vs ')} | {item['changed']}/{item['n']} | "
                f"{', '.join(item['left_only'][:8]) or '-'} | {', '.join(item['right_only'][:8]) or '-'} |"
            )
    return "\n".join(lines) + "\n"


def render_text_summary(summary: dict[str, Any]) -> str:
    lines = []
    for mode in summary["modes"]:
        item = summary["by_mode"][mode]
        lines.append(
            f"{mode}: ASR {item['attack']['successes']:.0f}/{item['attack']['n_scenarios']} "
            f"({_pct(item['attack']['asr'])}), TCR {_pct(item['benign']['tcr'])}, "
            f"false-block tasks {item['benign']['false_block_tasks']:.0f}, "
            f"p95 {item['latency']['end_to_end']['p95']:.1f} ms"
        )
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    import argparse

    parser = argparse.ArgumentParser(description="Summarize AgentFence episodes")
    parser.add_argument("path", nargs="?", default="results/main/episodes.jsonl")
    parser.add_argument("--out", default=None)
    args = parser.parse_args(argv)
    path = Path(args.path)
    out = Path(args.out) if args.out else path.parent
    summary = summarize(load_records(path), out)
    print(render_text_summary(summary))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
