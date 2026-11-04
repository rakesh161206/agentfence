"""Detector-quality sweeps.

Two controlled experiments vary the simulated detector while everything else
is fixed:

* recall sweep (FPR = 0): how much does attack success depend on recognising
  the injected instruction?
* false-positive sweep (recall = 1): what happens to benign utility when the
  detector over-flags content?

The sweep is intentionally a Monte Carlo experiment over detector errors, not
over the scenario text.  Each trial uses a different stable hash seed, so the
same detector sees the same action content consistently during approval
retries.
"""

from __future__ import annotations

import argparse
import csv
import json
import tempfile
import time
from collections import defaultdict
from pathlib import Path
from typing import Any

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt

from backend.fixtures import build_template

from .detector_sim import detector_factory
from .run import iter_episodes
from .scenarios import attack_scenarios, benign_scenarios

RECALL_MODES = ["B1", "B3", "B5"]
FPR_MODES = ["B1", "B3", "B5"]
COLORS = {"B1": "#E69F00", "B3": "#CC79A7", "B5": "#0072B2"}


def _scenario_means(records: list[dict[str, Any]], key: str) -> dict[str, float]:
    grouped: dict[str, list[float]] = defaultdict(list)
    for record in records:
        grouped[record["scenario_id"]].append(float(bool(record.get(key))))
    return {key_: sum(values) / len(values) for key_, values in grouped.items()}


def aggregate(records: list[dict[str, Any]], *, parameter: str) -> list[dict[str, Any]]:
    values = sorted({record[parameter] for record in records})
    modes = sorted({record["mode"] for record in records})
    output: list[dict[str, Any]] = []
    for value in values:
        for mode in modes:
            subset = [
                record
                for record in records
                if record["mode"] == mode and abs(record[parameter] - value) < 1e-12
            ]
            if not subset:
                continue
            attacks = [r for r in subset if r.get("kind") == "attack"]
            benign = [r for r in subset if r.get("kind") == "benign"]
            attack_means = _scenario_means(attacks, "attack_success")
            benign_means = _scenario_means(benign, "task_completed")
            false_block_tasks: dict[str, list[float]] = defaultdict(list)
            for record in benign:
                false_block_tasks[record["scenario_id"]].append(
                    float(int(record.get("false_blocks", 0)) > 0)
                )
            output.append(
                {
                    parameter: value,
                    "mode": mode,
                    "n_attack_scenarios": len(attack_means),
                    "asr": round(sum(attack_means.values()) / len(attack_means), 4)
                    if attack_means
                    else 0.0,
                    "n_benign_scenarios": len(benign_means),
                    "tcr": round(sum(benign_means.values()) / len(benign_means), 4)
                    if benign_means
                    else 0.0,
                    "false_block_tasks": round(
                        sum(
                            sum(values) / len(values)
                            for values in false_block_tasks.values()
                        ),
                        3,
                    ),
                    "approvals_attack": round(
                        sum(float(r.get("approvals_requested", 0)) for r in attacks)
                        / len(attacks),
                        3,
                    )
                    if attacks
                    else 0.0,
                    "approvals_benign": round(
                        sum(float(r.get("approvals_requested", 0)) for r in benign)
                        / len(benign),
                        3,
                    )
                    if benign
                    else 0.0,
                }
            )
    return output


def _write_csv(rows: list[dict[str, Any]], path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if not rows:
        path.write_text("", encoding="utf-8")
        return
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)


def _plot_recall(rows: list[dict[str, Any]], out: Path) -> list[str]:
    fig, axes = plt.subplots(1, 3, figsize=(7.2, 2.35), sharex=True)
    for mode in RECALL_MODES:
        subset = [row for row in rows if row["mode"] == mode]
        subset.sort(key=lambda row: row["detector_recall"])
        x = [row["detector_recall"] * 100 for row in subset]
        axes[0].plot(x, [row["asr"] * 100 for row in subset], marker="o", label=mode, color=COLORS[mode])
        axes[1].plot(x, [row["tcr"] * 100 for row in subset], marker="o", label=mode, color=COLORS[mode])
        axes[2].plot(
            x,
            [row["approvals_attack"] for row in subset],
            marker="o",
            label=mode,
            color=COLORS[mode],
        )
    axes[0].set_ylabel("ASR (%)")
    axes[0].set_ylim(-3, 105)
    axes[1].set_ylabel("TCR (%)")
    axes[1].set_ylim(-3, 105)
    axes[2].set_ylabel("Approvals / attack")
    axes[2].set_ylim(0, None)
    for ax in axes:
        ax.set_xlabel("Detector recall (%)")
        ax.set_xticks([0, 20, 40, 60, 80, 100])
    axes[0].legend(frameon=False, loc="best")
    axes[0].set_title("Security", pad=3)
    axes[1].set_title("Benign utility", pad=3)
    axes[2].set_title("Approval workload", pad=3)
    fig.tight_layout()
    out.mkdir(parents=True, exist_ok=True)
    paths = [out / "fig_detector_recall.png", out / "fig_detector_recall.pdf"]
    fig.savefig(paths[0], dpi=320, bbox_inches="tight", facecolor="white")
    fig.savefig(paths[1], dpi=320, bbox_inches="tight", facecolor="white")
    plt.close(fig)
    return [str(path) for path in paths]


def _plot_fpr(rows: list[dict[str, Any]], out: Path) -> list[str]:
    fig, axes = plt.subplots(1, 2, figsize=(5.2, 2.45), sharex=True)
    for mode in FPR_MODES:
        subset = [row for row in rows if row["mode"] == mode]
        subset.sort(key=lambda row: row["detector_fpr"])
        x = [row["detector_fpr"] * 100 for row in subset]
        axes[0].plot(x, [row["tcr"] * 100 for row in subset], marker="o", label=mode, color=COLORS[mode])
        axes[1].plot(
            x,
            [row["approvals_benign"] for row in subset],
            marker="o",
            label=mode,
            color=COLORS[mode],
        )
    axes[0].set_ylabel("Benign completion (%)")
    axes[0].set_xlabel("Detector false-positive rate (%)")
    axes[0].set_ylim(-3, 105)
    axes[1].set_ylabel("Approvals / benign task")
    axes[1].set_xlabel("Detector false-positive rate (%)")
    axes[1].set_ylim(0, None)
    axes[0].legend(frameon=False, loc="best")
    axes[0].set_title("Benign utility", pad=3)
    axes[1].set_title("Approval load", pad=3)
    fig.tight_layout()
    out.mkdir(parents=True, exist_ok=True)
    paths = [out / "fig_detector_fpr.png", out / "fig_detector_fpr.pdf"]
    fig.savefig(paths[0], dpi=320, bbox_inches="tight", facecolor="white")
    fig.savefig(paths[1], dpi=320, bbox_inches="tight", facecolor="white")
    plt.close(fig)
    return [str(path) for path in paths]


def _markdown(rows: list[dict[str, Any]], parameter: str, label: str) -> str:
    lines = [
        f"| {label} | Mode | ASR (%) | TCR (%) | False-block tasks | Approvals / attack | Approvals / benign |",
        "|---|---|---:|---:|---:|---:|---:|",
    ]
    for row in rows:
        lines.append(
            f"| {row[parameter] * 100:.0f}% | {row['mode']} | {row['asr'] * 100:.1f} | "
            f"{row['tcr'] * 100:.1f} | {row['false_block_tasks']:.1f} | "
            f"{row['approvals_attack']:.2f} | {row['approvals_benign']:.2f} |"
        )
    return "\n".join(lines)


def run_sweep(
    *,
    out: Path,
    trials: int = 5,
    seed: int = 20261026,
    recall_values: list[float] | None = None,
    fpr_values: list[float] | None = None,
) -> dict[str, Any]:
    out.mkdir(parents=True, exist_ok=True)
    template = Path(tempfile.mkdtemp(prefix="af-sweep-template-"))
    build_template(template)
    attacks = attack_scenarios()
    benign = benign_scenarios()
    started = time.time()

    recall_records: list[dict[str, Any]] = []
    recall_values = recall_values or [0.0, 0.2, 0.4, 0.6, 0.8, 1.0]
    for recall in recall_values:
        for trial in range(trials):
            for record in iter_episodes(
                [*attacks, *benign],
                RECALL_MODES,
                template,
                repeats=1,
                seed=seed + trial,
                detector_factory=detector_factory(recall, 0.0),
            ):
                record["detector_recall"] = recall
                record["detector_fpr"] = 0.0
                record["sweep_trial"] = trial
                recall_records.append(record)
        print(f"recall={recall:.1f} done ({len(recall_records)} records)", flush=True)

    fpr_records: list[dict[str, Any]] = []
    fpr_values = fpr_values or [0.0, 0.05, 0.10, 0.20, 0.30]
    for fpr in fpr_values:
        for trial in range(trials):
            for record in iter_episodes(
                benign,
                FPR_MODES,
                template,
                repeats=1,
                seed=seed + 10_000 + trial,
                detector_factory=detector_factory(1.0, fpr),
            ):
                record["detector_recall"] = 1.0
                record["detector_fpr"] = fpr
                record["sweep_trial"] = trial
                fpr_records.append(record)
        print(f"fpr={fpr:.2f} done ({len(fpr_records)} records)", flush=True)

    with (out / "recall_episodes.jsonl").open("w", encoding="utf-8") as handle:
        for record in recall_records:
            handle.write(json.dumps(record) + "\n")
    with (out / "fpr_episodes.jsonl").open("w", encoding="utf-8") as handle:
        for record in fpr_records:
            handle.write(json.dumps(record) + "\n")

    recall_rows = aggregate(recall_records, parameter="detector_recall")
    fpr_rows = aggregate(fpr_records, parameter="detector_fpr")
    _write_csv(recall_rows, out / "recall_summary.csv")
    _write_csv(fpr_rows, out / "fpr_summary.csv")
    (out / "recall_summary.json").write_text(json.dumps(recall_rows, indent=2), encoding="utf-8")
    (out / "fpr_summary.json").write_text(json.dumps(fpr_rows, indent=2), encoding="utf-8")
    (out / "summary.md").write_text(
        "# Detector sweeps\n\n## Recall sweep (FPR = 0)\n\n"
        + _markdown(recall_rows, "detector_recall", "Recall")
        + "\n\n## False-positive sweep (recall = 1)\n\n"
        + _markdown(fpr_rows, "detector_fpr", "FPR")
        + "\n",
        encoding="utf-8",
    )
    paths = _plot_recall(recall_rows, out / "figures")
    paths += _plot_fpr(fpr_rows, out / "figures")
    (out / "figures.json").write_text(json.dumps(paths, indent=2), encoding="utf-8")
    manifest = {
        "created_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "trials": trials,
        "seed": seed,
        "recall_values": recall_values,
        "fpr_values": fpr_values,
        "recall_records": len(recall_records),
        "fpr_records": len(fpr_records),
        "elapsed_seconds": round(time.time() - started, 3),
    }
    (out / "manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    print(f"\nDetector sweep written to {out} in {manifest['elapsed_seconds']}s")
    print((out / "summary.md").read_text(encoding="utf-8"))
    return {"recall": recall_rows, "fpr": fpr_rows, "manifest": manifest}


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Run detector recall / false-positive sweeps")
    parser.add_argument("--out", default="results/sweep")
    parser.add_argument("--trials", type=int, default=5)
    parser.add_argument("--seed", type=int, default=20261026)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    run_sweep(out=Path(args.out), trials=args.trials, seed=args.seed)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
