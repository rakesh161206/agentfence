"""Paper figures generated directly from the measured summary."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np

PALETTE = {
    "B0": "#7f7f7f",
    "B1": "#E69F00",
    "B2": "#56B4E9",
    "B3": "#CC79A7",
    "B4": "#009E73",
    "B5": "#0072B2",
    "B4T": "#D55E00",
    "B4TR": "#A0522D",
}
MARKERS = {"B0": "o", "B1": "s", "B2": "^", "B3": "D", "B4": "v", "B5": "*", "B4T": "P", "B4TR": "X"}


def _style() -> None:
    plt.rcParams.update(
        {
            "font.size": 9.5,
            "axes.titlesize": 11,
            "axes.labelsize": 9.5,
            "legend.fontsize": 8,
            "xtick.labelsize": 8.5,
            "ytick.labelsize": 8.5,
            "axes.spines.top": False,
            "axes.spines.right": False,
            "axes.grid": True,
            "grid.alpha": 0.25,
            "grid.linewidth": 0.6,
            "figure.dpi": 160,
            "savefig.dpi": 320,
            "savefig.bbox": "tight",
        }
    )


def _save(fig: plt.Figure, out: Path, stem: str) -> list[str]:
    out.mkdir(parents=True, exist_ok=True)
    png = out / f"{stem}.png"
    pdf = out / f"{stem}.pdf"
    fig.savefig(png, facecolor="white")
    fig.savefig(pdf, facecolor="white")
    plt.close(fig)
    return [str(png), str(pdf)]


def _short(mode: str) -> str:
    return {
        "B0": "B0 (none)",
        "B1": "B1 (filter)",
        "B2": "B2 (static RBAC)",
        "B3": "B3 (risk)",
        "B4": "B4 (capabilities)",
        "B5": "B5 (full)",
        "B4T": "B4T (+taint/DLP)",
        "B4TR": "B4TR (+risk hard-block)",
    }.get(mode, mode)


def fig_asr_by_family(summary: dict[str, Any], out: Path) -> list[str]:
    modes = [m for m in ["B0", "B1", "B2", "B3", "B4", "B5"] if m in summary["by_mode"]]
    families = sorted(
        {family for mode in modes for family in summary["by_mode"][mode]["attack"]["by_family"]}
    )
    x = np.arange(len(families))
    width = 0.8 / max(1, len(modes))
    fig, ax = plt.subplots(figsize=(7.2, 3.0))
    for index, mode in enumerate(modes):
        values = [
            100.0
            * summary["by_mode"][mode]["attack"]["by_family"].get(family, {}).get("asr", 0.0)
            for family in families
        ]
        ax.bar(
            x + (index - (len(modes) - 1) / 2) * width,
            values,
            width,
            label=_short(mode),
            color=PALETTE[mode],
            edgecolor="white",
            linewidth=0.5,
        )
    ax.set_ylabel("Attack success rate (%)")
    ax.set_ylim(0, 105)
    ax.set_xticks(x, families)
    ax.set_xlabel("Attack family")
    ax.legend(ncol=3, frameon=False, loc="upper center", bbox_to_anchor=(0.5, 1.16))
    ax.grid(axis="x", visible=False)
    fig.tight_layout()
    return _save(fig, out, "fig_asr_by_family")


def fig_security_utility(summary: dict[str, Any], out: Path) -> list[str]:
    modes = [m for m in ["B0", "B1", "B2", "B3", "B4", "B5", "B4T", "B4TR"] if m in summary["by_mode"]]
    fig, ax = plt.subplots(figsize=(4.4, 3.5))
    offsets = {
        "B0": (-34, -15),
        "B1": (5, 7),
        "B2": (5, 7),
        "B3": (5, 7),
        "B4": (5, -14),
        "B5": (5, 7),
        "B4T": (5, -14),
        "B4TR": (5, -14),
    }
    # B0 and B2 coincide at (100, 100); separate them by 1 pp so both
    # markers remain visible, and state the offset in the caption.
    jitter = {"B0": -1.0, "B2": 1.0}
    for mode in modes:
        item = summary["by_mode"][mode]
        asr = 100.0 * item["attack"]["asr"] + jitter.get(mode, 0.0)
        tcr = 100.0 * item["benign"]["tcr"]
        ax.scatter(
            asr,
            tcr,
            s=120 if mode == "B5" else 70,
            color=PALETTE[mode],
            marker=MARKERS[mode],
            zorder=3,
            edgecolor="white",
            linewidth=0.8,
        )
        ax.annotate(
            mode,
            (asr, tcr),
            xytext=offsets.get(mode, (4, 6)),
            textcoords="offset points",
            fontsize=8,
        )
    ax.set_xlabel("Attack success rate (%)  (lower is better)")
    ax.set_ylabel("Benign task completion (%)  (higher is better)")
    ax.set_xlim(-3, 108)
    ax.set_ylim(55, 105)
    ax.axvspan(-3, 10, color="#0072B2", alpha=0.06)
    ax.text(5, 57.0, "target region", color="#0072B2", fontsize=8)
    fig.tight_layout()
    return _save(fig, out, "fig_security_utility")


def fig_ablation(summary: dict[str, Any], out: Path) -> list[str]:
    modes = [m for m in ["B4", "B4T", "B4TR", "B5"] if m in summary["by_mode"]]
    if not modes:
        return []
    asr = [100.0 * summary["by_mode"][m]["attack"]["asr"] for m in modes]
    tcr = [100.0 * summary["by_mode"][m]["benign"]["tcr"] for m in modes]
    approvals = [summary["by_mode"][m]["benign"]["approvals_requested_mean"] for m in modes]
    x = np.arange(len(modes))
    fig, axes = plt.subplots(1, 3, figsize=(7.2, 2.6), sharex=True)
    panels = [
        (asr, "Attack success (%)", "Security"),
        (tcr, "Benign completion (%)", "Utility"),
        (approvals, "Approvals / benign task", "Approval burden"),
    ]
    for ax, (values, label, title) in zip(axes, panels, strict=False):
        bars = ax.bar(x, values, color=[PALETTE[m] for m in modes], width=0.65)
        ax.set_title(title, pad=4)
        ax.set_ylabel(label)
        ax.set_xticks(x, modes)
        maximum = max(values) if values else 1.0
        fraction = maximum <= 1.0
        top = maximum * 1.22 if fraction else 110.0
        ax.set_ylim(0, top)
        offset = top * 0.025
        for bar, value in zip(bars, values, strict=False):
            ax.text(
                bar.get_x() + bar.get_width() / 2,
                bar.get_height() + offset,
                f"{value:.2f}" if fraction else f"{value:.1f}",
                ha="center",
                va="bottom",
                fontsize=8,
            )
    fig.tight_layout()
    return _save(fig, out, "fig_ablation")


def fig_latency(summary: dict[str, Any], out: Path) -> list[str]:
    modes = [m for m in ["B0", "B1", "B2", "B3", "B4", "B5", "B4T", "B4TR"] if m in summary["by_mode"]]
    x = np.arange(len(modes))
    width = 0.26
    fig, ax = plt.subplots(figsize=(7.2, 2.9))
    for index, (key, label, color) in enumerate(
        [("p50", "p50", "#56B4E9"), ("p95", "p95", "#0072B2"), ("p99", "p99", "#D55E00")]
    ):
        values = [summary["by_mode"][mode]["latency"]["end_to_end"][key] for mode in modes]
        ax.bar(
            x + (index - 1) * width,
            values,
            width,
            label=label,
            color=color,
            edgecolor="white",
            linewidth=0.5,
        )
    ax.set_ylabel("End-to-end action latency (ms)")
    ax.set_xticks(x, modes)
    ax.legend(ncol=3, frameon=False, loc="upper left")
    ax.grid(axis="x", visible=False)
    fig.tight_layout()
    return _save(fig, out, "fig_latency")


def fig_leakage(summary: dict[str, Any], out: Path) -> list[str]:
    modes = [m for m in ["B0", "B1", "B2", "B3", "B4", "B5", "B4T", "B4TR"] if m in summary["by_mode"]]
    values = [summary["by_mode"][mode]["attack"]["leak_bytes_total"] for mode in modes]
    fig, ax = plt.subplots(figsize=(5.0, 2.7))
    bars = ax.bar(range(len(modes)), values, color=[PALETTE[m] for m in modes], width=0.65)
    ax.set_ylabel("Delivered bytes in successful attacks")
    ax.set_xticks(range(len(modes)), modes)
    for bar, value in zip(bars, values, strict=False):
        ax.text(
            bar.get_x() + bar.get_width() / 2,
            bar.get_height() + max(values) * 0.02,
            f"{value:.0f}",
            ha="center",
            va="bottom",
            fontsize=8,
        )
    ax.set_ylim(0, max(values) * 1.18 if values else 1)
    ax.grid(axis="x", visible=False)
    fig.tight_layout()
    return _save(fig, out, "fig_leakage")


def fig_architecture(out: Path) -> list[str]:
    """A compact architecture and decision-flow diagram for the paper."""

    from matplotlib.patches import FancyArrowPatch, FancyBboxPatch

    fig, ax = plt.subplots(figsize=(9.4, 6.0))
    ax.set_xlim(0, 9.4)
    ax.set_ylim(0, 6.0)
    ax.axis("off")

    def box(
        x: float,
        y: float,
        w: float,
        h: float,
        title: str,
        body: str = "",
        *,
        face: str = "#E8EEF7",
        edge: str = "#355070",
        title_size: float = 9.5,
        body_size: float = 7.6,
        rounded: float = 0.08,
    ) -> None:
        patch = FancyBboxPatch(
            (x, y),
            w,
            h,
            boxstyle=f"round,pad=0.012,rounding_size={rounded}",
            linewidth=1.0,
            edgecolor=edge,
            facecolor=face,
            zorder=2,
        )
        ax.add_patch(patch)
        ax.text(
            x + w / 2,
            y + h - 0.16 if body else y + h / 2,
            title,
            ha="center",
            va="top" if body else "center",
            fontsize=title_size,
            fontweight="bold",
            color="#1D2B3A",
            zorder=3,
        )
        if body:
            ax.text(
                x + w / 2,
                y + h - 0.42,
                body,
                ha="center",
                va="top",
                fontsize=body_size,
                color="#34495E",
                linespacing=1.25,
                zorder=3,
            )

    def arrow(
        start: tuple[float, float],
        end: tuple[float, float],
        *,
        color: str = "#355070",
        style: str = "-|>",
        lw: float = 1.35,
        dashed: bool = False,
        rad: float = 0.0,
    ) -> None:
        ax.add_patch(
            FancyArrowPatch(
                start,
                end,
                arrowstyle=style,
                mutation_scale=12,
                linewidth=lw,
                color=color,
                linestyle=(0, (3, 2)) if dashed else "solid",
                connectionstyle=f"arc3,rad={rad}",
                zorder=1,
            )
        )

    # Left: agent and data sources.
    box(0.15, 4.55, 2.05, 1.15, "Tool-using agent", "planner / executor\nuntrusted inputs", face="#F4F4F4")
    box(0.15, 2.55, 2.05, 1.10, "Untrusted content", "PDFs, web pages,\nemail, tool output", face="#FDF2E9", edge="#B9770E")
    box(0.15, 1.10, 2.05, 1.10, "Sensitive data", "credentials, board\nmemo, customer rows", face="#FDEDEC", edge="#A93226")

    # Gateway, with an ordered decision pipeline.
    gateway = FancyBboxPatch(
        (2.65, 0.35),
        4.25,
        5.35,
        boxstyle="round,pad=0.02,rounding_size=0.10",
        linewidth=1.4,
        edgecolor="#1F4E79",
        facecolor="#F8FBFF",
        zorder=0,
    )
    ax.add_patch(gateway)
    ax.text(4.775, 5.58, "AgentFence mediation point", ha="center", va="top", fontsize=10, fontweight="bold", color="#1F4E79")

    stages = [
        (4.70, "1  Capability authentication", "HMAC token, expiry, task scope, budget", "#E8EEF7"),
        (3.82, "2  Deterministic policy", "default deny; path, egress, rate, approval", "#E8EEF7"),
        (2.94, "3  Provenance and DLP", "labels, hash registry, encodings, split egress", "#E8EEF7"),
        (2.06, "4  Risk engine (advisory)", "injection, sensitivity, anomaly, destination", "#FFF4E5"),
        (1.18, "5  Approval transaction", "exact preview; hash-bound; single use", "#E8F6EF"),
    ]
    for y, title, body, face in stages:
        box(2.85, y, 3.85, 0.72, title, body, face=face, title_size=9.0, body_size=7.2, rounded=0.06)
    for upper, lower in zip([4.70, 3.82, 2.94, 2.06], [3.82, 2.94, 2.06, 1.18], strict=False):
        arrow((4.775, upper), (4.775, lower + 0.72), lw=1.2)

    # Right: human approver at the approval stage, tools below, audit above.
    box(7.25, 1.18, 1.95, 0.92, "Human approver", "exact preview and\ndecoded payload", face="#FFF4E5", edge="#B9770E")
    box(7.25, 0.18, 1.95, 0.78, "Simulated tools", "file  http  email  db", face="#E8F6EF", edge="#1E8449")
    box(7.25, 3.35, 1.95, 0.92, "Audit log", "hash chain + HMAC;\nall decisions", face="#F4ECF7", edge="#6C3483")

    # Data-flow arrows.
    arrow((2.20, 4.95), (2.85, 4.98), color="#1F4E79")
    ax.text(2.47, 5.08, "call", ha="center", fontsize=6.6, color="#1F4E79")
    arrow((2.20, 3.18), (2.85, 3.25), color="#B9770E", dashed=True)
    ax.text(2.45, 3.38, "data", ha="center", fontsize=6.6, color="#B9770E")
    arrow((2.20, 1.65), (2.85, 3.05), color="#A93226", dashed=True, rad=-0.18)
    ax.text(2.38, 2.30, "reads", ha="center", fontsize=6.8, color="#A93226", rotation=72)

    arrow((6.70, 1.64), (7.25, 1.64), color="#B9770E", style="<|-|>")
    ax.text(6.98, 1.96, "approve", ha="center", va="bottom", fontsize=6.3, color="#B9770E")
    arrow((6.62, 1.18), (7.25, 0.86), color="#1E8449")
    ax.text(7.00, 0.98, "execute", ha="center", fontsize=6.6, color="#1E8449")
    arrow((6.70, 2.40), (7.25, 3.58), color="#6C3483", dashed=True, rad=-0.10)
    ax.text(7.03, 3.06, "log", ha="center", fontsize=6.6, color="#6C3483")

    # Monotonicity callout.
    ax.text(
        4.775,
        0.66,
        "BLOCK is final.\nRisk and approvals can only tighten.",
        ha="center",
        va="center",
        fontsize=8.0,
        color="#A93226",
        fontweight="bold",
        linespacing=1.2,
    )

    fig.subplots_adjust(left=0, right=1, top=1, bottom=0)
    return _save(fig, out, "fig_architecture")


def write_figures(summary: dict[str, Any], out: Path) -> list[str]:
    _style()
    paths: list[str] = []
    paths += fig_architecture(out)
    paths += fig_asr_by_family(summary, out)
    paths += fig_security_utility(summary, out)
    paths += fig_ablation(summary, out)
    paths += fig_latency(summary, out)
    paths += fig_leakage(summary, out)
    (out / "figures.json").write_text(json.dumps(paths, indent=2), encoding="utf-8")
    return paths


def main(argv: list[str] | None = None) -> int:
    import argparse

    parser = argparse.ArgumentParser(description="Generate AgentFence figures")
    parser.add_argument("summary", nargs="?", default="results/main/summary.json")
    parser.add_argument("--out", default="results/main/figures")
    args = parser.parse_args(argv)
    summary = json.loads(Path(args.summary).read_text(encoding="utf-8"))
    print("\n".join(write_figures(summary, Path(args.out))))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
