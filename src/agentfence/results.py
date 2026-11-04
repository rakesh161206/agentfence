"""Read the evaluation artifacts for the dashboard.

The repository keeps experiment output under ``results/``.  A packaged install
does not ship that directory, so a compact snapshot is also kept in ``static/``
and used as a fallback.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

PACKAGE_DIR = Path(__file__).resolve().parent
REPO_DIR = PACKAGE_DIR.parents[1]
STATIC_DIR = PACKAGE_DIR / "static"


def _read_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None


def _first(*paths: Path) -> Any:
    for path in paths:
        value = _read_json(path)
        if value is not None:
            return value
    return None


def load_results() -> dict[str, Any]:
    main = _first(
        REPO_DIR / "results" / "main" / "summary.json",
        STATIC_DIR / "results_main.json",
    )
    recall = _first(
        REPO_DIR / "results" / "sweep" / "recall_summary.json",
        STATIC_DIR / "results_sweep_recall.json",
    )
    fpr = _first(
        REPO_DIR / "results" / "sweep" / "fpr_summary.json",
        STATIC_DIR / "results_sweep_fpr.json",
    )
    sweep_manifest = _first(
        REPO_DIR / "results" / "sweep" / "manifest.json",
        STATIC_DIR / "results_sweep_manifest.json",
    )
    deny_all = _first(
        REPO_DIR / "results" / "approval_deny" / "summary.json",
        STATIC_DIR / "results_approval_deny.json",
    )
    return {
        "main": main,
        "sweep": {
            "recall": recall or [],
            "fpr": fpr or [],
            "manifest": sweep_manifest or {},
        },
        "deny_all": deny_all,
        "available": main is not None,
    }
