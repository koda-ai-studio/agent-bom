"""Every graph container names its recorded time; only a container without one reads the clock."""

from __future__ import annotations

import ast
from pathlib import Path

SRC = Path(__file__).resolve().parents[1] / "src" / "agent_bom"

# Containers that may take the clock: each names why no recorded time exists.
_CLOCK_ALLOWED = {
    "hardware_evidence.py": "operator evidence documents carry no collection time; ingest is the observation",
    "graph/lifecycle.py": "single-agent view of a live or stored agent record that carries no time",
    "api/graph_presentation.py": "scratch proof graph used only to re-derive techniques; its times are never read",
    "api/neptune_graph.py": "the load path restores the stored snapshot time after construction",
}
_CONSTRUCTORS = {"UnifiedGraph", "StoreBackedUnifiedGraph", "open_store_backed_unified_graph"}


def _clock_constructions() -> list[str]:
    found: list[str] = []
    for path in sorted(SRC.rglob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        returned = {id(child) for node in ast.walk(tree) if isinstance(node, ast.Return) and node.value for child in ast.walk(node.value)}
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            name = getattr(node.func, "id", None) or getattr(node.func, "attr", None)
            if name not in _CONSTRUCTORS or id(node) in returned:
                continue
            if any(keyword.arg in {"created_at", "observed_at", None} for keyword in node.keywords):
                continue
            found.append(f"{path.relative_to(SRC).as_posix()}:{node.lineno}")
    return found


def test_every_graph_container_names_its_recorded_time() -> None:
    """A container without ``created_at`` stamps every untimed node with the wall clock.

    Returning an empty container directly is fine: it holds nothing to stamp.
    """
    offenders = [site for site in _clock_constructions() if site.rsplit(":", 1)[0] not in _CLOCK_ALLOWED]
    assert not offenders, f"pass observed_at= (the scan time) or created_at= (the snapshot time) to: {offenders}"
