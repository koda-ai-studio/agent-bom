"""Workload inventory from Kubernetes manifests and rendered Helm charts.

Walks the same paths the IaC scan walks. Plain YAML documents that carry
``apiVersion`` and ``kind`` are Kubernetes objects; a chart's ``templates/``
are rendered with ``helm template`` (default values, local only) and the
rendered objects join the inventory. A chart that cannot be rendered is named
in the returned notes, never dropped silently.
"""

from __future__ import annotations

from collections.abc import Iterable
from pathlib import Path
from typing import Any

import yaml  # type: ignore[import-untyped]

from agent_bom.evidence.scan_run import ScanIssue
from agent_bom.iac import helm_templates
from agent_bom.kubernetes.inventory import build_k8s_inventory
from agent_bom.traversal import iter_discovery_files

_MAX_MANIFEST_BYTES = 2 * 1024 * 1024
_SKIP_PARTS = frozenset({"node_modules", "__pycache__"})


def _documents(text: str) -> list[dict[str, Any]]:
    try:
        docs = list(yaml.safe_load_all(text))
    except yaml.YAMLError:
        return []
    return [doc for doc in docs if isinstance(doc, dict) and isinstance(doc.get("kind"), str) and doc.get("apiVersion")]


def _chart_root(path: Path) -> Path | None:
    for parent in path.parents:
        if parent.name == "templates" and (parent.parent / "Chart.yaml").is_file():
            return parent.parent
    return None


def _files(root: Path) -> list[Path]:
    if root.is_file():
        return [root]
    files = []
    for path in sorted(iter_discovery_files(root)):
        parts = path.relative_to(root).parts
        if path.suffix in {".yaml", ".yml"} and not any(p.startswith(".") or p in _SKIP_PARTS for p in parts):
            files.append(path)
    return files


def _render(chart: Path) -> tuple[list[dict[str, Any]], str]:
    output, reason = helm_templates.render_chart(chart)
    return (_documents(output), "") if output is not None else ([], reason)


def k8s_inventory_from_paths(paths: Iterable[str]) -> tuple[dict[str, Any] | None, list[str]]:
    """``(inventory, notes)``; the inventory is ``None`` when no Kubernetes object was found."""
    objects: list[dict[str, Any]] = []
    manifest_files: list[str] = []
    charts: dict[Path, str] = {}
    notes: list[str] = []
    for raw in paths:
        root = Path(raw).expanduser().resolve()
        if not root.exists():
            continue
        base = root.parent if root.is_file() else root
        for path in _files(root):
            chart = _chart_root(path)
            if chart is not None:
                charts.setdefault(chart, chart.relative_to(base).as_posix() if chart != base else chart.name)
                continue
            if path.name in {"Chart.yaml", "chart.yaml"} or path.stat().st_size > _MAX_MANIFEST_BYTES:
                continue
            docs = _documents(path.read_text(encoding="utf-8", errors="replace"))
            if docs:
                objects.extend(docs)
                manifest_files.append(path.relative_to(base).as_posix())
    rendered: list[str] = []
    for chart, label in sorted(charts.items()):
        docs, reason = _render(chart)
        if reason:
            notes.append(f"{label}: {reason}; its workloads are not in the Kubernetes inventory")
        elif docs:
            objects.extend(docs)
            rendered.append(label)
    if not objects:
        return None, notes
    inventory = build_k8s_inventory(objects, source="manifest")
    inventory["manifest_files"] = manifest_files
    inventory["helm_charts"] = rendered
    return inventory, notes


def manifest_inventory_with_issues(root: Path) -> tuple[dict[str, Any] | None, list[ScanIssue]]:
    """The inventory for one scanned tree, with each unrendered chart as a coverage issue."""
    inventory, notes = k8s_inventory_from_paths([str(root)])
    issues = [
        ScanIssue(
            code="helm_chart_not_rendered",
            stage="discovery",
            source="kubernetes-manifest",
            message=f"Helm chart {note}",
            severity="warning",
            affects_coverage=True,
        )
        for note in notes
    ]
    return inventory, issues
