"""Run a real ``agent-bom scan`` against loopback serving fixtures and store the graph."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from click.testing import CliRunner

from agent_bom.cli import main
from agent_bom.graph.builder import build_unified_graph_from_report


def scan_serving(tmp_path: Path, endpoints: list[str], *, fmt: str = "json", env: dict[str, str] | None = None) -> tuple[Path, str]:
    """Scan only the given ``RUNTIME=URL`` endpoints; return the output file and CLI output."""
    out = tmp_path / f"report-{len(list(tmp_path.glob('report-*')))}.{fmt}"
    args = ["scan", "--no-scan", "--quiet", "-f", fmt, "-o", str(out)]
    for endpoint in endpoints:
        args += ["--serving-endpoint", endpoint]
    result = CliRunner().invoke(main, args, env={"HOME": str(tmp_path), **(env or {})})
    assert out.exists(), result.output
    return out, result.output


def scan_serving_report(tmp_path: Path, endpoints: list[str]) -> dict[str, Any]:
    out, _output = scan_serving(tmp_path, endpoints)
    return json.loads(out.read_text())


def store_report(store: Any, report: dict[str, Any], *, scan_id: str, tenant_id: str = "default", created_at: str = "") -> Any:
    graph = build_unified_graph_from_report(report, scan_id=scan_id, tenant_id=tenant_id)
    if created_at:
        graph.created_at = created_at
    store.save_graph(graph)
    return graph


def serving_agent_ids(graph: Any) -> dict[str, str]:
    """``served_name -> node id`` for every agent node carrying serving evidence."""
    found: dict[str, str] = {}
    for node in graph.nodes.values():
        evidence = (node.attributes or {}).get("serving_evidence")
        if evidence:
            found[evidence["model"]["served_name"]] = node.id
    return found
