"""graph-html: header counts match the canvas, the first view fits the graph, entrypoints name their file."""

from __future__ import annotations

import json
import re
from pathlib import Path

from agent_bom.models import Agent, AgentType, AIBOMReport, MCPServer, Package, ServerSurface, TransportType
from agent_bom.output.graph import build_graph_elements, export_graph_html
from agent_bom.output.graph_html_template_body import _GRAPH_HTML_TEMPLATE_BODY


def _surface_agent(name: str, surfaces: int) -> Agent:
    servers = [
        MCPServer(
            name=f"{name}:surface-{index}",
            command="python",
            transport=TransportType.STDIO,
            surface=ServerSurface.OTHER,
            packages=[Package(name=f"pkg{index}", version="1.0.0", ecosystem="pypi")],
            config_path=f"/work/{name}/app_{index}.py",
        )
        for index in range(surfaces)
    ]
    return Agent(name=name, agent_type=AgentType.CUSTOM, config_path=f"/work/{name}", mcp_servers=servers, source="python-agents")


def _drawn(html: str) -> list[dict]:
    match = re.search(r"const els=(\[.*?\]);\nconst topRisks", html, re.S)
    assert match
    return json.loads(match.group(1))


def test_header_server_count_matches_drawn_server_nodes(tmp_path: Path) -> None:
    report = AIBOMReport(agents=[_surface_agent("autogen:alpha", 2), _surface_agent("crewai:beta", 1)], blast_radii=[])
    out = tmp_path / "graph.html"

    export_graph_html(report, None, str(out))

    html = out.read_text(encoding="utf-8")
    drawn = [el for el in _drawn(html) if str(el["data"].get("type", "")).startswith("server_")]
    assert len(drawn) == 3
    assert "<span>3 servers</span>" in html


def test_offline_header_server_count_matches_drawn_server_nodes(tmp_path: Path) -> None:
    report = AIBOMReport(agents=[_surface_agent("autogen:alpha", 2)], blast_radii=[])
    out = tmp_path / "graph.html"

    export_graph_html(report, None, str(out), offline_assets=True)

    assert "<strong>2</strong>servers" in out.read_text(encoding="utf-8")


def _function(source: str, name: str) -> str:
    start = source.index(f"function {name}(")
    end = source.index("\n}}\n", start)
    return source[start:end]


def test_initial_view_fits_the_whole_graph_not_a_single_finding() -> None:
    ready = _GRAPH_HTML_TEMPLATE_BODY[_GRAPH_HTML_TEMPLATE_BODY.index("cy.ready(") :]
    assert "fitAll()" in ready
    assert "focusRisk" not in ready and "focusTopRisk" not in ready

    apply_filters = _function(_GRAPH_HTML_TEMPLATE_BODY, "applyFilters")
    # "All severities" is no filter: it must not hide every node without a severity.
    assert "activeSeverity !== 'all'" in apply_filters
    fit_all = _function(_GRAPH_HTML_TEMPLATE_BODY, "fitAll")
    assert "cy.elements(':visible')" in fit_all


def test_application_entrypoint_label_names_its_file() -> None:
    report = AIBOMReport(agents=[], blast_radii=[])
    report.ai_inventory_data = {
        "ast_analysis": {
            "application_entrypoints": [
                {"name": "main", "handler": "main", "file": "app/routing.py", "line": 3, "kind": "language_main"},
                {"name": "main", "handler": "main", "file": "app/worker.py", "line": 9, "kind": "language_main"},
            ]
        }
    }

    labels = sorted(el["data"]["label"] for el in build_graph_elements(report) if el["data"].get("type") == "application_entrypoint")

    assert labels == ["main · routing.py", "main · worker.py"]
