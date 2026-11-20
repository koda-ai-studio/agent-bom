"""Every graph builder and export names each node once; shared packages get more edges, not more nodes."""

from __future__ import annotations

import json
from collections import Counter
from pathlib import Path
from unittest import mock

import pytest
from click.testing import CliRunner

from agent_bom.cli import main
from agent_bom.models import Agent, AgentType, AIBOMReport, BlastRadius, MCPServer, Package, Severity, Vulnerability
from agent_bom.output.graph import build_attack_flow_elements, build_graph_elements, sanitize_graph_elements
from agent_bom.output.html.sections import _attack_flow_elements, _cytoscape_elements


def _duplicate_node_ids(elements: list[dict]) -> dict[str, int]:
    counts = Counter(e["data"]["id"] for e in elements if "source" not in e["data"] and "id" in e["data"])
    return {node_id: n for node_id, n in counts.items() if n > 1}


def _shared_package_report() -> tuple[AIBOMReport, list[BlastRadius]]:
    def pkg() -> Package:
        return Package(name="requests", version="2.28.0", ecosystem="pypi")

    agents = [
        Agent(
            name=name,
            agent_type=AgentType.CLAUDE_DESKTOP,
            config_path=f"/tmp/{name}.json",
            mcp_servers=[
                MCPServer(name=f"{name}-a", command="uvx", args=["a"], packages=[pkg()]),
                MCPServer(name=f"{name}-b", command="uvx", args=["b"], packages=[pkg()]),
            ],
        )
        for name in ("alpha", "beta")
    ]
    vuln = Vulnerability(id="CVE-2023-32681", severity=Severity.MEDIUM, summary="leak", cvss_score=6.1)
    br = BlastRadius(
        package=pkg(),
        vulnerability=vuln,
        affected_agents=agents,
        affected_servers=[s for a in agents for s in a.mcp_servers],
        exposed_credentials=[],
        exposed_tools=[],
    )
    return AIBOMReport(agents=agents, blast_radii=[br]), [br]


@pytest.mark.parametrize(
    "kwargs",
    [{}, {"include_cve_nodes": False}, {"collapse_cves": True}, {"collapse_cves": True, "include_cve_nodes": False}],
)
def test_build_graph_elements_names_a_shared_package_once(kwargs) -> None:
    report, brs = _shared_package_report()
    elements = build_graph_elements(report, brs, **kwargs)
    assert _duplicate_node_ids(elements) == {}
    if not kwargs.get("collapse_cves"):
        edges = {(e["data"]["source"], e["data"]["target"]) for e in elements if "source" in e["data"]}
        pkg_edges = [pair for pair in edges if pair[1] == "pkg:pypi:requests@2.28.0"]
        assert len(pkg_edges) == 4


def test_shared_package_edges_carry_the_same_evidence_from_every_server() -> None:
    report, brs = _shared_package_report()
    edges = [e["data"] for e in build_graph_elements(report, brs) if e["data"].get("target") == "pkg:pypi:requests@2.28.0"]
    assert len(edges) == 4
    assert {edge.get("maxSeverity") for edge in edges} == {"medium"}
    assert {edge.get("vulnCount") for edge in edges} == {1}


def test_attack_flow_and_html_report_graphs_have_unique_node_ids() -> None:
    report, brs = _shared_package_report()
    assert _duplicate_node_ids(build_attack_flow_elements(report, brs)) == {}
    assert _duplicate_node_ids(json.loads(_cytoscape_elements(report, brs))) == {}
    assert _duplicate_node_ids(json.loads(_attack_flow_elements(report, brs))) == {}


def test_sanitize_graph_elements_never_emits_a_node_id_twice() -> None:
    elements = [
        {"data": {"id": "pkg:pypi:x@1", "label": "x"}},
        {"data": {"id": "pkg:pypi:x@1", "label": "x"}},
        {"data": {"source": "pkg:pypi:x@1", "target": "cve:1", "type": "affects"}},
    ]
    projected, _ = sanitize_graph_elements(elements)
    assert _duplicate_node_ids(projected) == {}
    assert len([e for e in projected if "source" in e["data"]]) == 1


def test_cli_demo_graph_export_has_unique_node_ids(tmp_path: Path) -> None:
    out = tmp_path / "demo.graph.json"
    with mock.patch("agent_bom.db.local_analytics.record_scan_report_best_effort", lambda *_a, **_k: None):
        CliRunner().invoke(
            main,
            ["scan", "--demo", "--offline", "--no-auto-update-db", "--quiet", "--format", "graph", "--output", str(out)],
            catch_exceptions=False,
        )
    elements = json.loads(out.read_text())["elements"]
    nodes = [e for e in elements if "source" not in e["data"]]
    assert len(nodes) > 50
    assert _duplicate_node_ids(elements) == {}
    node_ids = {e["data"]["id"] for e in nodes}
    dangling = [e["data"] for e in elements if "source" in e["data"] and not {e["data"]["source"], e["data"]["target"]} <= node_ids]
    assert dangling == []
