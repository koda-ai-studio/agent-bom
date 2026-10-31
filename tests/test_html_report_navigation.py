"""Exported reports keep investigation sections focused and inventory labels honest."""

import re

import pytest

from agent_bom.models import Agent, AgentType, AIBOMReport, BlastRadius, MCPServer, Package, Severity, Vulnerability
from agent_bom.output.graph import build_attack_flow_elements
from agent_bom.output.html import to_html
from agent_bom.output.html.scripts import SCALE_REPORT_SCRIPT, _apply_offline_assets_mode, render_graph_script


def project_report() -> AIBOMReport:
    package = Package(name="requests", version="2.25.0", ecosystem="pypi")
    vuln = Vulnerability(id="CVE-TEST", severity=Severity.MEDIUM, summary="fixture")
    package.vulnerabilities = [vuln]
    server = MCPServer(name="example", command="project", surface="other", packages=[package])
    agent = Agent(name="project:example", source="project", agent_type=AgentType.CUSTOM, config_path="/example", mcp_servers=[server])
    return AIBOMReport(
        agents=[agent],
        blast_radii=[
            BlastRadius(
                package=package,
                vulnerability=vuln,
                affected_agents=[agent],
                affected_servers=[server],
                exposed_credentials=[],
                exposed_tools=[],
            )
        ],
    )


def test_project_attack_graph_records_inventory_without_inventing_runtime_nodes():
    elements = build_attack_flow_elements(project_report())
    nodes = [item["data"] for item in elements if "source" not in item["data"]]
    assert {node["type"] for node in nodes} == {"cve", "pkg_vuln", "directory"}
    assert all("MCP Server" not in node.get("tip", "") for node in nodes)
    edges = [item["data"] for item in elements if "source" in item["data"]]
    assert any(edge["type"] == "recorded_in" for edge in edges)
    assert not any(edge["type"] == "compromises" for edge in edges)


def test_report_separates_graphs_findings_and_remediation_with_accessible_tabs():
    page = to_html(project_report())
    for section, tab in [
        ("riskmap", "graphs"),
        ("attackflow", "graphs"),
        ("inventory", "agents"),
        ("vulns", "findings"),
        ("remediation", "remediation"),
    ]:
        assert f'<section id="{section}" data-tab="{tab}"' in page
    assert 'role="tab" aria-selected="true"' in page
    assert 'aria-label="Report sections"' in page
    assert re.search(r'<section id="attackflow"[^>]*>\s*<details class="report-disclosure">', page)
    assert "Inventory sources" in page


def test_offline_report_retains_navigation_without_external_graph_libraries():
    page = to_html(project_report(), offline_assets=True)
    assert 'role="tablist"' in page
    assert 'data-tab="graphs"' in page
    assert "<script src=" not in page
    assert "Interactive rendering is disabled" in page
    assert "function activateTab" in page
    assert "window.PAGINATORS" in page
    assert "var CHART_DATA" not in page
    assert "cytoscape(" not in page


@pytest.mark.parametrize("suffix", ["</body>", "\n\n</body>", "\n\n\n</body>", '<script id="later">keep();</script></body>'])
def test_offline_replacement_preserves_adjacent_scripts_regardless_of_footer_spacing(suffix):
    graph_script = render_graph_script("{}", "[]", "[]")
    page = _apply_offline_assets_mode(SCALE_REPORT_SCRIPT + "\n" + graph_script + suffix)

    assert SCALE_REPORT_SCRIPT in page
    assert page.endswith(suffix)
    assert "Interactive rendering is disabled" in page
    assert "var CHART_DATA" not in page
    assert "cytoscape(" not in page
