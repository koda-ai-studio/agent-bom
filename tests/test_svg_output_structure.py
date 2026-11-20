"""Structural characterization of the static SVG supply-chain diagram."""

from __future__ import annotations

import re

from agent_bom.models import Agent, AgentType, AIBOMReport, BlastRadius, MCPServer, Package, Severity, Vulnerability
from agent_bom.output.svg import to_svg


def _report() -> tuple[AIBOMReport, list[BlastRadius]]:
    vulnerable = Package(name="lodash", version="4.17.20", ecosystem="npm")
    clean = Package(name="zod", version="3.22.0", ecosystem="npm")
    shared = Package(name="requests", version="2.28.0", ecosystem="pypi")
    cred_server = MCPServer(name="github", command="npx", packages=[vulnerable, shared], env={"GITHUB_TOKEN": "x"})
    clean_server = MCPServer(name="files", command="npx", packages=[clean, shared])
    desktop = Agent(name="desk", agent_type=AgentType.CLAUDE_DESKTOP, config_path="/c.json", mcp_servers=[cred_server, clean_server])
    cloud = Agent(
        name="bedrock-agent", agent_type=AgentType.CUSTOM, config_path="aws://x", source="aws-bedrock", mcp_servers=[clean_server]
    )
    radii = [
        BlastRadius(
            package=vulnerable,
            vulnerability=Vulnerability(id=cve, severity=severity, summary="s"),
            affected_agents=[desktop],
            affected_servers=[cred_server],
            exposed_credentials=["GITHUB_TOKEN"],
            exposed_tools=[],
        )
        for cve, severity in (("CVE-2024-0001", Severity.CRITICAL), ("CVE-2024-0002", Severity.HIGH))
    ]
    return AIBOMReport(agents=[desktop, cloud], blast_radii=radii), radii


def test_svg_structure_for_vulnerable_and_credentialed_estate() -> None:
    report, radii = _report()
    svg = to_svg(report, radii)

    assert svg.startswith('<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 1390 ')
    assert svg.endswith("</svg>")
    assert "2 agents | 3 servers | 3 packages | 2 CVEs</text>" in svg
    for header in ("Sources", "Agents", "MCP Servers", "Packages", "CVEs"):
        assert f">{header}</text>" in svg
    for label in ("Local", "AWS Bedrock", "github [1 cred]", "files", "lodash@4.17.20", "CVE-2024-0001", "CVE-2024-0002"):
        assert f">{label}</text>" in svg
    # Vulnerable server/package and per-severity CVE colors.
    assert 'fill="#fbe9e7" stroke="#ef9a9a"' in svg
    assert 'fill="#ffebee" stroke="#ef9a9a"' in svg
    assert 'fill="#ffcdd2" stroke="#ef5350"' in svg
    assert 'fill="#ffe0b2" stroke="#ff9800"' in svg
    assert svg.count("<rect ") == 2 + 2 + 3 + 3 + 2
    assert svg.count('marker-end="url(#arrow)"') == 2 + 3 + 6 + 2
    assert "data-version-source=" in svg
    assert "<metadata>" not in svg
    assert "page-1" not in svg
    assert "No agents discovered" not in svg


def test_svg_without_cves_drops_cve_column() -> None:
    report, _ = _report()
    svg = to_svg(AIBOMReport(agents=report.agents), [])
    assert 'viewBox="0 0 1120 ' in svg
    assert ">CVEs</text>" not in svg
    assert "0 CVEs</text>" in svg


def test_svg_empty_report_shows_empty_state() -> None:
    svg = to_svg(AIBOMReport(agents=[]), [])
    assert "0 agents | 0 servers | 0 packages | 0 CVEs</text>" in svg
    assert ">No agents discovered</text>" in svg
    assert svg.count("<rect ") == 0


def test_svg_unbounded_large_column_paginates_and_summarizes_cross_page_edges() -> None:
    packages = [Package(name=f"pkg-{idx:03d}", version="1.0.0", ecosystem="npm") for idx in range(120)]
    agent = Agent(
        name="a",
        agent_type=AgentType.CLAUDE_DESKTOP,
        config_path="/c.json",
        mcp_servers=[MCPServer(name="s", command="npx", packages=packages)],
    )
    svg = to_svg(AIBOMReport(agents=[agent]), [], max_rows_per_column=None)
    assert re.findall(r'<g id="page-(\d+)">', svg) == ["1", "2", "3"]
    assert "Page 3 of 3</text>" in svg
    assert "70 cross-page relationships summarized" in svg


def test_svg_bounded_column_records_omissions() -> None:
    packages = [Package(name=f"pkg-{idx:03d}", version="1.0.0", ecosystem="npm") for idx in range(10)]
    agent = Agent(
        name="a",
        agent_type=AgentType.CLAUDE_DESKTOP,
        config_path="/c.json",
        mcp_servers=[MCPServer(name="s", command="npx", packages=packages)],
    )
    svg = to_svg(AIBOMReport(agents=[agent]), [], max_rows_per_column=4)
    assert "<metadata>Bounded SVG export: omitted 7 packages and 7 edges." in svg
    assert "Bounded view: 7 nodes and 7 edges omitted" in svg
    assert ">7 more packages omitted</text>" in svg
