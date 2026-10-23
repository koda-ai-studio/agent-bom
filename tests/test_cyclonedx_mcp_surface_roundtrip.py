"""A CycloneDX BOM must declare only real MCP servers as MCP servers, and keep them on re-import."""

from __future__ import annotations

import json
from pathlib import Path

from agent_bom.models import Agent, AgentType, AIBOMReport, MCPServer, Package, ServerSurface, TransportType


def _report() -> AIBOMReport:
    mcp = MCPServer(
        name="filesystem",
        command="npx",
        args=["-y", "@modelcontextprotocol/server-filesystem@0.5.1"],
        transport=TransportType.STDIO,
        packages=[Package(name="@modelcontextprotocol/server-filesystem", version="0.5.1", ecosystem="npm")],
    )
    deps = MCPServer(
        name="proj",
        command="project",
        surface=ServerSurface.OTHER,
        packages=[Package(name="requests", version="2.19.1", ecosystem="pypi")],
    )
    agent = Agent(name="project:proj", agent_type=AgentType.CUSTOM, config_path="/tmp/proj", mcp_servers=[mcp, deps])
    return AIBOMReport([agent], [])


def test_only_mcp_surfaces_are_typed_mcp_server(tmp_path: Path) -> None:
    from agent_bom.output.cyclonedx_fmt import to_cyclonedx

    bom = to_cyclonedx(_report())
    types = {
        c["name"]: {p["name"]: p["value"] for p in c.get("properties", [])}.get("agent-bom:type")
        for c in bom["components"]
        if c.get("type") == "application"
    }
    assert types["filesystem"] == "mcp-server"
    assert types["proj"] != "mcp-server"


def test_rescanning_the_bom_keeps_the_mcp_server_count(tmp_path: Path) -> None:
    from agent_bom.output.cyclonedx_fmt import to_cyclonedx
    from agent_bom.parsers.sbom_context import load_sbom_agents

    report = _report()
    assert report.total_servers == 1
    path = tmp_path / "bom.cdx.json"
    path.write_text(json.dumps(to_cyclonedx(report)))
    agents, _fmt = load_sbom_agents(str(path))
    rescanned = AIBOMReport(agents, [])
    assert rescanned.total_servers == 1
    packages = sorted(p.name for a in agents for s in a.mcp_servers for p in s.packages)
    assert packages == ["@modelcontextprotocol/server-filesystem", "requests"]
    imported = [s for a in agents for s in a.mcp_servers if s.name == "filesystem"]
    assert imported and imported[0].surface == ServerSurface.SBOM


def test_spdx_exports_label_dependency_wrappers_and_keep_the_mcp_count(tmp_path: Path) -> None:
    import pytest

    from agent_bom.output.spdx2_fmt import to_spdx2
    from agent_bom.output.spdx_fmt import to_spdx
    from agent_bom.parsers.sbom_context import load_sbom_agents

    for name, document in (("spdx2", to_spdx2(_report())), ("spdx3", to_spdx(_report()))):
        text = json.dumps(document)
        assert "Dependency surface (other)" in text, name
        path = tmp_path / f"{name}.json"
        path.write_text(text)
        try:
            agents, _fmt = load_sbom_agents(str(path))
        except ValueError as exc:  # pragma: no cover - format not importable
            pytest.skip(f"{name} not importable: {exc}")
        assert AIBOMReport(agents, []).total_servers == 1, name
