"""Snowflake CLI connections are not MCP servers, and mesh counts agents the way scan does."""

from __future__ import annotations

import json
from dataclasses import asdict
from pathlib import Path

from agent_bom.discovery.config_parsers import parse_snowflake_connections
from agent_bom.models import Agent, AgentStatus, AgentType, AIBOMReport, MCPServer, ServerSurface
from agent_bom.output.agent_mesh import build_agent_mesh


def _connections(tmp_path: Path) -> str:
    path = tmp_path / "connections.toml"
    path.write_text('[prod]\naccount = "acme-prod"\nuser = "svc"\n\n[dev]\naccount = "acme-dev"\n', encoding="utf-8")
    return str(path)


def test_snowflake_cli_connections_are_not_mcp_servers(tmp_path: Path) -> None:
    servers = parse_snowflake_connections(_connections(tmp_path))
    assert [s.name for s in servers] == ["sf-connection:prod", "sf-connection:dev"]
    assert all(s.surface == ServerSurface.DATA_CONNECTION for s in servers)
    assert not any(s.counts_as_mcp_server for s in servers)


def _host(tmp_path: Path) -> list[Agent]:
    mcp = MCPServer(name="filesystem", command="npx", args=["@modelcontextprotocol/server-filesystem"])
    return [
        Agent(name="claude", agent_type=AgentType.CLAUDE_DESKTOP, config_path="/c", mcp_servers=[mcp]),
        Agent(
            name="snow",
            agent_type=AgentType.SNOWFLAKE_CLI,
            config_path="/s",
            mcp_servers=parse_snowflake_connections(_connections(tmp_path)),
        ),
        Agent(name="cursor", agent_type=AgentType.CURSOR, config_path="", status=AgentStatus.INSTALLED_NOT_CONFIGURED),
        Agent(name="windsurf", agent_type=AgentType.WINDSURF, config_path="", status=AgentStatus.INSTALLED_NOT_CONFIGURED),
    ]


def test_scan_counts_exclude_connections_and_unconfigured_clients(tmp_path: Path) -> None:
    report = AIBOMReport(agents=_host(tmp_path))
    assert report.total_agents == 2
    assert report.total_servers == 1


def test_mesh_counts_match_scan_for_live_discovery(tmp_path: Path) -> None:
    agents = _host(tmp_path)
    report = AIBOMReport(agents=agents)
    stats = build_agent_mesh([asdict(agent) for agent in agents])["stats"]
    assert stats["total_agents"] == report.total_agents
    assert stats["total_servers"] == report.total_servers


def test_mesh_counts_match_scan_for_saved_report(tmp_path: Path) -> None:
    from agent_bom.output.json_fmt import to_json

    agents = _host(tmp_path)
    report = AIBOMReport(agents=agents)
    saved = json.loads(json.dumps(to_json(report), default=str))
    stats = build_agent_mesh(saved["agents"])["stats"]
    assert stats["total_agents"] == report.total_agents
    assert stats["total_servers"] == report.total_servers


def test_graph_keeps_the_connection_surface(tmp_path: Path) -> None:
    from agent_bom.graph.builder import build_unified_graph_from_report
    from agent_bom.output.json_fmt import to_json

    report = AIBOMReport(agents=_host(tmp_path))
    graph = build_unified_graph_from_report(json.loads(json.dumps(to_json(report), default=str)))
    surfaces = {
        node.label: node.dimensions.surface for node in graph.nodes.values() if node.label.startswith(("sf-connection:", "filesystem"))
    }
    assert surfaces == {"sf-connection:prod": "data-connection", "sf-connection:dev": "data-connection", "filesystem": "mcp-server"}
