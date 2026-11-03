"""CLI and API MCP-server totals come from one rule: ``MCPServer.counts_as_mcp_server``."""

from __future__ import annotations

from agent_bom.api.push_evidence import derive_push_summary
from agent_bom.domain.inventory_types import ServerSurface
from agent_bom.domain.mcp_model import SBOM_DECLARED_MCP_SOURCE, MCPServer, server_dict_counts_as_mcp_server
from agent_bom.models import Agent, AgentType, AIBOMReport


def _servers() -> list[MCPServer]:
    return [
        MCPServer(name="fs", command="npx"),
        MCPServer(name="proj", surface=ServerSurface.FILESYSTEM),
        MCPServer(name="img", surface=ServerSurface.CONTAINER_IMAGE),
        MCPServer(name="bom-mcp", surface=ServerSurface.SBOM, discovery_sources=[SBOM_DECLARED_MCP_SOURCE]),
        MCPServer(name="bom-pkg", surface=ServerSurface.SBOM),
    ]


def _as_dict(server: MCPServer) -> dict:
    return {"name": server.name, "surface": server.surface.value, "discovery_sources": list(server.discovery_sources)}


def test_dict_rule_matches_the_model_rule() -> None:
    for server in _servers():
        assert server_dict_counts_as_mcp_server(_as_dict(server)) is server.counts_as_mcp_server, server.name
    assert server_dict_counts_as_mcp_server({}) is True  # legacy rows without a surface are MCP servers


def test_push_summary_counts_mcp_servers_like_the_cli() -> None:
    agent = Agent(name="a", agent_type=AgentType.CUSTOM, config_path="x", mcp_servers=_servers())
    report = AIBOMReport(agents=[agent])
    payload = {"scan_id": "s1", "agents": [{"name": "a", "mcp_servers": [_as_dict(s) for s in _servers()]}]}
    derive_push_summary(payload)
    assert payload["summary"]["total_mcp_servers"] == report.total_servers == 2


def test_fleet_counts_use_the_same_rule() -> None:
    from agent_bom.api.routes.fleet import _payload_counts, _server_counts

    agent = Agent(name="a", agent_type=AgentType.CUSTOM, config_path="x", mcp_servers=_servers())
    assert _server_counts(agent)[0] == 2
    assert _payload_counts({"mcp_servers": [_as_dict(s) for s in _servers()]})[0] == 2
