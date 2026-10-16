"""Configured overlap must not become delegation, credential access, or risk."""

from __future__ import annotations

import pytest

from agent_bom.models import (
    Agent,
    AgentStatus,
    AgentType,
    BlastRadius,
    MCPServer,
    MCPTool,
    Package,
    Severity,
    TransportType,
    Vulnerability,
)
from agent_bom.scanners import expand_blast_radius_hops


def _make_agent(name: str, servers: list[MCPServer]) -> Agent:
    return Agent(
        name=name,
        agent_type=AgentType.CUSTOM,
        config_path="/tmp/test",
        source="test",
        status=AgentStatus.CONFIGURED,
        mcp_servers=servers,
    )


def _make_server(name: str, packages: list[Package] | None = None, cred_names: list[str] | None = None) -> MCPServer:
    srv = MCPServer(
        name=name,
        command="node",
        args=[f"{name}.js"],
        transport=TransportType.STDIO,
        packages=packages or [],
    )
    # Set credential env vars via env dict for credential_names property
    if cred_names:
        srv.env = {k: "***" for k in cred_names}
    return srv


def _make_vuln(vuln_id: str = "CVE-2025-0001", severity: Severity = Severity.HIGH) -> Vulnerability:
    return Vulnerability(id=vuln_id, summary="Test vuln", severity=severity)


def _make_pkg(name: str = "test-pkg", version: str = "1.0.0") -> Package:
    return Package(name=name, version=version, ecosystem="npm")


def _make_blast_radius(
    vuln: Vulnerability,
    pkg: Package,
    servers: list[MCPServer],
    agents: list[Agent],
) -> BlastRadius:
    br = BlastRadius(
        vulnerability=vuln,
        package=pkg,
        affected_servers=servers,
        affected_agents=agents,
        exposed_credentials=[],
        exposed_tools=[MCPTool(name="read_file", description="Read a file")],
    )
    br.risk_score = 6.0
    return br


def test_shared_configuration_is_not_delegation_or_credential_access():
    vulnerable = _make_server("vulnerable")
    common = _make_server("common")
    secret = _make_server("private", cred_names=["OTHER_TENANT_API_KEY"])
    first = _make_agent("first", [vulnerable, common])
    second = _make_agent("second", [common, secret])
    result = _make_blast_radius(_make_vuln(), _make_pkg(), [vulnerable], [first])
    expand_blast_radius_hops([result], [first, second], max_depth=5)
    assert result.transitive_agents == []
    assert result.transitive_credentials == []
    assert result.delegation_chain == []
    assert result.graph_reachable is None


@pytest.mark.parametrize("depth", [0, 1, 2, 3, 5, 10])
@pytest.mark.parametrize("remote", [False, True])
def test_overlap_and_cycles_preserve_only_direct_scanner_scope(depth, remote):
    vulnerable = _make_server("vulnerable")
    common = _make_server("common", cred_names=["OTHER_API_KEY"])
    if remote:
        common.url = "https://shared.example/mcp"
        common.transport = TransportType.SSE
    first = _make_agent("same-label", [vulnerable, common])
    second = _make_agent("same-label", [common, vulnerable])
    second.config_path = "/other/config.json"
    second.parent_agent = first.name
    result = _make_blast_radius(_make_vuln(), _make_pkg(), [vulnerable], [first])
    before = result.model_dump() if hasattr(result, "model_dump") else repr(result)
    expand_blast_radius_hops([result], [first, second], max_depth=depth)
    assert result.hop_depth == 1
    assert result.delegation_chain == []
    assert result.transitive_agents == [] and result.transitive_credentials == []
    assert result.transitive_risk_score == 0
    assert result.graph_reachable is None and result.graph_min_hop_distance is None
    assert (result.model_dump() if hasattr(result, "model_dump") else repr(result)) == before


def test_compatibility_call_does_not_rewrite_existing_evidence():
    result = _make_blast_radius(_make_vuln(), _make_pkg(), [], [])
    result.delegation_chain = ["historical supplied receipt"]
    result.transitive_agents = [{"name": "historical", "evidence_id": "receipt-1"}]
    result.hop_depth = 2
    result.transitive_risk_score = 4.2
    before = repr(result)
    expand_blast_radius_hops([result], [], max_depth=5)
    assert repr(result) == before


def test_direct_scope_is_preserved_in_json_findings_and_graph():
    from agent_bom.graph.builder import build_unified_graph_from_report
    from agent_bom.graph.types import RelationshipType
    from agent_bom.models import AIBOMReport
    from agent_bom.output.json_fmt import to_json

    vulnerable = _make_server("vulnerable")
    common = _make_server("common", cred_names=["OTHER_API_KEY"])
    first, second = _make_agent("first", [vulnerable, common]), _make_agent("second", [common])
    result = _make_blast_radius(_make_vuln(), _make_pkg(), [vulnerable], [first])
    expand_blast_radius_hops([result], [first, second], max_depth=5)
    payload = to_json(AIBOMReport(agents=[first, second], blast_radii=[result], tool_version="0.0.0"))
    row = payload["blast_radius"][0]
    assert row["hop_depth"] == 1
    assert row["transitive_agents"] == [] and row["transitive_credentials"] == []
    assert row["transitive_risk_score"] == 0
    graph = build_unified_graph_from_report(payload)
    assert not any(edge.relationship == RelationshipType.DELEGATED_TO for edge in graph.edges)


def test_cli_help_does_not_promise_delegation_from_shared_configuration():
    from click.testing import CliRunner

    from agent_bom.cli import main

    result = CliRunner().invoke(main, ["scan", "--help-all"])
    assert result.exit_code == 0
    assert "Shared configuration does not prove delegation" in " ".join(result.output.split())
    assert "Higher values reveal transitive risk" not in result.output
