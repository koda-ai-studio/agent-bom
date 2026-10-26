"""Every CycloneDX component that has a graph node carries that node's canonical id."""

from __future__ import annotations

from agent_bom.graph import EntityType
from agent_bom.graph.builder import build_unified_graph_from_report
from agent_bom.models import Agent, AgentType, AIBOMReport, MCPServer, Package, TransportType
from agent_bom.output.cyclonedx_fmt import to_cyclonedx
from agent_bom.output.json_fmt import to_json


def _report() -> AIBOMReport:
    shared = Package(name="requests", version="2.19.1", ecosystem="pypi")
    servers = [
        MCPServer(
            name="filesystem",
            command="npx",
            args=["-y", "@modelcontextprotocol/server-filesystem@0.5.1"],
            transport=TransportType.STDIO,
            packages=[Package(name="@modelcontextprotocol/server-filesystem", version="0.5.1", ecosystem="npm"), shared],
        ),
        MCPServer(name="github", command="uvx", args=["mcp-server-github"], transport=TransportType.STDIO, packages=[shared]),
    ]
    agents = [
        Agent(name="claude-desktop", agent_type=AgentType.CLAUDE_DESKTOP, config_path="/work/a.json", mcp_servers=servers),
        Agent(name="cursor", agent_type=AgentType.CURSOR, config_path="/work/b.json", mcp_servers=[servers[1]]),
    ]
    return AIBOMReport(agents, [])


def _component_canonical_ids(bom: dict, kinds: set[str]) -> dict[str, set[str]]:
    joined: dict[str, set[str]] = {}
    for component in bom["components"]:
        props = {prop["name"]: prop["value"] for prop in component.get("properties", [])}
        kind = props.get("agent-bom:type") or ("package" if component.get("type") == "library" else "")
        if kind in kinds:
            assert props.get("agent-bom:canonical-id"), f"{component['bom-ref']} has no agent-bom:canonical-id"
            joined.setdefault(kind, set()).add(props["agent-bom:canonical-id"])
    return joined


def test_agent_server_and_package_components_join_their_graph_nodes():
    report = _report()
    bom = to_cyclonedx(report)
    graph = build_unified_graph_from_report(to_json(report), scan_id="cdx-join")

    joined = _component_canonical_ids(bom, {"ai-agent", "mcp-server", "package"})
    expected = {
        "ai-agent": {node.canonical_id for node in graph.nodes.values() if node.entity_type == EntityType.AGENT},
        "mcp-server": {node.canonical_id for node in graph.nodes.values() if node.entity_type == EntityType.SERVER},
        "package": {node.canonical_id for node in graph.nodes.values() if node.entity_type == EntityType.PACKAGE},
    }
    assert all(expected.values())
    assert joined == expected
