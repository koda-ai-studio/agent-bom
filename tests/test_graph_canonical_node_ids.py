"""One graph node per agent and per MCP server, whichever producer names it."""

from __future__ import annotations

from typing import Any

from agent_bom.canonical_ids import agent_graph_id, canonical_mcp_server_id, mcp_server_graph_id, mcp_server_graph_id_for
from agent_bom.finding import blast_radius_to_finding
from agent_bom.graph.builder import build_unified_graph_from_report
from agent_bom.graph.credential_reach import credential_routes
from agent_bom.graph.types import EntityType
from agent_bom.models import Agent, AgentType, BlastRadius, MCPServer, MCPTool, Package, Severity, TransportType, Vulnerability
from agent_bom.output.exposure_path import exposure_path_chain, exposure_path_for_report_finding
from agent_bom.output.graph_export import build_graph_from_scan_data

REMOTE_URL = "https://mcp.example.test/sse"


def _server(name: str, *, url: str = "", command: str = "", args: list[str] | None = None, creds: list[str] | None = None) -> dict:
    record: dict[str, Any] = {"name": name, "url": url, "command": command, "args": args or [], "transport": "sse" if url else "stdio"}
    if creds:
        record["credential_env_vars"] = creds
    record["tools"] = [{"name": "query"}]
    return record


def _agent(name: str, servers: list[dict], *, source_id: str = "") -> dict:
    record: dict[str, Any] = {"name": name, "type": "custom", "source": "local", "mcp_servers": servers}
    if source_id:
        record["source_id"] = source_id
    return record


def _servers(graph) -> list:
    return [node for node in graph.nodes.values() if node.entity_type == EntityType.SERVER]


def test_remote_server_named_differently_by_two_agents_is_one_node() -> None:
    report = {
        "agents": [
            _agent("desktop", [_server("docs", url=REMOTE_URL)]),
            _agent("ide", [_server("company-docs", url=REMOTE_URL)], source_id="laptop-2"),
        ]
    }

    graph = build_unified_graph_from_report(report)

    servers = _servers(graph)
    assert len(servers) == 1
    expected = f"server:{canonical_mcp_server_id('docs', url=REMOTE_URL)}"
    assert servers[0].id == expected
    assert servers[0].attributes["agents"] == sorted([agent_graph_id("desktop"), agent_graph_id("ide", "laptop-2")])
    assert {edge.source for edge in graph.edges_to(expected)} >= {agent_graph_id("desktop"), agent_graph_id("ide", "laptop-2")}


def test_every_producer_names_one_server_with_the_same_id() -> None:
    report = {"agents": [_agent("desktop", [_server("docs", url=REMOTE_URL)]), _agent("ide", [_server("docs-2", url=REMOTE_URL)])]}
    unified = {node.id for node in _servers(build_unified_graph_from_report(report))}
    export = {node.id for node in build_graph_from_scan_data(report).nodes if node.kind.startswith("server")}
    model = mcp_server_graph_id_for(MCPServer(name="docs", url=REMOTE_URL, transport=TransportType.SSE), Agent("ide", AgentType.CUSTOM, ""))

    assert unified == export == {model}


def test_equal_stdio_recipes_remain_distinct_per_declaring_agent() -> None:
    stdio = {"command": "npx", "args": ["-y", "@example/fs-server", "/srv"]}
    report = {
        "agents": [
            _agent("desktop", [_server("fs", **stdio)], source_id="device-a"),
            _agent("desktop", [_server("fs", **stdio)], source_id="device-b"),
            _agent("ide", [_server("files", **stdio)], source_id="device-b"),
        ]
    }

    servers = _servers(build_unified_graph_from_report(report))

    assert len(servers) == 3
    identity = canonical_mcp_server_id("fs", "npx", args=stdio["args"])
    assert {node.id for node in servers} == {
        f"server:device-a:desktop:{identity}",
        f"server:device-b:desktop:{identity}",
        f"server:device-b:ide:{identity}",
    }


def test_name_only_server_stays_under_its_agent() -> None:
    report = {"agents": [_agent("a", [_server("notes")]), _agent("b", [_server("notes")])]}

    assert {node.id for node in _servers(build_unified_graph_from_report(report))} == {"server:a:notes", "server:b:notes"}
    assert mcp_server_graph_id("notes", agent_key="a") == "server:a:notes"


def test_shared_server_never_hands_one_agent_another_agents_credential() -> None:
    report = {
        "agents": [
            _agent("owner", [_server("docs", url=REMOTE_URL, creds=["DOCS_TOKEN"])]),
            _agent("peer", [_server("docs", url=REMOTE_URL)]),
        ]
    }
    graph = build_unified_graph_from_report(report)

    routes = credential_routes(graph, [agent_graph_id("owner"), agent_graph_id("peer")], analyzer="test")

    assert len(routes[agent_graph_id("owner")]) == 1
    assert routes[agent_graph_id("peer")] == {}


def test_scoped_runtime_incident_marks_exactly_one_agent() -> None:
    stdio = {"command": "uvx", "args": ["example-server"]}
    report = {
        "agents": [
            _agent("assistant", [_server("svc", **stdio)], source_id="device-a"),
            _agent("assistant", [_server("svc", **stdio)], source_id="device-b"),
        ],
        "runtime_incident_feedback": [
            {
                "schema_version": "runtime_incident_feedback.v1",
                "agent_id": "assistant",
                "agent_source_id": "device-b",
                "kind": "reached_credential",
                "observed_at": "2026-10-01T00:00:00Z",
            }
        ],
    }

    graph = build_unified_graph_from_report(report)

    marked = [node.id for node in graph.nodes_by_type(EntityType.AGENT) if node.attributes.get("runtime_feedback")]
    assert marked == [agent_graph_id("assistant", "device-b")]


def test_unscoped_incident_for_an_ambiguous_name_marks_no_agent() -> None:
    report = {
        "agents": [_agent("assistant", [], source_id="device-a"), _agent("assistant", [], source_id="device-b")],
        "runtime_incident_feedback": [
            {
                "schema_version": "runtime_incident_feedback.v1",
                "agent_id": "assistant",
                "kind": "reached_credential",
                "observed_at": "2026-10-01T00:00:00Z",
            }
        ],
    }

    graph = build_unified_graph_from_report(report)

    assert not [node for node in graph.nodes_by_type(EntityType.AGENT) if node.attributes.get("runtime_feedback")]
    assert graph.analysis_status["runtime_incident_feedback"].reason_codes == ("ambiguous_agent_name",)


def _blast_radius() -> tuple[Agent, BlastRadius]:
    package = Package(name="lodash", version="4.17.20", ecosystem="npm")
    package.vulnerabilities = [Vulnerability(id="CVE-2024-0001", summary="x", severity=Severity.CRITICAL)]
    tool = MCPTool(name="deploy", description="Deploy workloads")
    server = MCPServer(name="prod-mcp", command="npx", args=["srv"], tools=[tool], packages=[package], env={"DEPLOY_TOKEN": "x"})
    agent = Agent(name="prod-agent", agent_type=AgentType.CLAUDE_DESKTOP, config_path="/tmp/a.json", mcp_servers=[server])
    br = BlastRadius(
        package=package,
        vulnerability=package.vulnerabilities[0],
        affected_agents=[agent],
        affected_servers=[server],
        exposed_credentials=["DEPLOY_TOKEN"],
        exposed_tools=[tool],
    )
    return agent, br


def test_exposure_path_refs_are_graph_node_ids() -> None:
    from agent_bom.models import AIBOMReport
    from agent_bom.output.json_fmt import to_json

    agent, br = _blast_radius()
    report = to_json(AIBOMReport(agents=[agent], blast_radii=[br], tool_version="0.0.0"))
    graph = build_unified_graph_from_report(report)

    path = exposure_path_for_report_finding(blast_radius_to_finding(br), br=br, rank=1)

    assert set(path["nodeIds"]) <= set(graph.nodes)
    assert {ref.split(":", 1)[0] for ref in path["nodeIds"]} == {"agent", "server", "pkg", "vuln", "tool", "cred"}
    assert exposure_path_chain(path) == "prod-agent → prod-mcp → lodash@4.17.20 → CVE-2024-0001 → deploy"
