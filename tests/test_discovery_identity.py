from __future__ import annotations

from agent_bom.discovery.identity import deduplicate_discovered_agents, server_identity_key
from agent_bom.models import Agent, AgentType, MCPServer, MCPTool, TransportType


def _agent(name: str, source: str, server: MCPServer) -> Agent:
    return Agent(
        name=name,
        agent_type=AgentType.CUSTOM,
        config_path=f"{source}://agent",
        source=source,
        mcp_servers=[server],
    )


def test_process_and_config_recipe_similarity_does_not_prove_one_instance() -> None:
    configured = MCPServer(
        name="filesystem",
        command="npx",
        args=["@modelcontextprotocol/server-filesystem", "/workspace"],
        config_path="/home/user/.config/claude/mcp.json",
        tools=[MCPTool(name="read_file", description="Read files")],
    )
    process = MCPServer(
        name="server-filesystem",
        command="/usr/local/bin/npx",
        args=["@modelcontextprotocol/server-filesystem", "/workspace"],
        config_path="pid:4242",
        tools=[MCPTool(name="write_file", description="Write files")],
    )

    merged = deduplicate_discovered_agents([_agent("config", "config", configured), _agent("process", "process", process)])

    assert len(merged) == 2
    assert [len(agent.mcp_servers) for agent in merged] == [1, 1]
    assert {tool.name for tool in merged[0].mcp_servers[0].tools} == {"read_file"}
    assert {tool.name for tool in merged[1].mcp_servers[0].tools} == {"write_file"}
    assert configured.discovery_sources == ["config:/home/user/.config/claude/mcp.json"]
    assert process.discovery_sources == ["process:pid:4242"]


def test_shared_remote_endpoint_retains_each_declaring_agent() -> None:
    configured = MCPServer(
        name="remote-docs",
        transport=TransportType.SSE,
        url="https://mcp.example.com/sse",
        config_path="/home/user/.cursor/mcp.json",
    )
    k8s = MCPServer(
        name="prod/docs-mcp",
        transport=TransportType.SSE,
        url="https://mcp.example.com/sse",
        config_path="k8s://prod/docs-mcp",
    )

    merged = deduplicate_discovered_agents([_agent("config", "config", configured), _agent("k8s", "kubernetes", k8s)])

    assert len(merged) == 2
    assert configured.canonical_id == k8s.canonical_id
    assert configured.discovery_sources == ["config:/home/user/.cursor/mcp.json"]
    assert k8s.discovery_sources == ["kubernetes:k8s://prod/docs-mcp"]


def test_commandless_servers_with_same_command_stay_distinct() -> None:
    # Two distinct servers that share a bare command and have no args/url/registry
    # must NOT collapse into one identity (regression for inventory dedup bug).
    first = MCPServer(name="alpha", command="server")
    second = MCPServer(name="beta", command="server")

    assert server_identity_key(first) != server_identity_key(second)

    merged = deduplicate_discovered_agents([_agent("a", "config", first), _agent("b", "process", second)])

    assert sum(len(agent.mcp_servers) for agent in merged) == 2


def test_distinct_servers_remain_distinct() -> None:
    first = MCPServer(name="fs", command="npx", args=["@modelcontextprotocol/server-filesystem", "/workspace"])
    second = MCPServer(name="github", command="npx", args=["@modelcontextprotocol/server-github"])

    merged = deduplicate_discovered_agents([_agent("a", "config", first), _agent("b", "process", second)])

    assert sum(len(agent.mcp_servers) for agent in merged) == 2
    assert server_identity_key(first) != server_identity_key(second)


def test_repeated_declaration_within_same_agent_merges_children_and_provenance():
    first = MCPServer(name="server", command="npx", args=["package"], tools=[MCPTool(name="one", description="First")])
    second = MCPServer(name="server", command="npx", args=["package"], tools=[MCPTool(name="two", description="Second")])
    merged = deduplicate_discovered_agents([_agent("same", "config", first), _agent("same", "config", second)])
    assert len(merged) == 1
    assert {tool.name for tool in merged[0].mcp_servers[0].tools} == {"one", "two"}
    assert all(tool.server_canonical_id == first.canonical_id for tool in first.tools)
