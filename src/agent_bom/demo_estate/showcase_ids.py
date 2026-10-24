"""Showcase agent, server, tool, credential and provider ids, derived as a scan derives them.

The showcase draws the bundled demo inventory by hand. Its node ids come from
the same identity functions the graph builder applies to a scan report, so the
showcase snapshot, the showcase job's graph export and ``scan --demo`` name one
node with one id. The short ids the showcase used before (``agent:cursor``,
``server:shell-runner-server``, ``cred:aws-secret`` ...) stay resolvable as node
aliases.
"""

from __future__ import annotations

from dataclasses import dataclass
from functools import cache

from agent_bom.canonical_ids import agent_graph_id_for, mcp_server_graph_id, mcp_server_graph_id_for
from agent_bom.graph.container import UnifiedGraph
from agent_bom.graph.node_aliases import record_node_aliases

# Former hand-written ids of the named credentials the hero chains point at.
_RETIRED_NAMED_CREDENTIALS: dict[tuple[str, str], str] = {
    ("shell-runner-server", "AWS_SECRET_ACCESS_KEY"): "cred:aws-secret",
    ("llm-orchestrator-server", "OPENAI_API_KEY"): "cred:openai-key",
    ("vector-db-server", "DATABASE_URL"): "cred:db-url",
    ("helpdesk-server", "JWT_SECRET"): "cred:jwt-secret",
    ("warehouse-server", "SNOWFLAKE_PASSWORD"): "cred:snowflake-pw",
    ("etl-server", "GCS_SERVICE_ACCOUNT_KEY"): "cred:gcs-key",
    ("github-server", "GITHUB_TOKEN"): "cred:github-token",
    ("team-chat-server", "SLACK_BOT_TOKEN"): "cred:slack-token",
}


@dataclass(frozen=True)
class ShowcaseIds:
    agents: dict[str, str]
    servers: dict[str, str]
    credentials: dict[tuple[str, str], str]
    provider: str


@cache
def showcase_ids() -> ShowcaseIds:
    from agent_bom.demo import DEMO_INVENTORY_SOURCE, demo_inventory_document
    from agent_bom.inventory import build_agents_from_inventory

    agents: dict[str, str] = {}
    servers: dict[str, str] = {}
    credentials: dict[tuple[str, str], str] = {}
    providers: set[str] = set()
    for agent in build_agents_from_inventory(demo_inventory_document(), DEMO_INVENTORY_SOURCE):
        agents[agent.name] = agent_graph_id_for(agent)
        providers.add(f"provider:{(agent.source or 'local').strip() or 'local'}")
        for server in agent.mcp_servers:
            server_id = mcp_server_graph_id_for(server, agent)
            servers[server.name] = server_id
            for env_var in server.credential_names:
                credentials[(server.name, env_var)] = f"cred:{server_id}:{env_var}"
    (provider,) = providers
    return ShowcaseIds(agents=agents, servers=servers, credentials=credentials, provider=provider)


def showcase_agent_id(name: str) -> str:
    return showcase_ids().agents[name]


def showcase_server_id(name: str) -> str:
    return showcase_ids().servers[name]


def showcase_tool_id(server: str, tool: str) -> str:
    return f"tool:{showcase_server_id(server)}:{tool}"


def showcase_credential_id(server: str, env_var: str) -> str:
    return showcase_ids().credentials[(server, env_var)]


# Drawn only in the baseline so drift shows an MCP server being removed.
_RETIRED_SERVER = ("legacy-chat-server", "support-copilot", ("send_message",))


def showcase_retired_server_id() -> str:
    """Baseline-only server, named as the builder names a server declared by name under its agent."""
    name, owner, _tools = _RETIRED_SERVER
    return mcp_server_graph_id(name, agent_key=showcase_agent_id(owner).removeprefix("agent:"))


def retired_showcase_credential_id(server: str, env_var: str) -> str:
    return _RETIRED_NAMED_CREDENTIALS.get((server, env_var)) or f"cred:{server}:{env_var.lower().replace('_', '-')}"


def retired_showcase_aliases() -> dict[str, list[str]]:
    """Current node id -> the hand-written ids it replaced."""
    from agent_bom.demo_estate.showcase_constants import SHOWCASE_SERVERS

    ids = showcase_ids()
    aliases: dict[str, list[str]] = {agent_id: [f"agent:{name}"] for name, agent_id in ids.agents.items()}
    for server, (_owner, tools) in SHOWCASE_SERVERS.items():
        aliases[showcase_server_id(server)] = [f"server:{server}"]
        for tool in tools:
            aliases[showcase_tool_id(server, tool)] = [f"tool:{server}:{tool}"]
    name, _owner, retired_tools = _RETIRED_SERVER
    aliases[showcase_retired_server_id()] = [f"server:{name}"]
    for tool in retired_tools:
        aliases[f"tool:{showcase_retired_server_id()}:{tool}"] = [f"tool:{name}:{tool}"]
    for (server, env_var), cred_id in ids.credentials.items():
        aliases[cred_id] = [retired_showcase_credential_id(server, env_var)]
    return aliases


def record_retired_showcase_inventory_ids(graph: UnifiedGraph) -> None:
    for node_id, retired in retired_showcase_aliases().items():
        node = graph.nodes.get(node_id)
        if node is not None:
            record_node_aliases(node, retired)


__all__ = [
    "ShowcaseIds",
    "record_retired_showcase_inventory_ids",
    "retired_showcase_aliases",
    "retired_showcase_credential_id",
    "showcase_agent_id",
    "showcase_credential_id",
    "showcase_ids",
    "showcase_retired_server_id",
    "showcase_server_id",
    "showcase_tool_id",
]
