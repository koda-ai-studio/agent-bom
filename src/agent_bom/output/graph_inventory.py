"""Cytoscape agent and inventory nodes named with the ids the persisted scan graph uses.

SBOM imports and repository manifests are static inventory, not running agents:
the graph draws an SBOM as its ``source_file:sbom:`` node holding its components,
and a repository as a ``directory:repository:`` node containing one
``directory:manifest:`` node per manifest directory. Running agents keep their
``provider`` → ``agent`` → ``server`` chain.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from agent_bom.canonical_ids import agent_graph_id_for, mcp_server_graph_id_for
from agent_bom.graph.agent_projection import AgentScope, _inventory_node_id, repository_manifest_node_id
from agent_bom.graph.projection_support import _is_repository_inventory, _is_sbom_import
from agent_bom.graph.types import EntityType
from agent_bom.output.graph_policy import _provider_label
from agent_bom.security import sanitize_path_label

if TYPE_CHECKING:
    from agent_bom.models import Agent, MCPServer


def _static_inventory(agent: "Agent") -> AgentScope | None:
    """The graph builder's inventory scope for an SBOM or repository wrapper; None for a running agent."""
    record = {
        "name": agent.name,
        "source": agent.source,
        "mcp_servers": [{"surface": getattr(srv.surface, "value", srv.surface), "command": srv.command} for srv in agent.mcp_servers],
    }
    scope = AgentScope(agent_dict=record, agent_metadata={}, agent_discovery_provenance=None)
    scope.sbom_import = _is_sbom_import(record)
    scope.repository_inventory = _is_repository_inventory(record)
    if not (scope.sbom_import or scope.repository_inventory):
        return None
    scope.static_inventory = True
    scope.inventory_type = EntityType.DIRECTORY if scope.repository_inventory else EntityType.SOURCE_FILE
    scope.agent_id = _inventory_node_id(scope, agent_graph_id_for(agent))
    scope.agent_node_key = scope.agent_id.removeprefix("agent:")
    return scope


def append_agent_elements(elements: list[dict], agent: "Agent", providers_seen: set[str]) -> tuple[str, AgentScope | None]:
    """Append the agent (or inventory) node; return its id and, for static inventory, its graph scope."""
    source = agent.source or "local"
    static = _static_inventory(agent)
    if static is None and source not in providers_seen:
        providers_seen.add(source)
        elements.append(
            {"data": {"id": f"provider:{source}", "label": _provider_label(source), "type": "provider", "tip": f"Source: {source}"}}
        )
    aid = static.agent_id if static is not None else agent_graph_id_for(agent)
    elements.append(
        {
            "data": {
                "id": aid,
                "label": agent.name,
                "type": static.inventory_type.value if static is not None else "agent",
                "tip": (
                    f"Inventory source: {agent.name}\nSource: {source}"
                    if static is not None
                    else f"Agent: {agent.name}\nType: {agent.agent_type.value}\nSource: {source}\nServers: {len(agent.mcp_servers)}"
                ),
                "agentType": agent.agent_type.value,
                "configPath": sanitize_path_label(agent.config_path) if agent.config_path else "",
                # "source"/"target" are reserved Cytoscape edge fields; a node-level
                # "source" key makes standards-following consumers misclassify nodes as edges.
                "discovery_source": source,
                "serverCount": len(agent.mcp_servers),
                "packageCount": agent.total_packages,
                "vulnCount": agent.total_vulnerabilities,
            }
        }
    )
    if static is None:
        elements.append({"data": {"source": f"provider:{source}", "target": aid, "type": "hosts"}})
    return aid, static


def server_node_id(agent: "Agent", static: AgentScope | None, server: "MCPServer") -> str:
    """An SBOM's components hang off its file node; a repository manifest is its own directory."""
    if static is None:
        return mcp_server_graph_id_for(server, agent)
    return static.agent_id if static.sbom_import else repository_manifest_node_id(static, server.name)


def append_server_elements(elements: list[dict], aid: str, static: AgentScope | None, server_data: dict[str, Any]) -> None:
    """Append a server node and its agent edge; an SBOM's file node already stands for its server."""
    sid = server_data["id"]
    if static is None:
        elements.append({"data": server_data})
        elements.append(
            {
                "data": {
                    "source": aid,
                    "target": sid,
                    "type": "uses",
                    "credentialEdge": 1 if server_data["hasCredentials"] else 0,
                    "securityBlocked": 1 if server_data["securityBlocked"] else 0,
                    "securityIntelligence": 1 if server_data["securityIntelligenceCount"] else 0,
                }
            }
        )
    elif sid != aid:
        elements.append({"data": {**server_data, "type": EntityType.DIRECTORY.value}})
        elements.append({"data": {"source": aid, "target": sid, "type": "contains"}})


def package_edge_type(static: AgentScope | None) -> str:
    return "contains" if static is not None and static.sbom_import else "depends_on"
