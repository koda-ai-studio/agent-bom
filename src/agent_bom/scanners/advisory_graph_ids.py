"""Graph node ids of a stored package occurrence, as the scan graph names them.

An "affected assets" row links into blast-radius investigation, so its ids
must be exactly the ids the graph builder gives the package, the server that
carries it and the agent above it. This mirrors the builder's own id choice
(SBOM imports and repository inventories included) instead of guessing.
"""

from __future__ import annotations

from typing import Any

from agent_bom.canonical_ids import mcp_server_graph_id_for
from agent_bom.graph.agent_projection import inventory_scope, repository_manifest_node_id
from agent_bom.graph.package_projection import _package_node_id


def occurrence_graph_ids(agent: dict[str, Any], server: dict[str, Any], package: dict[str, Any]) -> dict[str, str]:
    scope = inventory_scope(agent)
    if scope.sbom_import:
        server_id = scope.agent_id
    elif scope.repository_inventory:
        server_id = repository_manifest_node_id(scope, str(server.get("name", "unknown")))
    else:
        server_id = mcp_server_graph_id_for(server, agent)
    return {"package_node_id": _package_node_id(package), "server_node_id": server_id, "agent_node_id": scope.agent_id}
