"""Compact inventory references, including explicitly declared SBOM identities."""

from __future__ import annotations

from typing import TYPE_CHECKING

from agent_bom.canonical_ids import canonical_id, mcp_server_graph_id_for

if TYPE_CHECKING:
    from agent_bom.models import Agent, MCPServer


def server_occurrence_id(server: MCPServer, agent: Agent) -> str:
    """Retain validated imported references without claiming execution or trust."""
    declared = server.imported_canonical_id
    # MCPServer validates the declared UUID only for non-executable SBOM rows.
    if declared and server.surface == "sbom" and server.command == "sbom" and declared == server.canonical_id:
        return declared
    return canonical_id("mcp_server_occurrence", mcp_server_graph_id_for(server, agent))
