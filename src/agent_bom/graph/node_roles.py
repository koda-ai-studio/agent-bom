"""What a server or agent node stands for, so every surface counts one population.

The graph keeps code-defined agent runtimes (a framework entry launched by
``python``) as ``server`` nodes, because credential, exposure and path logic
depend on that type. Only some server nodes are MCP servers, and framework
agents defined in project code are ``agent`` nodes that the Agents page does
not list as AI agents. A role separates them without changing node types:

* ``mcp_server`` — a server node the MCP inventory rule counts
  (:func:`agent_bom.domain.mcp_model.surface_counts_as_mcp_server`);
* ``other_server`` — any other server node;
* ``agent`` — an AI agent, as the Agents page lists it;
* ``framework_agent`` — an agent defined in framework code inside a project.

A role depends only on the node's stored type and dimensions, so the SQL
expressions below derive it from one row in each store backend.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from agent_bom.domain.mcp_model import surface_counts_as_mcp_server

MCP_SERVER = "mcp_server"
OTHER_SERVER = "other_server"
AGENT = "agent"
FRAMEWORK_AGENT = "framework_agent"
ROLES: tuple[str, ...] = (AGENT, FRAMEWORK_AGENT, MCP_SERVER, OTHER_SERVER)
#: Facets a store's inventory read returns; ``role`` counts agent and server rows by role.
INVENTORY_FACET_NAMES: tuple[str, ...] = ("type", "source", "provider", "environment", "severity", "role")

#: ``dimensions.agent_type`` stamped on agents projected from framework code.
FRAMEWORK_AGENT_TYPE = "framework-agent"
# A server node with no stored surface predates the field and was an MCP server.
_MCP_SURFACES = ("", "mcp-server")


def node_role(entity_type: object, dimensions: Mapping[str, Any] | None) -> str | None:
    """The role of a server or agent node; ``None`` for every other type."""
    dims = dimensions or {}
    kind = str(getattr(entity_type, "value", entity_type) or "")
    if kind == "server":
        surface = str(dims.get("surface") or "")
        return MCP_SERVER if surface_counts_as_mcp_server(surface or None) else OTHER_SERVER
    if kind == "agent":
        return FRAMEWORK_AGENT if str(dims.get("agent_type") or "") == FRAMEWORK_AGENT_TYPE else AGENT
    return None


def _role_sql(surface: str, agent_type: str, alias: str) -> str:
    mcp = ", ".join(f"'{value}'" for value in _MCP_SURFACES)
    return (
        f"CASE {alias}.entity_type"
        f" WHEN 'server' THEN CASE WHEN COALESCE({surface}, '') IN ({mcp}) THEN '{MCP_SERVER}' ELSE '{OTHER_SERVER}' END"
        f" WHEN 'agent' THEN CASE WHEN COALESCE({agent_type}, '') = '{FRAMEWORK_AGENT_TYPE}'"
        f" THEN '{FRAMEWORK_AGENT}' ELSE '{AGENT}' END END"
    )


#: Role of the ``graph_nodes`` row aliased ``{alias}`` (format with ``alias=``), SQLite dialect.
SQLITE_ROLE_SQL = _role_sql("json_extract({alias}.dimensions, '$.surface')", "json_extract({alias}.dimensions, '$.agent_type')", "{alias}")
#: Same expression, PostgreSQL dialect (``dimensions`` is stored as JSON text).
POSTGRES_ROLE_SQL = _role_sql("{alias}.dimensions::jsonb ->> 'surface'", "{alias}.dimensions::jsonb ->> 'agent_type'", "{alias}")


def role_facet_sql(where_sql: str) -> str:
    """The inventory ``role`` facet over the ``assets`` CTE: agent and server rows only."""
    return (
        "SELECT 'role', inventory_role, COUNT(*) FROM assets"  # nosec B608 - where_sql holds generated placeholders only
        f" WHERE {where_sql} AND inventory_role IS NOT NULL GROUP BY inventory_role"
    )


__all__ = [
    "AGENT",
    "FRAMEWORK_AGENT",
    "FRAMEWORK_AGENT_TYPE",
    "INVENTORY_FACET_NAMES",
    "MCP_SERVER",
    "OTHER_SERVER",
    "POSTGRES_ROLE_SQL",
    "ROLES",
    "SQLITE_ROLE_SQL",
    "node_role",
    "role_facet_sql",
]
