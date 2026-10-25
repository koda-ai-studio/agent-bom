"""``graph_export`` over the bound tenant's persisted graph, never a scan of the MCP server host.

A server bound to a tenant, or backed by a Postgres control plane, exports that
tenant's current-estate graph from the store. A local server with neither keeps
exporting the agents discovered on this host.
"""

from __future__ import annotations

import asyncio
from collections.abc import Callable
from typing import Any

from agent_bom.core.settings import env_str
from agent_bom.mcp_errors import CODE_NOT_FOUND_RESOURCE, mcp_error_json
from agent_bom.mcp_tenant import mcp_tenant_bound, resolve_mcp_tool_tenant_id
from agent_bom.mcp_tools.estate_refusal import seeding_refusal
from agent_bom.mcp_tools.storage import default_graph_store
from agent_bom.output.graph_export import DepGraph
from agent_bom.output.unified_projection import merge_unified_graph

EXPORT_NODE_BUDGET = 20_000


def persisted_export_mode() -> bool:
    """A tenant-bound server, or one whose control plane lives in Postgres, exports persisted evidence only."""
    if mcp_tenant_bound():
        return True
    database = env_str("AGENT_BOM_DB").strip().lower()
    return bool(env_str("AGENT_BOM_POSTGRES_URL").strip()) or database.startswith(("postgres://", "postgresql://"))


def _load(store: Any, tenant_id: str) -> tuple[Any, str] | None:
    scan_id = store.latest_snapshot_id(tenant_id=tenant_id)
    if not scan_id:
        return None
    graph = store.load_graph(tenant_id=tenant_id, scan_id="", node_budget=EXPORT_NODE_BUDGET)
    return (graph, scan_id) if graph.nodes else None


async def persisted_export_graph(*, get_store: Callable[[], Any] = default_graph_store) -> tuple[DepGraph, dict[str, Any]] | str:
    """``(graph, export metadata)`` for the bound tenant's current estate, or a typed MCP error."""
    tenant_id = resolve_mcp_tool_tenant_id()
    refusal = seeding_refusal(tenant_id)
    if refusal is not None:
        return refusal
    loaded = await asyncio.to_thread(_load, get_store(), tenant_id)
    if loaded is None:
        return mcp_error_json(
            CODE_NOT_FOUND_RESOURCE,
            "No persisted graph nodes for this tenant; push a scan into the control plane, or pass config_path to export that directory.",
            details={"tenant_id": tenant_id},
        )
    unified, scan_id = loaded
    graph = DepGraph()
    merge_unified_graph(graph, unified)
    metadata = {
        "source": "persisted_graph",
        "scope": {"tenant_id": tenant_id, "scan_id": unified.scan_id or scan_id, "evidence_scope": "current_estate"},
        "completeness": unified.completeness.to_dict(),
    }
    return graph, metadata
