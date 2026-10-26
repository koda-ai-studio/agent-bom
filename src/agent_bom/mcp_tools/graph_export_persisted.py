"""``graph_export`` over the bound tenant's persisted graph, never a scan of the MCP server host.

A server bound to a tenant, or backed by a Postgres control plane, exports that
tenant's current-estate graph from the store one keyset page at a time. Each
page owns its nodes and their outgoing edges; an edge's target on another page
is included as a ``page_reference`` stub, so the union of all pages holds every
node and edge exactly once. The cursor pins the snapshot generation: a malformed
or foreign cursor is an invalid argument, and one from a replaced snapshot is a
stale conflict. A local server with neither keeps exporting the agents
discovered on this host.
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import json
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from agent_bom.core.settings import env_str
from agent_bom.graph import UnifiedGraph, UnifiedNode
from agent_bom.graph.completeness import graph_completeness
from agent_bom.mcp_errors import CODE_CONFLICT_STALE_CURSOR, CODE_NOT_FOUND_RESOURCE, CODE_VALIDATION_INVALID_ARGUMENT, mcp_error_json
from agent_bom.mcp_tenant import mcp_tenant_bound, resolve_mcp_tool_tenant_id
from agent_bom.mcp_tools.estate_refusal import seeding_refusal
from agent_bom.mcp_tools.storage import default_graph_store
from agent_bom.output.graph_export import DepGraph
from agent_bom.output.unified_projection import merge_unified_graph

EXPORT_PAGE_DEFAULT = 1000
EXPORT_PAGE_MAX = 5000


def persisted_export_mode() -> bool:
    """A tenant-bound server, or one whose control plane lives in Postgres, exports persisted evidence only."""
    if mcp_tenant_bound():
        return True
    database = env_str("AGENT_BOM_DB").strip().lower()
    return bool(env_str("AGENT_BOM_POSTGRES_URL").strip()) or database.startswith(("postgres://", "postgresql://"))


@dataclass(frozen=True)
class _Continuation:
    scan_id: str
    generation: str
    store_cursor: str
    offset: int


def _scope(tenant_id: str) -> str:
    return hashlib.sha256(json.dumps(["graph_export", tenant_id]).encode()).hexdigest()


def _encode(tenant_id: str, page: _Continuation) -> str:
    raw = {"v": 1, "scope": _scope(tenant_id), "scan": page.scan_id, "generation": page.generation, "after": page.store_cursor}
    raw["offset"] = page.offset
    return base64.urlsafe_b64encode(json.dumps(raw, separators=(",", ":")).encode()).decode()


def _decode(cursor: str, tenant_id: str) -> _Continuation:
    """The continuation; ``ValueError`` when the cursor is malformed or belongs to another tenant's export."""
    try:
        raw = json.loads(base64.urlsafe_b64decode(cursor.encode()).decode())
    except (ValueError, UnicodeDecodeError) as exc:
        raise ValueError("malformed cursor") from exc
    if not isinstance(raw, dict) or raw.get("v") != 1 or raw.get("scope") != _scope(tenant_id):
        raise ValueError("cursor does not belong to this export")
    fields = (raw.get("scan"), raw.get("generation"), raw.get("after"))
    if not all(isinstance(value, str) and value for value in fields) or not isinstance(raw.get("offset"), int) or raw["offset"] < 0:
        raise ValueError("cursor does not belong to this export")
    return _Continuation(raw["scan"], raw["generation"], raw["after"], raw["offset"])


def _stale() -> str:
    return mcp_error_json(
        CODE_CONFLICT_STALE_CURSOR,
        "The persisted graph changed since this cursor was issued; restart the export from its first page.",
        details={"argument": "cursor"},
    )


def _read_page(store: Any, tenant_id: str, after: _Continuation | None, limit: int) -> tuple[UnifiedGraph, dict[str, Any]] | str | None:
    """One generation-pinned page, or a typed error, or ``None`` when the tenant has no persisted graph."""
    identity = tuple(store.snapshot_identity(tenant_id=tenant_id, scan_id="", for_paging=True))
    scan_id, generation = str(identity[0]), str(identity[1])
    if after is not None and (scan_id, generation) != (after.scan_id, after.generation):
        return _stale()
    if not generation:
        return None
    read = {"tenant_id": tenant_id, "scan_id": scan_id}
    _scan, _created, nodes, total, next_store = store.page_nodes(**read, cursor=after.store_cursor if after else None, limit=limit)
    if not nodes and after is None:
        return None
    owned = {node.id for node in nodes}
    edges = store.edges_for_node_ids(**read, node_ids=owned, direction="out") if owned else []
    edges = [edge for edge in edges if edge.source in owned]
    foreign = {edge.target for edge in edges} - owned
    references = store.nodes_by_ids(**read, node_ids=foreign) if foreign else []
    if tuple(store.snapshot_identity(tenant_id=tenant_id, scan_id="", for_paging=True)) != identity:
        return _stale()
    graph = UnifiedGraph(scan_id=scan_id, tenant_id=tenant_id)
    for node in nodes:
        graph.add_node(node)
    for node in references:
        graph.add_node(UnifiedNode(id=node.id, entity_type=node.entity_type, label=node.label, attributes={"page_reference": True}))
    for edge in edges:
        graph.add_edge(edge)
    offset = after.offset if after else 0
    has_more = bool(next_store)
    next_cursor = _encode(tenant_id, _Continuation(scan_id, generation, str(next_store), offset + len(nodes))) if has_more else None
    metadata = {
        "source": "persisted_graph",
        "scope": {"tenant_id": tenant_id, "scan_id": scan_id, "evidence_scope": "current_estate"},
        "snapshot_generation": generation,
        "completeness": graph_completeness(
            returned=len(nodes), total=int(total), truncated=has_more, reason="page_limit" if has_more else ""
        ),
        "pagination": {
            "offset": offset,
            "limit": limit,
            "returned": len(nodes),
            "total": int(total),
            "has_more": has_more,
            "next_cursor": next_cursor,
        },
    }
    return graph, metadata


async def persisted_export_graph(
    *, limit: int = EXPORT_PAGE_DEFAULT, cursor: str | None = None, get_store: Callable[[], Any] = default_graph_store
) -> tuple[DepGraph, dict[str, Any]] | str:
    """``(graph page, export metadata)`` for the bound tenant's current estate, or a typed MCP error."""
    tenant_id = resolve_mcp_tool_tenant_id()
    refusal = seeding_refusal(tenant_id)
    if refusal is not None:
        return refusal
    if not 1 <= limit <= EXPORT_PAGE_MAX:
        return mcp_error_json(
            CODE_VALIDATION_INVALID_ARGUMENT, f"limit must be between 1 and {EXPORT_PAGE_MAX}", details={"argument": "limit"}
        )
    after = None
    if cursor:
        try:
            after = _decode(cursor, tenant_id)
        except ValueError:
            return mcp_error_json(
                CODE_VALIDATION_INVALID_ARGUMENT, "Invalid graph_export cursor; restart the export.", details={"argument": "cursor"}
            )
    page = await asyncio.to_thread(_read_page, get_store(), tenant_id, after, limit)
    if page is None:
        return mcp_error_json(
            CODE_NOT_FOUND_RESOURCE,
            "No persisted graph nodes for this tenant; push a scan into the control plane, or pass config_path to export that directory.",
            details={"tenant_id": tenant_id},
        )
    if isinstance(page, str):
        return page
    unified, metadata = page
    graph = DepGraph()
    merge_unified_graph(graph, unified)
    return graph, metadata
