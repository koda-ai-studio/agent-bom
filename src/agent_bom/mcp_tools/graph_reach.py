"""``graph_reach``: what can reach a node, or what a node reaches, over recorded edges.

Inbound reach is the store walk behind ``/v1/graph/impact`` (``impact_of``);
outbound reach is the same bounded walk in the forward direction. Both page
the walk's node set with a generation-pinned cursor.
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import json
from dataclasses import dataclass
from typing import Any

from agent_bom.api.graph_node_alias import resolve_snapshot_node_id
from agent_bom.graph.completeness import impact_completeness
from agent_bom.graph.reach_view import reach_interpretation
from agent_bom.graph.types import EntityType
from agent_bom.mcp_errors import (
    CODE_NOT_FOUND_RESOURCE,
    CODE_UNSUPPORTED_BACKEND,
    CODE_VALIDATION_INVALID_ARGUMENT,
    CODE_VALIDATION_MISSING_REQUIRED,
    mcp_error_json,
)
from agent_bom.mcp_tenant import resolve_mcp_tool_tenant_id
from agent_bom.mcp_tools.graph import _resolve_exposure_snapshot, guarded_graph_read
from agent_bom.mcp_tools.storage import default_graph_store

_WALK_NODE_BUDGET = 5000
_WALK_EDGE_BUDGET = 25_000
_ENTITY_TYPES = frozenset(member.value for member in EntityType)


def _type_value(node: Any) -> str:
    kind = getattr(node, "entity_type", "")
    return str(getattr(kind, "value", kind) or "")


def _invalid(message: str, argument: str) -> str:
    return mcp_error_json(CODE_VALIDATION_INVALID_ARGUMENT, message, details={"argument": argument})


def _validate(node_id: str, direction: str, max_depth: int, limit: int, entity_types: list[str]) -> str | None:
    if not node_id.strip():
        return mcp_error_json(CODE_VALIDATION_MISSING_REQUIRED, "node_id is required", details={"argument": "node_id"})
    if len(node_id) > 512 or "\x00" in node_id:
        return _invalid("node_id is not a valid graph identifier", "node_id")
    if direction not in {"in", "out"}:
        return _invalid("direction must be 'in' (what reaches the node) or 'out' (what the node reaches)", "direction")
    if not 1 <= max_depth <= 10:
        return _invalid("max_depth must be between 1 and 10", "max_depth")
    if not 1 <= limit <= 200:
        return _invalid("limit must be between 1 and 200", "limit")
    unknown = sorted(set(entity_types) - _ENTITY_TYPES)
    if unknown or len(entity_types) > 32:
        return _invalid(f"unknown entity types: {', '.join(unknown[:5])}", "entity_types")
    return None


def _cursor_scope(tenant_id: str, node_id: str, direction: str, max_depth: int, entity_types: list[str]) -> str:
    return hashlib.sha256(json.dumps([tenant_id, node_id, direction, max_depth, sorted(entity_types)]).encode()).hexdigest()


def _encode_cursor(scope: str, scan_id: str, generation: str, offset: int) -> str:
    raw = json.dumps({"v": 1, "scope": scope, "scan": scan_id, "generation": generation, "offset": offset}, separators=(",", ":"))
    return base64.urlsafe_b64encode(raw.encode()).decode()


def _decode_cursor(cursor: str, scope: str) -> dict[str, Any]:
    payload = json.loads(base64.urlsafe_b64decode(cursor.encode()).decode())
    if payload.get("v") != 1 or payload.get("scope") != scope or not isinstance(payload.get("offset"), int) or payload["offset"] < 0:
        raise ValueError("cursor does not belong to this query")
    return payload


def _walk(store: Any, *, tenant_id: str, scan_id: str, node_id: str, direction: str, max_depth: int) -> dict[str, Any] | None:
    """One bounded walk; inbound is exactly the REST impact walk."""
    if direction == "in":
        impact = store.impact_of(tenant_id=tenant_id, scan_id=scan_id, node_id=node_id, max_depth=max_depth)
        if impact is None:
            return None
        return {**impact, "types": None}
    graph, _depths, _truncated = store.traverse_subgraph(
        tenant_id=tenant_id,
        scan_id=scan_id,
        roots=[node_id],
        direction="forward",
        max_depth=max_depth,
        max_nodes=_WALK_NODE_BUDGET,
        max_edges=_WALK_EDGE_BUDGET,
        include_roots=True,
    )
    if node_id not in graph.nodes:
        return None
    types = {nid: _type_value(node) for nid, node in graph.nodes.items() if nid != node_id}
    by_type: dict[str, int] = {}
    for kind in types.values():
        by_type[kind] = by_type.get(kind, 0) + 1
    affected = sorted(types)
    return {
        "node_id": node_id,
        "affected_nodes": affected,
        "affected_by_type": by_type,
        "affected_count": len(affected),
        "completeness": impact_completeness(
            affected_count=len(affected),
            truncated=bool(graph.completeness.truncated),
            depth_limited=bool(graph.completeness.depth_limited),
        ),
        "types": types,
    }


@dataclass(slots=True)
class _ReachQuery:
    tenant_id: str
    node_id: str
    direction: str
    max_depth: int
    entity_types: list[str]
    limit: int
    offset: int
    scope: str
    scan_id: str | None
    generation: str | None


async def _filtered(store: Any, query: _ReachQuery, scan_id: str, walk: dict[str, Any]) -> list[str]:
    affected: list[str] = walk["affected_nodes"]
    if not query.entity_types:
        return affected
    types = walk["types"]
    if types is None:
        rows = await asyncio.to_thread(store.nodes_by_ids, tenant_id=query.tenant_id, scan_id=scan_id, node_ids=set(affected))
        types = {node.id: _type_value(node) for node in rows}
    return [nid for nid in affected if types.get(nid) in query.entity_types]


def _items(page_ids: list[str], rows: list[Any]) -> list[dict[str, Any]]:
    by_id = {node.id: node for node in rows}
    items: list[dict[str, Any]] = []
    for nid in page_ids:
        node = by_id.get(nid)
        if node is None:
            items.append({"id": nid, "label": nid, "entityType": "unknown"})
            continue
        item: dict[str, Any] = {"id": nid, "label": node.label, "entityType": _type_value(node)}
        severity = str(node.severity or "")
        if severity:
            item["severity"] = severity
        items.append(item)
    return items


async def _graph_reach(store: Any, query: _ReachQuery, truncate: Any) -> str:
    try:
        identity = await asyncio.to_thread(store.snapshot_identity, tenant_id=query.tenant_id, scan_id=query.scan_id or "", for_paging=True)
    except NotImplementedError:
        return mcp_error_json(
            CODE_UNSUPPORTED_BACKEND, "graph_reach requires generation-pinned graph reads, which this backend does not support."
        )
    pinned_scan_id, generation = identity
    if query.generation is not None and query.generation != generation:
        return _invalid("Graph snapshot changed; restart the query from its first page.", "cursor")
    node_id, resolved_from = await asyncio.to_thread(
        resolve_snapshot_node_id, store, tenant_id=query.tenant_id, scan_id=pinned_scan_id, node_id=query.node_id
    )
    walk = await asyncio.to_thread(
        _walk,
        store,
        tenant_id=query.tenant_id,
        scan_id=pinned_scan_id,
        node_id=node_id,
        direction=query.direction,
        max_depth=query.max_depth,
    )
    if walk is None:
        return mcp_error_json(CODE_NOT_FOUND_RESOURCE, "Node not found in this graph snapshot", details={"node_id": query.node_id})
    affected = await _filtered(store, query, pinned_scan_id, walk)
    page_ids = affected[query.offset : query.offset + query.limit]
    rows = await asyncio.to_thread(store.nodes_by_ids, tenant_id=query.tenant_id, scan_id=pinned_scan_id, node_ids=set(page_ids))
    if await asyncio.to_thread(store.snapshot_identity, tenant_id=query.tenant_id, scan_id=pinned_scan_id, for_paging=True) != identity:
        return _invalid("Graph snapshot changed during the read; restart the query.", "cursor")
    has_more = query.offset + len(page_ids) < len(affected)
    next_cursor = _encode_cursor(query.scope, pinned_scan_id, generation, query.offset + len(page_ids)) if has_more else None
    payload = {
        "schema_version": "v1",
        "tool": "graph_reach",
        "tenant_id": query.tenant_id,
        "scan_id": pinned_scan_id,
        "snapshot_generation": generation,
        "node_id": node_id,
        "resolved_from": resolved_from,
        "direction": query.direction,
        "max_depth": query.max_depth,
        "entity_types": query.entity_types,
        "total": len(affected),
        "affected_count": walk["affected_count"],
        "affected_by_type": walk["affected_by_type"],
        "items": _items(page_ids, list(rows)),
        "pagination": {
            "offset": query.offset,
            "limit": query.limit,
            "returned": len(page_ids),
            "has_more": has_more,
            "next_cursor": next_cursor,
        },
        "completeness": walk["completeness"],
        "interpretation": reach_interpretation(max_depth=query.max_depth, direction=query.direction),
    }
    encoded = json.dumps(payload, separators=(",", ":"), default=str)
    return truncate(encoded) if truncate is not None else encoded


async def graph_reach_impl(
    *,
    node_id: str,
    direction: str = "in",
    max_depth: int = 4,
    entity_types: list[str] | None = None,
    limit: int = 50,
    cursor: str | None = None,
    tenant_id: str = "default",
    scan_id: str | None = None,
    _get_graph_store=None,
    _truncate_response=None,
) -> str:
    """Page the nodes that reach ``node_id`` (in) or that it reaches (out)."""
    types_filter = sorted({value.strip() for value in entity_types or [] if value.strip()})
    invalid = _validate(node_id, direction, max_depth, limit, types_filter)
    if invalid:
        return invalid
    tenant_id = resolve_mcp_tool_tenant_id(tenant_id)
    scope = _cursor_scope(tenant_id, node_id, direction, max_depth, types_filter)
    offset, generation = 0, None
    if cursor:
        try:
            continuation = _decode_cursor(cursor, scope)
            scan_id, offset, generation = continuation["scan"], continuation["offset"], continuation["generation"]
        except (ValueError, TypeError, KeyError, UnicodeDecodeError):
            return _invalid("Invalid graph_reach cursor; restart the query.", "cursor")
    scan_id, resolution_error = await _resolve_exposure_snapshot(tenant_id, scan_id)
    if resolution_error:
        return resolution_error
    query = _ReachQuery(tenant_id, node_id, direction, max_depth, types_filter, limit, offset, scope, scan_id, generation)
    return await guarded_graph_read(_graph_reach((_get_graph_store or default_graph_store)(), query, _truncate_response))


__all__ = ["graph_reach_impl"]
