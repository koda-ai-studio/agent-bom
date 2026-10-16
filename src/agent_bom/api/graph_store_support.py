"""Module-level helpers shared by the SQLite and Postgres graph stores."""

from __future__ import annotations

import base64
import json
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    pass

from agent_bom.graph import (
    RelationshipType,
    UnifiedGraph,
    UnifiedNode,
)
from agent_bom.graph.ocsf import FINDING_ENTITY_TYPES
from agent_bom.graph.ports import GraphStoreProtocol as GraphStoreProtocol

_FINDING_ENTITY_TYPE_VALUES = frozenset(entity_type.value for entity_type in FINDING_ENTITY_TYPES)

# Deep OFFSET paging is O(offset): the store still walks and discards every
# skipped row, so ``offset=490000`` costs seconds even with the sort indexes.
# Past this threshold callers must switch to the flat keyset ``cursor=`` path.
# Shallow, human-scale offset browsing below the cap stays supported.
MAX_NODE_PAGE_OFFSET = 10_000


def _assert_offset_within_cap(offset: int, cursor: str | None) -> None:
    """Refuse a deep OFFSET at the store, not only at the route.

    Every node-paging read shares the cap, so a caller that reaches a store
    directly (MCP, a job, a future route) cannot buy an O(offset) scan the HTTP
    surface would have refused.
    """
    if not cursor and offset > MAX_NODE_PAGE_OFFSET:
        raise ValueError(
            f"offset={offset} exceeds the maximum supported node offset ({MAX_NODE_PAGE_OFFSET}); "
            "use the cursor= keyset parameter from the previous page's next_cursor for deep pagination."
        )


_CREATE_PRESET_TABLE_SQLITE = """\
CREATE TABLE IF NOT EXISTS graph_filter_presets (
    name TEXT NOT NULL,
    tenant_id TEXT NOT NULL DEFAULT 'default',
    description TEXT DEFAULT '',
    filters TEXT NOT NULL,
    created_at TEXT NOT NULL,
    PRIMARY KEY (name, tenant_id)
)
"""

_API_GRAPH_TENANT_TABLE_KEYS: dict[str, tuple[str, ...]] = {
    "graph_filter_presets": ("name",),
    "graph_node_search": ("node_id", "scan_id"),
}


def _escape_like_query(query: str) -> str:
    """Escape SQL LIKE wildcards so search terms are treated literally."""
    return query.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


def _node_search_text(node: UnifiedNode) -> str:
    parts: list[str] = [
        node.id,
        node.label,
        node.entity_type.value if hasattr(node.entity_type, "value") else str(node.entity_type),
        node.severity or "",
        " ".join(node.compliance_tags),
        " ".join(node.data_sources),
        json.dumps(node.attributes, default=str, sort_keys=True),
        json.dumps(node.dimensions.to_dict(), sort_keys=True),
    ]
    return " ".join(part for part in parts if part).lower()


def _node_sort_key(node: UnifiedNode) -> tuple[int, float, str, str]:
    return (int(node.severity_id or 0), float(node.risk_score or 0.0), node.label or "", node.id)


def encode_graph_cursor(node: UnifiedNode) -> str:
    payload = json.dumps(list(_node_sort_key(node)), separators=(",", ":"), ensure_ascii=True).encode()
    return base64.urlsafe_b64encode(payload).decode().rstrip("=")


def decode_graph_cursor(cursor: str) -> tuple[int, float, str, str]:
    try:
        padded = cursor + "=" * (-len(cursor) % 4)
        raw = base64.urlsafe_b64decode(padded.encode()).decode()
        values = json.loads(raw)
        if not isinstance(values, list) or len(values) != 4:
            raise ValueError
        severity_id, risk_score, label, node_id = values
        return int(severity_id), float(risk_score), str(label), str(node_id)
    except Exception as exc:  # pragma: no cover - normalized into ValueError for route handling
        raise ValueError("Invalid graph cursor") from exc


_DYNAMIC_RELATIONSHIP_VALUES = {
    RelationshipType.INVOKED.value,
    RelationshipType.ACCESSED.value,
    RelationshipType.DELEGATED_TO.value,
    RelationshipType.TRACE_STEP.value,
}


def _typed_containment_subtree(graph: UnifiedGraph, node_id: str) -> UnifiedGraph:
    """Drop nodes the walk reached over an edge the roll-up does not treat as containment.

    The store walk filters by relationship type only, so a ``USES`` edge out of
    an application widens it exactly like an agent's ``USES`` of its server. The
    roll-up types containment by endpoint; the subtree must use the same rule.
    """
    from agent_bom.graph.rollup import containment_descendants

    keep = {node_id, *containment_descendants(graph, node_id)}
    if len(keep) == len(graph.nodes):
        return graph
    return graph._inherit_completeness(graph._subgraph(node_filter=lambda node: node.id in keep))


def _attach_sibling_relationships(
    store: Any,
    graph: UnifiedGraph,
    *,
    tenant_id: str,
    scan_id: str,
) -> None:
    """Add the non-containment edges *between* the subtree's nodes.

    The walk above deliberately follows containment only — following ``USES``
    would leave the subtree and stop being a drill-down. But ``drill_down`` also
    aggregates the relationships *between* the children it returns, and those
    are exactly the edges the walk excluded, so the drill-down drew a row of
    disconnected cards for the same reason the top level did.

    Scoped to the subtree's own node ids, so the read stays proportional to the
    answer rather than to the estate — the property
    :func:`containment_drilldown_graph` exists to protect. Edges with one
    endpoint outside the subtree come back from the store (the query matches on
    either endpoint) and are dropped here; the roll-up would discard them
    anyway, having nothing at this level to attribute them to.

    A backend that cannot answer a scoped edge query keeps the subtree it
    already has: fewer relationships drawn, never a failed drill-down.
    """
    node_ids = set(graph.nodes)
    if not node_ids:
        return
    unsupported: tuple[type[BaseException], ...] = (*_unsupported_traversal_errors(), AttributeError)
    try:
        edges = store.edges_for_node_ids(tenant_id=tenant_id, scan_id=scan_id, node_ids=node_ids)
    except unsupported:
        return
    for edge in edges:
        if edge.source in node_ids and edge.target in node_ids:
            graph.add_stored_edge(edge)


def _drilldown_subtree_budget() -> int:
    from agent_bom.config import GRAPH_ROLLUP_DRILLDOWN_SUBTREE_BUDGET

    return GRAPH_ROLLUP_DRILLDOWN_SUBTREE_BUDGET


def _unsupported_traversal_errors() -> tuple[type[BaseException], ...]:
    """Backends that implement only part of the protocol, resolved lazily.

    Imported inside the call so selecting SQLite or Postgres never pulls the
    optional Neptune adapter into the import graph.
    """
    from agent_bom.api.neptune_graph import NeptuneGraphStoreUnsupportedOperationError

    return (NeptuneGraphStoreUnsupportedOperationError,)


SQLITE_INVENTORY_SEARCH_CLAUSE = (
    "(LOWER(label) LIKE ? ESCAPE '\\' OR LOWER(json_remove(attributes, '$._agent_bom_canonical_id')) LIKE ? ESCAPE '\\')"
)
