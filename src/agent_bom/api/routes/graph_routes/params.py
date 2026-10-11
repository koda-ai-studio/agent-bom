"""Graph route parameter parsing, limits and small response helpers."""

from __future__ import annotations

import json
from typing import Any

from fastapi import HTTPException

from agent_bom.graph import EntityType, GraphSemanticLayer, RelationshipType, UnifiedEdge
from agent_bom.graph.path_derivation import _rel_value
from agent_bom.mcp_errors import CODE_UNSUPPORTED_BACKEND, CODE_UPSTREAM_UNAVAILABLE

_ALLOWED_ENTITY_TYPES = {entity_type.value for entity_type in EntityType}


_GRAPH_QUERY_ABSOLUTE_LIMITS = {
    "max_depth": 10,
    "max_nodes": 5000,
    "max_edges": 25_000,
    "timeout_ms": 5000,
}


_GRAPH_QUERY_DEFAULT_BUDGET = {
    "max_depth": 5,
    "max_nodes": 1000,
    "max_edges": 10_000,
    "timeout_ms": 2500,
}


_FILTERED_GRAPH_ATTACK_PATH_LIMIT = 100


_GOVERNANCE_EDGE_LIMIT = 5_000


_GOVERNANCE_ATTACK_PATH_LIMIT = 100


_SEMANTIC_LAYER_LABELS = {
    GraphSemanticLayer.USER.value: "User",
    GraphSemanticLayer.IDENTITY.value: "Identity",
    GraphSemanticLayer.APP.value: "Application",
    GraphSemanticLayer.API_GATEWAY.value: "API / Gateway",
    GraphSemanticLayer.ORCHESTRATION.value: "Orchestration",
    GraphSemanticLayer.MCP_SERVER.value: "MCP Server",
    GraphSemanticLayer.TOOL.value: "Tool",
    GraphSemanticLayer.PACKAGE.value: "Package",
    GraphSemanticLayer.RUNTIME_EVIDENCE.value: "Runtime Evidence",
    GraphSemanticLayer.ASSET.value: "Asset",
    GraphSemanticLayer.INFRA.value: "Infrastructure",
    GraphSemanticLayer.FINDING.value: "Finding",
    GraphSemanticLayer.CODE.value: "Code",
    GraphSemanticLayer.CI.value: "CI/CD",
}


def _parse_entity_type_filter(raw: str | None) -> set[str] | None:
    if not raw:
        return None
    values = {value.strip() for value in raw.split(",") if value.strip()}
    invalid = sorted(values - _ALLOWED_ENTITY_TYPES)
    if invalid:
        raise HTTPException(status_code=422, detail=f"Unsupported graph entity type: {invalid[0]}")
    return values or None


def _parse_relationship_filter(raw: str | None) -> set[RelationshipType]:
    if not raw:
        return set()
    parsed: set[RelationshipType] = set()
    for value in raw.split(","):
        value = value.strip()
        if not value:
            continue
        try:
            parsed.add(RelationshipType(value))
        except ValueError as exc:
            raise HTTPException(status_code=422, detail=f"Unsupported graph relationship type: {value}") from exc
    return parsed


def _validate_relationship_list(values: list[str]) -> set[RelationshipType] | None:
    if not values:
        return None
    parsed: set[RelationshipType] = set()
    for value in values:
        cleaned = value.strip()
        if not cleaned:
            continue
        try:
            parsed.add(RelationshipType(cleaned))
        except ValueError as exc:
            raise HTTPException(status_code=422, detail=f"Unsupported graph relationship type: {cleaned}") from exc
    return parsed or None


def _validate_entity_type_list(values: list[str]) -> list[str]:
    cleaned = [value.strip() for value in values if value.strip()]
    invalid = sorted(set(cleaned) - _ALLOWED_ENTITY_TYPES)
    if invalid:
        raise HTTPException(status_code=422, detail=f"Unsupported graph entity type: {invalid[0]}")
    return cleaned


def _joined_edges(*groups: list[UnifiedEdge]) -> list[UnifiedEdge]:
    """Concatenate edge lists without listing the same edge twice.

    The containment-ancestor walk starts from the page's own edge list, so an
    edge reaching the page from a parent outside it is found there *and* stays
    in ``paged_edges`` — concatenating the two returned it twice. The key is the
    one ``UnifiedGraph.add_edge`` already uses, so the response cannot disagree
    with the graph about what makes an edge the same edge.
    """
    seen: set[tuple[str, str, str]] = set()
    joined: list[UnifiedEdge] = []
    for group in groups:
        for edge in group:
            key = (edge.source, edge.target, _rel_value(edge))
            if key in seen:
                continue
            seen.add(key)
            joined.append(edge)
    return joined


def _boundary_edge_count(edges: list[UnifiedEdge], node_ids: set[str]) -> int:
    """How many returned edges have an endpoint the response did not return.

    ``edges_for_node_ids`` matches ``source OR target`` deliberately: a page is
    ranked by severity, so on a dense finding page the asset each finding hangs
    off is usually not on the page, and dropping those edges would hand back a
    scatter of unattached findings (and would break the containment-ancestor
    walk, which finds parents precisely by looking at edges reaching in from
    outside). So the payload is *not* an induced subgraph — but a client that
    assumes it is will silently drop these edges or invent phantom endpoints.
    Counting them is the fail-closed half: the response says how much of its
    edge list reaches past its node list instead of leaving it to be discovered.
    """
    return sum(1 for edge in edges if edge.source not in node_ids or edge.target not in node_ids)


def _candidate_to_string(candidate: str | dict[str, Any]) -> str:
    if isinstance(candidate, str):
        return candidate.strip()
    return json.dumps(candidate, sort_keys=True, separators=(",", ":"), default=str)


def _raise_mcp_error_as_http(payload: dict[str, Any]) -> None:
    error = payload.get("error")
    if not isinstance(error, dict):
        return
    category = str(error.get("category") or "internal")
    if error.get("code") == CODE_UPSTREAM_UNAVAILABLE:
        raise HTTPException(status_code=503, detail=error)
    if error.get("code") == CODE_UNSUPPORTED_BACKEND:
        # Same status the direct store calls use for a backend capability gap.
        raise HTTPException(status_code=501, detail=error)
    status_by_category = {
        "validation": 422,
        "auth": 403,
        "rate_limited": 429,
        "not_found": 404,
        "unsupported": 400,
        "timeout": 504,
        "upstream": 502,
        "internal": 500,
    }
    raise HTTPException(status_code=status_by_category.get(category, 500), detail=error)


def _diff_entry_node_id(entry: Any) -> str | None:
    """Node id for a diff entry, tolerating both dict and bare-id shapes."""
    if isinstance(entry, dict):
        nid = entry.get("id")
        return str(nid) if nid is not None else None
    if entry is None:
        return None
    return str(entry)


def _diff_entry_edge_key(entry: Any) -> str:
    """Stable ``source|target|relationship`` key for a diff edge entry.

    Handles the three shapes the stores emit: ``(source, target, relationship)``
    tuples for added/removed edges, and ``{"before"|"after": edge}`` wrappers
    (or a bare edge dict) for changed edges.
    """
    if isinstance(entry, dict):
        edge = entry.get("after") or entry.get("before") or entry
        src = edge.get("source_id") or edge.get("source") or ""
        tgt = edge.get("target_id") or edge.get("target") or ""
        rel = edge.get("relationship") or ""
        return f"{src}|{tgt}|{rel}"
    if isinstance(entry, (list, tuple)) and len(entry) >= 3:
        return f"{entry[0]}|{entry[1]}|{entry[2]}"
    return str(entry)


def _tag_diff_change_kinds(diff: dict[str, Any]) -> dict[str, Any]:
    """Tag each diff node/edge with a ``change_kind`` for the drift UI lens.

    Adds an in-place ``change_kind`` (``new`` | ``removed`` | ``changed``) to
    every dict-shaped node/edge entry (leaving any pre-existing value intact)
    and attaches a ``change_kind_index`` mapping node ids and edge keys to
    their kind so the client can classify the rendered graph without having to
    reconcile the three heterogeneous entry shapes. Entries not present in the
    index are treated as ``unchanged`` by consumers.
    """
    if not isinstance(diff, dict):
        return diff

    node_kinds: dict[str, str] = {}
    for kind, key in (("new", "nodes_added"), ("removed", "nodes_removed"), ("changed", "nodes_changed")):
        for entry in diff.get(key) or []:
            nid = _diff_entry_node_id(entry)
            if nid is None:
                continue
            node_kinds[nid] = kind
            if isinstance(entry, dict):
                entry.setdefault("change_kind", kind)

    edge_kinds: dict[str, str] = {}
    for kind, key in (("new", "edges_added"), ("removed", "edges_removed"), ("changed", "edges_changed")):
        for entry in diff.get(key) or []:
            edge_kinds[_diff_entry_edge_key(entry)] = kind
            if isinstance(entry, dict):
                entry.setdefault("change_kind", kind)

    diff["change_kind_index"] = {"nodes": node_kinds, "edges": edge_kinds}
    return diff
