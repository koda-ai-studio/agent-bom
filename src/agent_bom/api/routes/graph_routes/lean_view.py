"""The ``GET /v1/graph`` projections: ``full`` by default, ``summary`` and ``canvas`` on request.

``view=summary`` (alias ``lean``) cuts nodes, edges and embedded paths to what
names and ranks them; a node's full attributes and evidence provenance then
come from ``/v1/graph/node/{id}`` and complete paths from
``/v1/graph/attack-paths``. ``summary`` becomes the default in 0.116.0.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Literal

from fastapi import HTTPException

from agent_bom.api.routes.graph_routes.canvas_view import canvas_projection

GraphView = Literal["full", "summary", "lean", "canvas"]
GraphInclude = Literal["attributes", "paths"]
GRAPH_INCLUDES: tuple[GraphInclude, ...] = ("attributes", "paths")

GRAPH_VIEW_DESCRIPTION = (
    "``full`` (the default in 0.115; ``summary`` becomes the default in 0.116.0) returns the whole node, edge and "
    "path records. ``summary`` (alias ``lean``) returns each node's id, entity_type, label, severity, risk_score, status and the "
    "attributes that name and badge it; each edge's endpoints, relationship, direction, weight, traversable "
    "and confidence (its id is relationship:source:target); and a summary of each embedded attack path. "
    "Full attributes and evidence_provenance come from /v1/graph/node/{node_id}, complete paths from "
    "/v1/graph/attack-paths. ``canvas`` returns the graph page's projection."
)
GRAPH_INCLUDE_DESCRIPTION = (
    "Comma-separated additions to the summary view (and selects it when no view is given): ``attributes`` returns "
    "whole node and edge records, ``paths`` "
    "whole attack-path records. Both together equal ``view=full``. Not valid with ``view=canvas``."
)

LEAN_NODE_FIELDS = ("id", "entity_type", "label", "severity", "risk_score", "status", "attributes")
# What names a node, picks its icon and badges it: display name, kind, ecosystem, provider and place.
LEAN_NODE_ATTRIBUTES = (
    "display_name",
    "agent_type",
    "server_type",
    "transport",
    "protocol",
    "is_mcp",
    "ecosystem",
    "version",
    "purl",
    "package_url",
    "subtype",
    "resource_type",
    "container_kind",
    "kubernetes_kind",
    "finding_kind",
    "provider",
    "cloud_provider",
    "environment",
    "region",
)
# No ``id``: an edge's id is always ``{relationship}:{source}:{target}``, a third of a lean edge's bytes.
LEAN_EDGE_FIELDS = ("source", "target", "relationship", "direction", "weight", "traversable", "confidence")
LEAN_ATTACK_PATH_FIELDS = (
    "source",
    "target",
    "hops",
    "edges",
    "composite_risk",
    "summary",
    "severity",
    "reachability",
    "vuln_ids",
    "finding_ids",
)
_LEAN_ATTRIBUTE_SET = frozenset(LEAN_NODE_ATTRIBUTES)


@dataclass(frozen=True)
class GraphProjection:
    """The resolved response projection; ``full`` leaves the payload untouched."""

    view: GraphView = "full"
    include: frozenset[str] = frozenset()


FULL_PROJECTION = GraphProjection()


def _parse_include(include: str | None) -> frozenset[str]:
    parts = frozenset(part.strip().lower() for part in (include or "").split(",") if part.strip())
    unknown = sorted(parts - set(GRAPH_INCLUDES))
    if unknown:
        raise HTTPException(status_code=422, detail=f"Unknown include value(s): {', '.join(unknown)}; expected attributes, paths")
    return parts


def resolve_projection(view: GraphView | None, include: str | None) -> GraphProjection:
    """The projection a request asked for; an unknown or contradictory request is 422."""
    parts = _parse_include(include)
    if view == "canvas":
        if parts:
            raise HTTPException(status_code=422, detail="include applies to the summary view, not view=canvas")
        return GraphProjection(view="canvas")
    if view == "full" or parts >= set(GRAPH_INCLUDES) or (view is None and not parts):
        return FULL_PROJECTION
    return GraphProjection(view="summary", include=parts)


def _lean_node(node: dict[str, Any]) -> dict[str, Any]:
    slim = {key: node[key] for key in LEAN_NODE_FIELDS if key in node}
    attributes = node.get("attributes")
    slim["attributes"] = (
        {key: value for key, value in attributes.items() if key in _LEAN_ATTRIBUTE_SET} if isinstance(attributes, dict) else {}
    )
    if node.get("context") is True:
        slim["context"] = True
    return slim


def _lean_edge(edge: dict[str, Any]) -> dict[str, Any]:
    return {key: edge[key] for key in LEAN_EDGE_FIELDS if key in edge}


def _lean_path(path: Any) -> Any:
    return {key: path[key] for key in LEAN_ATTACK_PATH_FIELDS if key in path} if isinstance(path, dict) else path


def lean_projection(payload: dict[str, Any], include: frozenset[str] = frozenset()) -> dict[str, Any]:
    """The payload with nodes, edges and paths cut to their summary records, labelled ``view: "summary"``."""
    projected = {**payload}
    if "attributes" not in include:
        projected["nodes"] = [_lean_node(node) for node in payload.get("nodes") or []]
        projected["edges"] = [_lean_edge(edge) for edge in payload.get("edges") or []]
    if "paths" not in include and "attack_paths" in payload:
        projected["attack_paths"] = [_lean_path(path) for path in payload["attack_paths"]]
    projected["view"] = "summary"
    if include:
        projected["include"] = sorted(include)
    return projected


def project_graph_payload(payload: dict[str, Any], projection: GraphProjection) -> dict[str, Any]:
    if projection.view == "canvas":
        return canvas_projection(payload)
    if projection.view == "summary":
        return lean_projection(payload, projection.include)
    return payload


__all__ = [
    "FULL_PROJECTION",
    "GRAPH_INCLUDES",
    "GRAPH_INCLUDE_DESCRIPTION",
    "GRAPH_VIEW_DESCRIPTION",
    "LEAN_ATTACK_PATH_FIELDS",
    "LEAN_EDGE_FIELDS",
    "LEAN_NODE_ATTRIBUTES",
    "LEAN_NODE_FIELDS",
    "GraphProjection",
    "GraphView",
    "lean_projection",
    "project_graph_payload",
    "resolve_projection",
]
