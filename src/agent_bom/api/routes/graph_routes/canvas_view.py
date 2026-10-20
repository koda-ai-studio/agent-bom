"""``view=canvas`` for ``GET /v1/graph``: the graph page's projection.

The default projection is the public contract and stays whole. The graph page
reads a known subset of it before a selection, and a selection refetches
``/v1/graph/node/{id}`` and merges the full node back, so the canvas view drops
only fields no module the page loads reads (guarded by
``tests/api/test_graph_canvas_view.py``) and the ``source_id``/``target_id``
edge aliases of ``source``/``target``.
"""

from __future__ import annotations

from typing import Any, Literal

GraphView = Literal["canvas"]
CANVAS_VIEW_DESCRIPTION = (
    "``canvas`` returns the graph page's projection: the same response without node and edge fields the "
    "page never reads before a selection (OCSF ids, canonical ids, provenance blocks, bulky attributes) "
    "and without the source_id/target_id edge aliases. Omit for the full projection."
)

CANVAS_DROPPED_NODE_FIELDS = ("evidence_provenance", "canonical_id", "category_uid", "class_uid", "type_uid", "severity_id")
CANVAS_DROPPED_NODE_ATTRIBUTES = (
    "finding_ids_by_asset",
    "tags",
    "configuration",
    "native_id",
    "resource_name",
    "ai_lane",
    "publicly_accessible",
    "over_permissive",
    "fictional",
)
CANVAS_DROPPED_EDGE_FIELDS = ("source_id", "target_id", "canonical_id", "valid_from", "valid_to", "activity_id", "source_run_id")


def _canvas_node(node: dict[str, Any]) -> dict[str, Any]:
    slim = {key: value for key, value in node.items() if key not in CANVAS_DROPPED_NODE_FIELDS}
    attributes = node.get("attributes")
    if isinstance(attributes, dict):
        slim["attributes"] = {key: value for key, value in attributes.items() if key not in CANVAS_DROPPED_NODE_ATTRIBUTES}
    return slim


def canvas_projection(payload: dict[str, Any]) -> dict[str, Any]:
    """The payload with the canvas view's unread fields removed, labelled ``view: "canvas"``."""
    return {
        **payload,
        "nodes": [_canvas_node(node) for node in payload.get("nodes") or []],
        "edges": [
            {key: value for key, value in edge.items() if key not in CANVAS_DROPPED_EDGE_FIELDS} for edge in payload.get("edges") or []
        ],
        "view": "canvas",
    }


__all__ = [
    "CANVAS_VIEW_DESCRIPTION",
    "CANVAS_DROPPED_EDGE_FIELDS",
    "CANVAS_DROPPED_NODE_ATTRIBUTES",
    "CANVAS_DROPPED_NODE_FIELDS",
    "GraphView",
    "canvas_projection",
]
