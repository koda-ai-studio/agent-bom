"""The semantic layer a graph node belongs to, stamped on every API node record.

One map per entity kind (the schema legend's ``layer``), overridden only by a
layer the producer recorded: ``attributes.semantic_layer`` first, then a
``dimensions.surface`` that names a layer. A surface that is not a layer name
(``container-image``) never overrides the kind.
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import Any

from agent_bom.graph.legend import ENTITY_LEGEND
from agent_bom.graph.node import UnifiedNode
from agent_bom.graph.types import GraphSemanticLayer, entity_type_value

LAYER_BY_ENTITY_TYPE: dict[str, str] = {entry.key: entry.layer for entry in ENTITY_LEGEND}
_LAYERS = frozenset(layer.value for layer in GraphSemanticLayer)


def semantic_layer(node: UnifiedNode) -> str:
    recorded = node.attributes.get("semantic_layer")
    if isinstance(recorded, str) and recorded in _LAYERS:
        return recorded
    if node.dimensions.surface in _LAYERS:
        return node.dimensions.surface
    return LAYER_BY_ENTITY_TYPE.get(entity_type_value(node.entity_type), GraphSemanticLayer.ASSET.value)


def node_payload(node: UnifiedNode) -> dict[str, Any]:
    """``UnifiedNode.to_dict`` plus ``semantic_layer``; the stored record stays unchanged."""
    return {**node.to_dict(), "semantic_layer": semantic_layer(node)}


def node_payloads(nodes: Sequence[UnifiedNode], *, context_from: int) -> list[dict[str, Any]]:
    """Node records for a page; those from ``context_from`` on are marked ``context: true``."""
    return [{**node_payload(node), "context": True} if index >= context_from else node_payload(node) for index, node in enumerate(nodes)]


__all__ = ["LAYER_BY_ENTITY_TYPE", "node_payload", "node_payloads", "semantic_layer"]
