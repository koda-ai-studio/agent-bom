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

# The left-to-right column each layer takes on a graph canvas: the estate scope
# that contains everything, then entry, workload, agent, MCP server, the tools and
# identities it reaches, and the data, packages and findings at the end. Layers
# sharing a column sit in the same column.
SEMANTIC_LAYER_COLUMNS: dict[str, int] = {
    GraphSemanticLayer.SCOPE.value: 0,
    GraphSemanticLayer.USER.value: 1,
    GraphSemanticLayer.APP.value: 2,
    GraphSemanticLayer.API_GATEWAY.value: 2,
    GraphSemanticLayer.INFRA.value: 3,
    GraphSemanticLayer.CI.value: 3,
    GraphSemanticLayer.CODE.value: 3,
    GraphSemanticLayer.ORCHESTRATION.value: 4,
    GraphSemanticLayer.MCP_SERVER.value: 5,
    GraphSemanticLayer.TOOL.value: 6,
    GraphSemanticLayer.IDENTITY.value: 6,
    GraphSemanticLayer.ASSET.value: 7,
    GraphSemanticLayer.RUNTIME_EVIDENCE.value: 7,
    GraphSemanticLayer.PACKAGE.value: 7,
    GraphSemanticLayer.FINDING.value: 7,
}
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


__all__ = ["LAYER_BY_ENTITY_TYPE", "SEMANTIC_LAYER_COLUMNS", "node_payload", "node_payloads", "semantic_layer"]
