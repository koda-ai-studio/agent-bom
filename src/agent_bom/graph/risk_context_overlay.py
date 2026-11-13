"""Write each asset's :mod:`agent_bom.graph.risk_context` onto the graph.

Runs once at the end of graph analysis, after the overlays that record
exposure, permissions and data classification, so the context reflects every
recorded fact without feeding back into the analysis that produced them.
"""

from __future__ import annotations

from typing import Any

from agent_bom.graph.container import UnifiedGraph
from agent_bom.graph.risk_context import RISK_CONTEXT_KEY, derive_node_risk_context
from agent_bom.graph.types import EntityType, RelationshipType

# Findings, code and package nodes describe evidence about an asset, not an
# asset an attacker stands on; they never carry exposure or privilege.
_NON_ASSET_TYPES = frozenset(
    {
        EntityType.PACKAGE,
        EntityType.VULNERABILITY,
        EntityType.MISCONFIGURATION,
        EntityType.DRIFT_INCIDENT,
        EntityType.TOOL_CALL,
        EntityType.SOURCE_FILE,
        EntityType.CODE_MODULE,
        EntityType.CONFIG_FILE,
        EntityType.EXTERNAL_IMPORT,
        EntityType.DIRECTORY,
        EntityType.FRAMEWORK,
        EntityType.BLUEPRINT,
    }
)
ASSET_TYPES = tuple(entity_type for entity_type in EntityType if entity_type not in _NON_ASSET_TYPES)

# The built-in Kubernetes role that grants every verb on every resource.
_CLUSTER_ADMIN = ("ClusterRole", "cluster-admin")


def _cluster_admin_grants(graph: UnifiedGraph) -> dict[str, list[dict[str, Any]]]:
    roles = {
        node.id
        for node in graph.iter_nodes_of_types((EntityType.ROLE,))
        if (node.attributes.get("kubernetes_kind"), node.attributes.get("kubernetes_name")) == _CLUSTER_ADMIN
    }
    if not roles:
        return {}
    grants: dict[str, list[dict[str, Any]]] = {}
    for edge in graph.edges:
        if edge.relationship != RelationshipType.INHERITS or edge.target not in roles:
            continue
        evidence = edge.evidence or {}
        grant = {"role": str(evidence.get("role") or "ClusterRole/cluster-admin"), "role_node": edge.target}
        if evidence.get("binding"):
            grant["binding"] = str(evidence["binding"])
        grants.setdefault(edge.source, []).append(grant)
    return grants


def apply_node_risk_context(graph: UnifiedGraph) -> dict[str, int]:
    """Store the derived context on every asset that has one; drop stale ones.

    Streams the assets read-only and takes a node for writing only when its
    stored context changes, so a store-backed build stays bounded.
    """
    grants = _cluster_admin_grants(graph)
    counts = {"nodes": 0, "internet_exposed": 0, "admin": 0, "sensitive": 0, "crown_jewel": 0}
    for node in graph.iter_nodes_of_types(ASSET_TYPES):
        entity_type = node.entity_type.value if isinstance(node.entity_type, EntityType) else str(node.entity_type)
        context = derive_node_risk_context(
            entity_type,
            node.attributes,
            scan_id=graph.scan_id,
            data_sources=node.data_sources,
            admin_grants=grants.get(node.id, ()),
        )
        if context != node.attributes.get(RISK_CONTEXT_KEY):
            writable = graph.get_node(node.id)
            if writable is not None:
                if context is None:
                    writable.attributes.pop(RISK_CONTEXT_KEY, None)
                else:
                    writable.attributes[RISK_CONTEXT_KEY] = context
        if context is None:
            continue
        counts["nodes"] += 1
        counts["internet_exposed"] += context["internet_exposed"] is True
        counts["admin"] += context["is_admin"] is True
        counts["sensitive"] += context["data_sensitivity"] not in (None, "none")
        counts["crown_jewel"] += context["crown_jewel"] is True
    return counts


__all__ = ["ASSET_TYPES", "apply_node_risk_context"]
