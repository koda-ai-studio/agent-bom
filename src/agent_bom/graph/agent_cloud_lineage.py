"""Agent cloud lineage for unified graph construction."""

from __future__ import annotations

from typing import Any

from agent_bom.graph.builder_cloud_lineage import (
    _add_cloud_principal_lineage,
    _add_lineage_resource_nodes,
    _add_lineage_scope_edges,
    _resolve_cloud_lineage,
)
from agent_bom.graph.container import UnifiedGraph


def _add_agent_cloud_lineage(
    graph: UnifiedGraph,
    *,
    agent_id: str,
    agent_dict: dict[str, Any],
    agent_metadata: dict[str, Any],
    data_source: str,
) -> None:
    """Promote normalized cloud-origin metadata into explicit lineage nodes.

    Cloud providers already normalize runtime identity into ``agent.metadata``.
    The graph should carry that as inventory too, otherwise cloud-discovered
    agents remain disconnected from provider/runtime assets.
    """
    origin = agent_metadata.get("cloud_origin")
    if not isinstance(origin, dict):
        return
    lineage = _resolve_cloud_lineage(agent_dict, origin, data_source)
    if lineage is None:
        return
    _add_lineage_resource_nodes(graph, lineage, agent_metadata)
    _add_lineage_scope_edges(graph, lineage, agent_id)
    principal = agent_metadata.get("cloud_principal")
    if isinstance(principal, dict):
        _add_cloud_principal_lineage(graph, lineage, principal, agent_id)
