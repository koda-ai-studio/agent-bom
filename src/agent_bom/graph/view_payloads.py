"""Pure graph projections shared by transport adapters."""

from typing import Any, Literal

from agent_bom.graph.completeness import graph_completeness
from agent_bom.graph.container import UnifiedGraph
from agent_bom.graph.rollup import RollupFilters, attack_path_view, drill_down, rollup_view
from agent_bom.graph.semantic_clusters import SEMANTIC_CLUSTER_KINDS, build_semantic_clusters, semantic_cluster_stats
from agent_bom.graph.snapshot_paths import resolve_snapshot_attack_paths


def _semantic_cluster_payload(
    graph: UnifiedGraph,
    *,
    selected_kinds: set[str],
    min_members: int,
    limit: int,
) -> dict[str, Any]:
    all_clusters = [
        cluster
        for cluster in build_semantic_clusters(graph.nodes.values(), graph.edges, min_members=min_members)
        if cluster.kind in selected_kinds
    ]
    clusters = all_clusters[:limit]
    return {
        "scan_id": graph.scan_id,
        "tenant_id": graph.tenant_id,
        "created_at": graph.created_at,
        "clusters": [cluster.to_dict() for cluster in clusters],
        "stats": semantic_cluster_stats(clusters),
        "available_kinds": list(SEMANTIC_CLUSTER_KINDS),
        "completeness": graph_completeness(
            returned=len(clusters),
            total=len(all_clusters),
            truncated=len(all_clusters) > len(clusters),
            reason="cluster_limit" if len(all_clusters) > len(clusters) else "",
        ),
    }


def _graph_rollup_payload(
    graph: UnifiedGraph,
    *,
    node: str | None,
    min_severity: str,
    exposed: bool,
    toxic: bool,
    mode: Literal["rollup", "attack_path"],
    offset: int = 0,
    limit: int | None = None,
    graph_store: Any = None,
) -> dict[str, Any]:
    filters = RollupFilters(
        min_severity=min_severity,
        exposed_only=exposed,
        toxic_only=toxic,
    )
    if node:
        return drill_down(graph, node, filters=filters, offset=offset, limit=limit)
    if mode == "attack_path":
        return attack_path_view(graph, resolve_snapshot_attack_paths(graph, graph_store), filters=filters)
    return rollup_view(graph, filters=filters, offset=offset, limit=limit)
