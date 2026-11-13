"""Documented 200 contract for ``GET /v1/graph/cluster-map`` (the grouped full map)."""

from __future__ import annotations

from typing import Literal

from agent_bom.api.read_models._base import ReadModel, ReadResponse


class GraphClusterSummary(ReadModel):
    """A group's card: what it holds and how bad the worst of it is."""

    cluster_key: str
    label: str
    tier: int
    tier_label: str
    member_count: int
    worst_severity: str
    severity_counts: dict[str, int]
    on_attack_path_count: int
    risky: bool
    entity_types: dict[str, int]


class GraphClusterListing(GraphClusterSummary):
    id: str
    folded: bool


class GraphClusterMapNode(ReadModel):
    """A drawn element: a group, one of an expanded group's members, or its "+K more" pager."""

    id: str
    kind: Literal["cluster", "member", "more"]
    label: str
    tier: int
    # Groups
    cluster_key: str | None = None
    tier_label: str | None = None
    member_count: int | None = None
    worst_severity: str | None = None
    severity_counts: dict[str, int] | None = None
    on_attack_path_count: int | None = None
    risky: bool | None = None
    entity_types: dict[str, int] | None = None
    expanded: bool | None = None
    shown_member_count: int | None = None
    folded_cluster_count: int | None = None
    # Members and pagers
    cluster_id: str | None = None
    entity_type: str | None = None
    severity: str | None = None
    risk_score: float | None = None
    on_attack_path: bool | None = None
    focused: bool | None = None
    count: int | None = None
    offset: int | None = None
    limit: int | None = None
    next_offset: int | None = None
    prev_offset: int | None = None


class GraphClusterRelationshipCount(ReadModel):
    relationship: str
    count: int


class GraphClusterMapEdge(ReadModel):
    """One bundled edge: the exact number of underlying edges per relationship."""

    id: str
    source: str
    target: str
    count: int
    relationships: list[GraphClusterRelationshipCount]
    risky: bool


class GraphClusterMapSummary(ReadModel):
    total_nodes: int
    total_edges: int
    cluster_count: int
    listed_cluster_count: int
    visible_cluster_count: int
    folded_cluster_count: int
    filtered_node_count: int
    filtered_edge_count: int
    internal_edge_count: int
    drawn_bundle_count: int
    hidden_bundle_count: int
    hidden_bundle_edge_count: int
    element_count: int
    element_budget: int
    dangling_edge_count: int


class GraphClusterMapFocus(ReadModel):
    node_id: str
    cluster_id: str | None = None
    found: bool


class GraphClusterMapFilters(ReadModel):
    risky_only: bool
    member_limit: int


class GraphClusterMapCost(ReadModel):
    edges_scanned: int
    bundles_considered: int


class GraphClusterMapResponse(ReadResponse):
    """Grouped full map of one snapshot: bounded groups, members and bundled edges with exact counts."""

    scan_id: str
    tenant_id: str
    snapshot_generation: str | None = None
    mode: Literal["cluster_map"]
    tiers: list[str]
    nodes: list[GraphClusterMapNode]
    edges: list[GraphClusterMapEdge]
    clusters: list[GraphClusterListing]
    filters: GraphClusterMapFilters
    focus: GraphClusterMapFocus | None = None
    summary: GraphClusterMapSummary
    cost: GraphClusterMapCost


__all__ = ["GraphClusterMapResponse"]
