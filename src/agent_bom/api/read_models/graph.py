"""Documented 200 contracts for the ``/v1/graph`` read endpoints.

Shared node, edge and attack-path records describe canonical serialization.
Provider evidence and endpoint-specific projections remain open objects.
"""

from __future__ import annotations

from typing import Annotated, Any

from pydantic import BaseModel, RootModel, WithJsonSchema

from agent_bom.api.read_models._base import ReadModel, ReadResponse
from agent_bom.api.read_models.graph_records import (
    GraphAgentRecord,
    GraphAttackPathRecord,
    GraphAttackPathSummary,
    GraphEdgeRecord,
    GraphNodeRecord,
)
from agent_bom.graph.semantic_clusters import SemanticCluster

Row = dict[str, Any]


def documented_list(model: type[BaseModel]) -> dict[str, Any]:
    """``documented`` for list bodies: same runtime serialization as ``list[dict]``."""
    ref = WithJsonSchema({"$ref": f"#/components/schemas/{model.__name__}"})
    return {"response_model": Annotated[list[dict[str, Any]], ref], "responses": {200: {"model": model}}}


class GraphCompleteness(ReadModel):
    status: str
    complete: bool
    sampled: bool
    truncated: bool
    returned: int
    total: int | None = None
    reason: str | None = None


class GraphPagination(ReadModel):
    total: int
    offset: int
    limit: int
    has_more: bool
    cursor: str | None = None
    next_cursor: str | None = None


class GraphBoundedPage(ReadModel):
    total: int
    limit: int
    has_more: bool


class GraphPageResponse(ReadResponse):
    """``GET /v1/graph``: one ranked node page plus incident edges and context."""

    snapshot_generation: str | None = None
    scan_id: str
    tenant_id: str
    created_at: str
    collection_coverage: Row | None = None
    nodes: list[GraphNodeRecord]
    edges: list[GraphEdgeRecord]
    attack_paths: list[GraphAttackPathRecord]
    attack_campaigns: list[Row] | None = None
    interaction_risks: list[Row]
    stats: Row
    pagination: GraphPagination
    completeness: GraphCompleteness
    attack_path_pagination: GraphBoundedPage | None = None
    evidence_scope: str | None = None


class GraphAgentsResponse(ReadResponse):
    snapshot_generation: str | None = None
    scan_id: str
    tenant_id: str
    created_at: str
    agents: list[GraphAgentRecord]
    pagination: GraphPagination
    completeness: GraphCompleteness


class GraphClustersResponse(ReadResponse):
    scan_id: str
    tenant_id: str
    created_at: str
    clusters: list[SemanticCluster]
    stats: dict[str, int]
    available_kinds: list[str]
    completeness: GraphCompleteness


class GraphComplianceResponse(ReadResponse):
    scan_id: str
    framework_count: int | None = None
    total_tagged_findings: int | None = None
    frameworks: dict[str, Row] | None = None
    completeness: GraphCompleteness | None = None


class GraphDiffPagination(ReadModel):
    offset: int
    limit: int
    returned: int
    has_more: bool
    next_cursor: str | None = None


class GraphDiffResponse(ReadResponse):
    """``GET /v1/graph/diff``: ``summary`` (default), ``detail`` rows, or capped ``full`` lists."""

    schema_version: str
    old: str
    new: str
    view: str
    summary: Row | None = None
    filters: dict[str, str] | None = None
    total: int | None = None
    items: list[Row] | None = None
    pagination: GraphDiffPagination | None = None
    nodes_added: list[Any] | None = None
    nodes_removed: list[Any] | None = None
    nodes_changed: list[Any] | None = None
    attribute_deltas: dict[str, list[Row]] | None = None
    edges_added: list[Any] | None = None
    edges_removed: list[Any] | None = None
    edges_changed: list[Any] | None = None
    change_kind_index: dict[str, dict[str, str]] | None = None
    truncated: bool | None = None
    complete: bool | None = None
    returned_changes: int | None = None
    total_changes: int | None = None
    limits: dict[str, int] | None = None
    omitted_fields: list[str] | None = None
    completeness: GraphCompleteness


class GraphEstateChangesPagination(ReadModel):
    offset: int
    limit: int
    returned: int
    total: int
    has_more: bool
    next_offset: int | None = None


class GraphEstateChangesResponse(ReadResponse):
    """``GET /v1/graph/changes``: each target scope's current snapshot against its own previous snapshot.

    ``sources`` are scopes with a comparable previous snapshot: the scope's own
    earlier scan (``baseline: scope_history``) or, for a scope scanned once, the
    store's earlier same-kind snapshot that no other scope owns
    (``baseline: snapshot_continuity``). Each changed source carries added and
    removed stored attack paths in ``highlights``. ``new_sources`` are first
    observations and are never counted as additions. ``totals`` cover the
    returned page of scopes; ``completeness`` says whether more scopes exist.
    """

    schema_version: str
    evidence_scope: str
    sources: list[Row]
    new_sources: list[Row]
    totals: Row
    pagination: GraphEstateChangesPagination
    completeness: GraphCompleteness
    completeness_reasons: list[str]


class GraphActiveEdgesResponse(RootModel[list[Row]]):
    """``GET /v1/graph/edges/active``: edge versions active at ``at``."""


class GraphEdgeChangeSummary(ReadModel):
    added: int
    removed: int
    changed: int
    unchanged: int


class GraphEdgeChangesResponse(ReadResponse):
    scan_id_old: str | None = None
    scan_id_new: str | None = None
    edges_added: list[Row] | None = None
    edges_removed: list[Row] | None = None
    edges_changed: list[Row] | None = None
    edges_unchanged: list[Row] | None = None
    summary: GraphEdgeChangeSummary | None = None
    completeness: GraphCompleteness | None = None


class GraphEvidenceManifestResponse(ReadResponse):
    schema_version: str
    tenant_id: str
    scan_id: str
    generated_at: str | None = None
    scan_created_at: str | None = None
    graph_digest: str | None = None
    findings_digest: str | None = None
    diff_baseline_scan_id: str | None = None
    diff_summary: Row | None = None
    counts: dict[str, int] | None = None
    included_tables: list[str] | None = None
    excluded_private_fields: list[str] | None = None
    retention_policy: Row | None = None
    evidence_scope: str | None = None
    collection_coverage: Row | None = None
    snapshot_generation: str | None = None


class GraphExposurePathsResponse(ReadResponse):
    schema_version: str
    tool: str
    tenant_id: str
    scan_id: str | None = None
    evidence_scope: str | None = None
    snapshot_generation: str | None = None
    collection_coverage: Row | None = None
    created_at: str | None = None
    count: int
    total: int | None = None
    count_metadata: Row | None = None
    snapshot_total: int | None = None
    view: str | None = None
    ranking: Row | None = None
    risk_scale: Row | None = None
    filters: Row | None = None
    paths: list[Row]
    nodes: list[GraphNodeRecord] | None = None
    edges: list[GraphEdgeRecord] | None = None
    stats: Row | None = None
    completeness: GraphCompleteness | None = None
    pagination: Row | None = None
    message: str | None = None


class GraphGovernanceStats(ReadModel):
    node_count: int
    edge_count: int
    analysis_status: Row


class GraphGovernanceResponse(ReadResponse):
    scan_id: str
    tenant_id: str
    created_at: str
    nodes: list[GraphNodeRecord]
    edges: list[GraphEdgeRecord]
    attack_paths: list[GraphAttackPathRecord]
    overlay: dict[str, int]
    governance_counts: dict[str, int]
    stats: GraphGovernanceStats
    edge_pagination: GraphBoundedPage
    attack_path_pagination: GraphBoundedPage
    completeness: GraphCompleteness


class GraphHistoryResponse(ReadResponse):
    schema_version: str | None = None
    tenant_id: str | None = None
    retention_policy: Row | None = None
    snapshots: list[Row]
    window: Row | None = None


class GraphImpactInterpretation(ReadModel):
    basis: str
    execution: str
    collection_coverage: str
    traversable_only: bool
    max_depth: int
    traversal_classes: list[str]
    excluded_traversal_classes: list[str]
    # Relationships inside a walked class that are still never reach (trace order).
    excluded_relationships: list[str]


class GraphImpactResponse(ReadResponse):
    node_id: str
    affected_nodes: list[str]
    affected_by_type: dict[str, int]
    affected_nodes_detail: list[Row] | None = None
    direction: str | None = None
    affected_count: int
    max_depth_reached: int
    completeness: Row
    scan_id: str
    tenant_id: str
    snapshot_generation: str | None
    interpretation: GraphImpactInterpretation
    resolved_from: str | None = None


class GraphLegendResponse(ReadResponse):
    entities: list[Row]
    relationships: list[Row]


class GraphNhiCounts(ReadModel):
    over_granted: int
    dormant: int
    orphaned: int
    by_risk_band: dict[str, int]


class GraphNhiGovernanceResponse(ReadResponse):
    status: str
    secret_values_included: bool
    evaluated: int
    dormant_after_days: int
    counts: GraphNhiCounts
    identities: list[Row]
    message: str
    generated_from: str
    scan_id: str
    tenant_id: str


class GraphNodeContextResponse(ReadResponse):
    scan_id: str
    tenant_id: str
    snapshot_generation: str | None
    node: GraphNodeRecord
    edges_out: list[GraphEdgeRecord]
    edges_in: list[GraphEdgeRecord]
    neighbors: list[Any]
    sources: list[Any]
    impact: Row
    completeness: Row
    resolved_from: str | None = None


class GraphNodeNeighborsResponse(ReadResponse):
    node_id: str
    scan_id: str
    found: bool
    direction: str
    limit: int
    total_neighbors: int | None
    truncated: bool
    neighbors: list[GraphNodeRecord]
    edges: list[GraphEdgeRecord]
    completeness: GraphCompleteness
    resolved_from: str | None = None


class GraphPathHop(ReadModel):
    target: str
    hops: list[str]
    depth: int


class GraphPathsResponse(ReadResponse):
    source: str
    source_id: str
    max_depth: int
    reachable_count: int
    reachable_nodes: list[str]
    paths: list[GraphPathHop]
    attack_paths: list[GraphAttackPathRecord]
    pagination: GraphPagination
    truncated: bool
    depth_limited: bool
    completeness: GraphCompleteness
    resolved_from: str | None = None


class GraphPresetsResponse(RootModel[list[Row]]):
    """``GET /v1/graph/presets``: saved filter presets for the tenant."""


class GraphRollupEdge(ReadModel):
    """Aggregate counts and recorded directions, not a single evidence edge."""

    source: str
    target: str
    count: int
    relationships: list[str]
    directions: list[str] | None = None
    relationship_counts: dict[str, int] | None = None


class GraphRollupResponse(ReadResponse):
    """Roll-up, attack-path-first, or drill-down view, selected by ``mode``."""

    scan_id: str
    tenant_id: str
    created_at: str
    mode: str
    filters: Row
    summary: Row
    completeness: GraphCompleteness
    snapshot_generation: str | None = None
    top_level: list[Row] | None = None
    edges: list[GraphRollupEdge] | None = None
    edge_count_metadata: Row | None = None
    aggregate_count_metadata: Row | None = None
    orphan_summary: Row | None = None
    node: Row | None = None
    children: list[Row] | None = None
    pagination: Row | None = None
    attack_paths: list[GraphAttackPathSummary] | None = None
    path_nodes: list[GraphNodeRecord] | None = None
    path_edges: list[GraphEdgeRecord] | None = None
    resolved_from: str | None = None
    collapsed: list[Row] | None = None


class GraphSchemaResponse(ReadResponse):
    version: int
    interchange: dict[str, str]
    semantic_layers: list[dict[str, str]]
    node_kinds: list[Row]
    edge_kinds: list[Row]
    node_types: list[str]
    edge_types: list[str]


class GraphSearchFilters(ReadModel):
    scan_id: str
    entity_types: list[str]
    min_severity: str
    compliance_prefixes: list[str]
    data_sources: list[str]


class GraphSearchResponse(ReadResponse):
    snapshot_generation: str | None
    query: str
    filters: GraphSearchFilters
    results: list[GraphNodeRecord]
    pagination: GraphPagination
    completeness: GraphCompleteness


class GraphSnapshotsResponse(RootModel[list[Row]]):
    """``GET /v1/graph/snapshots``: retained snapshots, newest first."""
