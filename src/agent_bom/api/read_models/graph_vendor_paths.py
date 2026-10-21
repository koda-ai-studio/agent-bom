"""Documented 200 contract for ``GET /v1/graph/attack-paths/cross-vendor``."""

from __future__ import annotations

from typing import Any, Literal

from agent_bom.api.read_models._base import ReadModel, ReadResponse

Row = dict[str, Any]


class GraphVendorPair(ReadModel):
    source_vendor: str
    target_vendor: str
    paths: int


class GraphVendorFacets(ReadModel):
    """Cross-vendor path counts per (source vendor, target vendor) over the whole snapshot queue."""

    unit: Literal["paths"]
    snapshot_paths: int
    cross_vendor_paths: int
    pairs: list[GraphVendorPair]
    selected: dict[str, str] | None = None
    covers_all_paths: bool


class GraphCrossVendorPathsResponse(ReadResponse):
    """The attack-path queue page restricted to paths whose source and target nodes are in different vendors."""

    scan_id: str
    tenant_id: str
    created_at: str | None = None
    nodes: list[Row]
    edges: list[Row]
    attack_paths: list[Row]
    interaction_risks: list[Row]
    stats: Row
    pagination: Row
    completeness: Row | None = None
    count_metadata: Row | None = None
    snapshot_generation: str | None = None
    vendor_facets: GraphVendorFacets


__all__ = ["GraphCrossVendorPathsResponse", "GraphVendorFacets", "GraphVendorPair"]
