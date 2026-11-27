"""``GET /v1/graph/node-aggregates``: per-node roll-up aggregates."""

from __future__ import annotations

from pydantic import Field

from agent_bom.api.read_models._base import ReadModel, ReadResponse


class GraphRollupAggregate(ReadModel):
    """The containment aggregate a roll-up entry carries for its node."""

    descendant_count: int
    by_type: dict[str, int]
    severity_counts: dict[str, int] = Field(description="Open issues per severity, the same histogram as the roll-up.")
    issue_count: int = Field(description="Distinct open issues in the node's containment scope.")
    finding_occurrence_count: int
    worst_severity: str
    worst_severity_rank: int
    internet_exposed: bool
    toxic_combo: bool
    exposed_count: int = Field(description="Internet-exposed nodes in the node's containment scope.")
    toxic_count: int


class GraphFindingDisclosure(ReadModel):
    """Issues not already disclosed by another requested descendant scope."""

    issue_count: int
    severity_counts: dict[str, int]
    exclude_node_ids: list[str]


class GraphNodeAggregate(ReadModel):
    node_id: str
    semantic_layer: str
    aggregate: GraphRollupAggregate
    finding_disclosure: GraphFindingDisclosure | None = None


class GraphNodeAggregatesResponse(ReadResponse):
    scan_id: str
    tenant_id: str
    snapshot_generation: str | None = None
    aggregates: list[GraphNodeAggregate]
    missing_node_ids: list[str] = Field(description="Requested ids not in the snapshot.")


class GraphScopeFinding(ReadModel):
    issue_key: str
    label: str
    severity: str
    node_ids: list[str]


class GraphScopeFindingsResponse(ReadResponse):
    scan_id: str
    tenant_id: str
    snapshot_generation: str
    node_id: str
    finding_revision: str
    total: int
    offset: int
    limit: int
    findings: list[GraphScopeFinding]


__all__ = ["GraphNodeAggregate", "GraphNodeAggregatesResponse", "GraphRollupAggregate", "GraphScopeFinding", "GraphScopeFindingsResponse"]
