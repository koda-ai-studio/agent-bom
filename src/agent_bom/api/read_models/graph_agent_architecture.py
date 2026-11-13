"""Documented 200 contract for ``GET /v1/graph/agent-architecture``."""

from __future__ import annotations

from typing import Literal

from agent_bom.api.read_models._base import ReadModel, ReadResponse

HarnessRole = Literal["harness", "orchestrator", "subgraph", "sub_agent"]
FlowKind = Literal["entry", "sequential", "conditional", "handoff", "fan_out", "subgraph", "finish", "member", "peer"]


class HarnessAgentSecurity(ReadModel):
    """What the graph records for the agent: its severity and risk, findings it is vulnerable to, outgoing reach."""

    severity: str
    risk_score: float
    findings: int
    max_finding_severity: str
    reach: dict[str, int]


class HarnessAgent(ReadModel):
    id: str
    label: str
    framework: str
    role: HarnessRole
    layer: int
    entry: bool
    parent_id: str
    file_path: str
    line_number: int
    model_refs: list[str]
    tools: list[str]
    credential_refs: list[str]
    dynamic_edges: bool
    security: HarnessAgentSecurity


class HarnessLayer(ReadModel):
    layer: int
    agents: list[HarnessAgent]


class HarnessFlowEdge(ReadModel):
    """A declared edge between two agents of the harness; ``kind`` is read from its recorded evidence."""

    source: str
    target: str
    relationship: Literal["delegated_to", "shares_server"]
    kind: FlowKind
    conditional: bool
    branches: list[str]
    evidence: str
    provenance: str
    confidence: str
    file_path: str
    line_number: int


class HarnessUnresolvedRoute(ReadModel):
    agent_id: str
    status: Literal["unresolved"]
    evidence: str
    line_number: int
    reason: str


class HarnessProject(ReadModel):
    id: str
    label: str
    severity: str
    risk_score: float


class HarnessSecurity(ReadModel):
    max_severity: str
    max_risk_score: float
    agents_with_findings: int
    findings: int
    credential_refs: list[str]


class HarnessTruncation(ReadModel):
    agents: bool
    flow_edges: bool


class AgentHarness(ReadModel):
    harness_id: str
    label: str
    framework: str
    harness_kind: str
    file_path: str
    line_number: int
    agent_count: int
    layer_count: int
    entry_agent_ids: list[str]
    orchestrator_ids: list[str]
    models: list[str]
    layers: list[HarnessLayer]
    flow_edges: list[HarnessFlowEdge]
    unresolved_route_count: int
    unresolved_routes: list[HarnessUnresolvedRoute]
    truncated: HarnessTruncation
    declared_in: HarnessProject | None = None
    security: HarnessSecurity


class HarnessSummary(ReadModel):
    harnesses: int
    framework_agents: int
    placed_agents: int
    unplaced_framework_agents: int
    frameworks: dict[str, int]


class HarnessCoverage(ReadModel):
    model: str
    provenance: Literal["declared"]
    frameworks_modelled: list[str]
    gaps: list[str]
    complete: bool
    framework_agent_cap: int


class HarnessPagination(ReadModel):
    offset: int
    limit: int
    total: int
    returned: int
    cursor: str
    next_cursor: str
    has_more: bool


class GraphAgentArchitectureResponse(ReadResponse):
    """Multi-agent harnesses declared in the snapshot: layers, flow edges, unresolved routes and the security overlay."""

    schema_version: Literal["v1"]
    scan_id: str
    tenant_id: str
    snapshot_generation: str
    harnesses: list[AgentHarness]
    summary: HarnessSummary
    coverage: HarnessCoverage
    pagination: HarnessPagination


__all__ = ["AgentHarness", "GraphAgentArchitectureResponse"]
