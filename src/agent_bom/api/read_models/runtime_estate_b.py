"""Response contracts: runtime production index, shield, connectors, registry, discovery, fleet and MCP config reads."""

from __future__ import annotations

from typing import Any

from agent_bom.api.read_models._base import Num, ReadModel, ReadResponse

# ── runtime production index + shield ────────────────────────────────────────


class RuntimeNamedCount(ReadModel):
    name: str
    count: int


class RuntimeIndexTraffic(ReadModel):
    total_tool_calls: int
    allowed_tool_calls: int
    blocked_tool_calls: int
    block_rate: Num
    calls_by_tool: dict[str, int]
    top_tools: list[RuntimeNamedCount]
    blocked_by_reason: dict[str, int]
    uptime_seconds: Num
    latency_p95_ms: Num | None


class RuntimeIndexPolicyDecisions(ReadModel):
    allowed: int
    blocked: int
    gateway_actions: dict[str, int]


class RuntimeAuthorizationEvent(ReadModel):
    ts: Any
    trace_class: str
    producer_assurance: str
    source_id: Any
    session_id: Any
    tool_name: Any
    decision: Any
    detector: Any


class RuntimeAuthorizationTrace(ReadModel):
    authorized: int
    blocked: int
    data_filter_applied: int
    approval_required: int
    recent: list[RuntimeAuthorizationEvent]
    retention: str


class RuntimeIndexAlerts(ReadModel):
    total_alerts: int
    blocked_alerts: int
    alerts_by_severity: dict[str, int]
    alerts_by_detector: dict[str, int]
    latest_alert_at: Any


class RuntimeIndexFreshness(ReadModel):
    has_metrics: bool
    has_alerts: bool
    metrics_received_at: str
    latest_alert_at: str


class RuntimeRetentionPosture(ReadModel):
    default_mode: str
    modes: dict[str, str]
    event_classes: dict[str, str]
    guarantees: list[str]


class RuntimeProductionIndexResponse(ReadResponse):
    schema_version: str
    producer_assurance: str
    producer_assurance_counts: dict[str, int]
    producer_assurance_count_basis: str
    evidence_basis: str
    tenant_id: str
    generated_at: str
    status: str
    traffic: RuntimeIndexTraffic
    policy_decisions: RuntimeIndexPolicyDecisions
    authorization_trace: RuntimeAuthorizationTrace
    alerts: RuntimeIndexAlerts
    active_sources: list[RuntimeNamedCount]
    active_sessions: list[RuntimeNamedCount]
    freshness: RuntimeIndexFreshness
    retention_posture: RuntimeRetentionPosture


class ShieldAssessment(ReadModel):
    threat_level: str
    composite_score: Num
    detectors_triggered: list[str]
    alert_count_in_window: int
    blocked: bool


class ShieldStatusResponse(ReadResponse):
    """Shield session status; an inactive session carries only ``message``."""

    active: bool
    tenant_id: str
    session_id: str
    message: str | None = None
    started_at: str | None = None
    traces_processed: int | None = None
    tool_calls_analyzed: int | None = None
    alerts_generated: int | None = None
    detectors: list[str] | None = None
    detectors_active: int | None = None
    session_graph: dict[str, Any] | None = None
    incident_summary: dict[str, Any] | None = None
    shield: dict[str, Any] | None = None
    assessment: ShieldAssessment | None = None


# ── connectors, registry and package lookups ─────────────────────────────────


class ConnectorHealthResponse(ReadResponse):
    connector: str
    state: str
    message: str
    api_version: str | None


class MaliciousCheckResponse(ReadResponse):
    package: str
    ecosystem: str
    is_typosquat: bool
    typosquat_target: str | None


class RegistryServerPackage(ReadModel):
    ecosystem: str
    name: str


class RegistryServerDetailResponse(ReadResponse):
    id: str
    name: str
    publisher: str
    description: str
    category: str | None
    transport: str
    verified: bool
    risk_level: str
    risk_justification: str | None
    license: str | None
    latest_version: str | None
    source_url: str | None
    sigstore_bundle: Any
    command_patterns: list[str]
    credential_env_vars: list[str]
    known_cves: list[str]
    packages: list[RegistryServerPackage]
    tools: list[str]


class ScorecardLookupResponse(ReadResponse):
    """``scorecard`` is null with an ``error`` when the repository or its scorecard cannot be resolved."""

    package: str
    ecosystem: str
    scorecard: dict[str, Any] | None
    repo: str | None = None
    error: str | None = None


# ── discovery ────────────────────────────────────────────────────────────────


class AgentFlowPosition(ReadModel):
    x: Num
    y: Num


class AgentFlowNode(ReadModel):
    id: str
    type: str
    position: AgentFlowPosition
    data: dict[str, Any]


class AgentFlowEdge(ReadModel):
    data: dict[str, Any] | None = None
    id: str
    source: str
    target: str
    type: str | None = None
    animated: bool | None = None
    style: dict[str, str] | None = None
    label: str | None = None


class AgentGraphStats(ReadModel):
    total_agents: int | None = None
    total_servers: int
    total_packages: int
    total_tools: int
    total_credentials: int
    total_vulnerabilities: int
    severity_breakdown: dict[str, int] | None = None


class AgentMeshResponse(ReadResponse):
    nodes: list[AgentFlowNode]
    edges: list[AgentFlowEdge]
    stats: AgentGraphStats


class AgentDetailSummary(ReadModel):
    total_servers: int
    total_packages: int
    total_tools: int
    total_credentials: int
    total_vulnerabilities: int
    severity_breakdown: dict[str, int]


class AgentDetailResponse(ReadResponse):
    """``agent`` is the live-discovery or scanned-estate agent record, whichever source serves the tenant."""

    agent: dict[str, Any]
    summary: AgentDetailSummary
    blast_radius: list[dict[str, Any]]
    credentials: list[str]
    fleet: dict[str, Any] | None


class AgentLifecycleResponse(ReadResponse):
    graph: dict[str, Any]
    nodes: list[AgentFlowNode]
    edges: list[AgentFlowEdge]
    stats: AgentDetailSummary


# ── fleet ────────────────────────────────────────────────────────────────────


class FleetEndpointSummary(ReadModel):
    endpoint_id: str
    tenant_id: str
    platform: dict[str, str]
    counts: dict[str, int | None]
    collector_status: dict[str, str]
    collector_messages: dict[str, str]
    privacy: dict[str, bool]
    completeness: str
    last_scan_id: str
    observed_at: str
    updated_at: str


class FleetEndpointsResponse(ReadResponse):
    endpoints: list[FleetEndpointSummary]
    count: int
    total: int
    limit: int
    offset: int
    has_more: bool


class FleetEndpointDetailResponse(FleetEndpointSummary, ReadResponse):
    pass


class FleetAgentDetailResponse(ReadResponse):
    agent_id: str
    canonical_id: str
    name: str
    agent_name: str
    agent_type: str
    config_path: str
    source_id: str
    device_fingerprint: str
    enrollment_name: str
    mdm_provider: str
    lifecycle_state: str
    owner: str | None
    environment: str | None
    tags: list[str]
    trust_score: Num
    trust_factors: dict[str, Any]
    server_count: int
    package_count: int
    credential_count: int
    vuln_count: int
    tenant_id: str
    last_discovery: str | None
    last_scan: str | None
    last_seen: str | None
    created_at: str
    updated_at: str
    notes: str


# ── MCP client config ────────────────────────────────────────────────────────


class McpConfigAssignment(ReadModel):
    config_id: str
    tenant_id: str
    name: str
    profile_id: str
    connector_ids: list[str]
    connection_ids: list[str]
    created_at: str
    created_by: str
    updated_at: str
    revoked: bool
    identity_id: str
    issuer: str
    environment: str
    allowed_tools: list[str]
    required_scopes: list[str]
    policy_ids: list[str]
    owner: str
    status: str
    revision: int
    expires_at: str


class McpConfigAssignmentRow(McpConfigAssignment):
    config_url: str


class McpConfigAssignmentsResponse(ReadResponse):
    schema_version: str
    tenant_id: str
    count: int
    assignments: list[McpConfigAssignmentRow]


class McpConfigAssignmentDetailResponse(ReadResponse):
    schema_version: str
    assignment: McpConfigAssignment
    config_url: str
