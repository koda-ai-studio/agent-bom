"""Response contracts: governance, blueprints, datasets, evaluations, correlations and scenarios."""

from __future__ import annotations

from typing import Any

from pydantic import ConfigDict, Field

from agent_bom.api.read_models._base import Completeness, Num, ReadModel, ReadResponse

# ── Snowflake governance + Cortex telemetry ──────────────────────────────────


class GovernanceFindingRow(ReadModel):
    category: str
    severity: str
    title: str
    description: str
    agent_or_role: str
    object_name: str
    details: dict[str, Any]


class GovernanceReportSummary(ReadModel):
    access_records: int
    privilege_grants: int
    data_classifications: int
    agent_usage_records: int
    cortex_agents: int = 0
    cortex_events: int = 0
    findings: int
    critical_findings: int
    high_findings: int


class GovernanceAccessRecordRow(ReadModel):
    query_id: str
    user_name: str
    role_name: str
    query_start: str
    object_name: str
    object_type: str
    columns: list[str]
    operation: str
    is_write: bool
    source_field: str
    base_objects: list[str]


class GovernancePrivilegeGrantRow(ReadModel):
    grantee: str
    grantee_type: str
    privilege: str
    granted_on: str
    object_name: str
    is_elevated: bool
    grant_option: bool
    granted_by: str


class GovernanceDataClassificationRow(ReadModel):
    object_name: str
    object_type: str
    column_name: str | None
    tag_name: str
    tag_value: str


class GovernanceAgentUsageRow(ReadModel):
    agent_name: str
    database_name: str = ""
    schema_name: str = ""
    user_name: str
    role_name: str
    start_time: str
    total_tokens: int
    credits_used: Num
    model_name: str
    tool_calls: int
    status: str


class GovernanceCortexToolResource(ReadModel):
    kind: str
    fqn: str


class GovernanceCortexTool(ReadModel):
    name: str
    type: str
    resources: list[GovernanceCortexToolResource]


class GovernanceCortexExecutionRole(ReadModel):
    role: str
    privilege: str
    granted_to: str


class GovernanceCortexAgentRow(ReadModel):
    """One Cortex Agent from DESCRIBE AGENT; ``tools`` are only those its specification declares."""

    account: str
    database: str
    schema_name: str = Field(alias="schema")
    name: str
    fqn: str
    node_id: str
    display_name: str
    owner: str
    is_secure: bool
    spec_status: str
    tools: list[GovernanceCortexTool]
    execution_roles: list[GovernanceCortexExecutionRole]


class GovernanceCortexEventRow(ReadModel):
    """Normalized Cortex observability span: metadata, digests and derived signals only."""

    tenant_id: str | None
    source: str
    source_trace_id: str | None
    source_span_id: str | None
    parent_span_id: str | None
    started_at: str | None
    ended_at: str | None
    kind: str
    agent_name: str
    agent_ref: str
    model_provider: str | None
    model_name: str | None
    tool_name: str | None
    mcp_server_ref: str | None
    resource_refs: list[str]
    principal_hash: str | None
    role_name: str | None
    credential_ref: str | None
    input_tokens: int | None
    output_tokens: int | None
    cost_usd: Num | None
    status: str
    signals: list[str]
    content_sha256: str | None
    match_method: str
    match_node_id: str | None


class GovernanceReportResponse(ReadResponse):
    account: str
    discovered_at: str
    summary: GovernanceReportSummary
    findings: list[GovernanceFindingRow]
    access_records: list[GovernanceAccessRecordRow]
    privilege_grants: list[GovernancePrivilegeGrantRow]
    data_classifications: list[GovernanceDataClassificationRow]
    agent_usage: list[GovernanceAgentUsageRow]
    cortex_agents: list[GovernanceCortexAgentRow] = Field(default_factory=list)
    cortex_events: list[GovernanceCortexEventRow] = Field(default_factory=list)
    warnings: list[str]


class GovernanceFindingsCountMetadata(ReadModel):
    definition: str
    source: str
    scope: str
    window: dict[str, Any] | None
    filters: dict[str, Any]
    returned: int
    total: int | None
    total_kind: str
    completeness: Completeness


class GovernanceFindingsResponse(ReadResponse):
    schema_version: str
    findings: list[GovernanceFindingRow]
    count: int
    total: int | None
    limit: int
    offset: int
    sort: str | None
    scan_id: str | None
    cursor: str
    next_cursor: str
    has_more: bool
    filters: dict[str, Any]
    warnings: list[str]
    count_metadata: GovernanceFindingsCountMetadata
    total_approximate: bool | None = None


class CortexAgentHealthState(ReadModel):
    status: str
    issues: list[str]


class CortexAgentTelemetryRow(ReadModel):
    name: str
    total_calls: int
    error_count: int
    error_rate: Num
    avg_latency_ms: Num
    p95_latency_ms: Num
    total_tokens: int
    total_credits: Num
    top_tools: list[str]
    health: CortexAgentHealthState


class CortexTelemetryResponse(ReadResponse):
    period_hours: int
    agent_filter: str | None
    agents: list[CortexAgentTelemetryRow]
    observability: dict[str, Any]
    warnings: list[str]


class CortexAgentHealthRow(ReadModel):
    name: str
    status: str
    issues: list[str]


class CortexHealthResponse(ReadResponse):
    agents: list[CortexAgentHealthRow]
    warnings: list[str]


# ── AI-system blueprints ─────────────────────────────────────────────────────


class GovernanceBlueprintRow(ReadModel):
    blueprint_id: str
    tenant_id: str
    name: str
    owner: str
    owner_type: str
    description: str
    created_at: str
    updated_at: str
    current_version: int
    latest_version: int
    approval_status: str
    seeded_from: str


class GovernanceBlueprintComposition(ReadModel):
    agents: list[str]
    models: list[str]
    tools: list[str]
    datasets: list[str]
    identities: list[str]
    owners: list[str]
    guardrails: list[str]


class GovernanceBlueprintVersionRow(ReadModel):
    version_id: str
    blueprint_id: str
    tenant_id: str
    version: int
    status: str
    composition: GovernanceBlueprintComposition
    created_at: str
    created_by: str
    submitted_at: str
    submitted_by: str
    decided_at: str
    approver: str
    decision_note: str
    seeded_from: str


class GovernanceBlueprintsResponse(ReadResponse):
    schema_version: str
    tenant_id: str
    count: int
    next_offset: int | None
    blueprints: list[GovernanceBlueprintRow]


class GovernanceBlueprintDetailResponse(ReadResponse):
    schema_version: str
    tenant_id: str
    blueprint: GovernanceBlueprintRow
    versions: list[GovernanceBlueprintVersionRow]


class GovernanceBlueprintVersionsResponse(ReadResponse):
    schema_version: str
    tenant_id: str
    blueprint_id: str
    count: int
    versions: list[GovernanceBlueprintVersionRow]


class GovernanceBlueprintVersionResponse(ReadResponse):
    schema_version: str
    tenant_id: str
    version: GovernanceBlueprintVersionRow


class GovernanceBlueprintDiffAxis(ReadModel):
    added: list[str]
    removed: list[str]
    persistent: list[str]


class GovernanceBlueprintDiff(ReadModel):
    blueprint_id: str
    from_version: int
    to_version: int
    axes: dict[str, GovernanceBlueprintDiffAxis]
    added_count: int
    removed_count: int
    persistent_count: int
    net_change: int


class GovernanceBlueprintDiffResponse(ReadResponse):
    schema_version: str
    tenant_id: str
    diff: GovernanceBlueprintDiff


# ── runtime role blueprints ──────────────────────────────────────────────────


class RuntimeRoleBlueprintRow(ReadModel):
    blueprint_id: str
    label: str
    description: str
    intended_users: list[str]
    allowed_tool_categories: list[str]
    restricted_tool_categories: list[str]
    approval_required_for: list[str]
    default_decision: str
    retention_mode: str
    evidence_required: list[str]
    revision: int


class RuntimeRoleBlueprintsResponse(ReadResponse):
    schema_version: str
    tenant_id: str
    blueprints: list[RuntimeRoleBlueprintRow]


class RuntimeRoleBlueprintResponse(ReadResponse):
    schema_version: str
    tenant_id: str
    blueprint: RuntimeRoleBlueprintRow


class RuntimeBlueprintDriftTool(ReadModel):
    name: str
    category: str
    count: int


class RuntimeBlueprintDriftObserved(ReadModel):
    total_tool_calls: int
    categories: dict[str, int]
    tools: list[RuntimeBlueprintDriftTool]


class RuntimeBlueprintDriftItem(ReadModel):
    type: str
    severity: str
    tool_name: str | None = None
    category: str | None = None
    observed_count: int
    recommendation: str


class RuntimeBlueprintDriftResponse(ReadResponse):
    schema_version: str
    evidence_basis: str
    comparison_scope: str
    producer_assurance: str
    producer_assurance_counts: dict[str, int]
    producer_assurance_count_basis: str
    evidence_limitation: str
    tenant_id: str
    blueprint_id: str
    evaluated_at: str
    status: str
    drift_score: Num
    runtime_status: str
    observed: RuntimeBlueprintDriftObserved
    blueprint: RuntimeRoleBlueprintRow
    violations: list[RuntimeBlueprintDriftItem]
    warnings: list[RuntimeBlueprintDriftItem]
    retention: str
    incident_id: str | None = None


# ── datasets + evaluations ───────────────────────────────────────────────────


class DatasetVersionRow(ReadModel):
    tenant_id: str
    dataset_id: str
    version_id: str
    created_at: str
    source: str
    artifact_uri: str | None
    digest: str | None
    digest_algorithm: str
    metadata: dict[str, Any]


class DatasetVersionsResponse(ReadResponse):
    schema_version: str
    tenant_id: str
    dataset_id: str
    versions: list[DatasetVersionRow]
    count: int


class DatasetVersionResponse(ReadResponse):
    schema_version: str
    dataset: DatasetVersionRow


class EvaluationRunRow(ReadModel):
    tenant_id: str
    evaluation_id: str
    created_at: str
    updated_at: str
    name: str | None
    status: str
    dataset_id: str | None
    dataset_version_id: str | None
    trace_id: str | None
    model: str | None
    prompt_hash: str | None
    source: str
    scores: dict[str, Num]
    summary: dict[str, Any]
    cases: list[dict[str, Any]]
    metadata: dict[str, Any]


class EvaluationRunsResponse(ReadResponse):
    schema_version: str
    tenant_id: str
    evaluations: list[EvaluationRunRow]
    count: int
    limit: int
    offset: int


class EvaluationRunResponse(ReadResponse):
    schema_version: str
    evaluation: EvaluationRunRow


# ── graph correlations + scenarios ───────────────────────────────────────────


class GraphCorrelationRunResponse(ReadResponse):
    correlation_id: str
    tenant_id: str
    idempotency_key: str
    name: str
    status: str
    max_age_hours: int
    allow_stale: bool
    input_manifest: list[dict[str, Any]]
    result_manifest: dict[str, Any]
    manifest_sha256: str
    output_scan_id: str
    failure_code: str
    created_at: str
    started_at: str
    completed_at: str


class GraphCorrelationRuntimeFactsPayload(ReadModel):
    schema_version: str
    correlation_id: str
    tenant_id: str
    manifest_sha256: str
    evidence_freshness: str
    analysis_bounds: dict[str, Any]
    issued_at: str
    expires_at: str
    facts: Any
    input_freshness: dict[str, Any] | None = None


class GraphCorrelationRuntimeFactsSignature(ReadModel):
    algorithm: str
    key_id: str
    value: str


class GraphCorrelationRuntimeFactsResponse(ReadResponse):
    payload: GraphCorrelationRuntimeFactsPayload
    signature: GraphCorrelationRuntimeFactsSignature


class GraphScenarioRow(ReadModel):
    scenario_id: str
    tenant_id: str
    base_scan_id: str
    revision: int
    name: str
    description: str
    changes: list[dict[str, Any]]
    assumptions: list[str]
    created_by: str
    provenance: dict[str, Any]
    created_at: str
    updated_at: str
    base_status: str | None = None


class GraphScenarioDetailResponse(ReadResponse):
    model_config = ConfigDict(extra="allow", populate_by_name=True)

    schema_name: str = Field(alias="schema")
    scenario: GraphScenarioRow


class GraphScenarioComparisonCurrent(ReadModel):
    scan_id: str
    node_count: int
    edge_count: int
    completeness: dict[str, Any]
    base_status: str
    latest_scan_id: str | None
    path_completeness: dict[str, Any] | None = None


class GraphScenarioComparisonProposed(ReadModel):
    node_count: int
    edge_count: int
    modeled: bool
    completeness: dict[str, Any]
    nodes: list[dict[str, Any]]
    edges: list[dict[str, Any]]


class GraphScenarioComparisonDifference(ReadModel):
    nodes_added: list[str]
    nodes_removed: list[str]
    nodes_changed: list[str]
    edges_added: list[str]
    edges_removed: list[str]
    touched_observed_path_count: int
    touched_observed_path_ids: list[str]
    touched_observed_paths_completeness: dict[str, Any] | None = None


class GraphScenarioComparisonResponse(ReadResponse):
    model_config = ConfigDict(extra="allow", populate_by_name=True)

    schema_name: str = Field(alias="schema")
    scenario: GraphScenarioRow
    current: GraphScenarioComparisonCurrent
    proposed: GraphScenarioComparisonProposed
    difference: GraphScenarioComparisonDifference
    available: bool
    unavailable_reason: str | None
    base_status: str
    stale: bool
