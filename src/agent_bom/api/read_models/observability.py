"""Response contracts: runtime traces, LLM cost observability and adoption funnel."""

from __future__ import annotations

from typing import Any

from agent_bom.api.read_models._base import Num, ReadModel, ReadResponse

# ── trace connectors ─────────────────────────────────────────────────────────


class ObsTraceConnector(ReadModel):
    name: str
    kind: str
    auth_fields: list[str]
    supports_content: bool


class ManagedTraceConnection(ReadModel):
    id: str
    provider: str
    display_name: str


class TraceConnectorsResponse(ReadResponse):
    schema_version: str
    connectors: list[ObsTraceConnector]
    connections: list[ManagedTraceConnection] = []


# ── runtime sessions + observations ──────────────────────────────────────────


class ObsRuntimeSession(ReadModel):
    tenant_id: str
    session_id: str
    first_seen: str
    last_seen: str
    source: str
    agent_name: str
    trace_id: str
    observation_count: int
    event_types: dict[str, int]
    verdicts: dict[str, int]
    severities: dict[str, int]
    tools: list[str]
    redaction_status: str


class ObsRuntimeObservation(ReadModel):
    tenant_id: str
    observation_id: str
    session_id: str
    observed_at: str
    source: str
    surface: str
    event_type: str
    severity: str
    verdict: str
    tool_name: str
    agent_name: str
    trace_id: str
    span_id: str
    request_id: str
    summary: dict[str, Any]
    metadata: dict[str, Any]
    redaction_status: str
    raw_payload_stored: bool


class RuntimeSessionsResponse(ReadResponse):
    schema_version: str
    tenant_id: str
    count: int
    limit: int
    offset: int
    sessions: list[ObsRuntimeSession]


class RuntimeObservationsResponse(ReadResponse):
    schema_version: str
    tenant_id: str
    count: int
    limit: int
    offset: int
    observations: list[ObsRuntimeObservation]


class RuntimeSessionObservationsResponse(ReadResponse):
    schema_version: str
    tenant_id: str
    session: ObsRuntimeSession
    count: int
    observations: list[ObsRuntimeObservation]


# ── trace explorer + approval queue ──────────────────────────────────────────


class ObsTraceLinkedFinding(ReadModel):
    correlation_basis: str = "candidate_name"
    finding_id: str | None
    vulnerability_id: str | None
    severity: str | None
    risk_score: Num | None
    effective_reach_band: str | None
    framework_tags: list[str]
    runtime_evidence: dict[str, Any] | None
    policy_state: Any


class ObsTraceSpan(ReadModel):
    surface: str = "runtime"
    parent_span_id: str = ""
    parent_state: str = "root"
    depth: int = 0
    logical_root: bool | None = None
    native_type: str = ""
    native_name: str = ""
    event_time_missing: bool = False
    collected_at: str | None = None
    end_time_unix_nano: str | None = None
    correlation_state: str = "candidate_name"
    source_scope: dict[str, str] = {}
    inventory_binding: dict[str, Any] | None = None

    span_id: str
    timestamp: str | None
    agent: str
    tool: str
    action_type: str
    verdict: str
    detail: str | None
    shadow: bool
    source: str | None
    trace_id: str | None = None
    session_id: str | None = None
    linked_findings: list[ObsTraceLinkedFinding]
    compliance_controls: list[str]


class ObsTraceSession(ReadModel):
    session_id: str
    agent: str
    trace_id: str
    spans: list[ObsTraceSpan]
    blocked_count: int
    observed_count: int
    first_seen: str | None = None
    last_seen: str | None = None
    observation_count: int | None = None


class RuntimeTraceExplorerResponse(ReadResponse):
    retained_total: int = 0
    source_counts: dict[str, int] = {}
    offset: int = 0
    limit: int = 100
    has_more: bool = False
    feed_included: bool = False
    counts_scope: str = "matching_retained_observations"
    schema_version: str
    tenant_id: str
    session_count: int
    span_count: int
    blocked_count: int
    sessions: list[ObsTraceSession]


class ObsApprovalQueueItem(ReadModel):
    item_id: str
    tenant_id: str
    span_id: str
    session_id: str
    agent: str
    tool: str
    timestamp: str | None
    detail: str
    source: str | None
    status: str
    linked_findings: list[ObsTraceLinkedFinding]
    linked_finding_ids: list[str]
    compliance_controls: list[str]
    decided_by: str
    decided_at: str
    note: str


class RuntimeApprovalQueueResponse(ReadResponse):
    schema_version: str
    tenant_id: str
    count: int
    pending_count: int
    items: list[ObsApprovalQueueItem]


# ── LLM costs ────────────────────────────────────────────────────────────────


class ObsCostRollup(ReadModel):
    key: str
    calls: int
    input_tokens: int
    output_tokens: int
    cost_usd: Num
    unpriced_calls: int


class ObsCostHistory(ReadModel):
    limit: int
    returned_calls: int
    complete: bool


class ObsCostScope(ReadModel):
    agent: str | None
    cost_center: str | None


class ObsCostTagRollup(ReadModel):
    tag_key: str
    total_cost_usd: Num
    by_tag: list[ObsCostRollup]


class ObsBudgetStatus(ReadModel):
    configured: bool
    agent: str | None = None
    cost_center: str | None = None
    owner: str | None = None
    workflow: str | None = None
    mode: str | None = None
    limit_usd: Num | None
    spend_usd: Num
    remaining_usd: Num | None
    exceeded: bool
    utilization: Num | None


class ObsCostForecast(ReadModel):
    schema_version: str
    agent: str | None
    now: str
    current_spend_usd: Num | None
    budget_limit_usd: Num | None
    burn_rate_usd_per_day: Num | None
    burn_rate_basis: str | None
    projected_period_spend_usd: Num | None
    period_start: str | None
    period_end: str | None
    days_remaining: Num | None
    projected_exhaustion_at: str | None
    history_span_hours: Num | None
    status: str


class ObservabilityCostsResponse(ReadResponse):
    schema_version: str
    tenant_id: str
    price_model_captured: str
    total_cost_usd: Num
    total_calls: int
    total_input_tokens: int
    total_output_tokens: int
    unpriced_calls: int
    agents: int
    first_recorded_at: str | None
    last_recorded_at: str | None
    period: str
    basis: str
    by_agent: list[ObsCostRollup]
    by_model: list[ObsCostRollup]
    by_provider: list[ObsCostRollup]
    by_cost_center: list[ObsCostRollup]
    by_owner: list[ObsCostRollup]
    tag_rollup: ObsCostTagRollup | None = None
    history: ObsCostHistory
    scope: ObsCostScope
    budget: ObsBudgetStatus
    forecast: ObsCostForecast


class ObservabilityCostBudgetResponse(ReadResponse, ObsBudgetStatus):
    schema_version: str
    tenant_id: str


class ObservabilityCostForecastResponse(ReadResponse, ObsCostForecast):
    tenant_id: str


# ── anomalies ────────────────────────────────────────────────────────────────


class ObsCostAnomaly(ReadModel):
    type: str
    severity: str
    agent: str
    metric: str
    value: Num
    baseline_median: Num
    z_score: Num
    recommendation: str


class ObsBehaviorAnomaly(ReadModel):
    type: str
    severity: str
    session_id: str
    metric: str
    value: Num
    baseline_median: Num
    z_score: Num
    recommendation: str


class ObsTimeBucket(ReadModel):
    day_of_week: int
    hour: int


class ObsTemporalCostAnomaly(ReadModel):
    type: str
    severity: str
    agent: str
    metric: str
    value: Num
    bucket: ObsTimeBucket
    seasonal_baseline: Num | None
    ewma_baseline: Num
    signals: list[str]
    seasonal_ratio: Num | None = None
    ewma_ratio: Num | None = None
    recommendation: str


class ObservabilityAnomaliesResponse(ReadResponse):
    schema_version: str
    tenant_id: str
    z_threshold: Num
    cost_anomalies: list[ObsCostAnomaly]
    temporal_cost_anomalies: list[ObsTemporalCostAnomaly]
    behavior_anomalies: list[ObsBehaviorAnomaly]
    anomaly_count: int


# ── adoption funnel ──────────────────────────────────────────────────────────


class ObsAdoptionTransition(ReadModel):
    numerator: int
    denominator: int
    rate: Num | None


class ObsAdoptionTransitions(ReadModel):
    scan_to_artifact: ObsAdoptionTransition
    artifact_to_investigation: ObsAdoptionTransition
    investigation_to_verification: ObsAdoptionTransition


class ObsAdoptionFunnel(ReadModel):
    unit: str
    transitions: ObsAdoptionTransitions
    limitations: list[str]


class ObsAdoptionPrivacy(ReadModel):
    telemetry_disabled_by_default: bool
    stores_source_contents: bool
    stores_secrets_or_credentials: bool
    stores_raw_findings: bool
    stores_customer_resource_identifiers: bool
    stores_tenant_identifiers: bool
    dimensions: list[str]


class ObservabilityAdoptionResponse(ReadResponse):
    schema_version: str
    enabled: bool
    counts: dict[str, int]
    funnel: ObsAdoptionFunnel
    privacy: ObsAdoptionPrivacy
