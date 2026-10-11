"""Response contracts: inventory, outbox, sources, ticketing, assets, intel and operator reads."""

from __future__ import annotations

from typing import Any

from agent_bom.api.read_models._base import Num, ReadModel, ReadResponse

# ── unified asset inventory ──────────────────────────────────────────────────


class InventoryCollectionCoverage(ReadModel):
    status: str
    reason: str
    reason_codes: list[str] | None = None


class InventoryFacetBucket(ReadModel):
    value: str | None
    count: int


class InventoryFacet(ReadModel):
    buckets: list[InventoryFacetBucket]


class InventoryFacetMetadata(ReadModel):
    basis: str
    mode: str
    exact: bool
    scan_id: str


class InventoryFilters(ReadModel):
    type: list[str] | None = None
    search: str | None = None
    environment: str | None = None
    provider: str | None = None
    source: str | None = None
    severity: str | None = None
    min_severity: str | None = None


class InventoryCompleteness(ReadModel):
    status: str
    complete: bool
    sampled: bool
    truncated: bool
    returned: int
    total: int | None = None
    reason: str | None = None


class InventoryFindingSummary(ReadModel):
    total: int
    by_severity: dict[str, int]
    ids: list[str]
    top_severity: str


class InventoryAssetRow(ReadModel):
    id: str
    type: str
    name: str
    environment: str
    provider: str
    risk: Num
    risk_assessment: dict[str, Any]
    severity: str
    status: str
    source: str
    sources: list[str]
    first_seen: str
    last_seen: str
    attributes: dict[str, Any]
    compliance_tags: list[str]
    ecosystem: str
    version: str
    finding_summary: InventoryFindingSummary | None = None
    relationship_count: int | None = None


class InventoryPagination(ReadModel):
    total: int
    offset: int
    limit: int
    cursor: str
    next_cursor: str
    has_more: bool
    facet_filtered: bool


class InventorySummaryResponse(ReadResponse):
    schema_version: str
    scope: str
    evidence_scope: str
    snapshot_generation: str | None = None
    collection_coverage: InventoryCollectionCoverage
    finding_count_scope: str
    count_definition: str
    tenant_id: str
    scan_id: str
    created_at: str
    total_assets: int
    by_type: dict[str, int]
    by_group: dict[str, int]
    finding_count: int
    filters: InventoryFilters
    count_exact: bool
    count_basis: str
    facets: dict[str, InventoryFacet]
    facet_metadata: InventoryFacetMetadata
    completeness: InventoryCompleteness
    status: str | None = None


class InventoryAssetsResponse(ReadResponse):
    schema_version: str
    scope: str
    evidence_scope: str
    snapshot_generation: str | None
    collection_coverage: InventoryCollectionCoverage
    finding_count_scope: str
    count_definition: str
    tenant_id: str
    scan_id: str
    created_at: str
    assets: list[InventoryAssetRow]
    finding_count: int
    filters: InventoryFilters
    pagination: InventoryPagination
    facets: dict[str, InventoryFacet]
    facet_metadata: InventoryFacetMetadata
    completeness: InventoryCompleteness


class InventoryAssetDetailResponse(ReadResponse):
    schema_version: str
    evidence_scope: str
    tenant_id: str
    scan_id: str
    snapshot_generation: str
    asset: InventoryAssetRow
    node: dict[str, Any]
    nodes: list[dict[str, Any]]
    edges_out: list[dict[str, Any]]
    edges_in: list[dict[str, Any]]
    neighbors: list[str]
    sources: list[str]
    evidence_sources: list[str]
    impact: dict[str, Any]
    impact_status: str
    next_cursor: str | None
    completeness: dict[str, Any]


# ── posture webhook outbox ───────────────────────────────────────────────────


class PostureWebhookOutboxStats(ReadModel):
    tenant_id: str
    total: int
    by_status: dict[str, int]
    oldest_pending_created_at: Num | None
    next_pending_attempt_at: Num | None


class PostureWebhookOutboxRow(ReadModel):
    row_id: int
    event_id: str
    tenant_id: str
    destination_id: str
    url: str
    status: str
    attempts: int
    next_attempt_at: Num
    created_at: Num
    delivered_at: Num | None
    last_error: str


class PostureWebhookOutboxResponse(ReadResponse):
    schema_version: str
    tenant_id: str
    status: str | None
    count: int
    records: list[PostureWebhookOutboxRow]
    stats: PostureWebhookOutboxStats


class PostureWebhookOutboxStatsResponse(ReadResponse):
    schema_version: str
    stats: PostureWebhookOutboxStats


# ── data sources + ticketing ─────────────────────────────────────────────────


class SourceDetailResponse(ReadResponse):
    source_id: str
    tenant_id: str
    kind: str
    display_name: str
    description: str
    owner: str
    status: str
    enabled: bool
    config: dict[str, Any]
    connector_name: str | None
    credential_mode: str
    credential_ref: str | None
    created_at: str
    updated_at: str
    last_job_id: str | None
    last_run_at: str | None
    last_run_status: str | None
    last_test_message: str | None
    last_test_status: str | None
    last_tested_at: str | None


class SourceJobRow(ReadModel):
    job_id: str
    tenant_id: str
    batch_id: str | None
    correlation_cohort_id: str | None
    correlation_cohort_manifest_hash: str | None
    correlation_max_age_hours: int | None
    parent_job_id: str | None
    child_job_ids: list[str]
    target: dict[str, Any] | None
    target_index: int | None
    target_count: int | None
    source_id: str | None
    schedule_id: str | None
    triggered_by: str | None
    status: str
    created_at: str
    started_at: str | None
    completed_at: str | None
    request: dict[str, Any]
    progress: list[str]
    result: dict[str, Any] | None
    result_document: dict[str, Any] | str | None
    error: str | None
    result_format: str


class SourceJobsResponse(ReadResponse):
    source_id: str
    jobs: list[SourceJobRow]
    count: int


class TicketingConnectionDetailResponse(ReadResponse):
    id: str
    tenant_id: str
    provider: str
    transport: str
    auth_method: str
    display_name: str
    endpoint: str
    auth_params: dict[str, str]
    status: str
    status_detail: str
    created_at: str
    updated_at: str
    has_secret: bool


class TicketingTicketRow(ReadModel):
    id: str
    tenant_id: str
    connection_id: str
    dedupe_key: str
    provider: str
    status: str
    external_id: str
    key: str
    url: str
    created_at: str
    updated_at: str


class TicketingTicketsResponse(ReadResponse):
    schema_version: str
    tenant_id: str
    tickets: list[TicketingTicketRow]
    count: int


# ── vulnerability asset lifecycle ────────────────────────────────────────────


class VulnerabilityAssetRow(ReadModel):
    tenant_id: str
    vuln_id: str
    package: str
    ecosystem: str
    severity: str
    status: str
    first_seen: str
    last_seen: str
    resolved_at: str | None
    scan_count: int
    metadata: dict[str, Any]


class VulnerabilityAssetStats(ReadModel):
    total: int | None = None
    open: int | None = None
    resolved: int | None = None
    reopened: int | None = None
    critical_open: int | None = None
    high_open: int | None = None
    avg_scan_count: Num | None = None


class VulnerabilityAssetsResponse(ReadResponse):
    schema_version: str
    scope: str
    count_definition: str
    assets: list[VulnerabilityAssetRow]
    count: int
    stats: VulnerabilityAssetStats
    mttr_days: Num | None
    error: str | None = None


class VulnerabilityAssetStatsResponse(ReadResponse):
    schema_version: str
    scope: str
    count_definition: str
    stats: VulnerabilityAssetStats
    mttr_days: Num | None
    error: str | None = None


# ── estate correlations + intel advisories ───────────────────────────────────


class EstateCorrelationMatch(ReadModel):
    local_agent_name: str
    local_agent_type: str
    cloud_agent_name: str
    cloud_provider: str
    cloud_service: str
    cloud_account_id: str | None
    cloud_region: str | None
    cloud_model_id: str | None
    confidence: str
    matched_signals: list[str]
    rationale: str


class EstateCorrelationsResponse(ReadResponse):
    schema_version: str
    tenant_id: str
    scan_id: str | None
    count: int
    high_confidence_count: int
    low_confidence_count: int
    matches: list[EstateCorrelationMatch]


class IntelAdvisoryCanonicalIds(ReadModel):
    cves: list[str]
    ghsas: list[str]
    osv: list[str]
    cwes: list[str]


class IntelAdvisoryAffected(ReadModel):
    ecosystem: str
    package_name: str
    introduced: str | None
    fixed: str | None
    last_affected: str | None


class IntelAdvisorySourcePolicy(ReadModel):
    source_id: str
    support_status: str
    redistribution: str
    license_or_terms_url: str | None
    validation_status: str


class IntelAdvisory(ReadModel):
    id: str
    canonical_ids: IntelAdvisoryCanonicalIds
    summary: str | None
    severity: str | None
    cvss_score: Num | None
    cvss_vector: str | None
    fixed_version: str | None
    source: str | None
    published_at: str | None
    modified_at: str | None
    epss_probability: Num | None
    epss_percentile: Num | None
    is_kev: bool
    kev_date_added: str | None
    affected: list[IntelAdvisoryAffected]
    matched_by: str
    match_method: str
    match_confidence: str
    match_reason: str
    source_policy: IntelAdvisorySourcePolicy
    evidence_links: list[dict[str, str]]


class IntelAdvisoryResponse(ReadResponse):
    schema_version: str
    found: bool
    query: str
    advisory: IntelAdvisory | None


# ── MITRE coverage, exec score config, plugins, self-posture ─────────────────


class MitreCoveredTechnique(ReadModel):
    id: str
    label: str
    finding_count: int
    finding_refs: list[str]
    finding_refs_truncated: bool


class MitreFrameworkCoverage(ReadModel):
    framework: str
    name: str
    evidence_source: str
    catalogue_total: int
    catalogue_version: str | None = None
    catalogue_upstream_total: int | None = None
    covered_count: int
    coverage_pct: Num
    covered_techniques: list[MitreCoveredTechnique]


class MitreCoverageSources(ReadModel):
    hub_findings: int
    native_findings: int


class MitreCoverageResponse(ReadResponse):
    covered_definition: str
    uncovered_definition: str
    finding_count: int
    frameworks: list[MitreFrameworkCoverage]
    sources: MitreCoverageSources


class OverviewScoreDriver(ReadModel):
    driver: str
    label: str
    default_weight: Num
    weight: Num
    overridden: bool


class OverviewScoreDefaults(ReadModel):
    weights: dict[str, Num]
    grade_thresholds: dict[str, Num]
    display_format: str


class OverviewScoreConfigResponse(ReadResponse):
    active_override: bool
    source: str
    override_endpoint: str
    display_format: str
    display_formats: list[str]
    weights: dict[str, Num]
    grade_thresholds: dict[str, Num]
    drivers: list[OverviewScoreDriver]
    defaults: OverviewScoreDefaults
    overrides: dict[str, Any]
    message: str


class PluginEntrypointRow(ReadModel):
    name: str
    value: str
    distribution: str


class PluginRegistryGroup(ReadModel):
    group: str
    label: str
    description: str
    builtin_count: int
    declared_entrypoint_count: int
    declared_entrypoints: list[PluginEntrypointRow]
    activation_enabled: bool


class PluginRegistryTotals(ReadModel):
    groups: int
    builtin_registrations: int
    declared_entrypoints: int


class PluginRegistryStatusResponse(ReadResponse):
    schema_version: str
    entrypoints_enabled: bool
    metadata_only: bool
    activation_env: str
    activation: dict[str, bool]
    totals: PluginRegistryTotals
    groups: list[PluginRegistryGroup]
    warnings: list[str]


class SelfPostureCheck(ReadModel):
    id: str
    category: str
    title: str
    status: str
    detail: str
    remediation: str


class SelfPostureResponse(ReadResponse):
    schema_version: int
    overall_status: str
    hardened: bool
    deployment_env: str
    counts: dict[str, int]
    checks: list[SelfPostureCheck]
