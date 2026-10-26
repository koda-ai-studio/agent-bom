"""Response contracts: cloud inventory, CIS, account, side-scan and connection reads, KSPM, gateway and firewall."""

from __future__ import annotations

from typing import Any, Literal

from agent_bom.api.read_models._base import Num, ReadModel, ReadResponse

# ── cloud inventory + CIS ────────────────────────────────────────────────────


class CloudInventoryProviderSummary(ReadModel):
    provider: str
    status: str
    account: str | None
    region: str
    resource_count: int
    identity_count: int
    node_summary: dict[str, int]
    warnings: list[str]


class CloudReadAuditMetadata(ReadModel):
    read_only: bool
    writes_performed: bool
    note: str
    provider: str | None = None
    scan_modes: list[str] | None = None
    permissions_used: list[str] | None = None
    discovery_scope: list[str] | None = None
    redaction_status: list[str] | None = None


class CloudInventorySummaryResponse(ReadResponse):
    """Inventory summary; a provider timeout returns ``error`` + ``timed_out`` instead of the counts."""

    tenant_id: str
    status: str
    audit_metadata: CloudReadAuditMetadata
    schema_version: str | None = None
    total_resources: int | None = None
    total_identities: int | None = None
    providers: list[CloudInventoryProviderSummary] | None = None
    note: str | None = None
    error: str | None = None
    provider: str | None = None
    timed_out: bool | None = None


class CloudCisBenchmarkResponse(ReadResponse):
    """Provider posture report, or a ``disabled``/``unavailable`` envelope carrying ``error``."""

    tenant_id: str
    provider: str | None = None
    status: str | None = None
    error: str | None = None
    audit_metadata: CloudReadAuditMetadata | None = None
    benchmark: str | None = None
    benchmark_version: str | None = None
    benchmark_manifest: dict[str, Any] | None = None
    pass_rate: Num | None = None
    passed: int | None = None
    failed: int | None = None
    errored: int | None = None
    not_applicable: int | None = None
    no_data: int | None = None
    evaluated: int | None = None
    total: int | None = None
    checks: list[dict[str, Any]] | None = None
    warnings: list[Any] | None = None
    completeness: Any = None
    scope: Any = None
    source_health: Any = None
    account: str | None = None
    account_id: str | None = None
    accounts_scanned: Any = None
    region: str | None = None
    regions_scanned: Any = None
    subscription_id: str | None = None
    subscriptions_scanned: Any = None
    project_id: str | None = None
    projects_scanned: Any = None
    workspace_host: str | None = None


# ── cloud account summary ────────────────────────────────────────────────────


class CloudAccountDomain(ReadModel):
    domain: str
    label: str
    count: int
    severity: dict[str, int]
    href: str


class CloudAccountBenchmark(ReadModel):
    provider: str
    benchmark: str
    passed: int
    failed: int
    evaluated: int
    pass_rate: Num | None


class CloudAccountCompliance(ReadModel):
    evaluated: int
    passed: int
    failed: int
    pass_rate: Num | None
    benchmarks: list[CloudAccountBenchmark]
    href: str


class CloudAccountAssets(ReadModel):
    count: int
    href: str
    note: str


class CloudAccountIdentities(ReadModel):
    count: int
    roles: int
    note: str


class CloudAccountDrill(ReadModel):
    findings_href: str
    graph_href: str


class CloudAccountSummaryResponse(ReadResponse):
    schema_version: str
    tenant_id: str
    account_ref: str
    provider: str
    account: str
    regions: list[str]
    environments: list[str]
    findings_total: int
    severity: dict[str, int]
    domains: list[CloudAccountDomain]
    compliance: CloudAccountCompliance
    assets: CloudAccountAssets
    identities: CloudAccountIdentities
    drill: CloudAccountDrill
    truncated: bool
    empty: bool
    note: str


# ── cloud side-scan ──────────────────────────────────────────────────────────


class SideScanCleanupOwnership(ReadModel):
    execution_id: str
    owner_id: str
    scope_hash: str
    required_tags: dict[str, str]


class SideScanTemporaryResource(ReadModel):
    kind: str
    resource_id: str
    status: str
    ownership_tags: dict[str, str]


class SideScanCounts(ReadModel):
    package_count: int
    vulnerability_count: int
    secret_count: int
    config_finding_count: int
    ioc_finding_count: int


class SideScanExecution(ReadModel):
    schema_version: str
    execution_id: str
    idempotency_key: str
    tenant_id: str
    provider: str
    account_id: str
    target_id: str
    collector_id: str
    status: str
    phase: str
    cleanup_status: str
    cleanup_ownership: SideScanCleanupOwnership
    resources: list[SideScanTemporaryResource]
    counts: SideScanCounts
    failure_code: str
    warning_codes: list[str]
    request_fingerprint: str | None = None
    state_version: int
    created_at: str
    updated_at: str


class SideScanPage(ReadModel):
    limit: int
    offset: int
    returned: int
    total: int
    has_more: bool
    completeness: str


class SideScanProviderCapability(ReadModel):
    provider: str
    target_discovery: bool
    lifecycle_contract: bool
    executor: str
    cli_available: bool
    credentialed_smoke: bool
    image_scan: Literal["ami", "image", "unsupported"]
    image_scan_note: str
    mutation: str


class CloudSideScanListResponse(ReadResponse):
    tenant_id: str
    executions: list[SideScanExecution]
    page: SideScanPage
    capabilities: list[SideScanProviderCapability]
    credentialed_smoke: bool


class SideScanEvidence(ReadModel):
    schema_version: str
    execution_id: str
    provider: str
    account_id: str
    target_id: str
    execution_status: str
    cleanup_status: str
    disposition: str
    negative_result_scope: str
    clean_workload_assertion: bool
    package_count: int
    vulnerability_count: int
    secret_count: int
    config_finding_count: int
    ioc_finding_count: int
    failure_code: str
    warning_codes: list[str]
    data_boundary: str
    redaction: str
    updated_at: str


class CloudSideScanStatusResponse(ReadResponse):
    status: str
    execution_id: str
    provider: str
    tenant_id: str
    execution: SideScanExecution
    evidence: SideScanEvidence


# ── cloud connection detail ──────────────────────────────────────────────────


class CloudConnectionDetailResponse(ReadResponse):
    id: str
    tenant_id: str
    provider: str
    display_name: str
    status: str
    status_detail: str
    auth_params: dict[str, str]
    auto_scan_on_create: bool
    capability_probe_status: str
    credential_present: bool
    has_external_id: bool
    inventory_scope: str
    regions: list[str]
    role_ref: str | None
    scan_interval_minutes: int | None
    scan_mode: str
    verified_capabilities: list[str]
    created_at: str
    updated_at: str
    last_event_at: str | None
    last_scan_at: str | None
    last_scan_id: str | None


# ── KSPM ─────────────────────────────────────────────────────────────────────


class KspmCollector(ReadModel):
    collector_id: str
    state: str
    object_count: int
    pages: int
    truncated: bool
    message: str | None
    transport: str


class KspmScanRun(ReadModel):
    outcome: str
    issues: list[dict[str, Any]]
    warning_count: int
    requested_scope_count: int | None = None
    complete_scope_count: int | None = None
    incomplete_scope_count: int | None = None
    scopes: list[dict[str, Any]] | None = None


class KspmClusterPostureResponse(ReadResponse):
    """Latest cluster-posture run; ``status: no_data`` with null run fields when none exists."""

    schema_version: str
    resource: str
    run_id: str | None
    created_at: str | None
    cluster_ref: str | None
    status: str
    transport: str
    benchmark: dict[str, Any] | None
    collectors: list[KspmCollector]
    finding_count: int
    severity_summary: dict[str, int]
    scan_run: KspmScanRun
    note: str


# ── gateway + firewall ───────────────────────────────────────────────────────


class GatewayRuleDetail(ReadModel):
    id: str
    description: str
    action: str
    block_tools: list[str]
    tool_name: str | None
    tool_name_pattern: str | None
    arg_pattern: dict[str, str]
    deny_tool_classes: list[str]
    read_only: bool
    block_secret_paths: bool
    block_unknown_egress: bool
    allowed_hosts: list[str]
    rate_limit: int | None
    require_registry_verified: bool


class GatewayPolicyDetailResponse(ReadResponse):
    policy_id: str
    name: str
    description: str
    mode: str
    rules: list[GatewayRuleDetail]
    bound_agents: list[str]
    bound_agent_types: list[str]
    bound_environments: list[str]
    created_at: str
    updated_at: str
    enabled: bool
    tenant_id: str


class GatewayAuditEntry(ReadModel):
    entry_id: str
    policy_id: str
    policy_name: str
    rule_id: str
    agent_name: str
    tool_name: str
    arguments_preview: dict[str, Any]
    action_taken: str
    reason: str
    timestamp: str
    tenant_id: str


class GatewayAuditResponse(ReadResponse):
    entries: list[GatewayAuditEntry]
    count: int


class DiscoveredUpstream(ReadModel):
    name: str
    url: str
    transport: str
    auth: str
    source_agents: list[str]
    original_name: str | None = None


class DiscoveredUpstreamConflict(ReadModel):
    name: str
    urls: list[str]


class GatewayDiscoveredUpstreamsResponse(ReadResponse):
    generated_at: str
    tenant_id: str
    source: str
    upstreams: list[DiscoveredUpstream]
    conflicts: list[DiscoveredUpstreamConflict]


class FirewallPairTally(ReadModel):
    source_agent: str
    target_agent: str
    allow: int
    warn: int
    deny: int


class FirewallDecision(ReadModel):
    timestamp: Num
    source_agent: str
    target_agent: str
    decision: str
    effective_decision: str
    matched_rule: dict[str, Any] | None
    enforcement_mode: str | None


class FirewallStats(ReadModel):
    total_decisions: int
    allow: int
    warn: int
    deny: int
    last_seen_ts: Num | None
    top_pairs: list[FirewallPairTally]
    recent: list[FirewallDecision]


class FirewallStatsResponse(FirewallStats, ReadResponse):
    pass


class GatewayPolicyRuntime(ReadModel):
    source: str
    source_kind: str
    enabled_policies: int
    rollout_mode: str
    summary: str
    total_rules: int
    blocking_rules: int
    advisory_rules: int
    allowlist_rules: int
    default_deny_rules: int
    read_only_rules: int
    secret_path_rules: int
    unknown_egress_rules: int
    denied_tool_classes: list[str]
    blocks_requests: bool
    advisory_only: bool
    default_deny: bool
    protects_secret_paths: bool
    restricts_unknown_egress: bool


class GatewayStatsResponse(ReadResponse):
    total_policies: int
    enforce_count: int
    audit_count: int
    enabled_count: int
    total_rules: int
    audit_entries: int
    blocked_count: int
    alerted_count: int
    policy_runtime: GatewayPolicyRuntime
    firewall_runtime: FirewallStats
