"""Response contracts: identity governance, credentials, model keys, entitlements,
privacy export, webhooks, findings exports, scan schedules and report jobs."""

from __future__ import annotations

from typing import Annotated, Any

from pydantic import BaseModel, RootModel, WithJsonSchema

from agent_bom.api.read_models._base import Num, ReadModel, ReadResponse


def documented_list(model: type[BaseModel]) -> dict[str, Any]:
    """Route kwargs that document a top-level JSON array body without validating it."""
    ref = WithJsonSchema({"$ref": f"#/components/schemas/{model.__name__}"})
    return {"response_model": Annotated[list[dict[str, Any]], ref], "responses": {200: {"model": model}}}


# ── identity governance ──────────────────────────────────────────────────────


class IdentityJitGrantRow(ReadModel):
    grant_id: str
    identity_id: str
    agent_id: str
    tenant_id: str
    tool_name: str
    status: str
    requested_at: str
    requested_by: str
    approved_at: str
    approved_by: str
    starts_at: str
    expires_at: str
    reason: str
    ticket_id: str
    revoked_at: str
    revoked_reason: str
    denied_at: str
    denied_reason: str


class IdentityJitGrantsResponse(ReadResponse):
    schema_version: str
    tenant_id: str
    identity_id: str | None = None
    count: int
    grants: list[IdentityJitGrantRow]


class ConditionalAccessPolicyRow(ReadModel):
    policy_id: str
    tenant_id: str
    name: str
    effect: str
    status: str
    created_at: str
    priority: int
    identity_ids: list[str]
    agent_ids: list[str]
    tools: list[str]
    allowed_environments: list[str]
    allowed_hours_utc: list[int]
    allowed_weekdays: list[int]
    allowed_source_cidrs: list[str]
    allowed_devices: list[str]
    allowed_groups: list[str]
    allowed_clients: list[str]
    require_device_managed: bool
    require_device_compliant: bool
    require_device_disk_encrypted: bool
    updated_at: str
    description: str


class ConditionalAccessPoliciesResponse(ReadResponse):
    schema_version: str
    tenant_id: str
    count: int
    policies: list[ConditionalAccessPolicyRow]


class ConditionalAccessPolicyResponse(ReadResponse):
    schema_version: str
    policy: ConditionalAccessPolicyRow


class AccessReviewCampaignRow(ReadModel):
    campaign_id: str
    tenant_id: str
    name: str
    status: str
    created_at: str
    created_by: str
    due_at: str
    completed_at: str
    description: str
    item_count: int
    decided_count: int


class AccessReviewItemRow(ReadModel):
    item_id: str
    campaign_id: str
    tenant_id: str
    subject_id: str
    subject_name: str
    subject_type: str
    provider: str
    owner: str
    permissions: list[str]
    permission_count: int
    privileged: bool
    decision: str
    decided_by: str
    decided_at: str
    decision_note: str


class AccessReviewsResponse(ReadResponse):
    schema_version: str
    tenant_id: str
    count: int
    campaigns: list[AccessReviewCampaignRow]


class AccessReviewDetailResponse(ReadResponse):
    schema_version: str
    campaign: AccessReviewCampaignRow
    count: int
    items: list[AccessReviewItemRow]


class AccessReviewEvidenceResponse(ReadResponse):
    schema_version: str
    secret_values_included: bool
    generated_at: str
    tenant_id: str
    campaign: AccessReviewCampaignRow
    decision_counts: dict[str, int]
    revoke_recommended: list[str]
    flagged: list[str]
    items: list[AccessReviewItemRow]


class AgentIdentityRecord(ReadModel):
    identity_id: str
    agent_id: str
    tenant_id: str
    token_prefix: str
    role: str
    blueprint_id: str
    status: str
    issued_at: str
    expires_at: str
    allowed_tools: list[str]
    owner: str
    owner_type: str
    rotated_to_id: str
    revoked_at: str
    revoked_reason: str
    last_used_at: str
    rotation_due: bool
    rotation_due_at: str
    max_requests_per_window: int
    max_cost_usd_per_window: Num
    quota_window_seconds: int


class AgentIdentityResponse(ReadResponse):
    schema_version: str
    identity: AgentIdentityRecord


class DevicePostureSignalRow(ReadModel):
    tenant_id: str
    device_id: str
    source: str
    managed: bool | None
    compliant: bool | None
    disk_encrypted: bool | None
    os_version: str
    hostname: str
    risk_level: str
    last_seen: str
    observed_at: str
    attributes: dict[str, Any]


class DevicePostureResponse(ReadResponse):
    schema_version: str
    device: DevicePostureSignalRow


# ── credential references ────────────────────────────────────────────────────


class CredentialRefRow(ReadModel):
    credential_ref_id: str
    tenant_id: str
    display_name: str
    provider: str
    mode: str
    external_ref: str | None
    description: str
    owner: str
    scopes: list[str]
    credential_class: str
    last_rotated_at: str | None
    expires_at: str | None
    rotation_interval_days: int | None
    max_age_days: int | None
    expiry_warning_days: int | None
    enabled: bool
    status: str
    last_validated_at: str | None
    last_validation_status: str | None
    last_validation_message: str | None
    created_at: str
    updated_at: str


class CredentialRefsResponse(ReadResponse):
    schema_version: str
    credentials: list[CredentialRefRow]
    count: int
    total: int
    limit: int
    offset: int


class CredentialRefResponse(CredentialRefRow, ReadResponse):
    pass


class CredentialRotationPolicy(ReadModel):
    rotation_interval_days: int
    max_age_days: int
    expiry_warning_days: int


class CredentialRotationEvidence(ReadModel):
    reference_only: bool
    secret_material_stored: bool
    external_ref_recorded: bool


class CredentialRotationRow(ReadModel):
    credential_ref_id: str
    display_name: str
    provider: str
    mode: str
    credential_class: str
    owner: str
    enabled: bool
    rotation_status: str
    severity: str
    age_days: int | None
    days_until_expiry: int | None
    last_rotated_at: str | None
    expires_at: str | None
    policy: CredentialRotationPolicy
    message: str
    evidence: CredentialRotationEvidence


class CredentialRotationFinding(ReadModel):
    finding_id: str
    type: str
    severity: str
    status: str
    credential_ref_id: str
    credential_class: str
    title: str
    message: str
    compliance_tags: list[str]
    evidence: CredentialRotationEvidence


class CredentialRotationDefaults(ReadModel):
    default_expiry_warning_days: int
    default_rotation_days_by_class: dict[str, int]
    default_max_age_days_by_class: dict[str, int]


class CredentialRotationSummary(ReadModel):
    total: int
    ok: int
    disabled: int
    unknown_age: int
    near_expiry: int
    rotation_due: int
    max_age_exceeded: int
    expired: int
    findings: int


class CredentialRotationPostureResponse(ReadResponse):
    schema_version: str
    tenant_id: str
    measured_at: str
    policy: CredentialRotationDefaults
    summary: CredentialRotationSummary
    credentials: list[CredentialRotationRow]
    findings: list[CredentialRotationFinding]


# ── model-key broker ─────────────────────────────────────────────────────────


class ModelProviderKeyRow(ReadModel):
    provider_key_id: str
    tenant_id: str
    provider: str
    display_name: str
    status: str
    created_at: str
    updated_at: str
    owner: str
    owner_type: str
    has_secret: bool


class ModelProviderKeyResponse(ModelProviderKeyRow, ReadResponse):
    pass


class ModelProviderKeysResponse(ReadResponse):
    schema_version: str
    tenant_id: str
    provider_keys: list[ModelProviderKeyRow]
    count: int
    supported_providers: list[str]


class ModelVirtualKeyRow(ReadModel):
    virtual_key_id: str
    tenant_id: str
    provider_key_id: str
    provider: str
    token_prefix: str
    holder_id: str
    status: str
    holder_type: str
    issued_at: str
    expires_at: str
    allowed_models: list[str]
    revoked_at: str
    revoked_reason: str
    last_used_at: str
    use_count: int
    owner: str
    owner_type: str


class ModelVirtualKeysResponse(ReadResponse):
    schema_version: str
    tenant_id: str
    virtual_keys: list[ModelVirtualKeyRow]
    count: int


# ── entitlements ─────────────────────────────────────────────────────────────


class EntitlementCheckRow(ReadModel):
    feature: str
    enabled: bool
    status: str
    reason: str
    metadata_only: bool


class EntitlementSupport(ReadModel):
    tier: str
    sla: str | None


class EntitlementsResponse(ReadResponse):
    schema_version: str
    status: str
    valid: bool
    lane: str
    enabled_features: list[str]
    support: EntitlementSupport
    expires_at: str | None
    source: str
    errors: list[str]
    metadata_only: bool
    current_oss_paths_gated: bool
    checks: list[EntitlementCheckRow]


class EntitlementCheckResponse(ReadResponse):
    schema_version: str
    lane: str
    metadata_only: bool
    current_oss_paths_gated: bool
    check: EntitlementCheckRow


# ── tenant privacy export ────────────────────────────────────────────────────


class TenantDataCounts(ReadModel):
    jobs: int
    fleet_agents: int
    fleet_endpoints: int
    gateway_policies: int
    scan_schedules: int
    sources: int
    exceptions: int
    cloud_connections: int
    credential_refs: int
    api_keys: int
    graph_snapshots: int
    tenant_quota_overrides: int
    graph_scenarios: int
    audit_log_entries_retained: int
    policy_audit_entries_retained: int


class TenantDataRetention(ReadModel):
    audit_log: str
    policy_audit_log: str
    api_keys: str


class TenantDataRecords(ReadModel):
    jobs: list[dict[str, Any]]
    fleet_agents: list[dict[str, Any]]
    fleet_endpoints: list[dict[str, Any]]
    gateway_policies: list[dict[str, Any]]
    scan_schedules: list[dict[str, Any]]
    sources: list[dict[str, Any]]
    exceptions: list[dict[str, Any]]
    cloud_connections: list[dict[str, Any]]
    credential_refs: list[dict[str, Any]]
    api_keys: list[dict[str, Any]]
    graph_snapshots: list[dict[str, Any]]
    tenant_quota_overrides: dict[str, Any]
    graph_scenarios: list[dict[str, Any]]


class TenantDataExportResponse(ReadResponse):
    tenant_id: str
    counts: TenantDataCounts
    retention: TenantDataRetention
    unavailable: dict[str, str] | None = None
    records: TenantDataRecords | None = None


# ── governance webhooks ──────────────────────────────────────────────────────


class WebhookSubscriptionRow(ReadModel):
    subscription_id: str
    tenant_id: str
    url: str
    event_types: list[str]
    status: str
    description: str
    created_at: str
    updated_at: str
    allow_private_networks: bool
    secret_fingerprint: str


class WebhookSubscriptionsResponse(ReadResponse):
    schema_version: str
    tenant_id: str
    event_catalog: list[str]
    count: int
    subscriptions: list[WebhookSubscriptionRow]


class WebhookSubscriptionResponse(ReadResponse):
    schema_version: str
    subscription: WebhookSubscriptionRow


# ── findings exports ─────────────────────────────────────────────────────────


class ExportDestinationRow(ReadModel):
    id: str
    tenant_id: str
    kind: str
    display_name: str
    config: dict[str, Any]
    status: str
    status_detail: str
    created_at: str
    updated_at: str
    last_run_at: str | None
    last_run_status: str | None
    has_secret: bool


class ExportDestinationResponse(ExportDestinationRow, ReadResponse):
    pass


class ExportDestinationsResponse(RootModel[list[ExportDestinationRow]]):
    pass


class ExportScheduleRow(ReadModel):
    schedule_id: str
    name: str
    cron_expression: str
    destination_id: str
    tenant_id: str
    enabled: bool
    sort: str
    severity: str | None
    since_days: int | None
    last_run: str | None
    next_run: str | None
    last_run_status: str | None
    last_row_count: int | None
    created_at: str
    updated_at: str


class ExportSchedulesResponse(RootModel[list[ExportScheduleRow]]):
    pass


# ── scan schedules ───────────────────────────────────────────────────────────


class ScanScheduleRow(ReadModel):
    schedule_id: str
    name: str
    cron_expression: str
    scan_config: dict[str, Any]
    enabled: bool
    last_run: str | None
    next_run: str | None
    last_job_id: str | None
    created_at: str
    updated_at: str
    tenant_id: str


class ScanScheduleResponse(ScanScheduleRow, ReadResponse):
    pass


class ScanSchedulesResponse(RootModel[list[ScanScheduleRow]]):
    pass


# ── async report jobs ────────────────────────────────────────────────────────


class ReportJobStatusResponse(ReadResponse):
    lane: str | None = None
    job_id: str
    tenant_id: str
    status: str
    format: str
    sort: str
    severity: str | None
    q: str | None
    scan_id: str | None
    provider: str | None
    account: str | None
    environment: str | None
    domain: str | None
    owner: str | None
    sla: str | None
    finding_class: str | None
    finding_status: str
    window_days: int | None
    created_at: str
    started_at: str | None
    completed_at: str | None
    row_count: int | None
    byte_count: int | None
    artifact_backend: str | None
    artifact_uri: str | None
    error: str | None
    download_url: str | None = None
    download_token: str | None = None
    download_token_header: str | None = None
