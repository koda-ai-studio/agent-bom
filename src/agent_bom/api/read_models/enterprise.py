"""Typed OpenAPI contracts for the enterprise auth, audit, exception and triage reads.

Documentation-only, like every model in this package: routes declare them via
:func:`agent_bom.api.read_models._base.documented`, so request-time bodies are
not validated. Keys a handler always sets are required; keys that come from a
delegated posture producer, or that only some code paths set, default to
``None`` and are emitted only when present.
"""

from __future__ import annotations

from typing import Any

from agent_bom.api.read_models._base import ReadModel, ReadResponse

# ── auth ─────────────────────────────────────────────────────────────────────


class ApiKeysResponse(ReadResponse):
    schema_version: str
    keys: list[dict[str, Any]]


class AuthPolicyResponse(ReadResponse):
    api_key: dict[str, Any]
    rate_limit_key: dict[str, Any]
    audit_hmac: dict[str, Any]
    ui: dict[str, Any]
    rate_limit_runtime: dict[str, Any]
    auth_session_client_identity: dict[str, Any]
    trusted_proxy_auth: dict[str, Any]
    proxy_control_plane_mtls: dict[str, Any]
    security_headers: dict[str, Any]
    backpressure: dict[str, Any]
    proxy_sandbox: dict[str, Any]
    data_access_boundaries: dict[str, Any]
    auth_state_backend: dict[str, Any]
    secret_integrity: dict[str, Any]
    secret_lifecycle: dict[str, Any]
    tenant_quotas: dict[str, Any]
    tenant_quota_runtime: dict[str, Any]
    storage_schema: dict[str, Any]
    identity_provisioning: dict[str, Any]


class AuthScopesResponse(ReadResponse):
    schema_version: str
    count: int
    wildcard_examples: list[str]
    scopes: list[dict[str, Any]]


class SecretLifecycleResponse(ReadResponse):
    status: str | None = None
    rotation_statuses: list[str] | None = None
    blockers: list[Any] | None = None
    warnings: list[Any] | None = None
    external_secret_provider: dict[str, Any] | None = None
    secrets: dict[str, Any] | None = None
    message: str | None = None


class SecretRotationPlanResponse(ReadResponse):
    status: str | None = None
    generated_from: str | None = None
    secret_values_included: bool | None = None
    provider: str | None = None
    rotation_adapter: dict[str, Any] | None = None
    supported_rotation_adapters: list[dict[str, Any]] | None = None
    external_secret_provider_configured: bool | None = None
    action_count: int | None = None
    actions: list[dict[str, Any]] | None = None
    all_secrets: list[dict[str, Any]] | None = None
    operator_sequence: list[str] | None = None
    message: str | None = None


class CredentialExpiryResponse(ReadResponse):
    status: str | None = None
    secret_values_included: bool | None = None
    evaluated: int | None = None
    counts: dict[str, int] | None = None
    blockers: list[Any] | None = None
    warnings: list[Any] | None = None
    thresholds: dict[str, Any] | None = None
    credentials: list[dict[str, Any]] | None = None
    action_required: list[Any] | None = None
    message: str | None = None
    generated_from: str | None = None
    control_plane_included: bool | None = None
    discovered_credential_count: int | None = None


class ScimConfigResponse(ReadResponse):
    supported: bool | None = None
    configured: bool | None = None
    status: str | None = None
    base_path: str | None = None
    token_configured: bool | None = None
    token_binding_mode: str | None = None
    token_binding_count: int | None = None
    tenant_count: int | None = None
    tenant_id: str | None = None
    tenant_ids: list[str] | None = None
    tenant_id_source: str | None = None
    storage_backend: str | None = None
    configured_api_replicas: int | None = None
    shared_store_required: bool | None = None
    multi_node_ready: bool | None = None
    lifecycle_endpoints: dict[str, Any] | None = None
    external_id_attribute: str | None = None
    role_attribute: str | None = None
    default_role: str | None = None
    role_values: list[str] | None = None
    tenant_attribute: str | None = None
    tenant_assignment: dict[str, Any] | None = None
    provisioning_authority: str | None = None
    auth_authority: str | None = None
    runtime_auth_enforced: bool | None = None
    deprovisioning_boundary: str | None = None
    groups_required: bool | None = None
    verified_idp_templates: list[dict[str, Any]] | None = None
    message: str | None = None


class TenantQuotaRuntimeResponse(ReadResponse):
    source: str | None = None
    per_tenant_overrides: bool | None = None
    active_override: bool | None = None
    override_endpoint: str | None = None
    message: str | None = None
    overrides: dict[str, Any] | None = None
    usage: dict[str, Any] | None = None


class ManagedTrialTenantResponse(ReadResponse):
    tenant_id: str
    state: str
    created_at: str
    trial_ends_at: str
    cleanup_after: str
    updated_at: str
    cleanup_attempts: int
    cleanup_pending: bool
    cleanup_error: str | None
    cleanup_completed_at: str | None


class AuthDebugResponse(ReadResponse):
    authenticated: bool
    auth_required: bool
    configured_modes: list[str]
    recommended_ui_mode: str
    auth_method: str | None
    subject: str | None
    role: str | None
    tenant_id: str | None
    oidc_issuer_suffix: str | None
    api_key_id_prefix: str | None
    request_id: str | None
    trace_id: str | None
    span_id: str | None


# ── audit ────────────────────────────────────────────────────────────────────


class AuditEntryRow(ReadModel):
    entry_id: str
    timestamp: str
    action: str
    actor: str
    resource: str
    details: dict[str, Any]
    prev_signature: str
    hmac_signature: str


class AuditEntriesResponse(ReadResponse):
    schema_version: str
    entries: list[AuditEntryRow]
    total: int
    limit: int
    offset: int


class AuditChain(ReadModel):
    name: str
    algorithm: str
    algorithms: list[str] | None = None
    verified: int
    tampered: int
    checked: int
    tenant_scoped: bool
    source: str | None = None
    error: str | None = None


class AuditIntegrityResponse(ReadResponse):
    verified: int
    tampered: int
    checked: int
    algorithms: list[str]
    chains: list[AuditChain]


class AuditExportFilters(ReadModel):
    action: str | None
    resource: str | None
    since: str | None
    limit: int
    offset: int


class AuditExportIntegrity(ReadModel):
    verified: int
    tampered: int
    checked: int


class AuditExportResponse(ReadResponse):
    """The ``format=json`` packet; ``format=jsonl`` streams NDJSON instead."""

    exported_at: str
    tenant_id: str
    filters: AuditExportFilters
    integrity: AuditExportIntegrity
    entries: list[AuditEntryRow]


# ── exceptions + finding triage ──────────────────────────────────────────────


class VulnExceptionRow(ReadModel):
    exception_id: str
    vuln_id: str
    package_name: str
    server_name: str
    reason: str
    requested_by: str
    approved_by: str
    status: str
    created_at: str
    expires_at: str
    approved_at: str
    revoked_at: str
    tenant_id: str
    approval_version: int
    decided_by: str
    suppression_active: bool
    approval_required: bool


class VulnExceptionResponse(ReadResponse, VulnExceptionRow):
    pass


class VulnExceptionsResponse(ReadResponse):
    schema_version: str
    exceptions: list[VulnExceptionRow]
    total: int
    limit: int
    offset: int


class FindingFeedbackRow(ReadModel):
    id: str
    vulnerability_id: str
    package: str
    server_name: str
    state: str
    reason: str
    marked_by: str
    status: str
    created_at: str
    expires_at: str
    tenant_id: str


class FindingFeedbackResponse(ReadResponse):
    feedback: list[FindingFeedbackRow]
    total: int


class FindingTriageRow(ReadModel):
    id: str
    vulnerability_id: str
    package: str
    server_name: str
    queue_state: str
    decision: str
    justification: str | None
    decision_reason: str
    assignee: str
    created_by: str
    created_at: str
    reviewed_at: str
    expires_at: str
    tenant_id: str
    vex_eligible: bool
    decided_by: str
    approval_status: str
    approval_required: bool


class FindingTriageResponse(ReadResponse):
    schema_version: str
    triage: list[FindingTriageRow]
    total: int
    limit: int
    offset: int


class FindingTriageVexResponse(ReadResponse):
    schema_version: str
    tenant_id: str
    count: int
    format: str
    filters: dict[str, Any]
    finding_scope: dict[str, Any] | None = None
    vex: dict[str, Any]
    signature: dict[str, Any]


class FalsePositiveRow(ReadModel):
    id: str
    vulnerability_id: str
    package: str
    reason: str
    marked_by: str
    status: str
    created_at: str


class FalsePositivesResponse(ReadResponse):
    false_positives: list[FalsePositiveRow]
    total: int
