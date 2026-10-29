import type { ApiSchemas } from "./shared";

export interface Tool {
  name: string;
  description?: string | undefined;
}

export interface Summary {
  total_agents: number;
  total_servers: number;
  total_packages: number;
  total_vulnerabilities: number;
  critical_findings: number;
  high_findings: number;
  medium_findings: number;
  low_findings: number;
  /** Unified finding model totals (every domain); critical is a subset of total. */
  total_findings?: number | undefined;
  critical_unified_findings?: number | undefined;
}

export interface ScorecardSummary {
  total_packages: number;
  unique_packages: number;
  eligible_packages: number;
  attempted_packages: number;
  enriched_packages: number;
  unresolved_packages: number;
  failed_packages: number;
  transient_failed_packages?: number | undefined;
  persistent_failed_packages?: number | undefined;
  failed_reasons?: Record<string, number> | undefined;
}

export interface PostureDimension {
  name: string;
  score: number;
  weight: number;
  weighted_score: number;
  details: string;
  /** False when the lane this dimension grades was skipped (e.g. --no-scan). */
  assessed?: boolean;
}

export interface PostureScorecard {
  grade: string;
  score: number;
  summary: string;
  dimensions: Record<string, PostureDimension>;
}

export interface HealthResponse {
  status: string;
  version: string;
  auth_required?: boolean | undefined;
  auth_configured?: boolean | undefined;
  configured_auth_modes?: string[] | undefined;
  unauthenticated_allowed?: boolean | undefined;
  /** Demo estate mode only: "pending" while the seed is still writing. */
  demo_seed?: "pending" | "complete" | null | undefined;
  experimental_features?: ExperimentalFeatureHealth[] | undefined;
}

export interface ExperimentalFeatureHealth {
  id: string;
  title: string;
  surfaces: string[];
  enabled_by: string;
  doc: string;
  flag_gated: boolean;
  enabled: boolean;
}

export interface VersionInfo {
  version: string;
  api_version: string;
  python_package: string;
}

export interface AuthDebugResponse {
  authenticated: boolean;
  auth_required: boolean;
  configured_modes: string[];
  recommended_ui_mode: string;
  auth_method: string | null;
  subject: string | null;
  role: string | null;
  tenant_id: string;
  oidc_issuer_suffix: string | null;
  api_key_id_prefix: string | null;
  request_id: string | null;
  trace_id: string | null;
  span_id: string | null;
}

export interface AuthRoleCapability {
  id: string;
  label: string;
  description: string;
  minimum_role: string;
  minimum_role_label: string;
  allowed: boolean;
}

export interface AuthRoleSummary {
  role: string;
  ui_role: string;
  display_name: string;
  description: string;
  capabilities: string[];
  capability_matrix: AuthRoleCapability[];
  can_see: string[];
  can_do: string[];
  cannot_do: string[];
}

export interface AuthMembership {
  tenant_id: string;
  role: string;
  ui_role: string;
  display_name: string;
  active: boolean;
}

export interface ManagedTrialEnvelope {
  providers: string[];
  inventory_scope: "account";
  max_regions: number;
  cloud_connections: number;
  cloud_connections_per_provider: number;
  active_scan_jobs: number;
  retained_scan_jobs: number;
  scan_credits_24h: number;
  auto_scan_on_create: boolean;
  schedules: boolean;
  continuous_scans: boolean;
}

export interface AuthMeResponse {
  authenticated: boolean;
  auth_required: boolean;
  configured_modes: string[];
  recommended_ui_mode: string;
  /** Detected brand of the configured browser-OIDC issuer (okta/entra/google) or null. */
  sso_provider?: string | null | undefined;
  auth_method: string | null;
  /** True when the server-wide managed-trial route allowlist is active. */
  managed_trial_mode?: boolean | undefined;
  /** Server-authoritative limits for the active managed trial, otherwise null. */
  managed_trial_envelope?: ManagedTrialEnvelope | null | undefined;
  subject: string | null;
  tenant_id: string;
  role: string | null;
  role_summary: AuthRoleSummary | null;
  memberships: AuthMembership[];
  request_id: string | null;
  trace_id: string | null;
  span_id: string | null;
}

export interface DataAccessBoundaryMode {
  mode: string;
  reads: string[];
  evidence?: string[] | undefined;
  required_identity?: string | undefined;
  controls?: string[] | undefined;
  operator_controls?: string[] | undefined;
  does_not_read?: string[] | undefined;
  does_not_store?: string[] | undefined;
  does_not_do?: string[] | undefined;
}

export interface DataAccessBoundaries {
  default_posture: {
    self_hosted_first: boolean;
    mandatory_hosted_control_plane: boolean;
    hidden_telemetry: boolean;
    default_network_mode: string;
    credential_values_stored: boolean;
    credential_values_transmitted: boolean;
    credential_values_validated_by_default: boolean;
    support_access_default: string;
  };
  modes: DataAccessBoundaryMode[];
  network_boundaries: {
    telemetry: string;
    vulnerability_enrichment: string;
    cloud_provider_api_calls: string;
    outbound_exports: string;
    proxy_gateway_egress: string;
    disable_controls: string[];
  };
  storage_boundaries: {
    local_default: string;
    control_plane_default: string;
    secret_values: string;
    secret_previews: string;
    raw_artifact_exports: string;
    support_bundle_default: string;
  };
  auth_boundaries: {
    api: string[];
    authorization: string[];
    scim: {
      provisioning_authority: string;
      runtime_auth_overlay: string;
      tenant_source: string;
      payload_tenant_attributes_ignored: boolean;
    };
    does_not_do: string[];
  };
  deployment_boundaries: Record<string, string[]>;
  extension_boundaries: {
    connectors: {
      default_posture: string;
      credential_scope: string;
      does_not_do: string[];
      stronger_actions_require: string[];
    };
    plugins_and_skills: {
      default_posture: string;
      execution_boundary: string;
      does_not_do: string[];
      controls: string[];
    };
    roles: {
      viewer: string[];
      analyst: string[];
      admin: string[];
      principle: string;
    };
  };
  posture_vocabulary: {
    capability_flags: string[];
    enforcement_flags: string[];
    intentional_boundary_flags: string[];
  };
  operator_controls: {
    scope_preview: string;
    inventory_only: string;
    project_scope: string;
    config_scope: string;
    disable_vulnerability_network: string;
    disable_scan_network_and_vuln_lookup: string;
    disable_skill_scan: string;
    isolate_skill_scan: string;
    api_access_control: string[];
    optional_exports: string[];
  };
  credential_evidence: {
    config_env_vars: string;
    project_secret_scan: string;
    stores_matched_value: boolean;
    stores_matched_prefix: boolean;
    validates_live_secret: boolean;
  };
  redacted_evidence_context: {
    allowed_context: string[];
    never_show: string[];
    display_model: string;
  };
}

export interface AuthPolicyResponse {
  api_key: {
    default_ttl_seconds: number;
    max_ttl_seconds: number;
    default_overlap_seconds: number;
    max_overlap_seconds: number;
    rotation_policy: string;
    rotation_endpoint: string;
  };
  rate_limit_key: {
    status: string;
    last_rotated: string | null;
    age_days: number | null;
    rotation_days?: number | null | undefined;
    max_age_days?: number | null | undefined;
    message?: string | undefined;
    fallback_source?: string | null | undefined;
    [key: string]: unknown;
  };
  audit_hmac: {
    status: string;
    configured: boolean;
    key_id_configured?: boolean | undefined;
    rotation_tracking_supported?: boolean | undefined;
    [key: string]: unknown;
  };
  ui: {
    recommended_mode: string;
    configured_modes: string[];
    browser_session: string;
    session_storage_fallback: string;
    credentials_mode: string;
    trusted_proxy_headers: string[];
    message: string;
  };
  rate_limit_runtime: {
    backend: string;
    postgres_configured: boolean;
    configured_api_replicas: number;
    shared_required: boolean;
    shared_across_replicas: boolean;
    fail_closed: boolean;
    message: string;
  };
  secret_integrity: {
    audit_hmac: {
      status: string;
      configured: boolean;
      required: boolean;
      source: string;
      persists_across_restart: boolean;
      rotation_tracking_supported: boolean;
      rotation_status: string;
      rotation_method: string;
      rotation_days: number | null;
      max_age_days: number | null;
      last_rotated: string | null;
      age_days: number | null;
      rotation_message: string;
      message: string;
    };
    compliance_signing: {
      algorithm: string;
      mode: string;
      configured: boolean;
      key_id: string | null;
      public_key_endpoint: string | null;
      auditor_distributable: boolean;
      uses_audit_hmac_secret: boolean;
      persists_across_restart: boolean;
      rotation_tracking_supported: boolean;
      rotation_status: string;
      rotation_method: string;
      rotation_days: number | null;
      max_age_days: number | null;
      last_rotated: string | null;
      age_days: number | null;
      rotation_message: string;
      message: string;
    };
  };
  tenant_quotas: {
    active_scan_jobs: number;
    retained_scan_jobs: number;
    fleet_agents: number;
    schedules: number;
  };
  tenant_quota_runtime: {
    source: string;
    per_tenant_overrides: boolean;
    active_override: boolean;
    override_endpoint: string;
    message: string;
    overrides: Partial<
      Record<
        | "active_scan_jobs"
        | "retained_scan_jobs"
        | "fleet_agents"
        | "schedules",
        number
      >
    >;
    usage: Record<
      "active_scan_jobs" | "retained_scan_jobs" | "fleet_agents" | "schedules",
      {
        limit: number;
        default_limit: number;
        override_limit: number | null;
        current: number;
        remaining: number | null;
        enforced: boolean;
        source: string;
        utilization_pct: number | null;
        status: "ok" | "near_limit" | "at_limit" | "unlimited" | string;
        recommended_action: string;
      }
    >;
  };
  identity_provisioning: {
    oidc: {
      supported: boolean;
      configured: boolean;
      mode: string;
      issuer_hosts: string[];
      provider_count: number;
      audience_configured: boolean;
      role_claim: string | null;
      tenant_claim: string | null;
      require_role_claim: boolean;
      require_tenant_claim: boolean;
      allow_default_tenant: boolean;
      required_nonce: boolean;
      message: string;
    };
    saml: {
      supported: boolean;
      configured: boolean;
      metadata_endpoint: string;
      acs_path: string | null;
      idp_host: string | null;
      role_attribute: string;
      tenant_attribute: string;
      require_role_attribute: boolean;
      require_tenant_attribute: boolean;
      session_ttl_seconds: number;
      message: string;
    };
    scim: {
      supported: boolean;
      configured: boolean;
      status: string;
      base_path: string;
      token_configured: boolean;
      external_id_attribute: string;
      role_attribute: string;
      default_role: string;
      role_values: string[];
      tenant_attribute: string;
      tenant_assignment: {
        source: string;
        payload_tenant_attributes_ignored: boolean;
      };
      provisioning_authority: string;
      auth_authority: string;
      runtime_auth_enforced: boolean;
      deprovisioning_boundary: string;
      groups_required: boolean;
      verified_idp_templates?: Array<{
        idp: string;
        status: string;
        notes: string;
      }>;
      message: string;
    };
    session_revocation: {
      service_keys: string;
      session_api_key: string;
      browser_sessions: string;
    };
  };
  data_access_boundaries: DataAccessBoundaries;
}

export type ApiKeyLifecycleState =
  "active" | "rotation_overlap" | "rotated" | "revoked" | "expired";

export interface ApiKeyRecord {
  key_id: string;
  key_prefix: string;
  name: string;
  role: string;
  created_at: string;
  expires_at: string | null;
  scopes: string[];
  tenant_id: string;
  revoked_at: string | null;
  rotation_overlap_until: string | null;
  replacement_key_id: string | null;
  owner?: string | null | undefined;
  state: ApiKeyLifecycleState;
  overlap_seconds_remaining: number | null;
}

export interface ListKeysResponse {
  keys: ApiKeyRecord[];
}

export interface CreateApiKeyRequest {
  name: string;
  role: string;
  expires_at?: string | null | undefined;
  scopes?: string[] | undefined;
  owner?: string | null | undefined;
}

export interface CreateApiKeyResponse extends ApiKeyRecord {
  raw_key: string;
  message: string;
}

export interface RotateApiKeyRequest {
  name?: string | null | undefined;
  expires_at?: string | null | undefined;
  overlap_seconds?: number | null | undefined;
}

export interface RotateApiKeyResponse extends ApiKeyRecord {
  raw_key: string;
  replaced_key_id: string;
  overlap_until: string;
  overlap_seconds: number;
  message: string;
}

export interface TenantQuotaUpdateRequest {
  active_scan_jobs?: number | null | undefined;
  retained_scan_jobs?: number | null | undefined;
  fleet_agents?: number | null | undefined;
  schedules?: number | null | undefined;
}

export type ConnectorsResponse = ApiSchemas["ConnectorsResponse"];

export interface ConnectorHealthResponse {
  connector: string;
  state: string;
  message: string;
  api_version: string | null;
}

export type SourceKind =
  | "scan.repo"
  | "scan.image"
  | "scan.iac"
  | "scan.cloud"
  | "scan.mcp_config"
  | "connector.cloud_read_only"
  | "connector.registry"
  | "connector.warehouse"
  | "ingest.fleet_sync"
  | "ingest.trace_push"
  | "ingest.result_push"
  | "ingest.artifact_import"
  | "runtime.proxy"
  | "runtime.gateway";
