import type { ApiSchemas,ContractEnvelope } from "./shared";

// ─── Compliance Hub (#1044) ─────────────────────────────────────────────────

export type HubPostureResponse = ApiSchemas["HubPostureResponse"];

// ── Runtime governance cockpits: cost, identity, drift ──────────────────────

export interface CostBudgetStatus {
  configured: boolean;
  agent?: string | null;
  cost_center?: string | null;
  /** Accountable owner this budget is scoped to, from the governing blueprint
   *  header (#3909). Null when the budget is not owner-scoped. */
  owner?: string | null;
  /** Optional owner sub-scope: a single governing blueprint ("workflow"). */
  workflow?: string | null;
  mode?: string; // "report" | "enforce"
  limit_usd: number | null;
  spend_usd: number;
  remaining_usd: number | null;
  exceeded: boolean;
  utilization: number | null; // 0-1
}

export interface CostBreakdownRow {
  key: string;
  calls: number;
  input_tokens: number;
  output_tokens: number;
  cost_usd: number;
  unpriced_calls: number;
}

/** Forward-looking burn-rate + budget-runway projection (#2925).
 *
 * Mirrors `agent_bom.api.cost_forecast.forecast_spend`. Reference-only — a
 * forecast never blocks a call. Every projection field is nullable: a sparse or
 * empty history yields a clear `status` and `null` projections. */
export type CostForecastStatus =
  "insufficient_history" | "budget_exceeded" | "no_budget" | "stale" | "ok";

export interface CostForecast {
  schema_version: string;
  agent: string | null;
  now: string;
  status: CostForecastStatus | string;
  current_spend_usd: number | null;
  budget_limit_usd: number | null;
  burn_rate_usd_per_day: number | null;
  burn_rate_basis: "trailing_24h" | "trailing_7d" | string | null;
  projected_period_spend_usd: number | null;
  period_start: string | null;
  period_end: string | null;
  days_remaining: number | null;
  projected_exhaustion_at: string | null;
  history_span_hours?: number | null | undefined;
  tenant_id?: string | undefined;
}

/** One freeform allocation-tag showback slice (returned when `tag` is passed). */
export interface CostTagRollup {
  tag_key: string;
  total_cost_usd: number;
  by_tag: CostBreakdownRow[];
}

export interface CostReport {
  schema_version: string;
  tenant_id: string;
  price_model_captured: string;
  period?: "all_recorded";
  basis?: "estimated_token_cost";
  agents?: number;
  first_recorded_at?: string | null;
  last_recorded_at?: string | null;
  history?: { limit: number; returned_calls: number; complete: boolean };
  scope?: { agent: string | null; cost_center: string | null };
  total_cost_usd: number;
  total_calls: number;
  total_input_tokens: number;
  total_output_tokens: number;
  unpriced_calls: number;
  by_agent: CostBreakdownRow[];
  by_model: CostBreakdownRow[];
  by_provider: CostBreakdownRow[];
  /** Chargeback/showback rollup by cost-center (#2925). Unallocated spend
   *  rolls up under the `"unallocated"` key. */
  by_cost_center?: CostBreakdownRow[] | undefined;
  /** Owner-attributed rollup (#3909): spend grouped by the accountable owner
   *  governing each agent. Spend from an ungoverned agent rolls up under the
   *  `"unattributed"` key. */
  by_owner?: CostBreakdownRow[] | undefined;
  /** Present only when a `tag` query param was supplied. */
  tag_rollup?: CostTagRollup | undefined;
  /** Forward-looking burn-rate + runway projection embedded on the report. */
  forecast?: CostForecast | undefined;
  budget: CostBudgetStatus;
}

export interface CostAnomaly {
  type: string;
  severity: string;
  agent?: string;
  session_id?: string;
  metric: string;
  value: number;
  baseline_median: number;
  z_score: number;
  recommendation: string;
}

export interface AnomaliesReport {
  schema_version: string;
  tenant_id: string;
  z_threshold: number;
  anomaly_count: number;
  cost_anomalies: CostAnomaly[];
  behavior_anomalies: CostAnomaly[];
}

export interface AgentIdentitySummary {
  identity_id: string;
  agent_id: string;
  tenant_id: string;
  token_prefix: string;
  role: string;
  blueprint_id: string;
  status: "active" | "rotating" | "revoked" | "expired";
  issued_at: string;
  expires_at: string;
  allowed_tools: string[];
  rotated_to_id: string;
  revoked_at: string;
  revoked_reason: string;
}

export type IdentitiesResponse = ContractEnvelope<ApiSchemas["IdentitiesResponse"], { identities: AgentIdentitySummary[] }>;

export interface JITGrant {
  grant_id: string;
  identity_id: string;
  agent_id: string;
  tenant_id: string;
  tool_name: string;
  status: "requested" | "active" | "denied" | "revoked";
  requested_at: string;
  requested_by: string;
  approved_at: string;
  approved_by: string;
  starts_at: string;
  expires_at: string;
  reason: string;
  ticket_id: string;
  revoked_at: string;
  revoked_reason: string;
  denied_at: string;
  denied_reason: string;
}

export interface JITGrantsResponse {
  schema_version: string;
  tenant_id: string;
  count: number;
  grants: JITGrant[];
}

export interface ConditionalAccessPolicy {
  policy_id: string;
  tenant_id: string;
  name: string;
  effect: "require" | "deny";
  status: "active" | "disabled";
  created_at: string;
  priority: number;
  identity_ids: string[];
  agent_ids: string[];
  tools: string[];
  allowed_environments: string[];
  allowed_hours_utc: number[];
  allowed_weekdays: number[];
  allowed_source_cidrs: string[];
  // ABAC device/group/client conditions (evaluated fail-closed alongside the
  // environment/time/CIDR guardrails).
  allowed_devices: string[];
  allowed_groups: string[];
  allowed_clients: string[];
  updated_at: string;
  description: string;
}

export interface ConditionalAccessResponse {
  schema_version: string;
  tenant_id: string;
  count: number;
  policies: ConditionalAccessPolicy[];
}

export interface DriftViolation {
  tool_name?: string;
  type?: string;
  [key: string]: unknown;
}

export interface DriftIncident {
  incident_id: string;
  tenant_id: string;
  blueprint_id: string;
  status: string;
  drift_score: number;
  violation_count: number;
  warning_count: number;
  top_violations: DriftViolation[];
  first_detected_at: string;
  last_detected_at: string;
  occurrences: number;
  resolved: boolean;
  resolved_at: string;
  resolved_by: string;
  resolution_note: string;
}

export type DriftIncidentsResponse = ContractEnvelope<ApiSchemas["DriftIncidentsResponse"], { incidents: DriftIncident[] }>;

/** Summary of a blueprint version promoted from accepted drift (#3905). */
export interface DriftPromotedVersion {
  blueprint_id: string;
  version: number;
  status: string; // "pending" — accepting drift never auto-approves
  version_id: string;
}

/** Response to `POST /v1/runtime/drift/incidents/{id}/resolve`.
 *
 * With an "accept"/"accept_drift" `disposition`, the observed drift is promoted
 * into a new draft version of the governing blueprint and submitted for approval
 * (`promoted_version`, status `pending`); a plain close omits it (#3905). */
export interface DriftIncidentResolveResponse {
  schema_version: string;
  tenant_id: string;
  resolved: boolean;
  disposition: string; // "close" | "reject" | "accept_drift" | ...
  incident: DriftIncident;
  promoted_version?: DriftPromotedVersion | null | undefined;
}

// ── NHI / identity governance: credential expiry, access reviews, discovery ──
//
// Mirrors `GET /v1/auth/secrets/credential-expiry`,
// `GET /v1/identities/access-reviews`, and `POST /v1/identities/discover`.
// All three are reference-only and never carry secret values.

export type CredentialExpiryState =
  "overdue" | "expired" | "rotation_due" | "near_expiry" | "unknown_age" | "ok";

export interface CredentialExpiryItem {
  id: string | null;
  name: string | null;
  provider: string | null;
  identity_type: string | null;
  state: CredentialExpiryState | string;
  priority: number;
  blocking: boolean;
  age_days: number | null;
  days_until_expiry: number | null;
  credential_expires_at: string | null;
  last_rotated: string | null;
  near_expiry_days: number;
  rotation_days: number | null;
  max_age_days: number | null;
  reasons: string[];
}

export interface CredentialExpiryReport {
  status: "ok" | "attention_required" | "blocked" | string;
  secret_values_included: boolean;
  evaluated: number;
  counts: Record<string, number>;
  blockers: Array<string | null>;
  warnings: Array<string | null>;
  thresholds: {
    near_expiry_days: number;
    rotation_days: number | null;
    max_age_days: number | null;
  };
  credentials: CredentialExpiryItem[];
  action_required: CredentialExpiryItem[];
  message: string;
  generated_from: string;
  control_plane_included: boolean;
  discovered_credential_count: number;
}

export type AccessReviewStatus =
  "open" | "in_progress" | "completed" | "overdue";

export interface AccessReviewCampaign {
  campaign_id: string;
  tenant_id: string;
  name: string;
  status: AccessReviewStatus | string;
  created_at: string;
  created_by: string;
  due_at: string;
  completed_at: string;
  description: string;
  item_count: number;
  decided_count: number;
}

export interface AccessReviewsResponse {
  schema_version: string;
  tenant_id: string;
  count: number;
  campaigns: AccessReviewCampaign[];
}

export interface NhiDiscoveryProvider {
  provider: string | null;
  status: string | null;
  count: number;
}

export interface DiscoveredNonHumanIdentity {
  identity_id: string;
  name: string;
  identity_type: string;
  provider: string;
  status: string;
  owner?: string | null | undefined;
  created_at?: string | null | undefined;
  last_used_at?: string | null | undefined;
  credential_expires_at?: string | null | undefined;
  scopes: string[];
  raw_identity?: Record<string, unknown> | undefined;
}

export interface NhiDiscoveryResponse {
  schema_version: string;
  tenant_id: string;
  status: "ok" | "empty" | string;
  providers: NhiDiscoveryProvider[];
  count: number;
  identities: DiscoveredNonHumanIdentity[];
  warnings: string[];
}

// ── Cloud connections plane (#3175) ──────────────────────────────────────────
//
// Mirrors `src/agent_bom/api/routes/cloud_connections.py`. A connection is a
// stored, encrypted, tenant-scoped record of how the control plane reaches a
// customer cloud account in read-only mode. The `external_id` secret is
// write-only: it is accepted on create, encrypted at rest, and is NEVER returned
// by the API. `has_external_id` is the only signal that a secret is configured.

export type CloudConnectionProvider = "aws" | "azure" | "gcp" | "snowflake" | "database" | "databricks";

export type CloudConnectionStatus = "pending" | "active" | "error";

/** Non-secret public shape of `CloudConnectionRecord.to_public_dict()`. */
export interface CloudConnectionRecord {
  id: string;
  tenant_id: string;
  provider: CloudConnectionProvider | string;
  display_name: string;
  role_ref: string;
  /** True when an encrypted secret is stored. The secret itself never leaves the API. */
  has_external_id: boolean;
  /** Credential configuration only; this does not imply provider capability. */
  credential_present: boolean;
  regions: string[];
  status: CloudConnectionStatus | string;
  status_detail: string;
  created_at: string;
  updated_at: string;
  last_scan_at: string | null;
  /** Last event-driven posture re-evaluation. Null means polling/manual only so far. */
  last_event_at: string | null;
  /** Last successfully persisted scan id for durable handoff links. */
  last_scan_id: string | null;
  /** Recurring read-only scan cadence. Null means manual-only. */
  scan_interval_minutes: number | null;
  /** Non-secret provider-specific params (Azure tenant/subscription, GCP project, Snowflake user/role/warehouse). */
  auth_params?: Record<string, string>;
  /** ``account`` (default) or ``organization`` — org fans Connections scan across member accounts. */
  inventory_scope?: "account" | "organization" | string;
  /** ``full`` (default) polling cadence; ``continuous`` intends event-driven mid-interval refresh. */
  scan_mode?: "full" | "continuous" | string;
  /** When true (Create default), a follow-up path may enqueue a scan after create. */
  auto_scan_on_create?: boolean;
  /** Result of the bounded provider capability probe. */
  capability_probe_status:
    | "not_run"
    | "verified"
    | "invalid_credentials"
    | "permission_denied"
    | "timeout"
    | "invalid_configuration"
    | "unavailable"
    | string;
  /** Stable, non-secret provider reads proved by the latest successful probe. */
  verified_capabilities: string[];
}

export type CloudConnectionsResponse = ContractEnvelope<ApiSchemas["CloudConnectionsResponse"], { connections: CloudConnectionRecord[] }>;

/** Request body for `POST /v1/cloud/connections`. `external_id` is write-only. */
export interface CloudConnectionCreateRequest {
  provider: string;
  display_name: string;
  role_ref: string;
  external_id?: string;
  regions: string[];
  /** Non-secret provider-specific params. Never carries a secret (that is `external_id`). */
  auth_params?: Record<string, string>;
  /** Optional recurring read-only scan cadence. Null/default means manual-only. */
  scan_interval_minutes?: number | null;
  /** ``account`` (default) or ``organization`` for Connections scan fan-out. */
  inventory_scope?: "account" | "organization";
  /** ``full`` (default) or ``continuous``. */
  scan_mode?: "full" | "continuous";
  /** Defaults true on create; persisted for a follow-up create-time scan path. */
  auto_scan_on_create?: boolean;
}

export interface CloudConnectionUpdateRequest {
  /** Recurring read-only scan cadence. Null disables scheduling. Omitted = leave unchanged. */
  scan_interval_minutes?: number | null;
  /** Optional org fan-out scope for subsequent Connections scans. */
  inventory_scope?: "account" | "organization";
  /** Optional scan cadence mode. */
  scan_mode?: "full" | "continuous";
  /** Optional create-time auto-scan flag. */
  auto_scan_on_create?: boolean;
}

export interface AuthorizationEvidenceSummary {
  status: "complete" | "partial" | "indeterminate";
  required_source_count: number;
  complete_source_count: number;
  partial_source_count: number;
  indeterminate_source_count: number;
}

export interface CloudConnectionScanInventory {
  provider: string;
  /** Present for AWS/Azure/GCP; "ok" for Snowflake. */
  status?: string;
  account?: string | null;
  region?: string;
  /** AWS/Azure/GCP estate-inventory counts. */
  resource_count?: number;
  identity_count?: number;
  node_summary?: {
    buckets: number;
    instances: number;
    security_groups: number;
    roles: number;
    users: number;
  };
  /** Snowflake discovery count (Cortex/MCP agents). */
  agent_count?: number;
  warnings?: string[];
  /** Count-only authorization evidence state. Raw bindings and diagnostics are never returned here. */
  authorization_evidence?: AuthorizationEvidenceSummary | null;
}

export interface CloudConnectionScanCis {
  benchmark: string | null;
  benchmark_version: string | null;
  passed: number | null;
  failed: number | null;
  total: number | null;
  pass_rate: number | null;
}

/** Response from `POST /v1/cloud/connections/{id}/test`; no scan is created. */
export interface CloudConnectionTestResponse {
  schema_version: string;
  connection_id: string;
  tenant_id: string;
  provider: string;
  status: "ok" | string;
  credential_present: boolean;
  capability_probe_status: "verified" | string;
  verified_capabilities: string[];
  audit_metadata: {
    read_only: boolean;
    writes_performed: boolean;
    note: string;
  };
  connection: CloudConnectionRecord;
}

/** Accepted durable job from `POST /v1/cloud/connections/{id}/scan`. */
export interface CloudConnectionScanResponse {
  schema_version: string;
  connection_id: string;
  tenant_id: string;
  provider: string;
  job_id: string;
  status: "pending" | "running" | "done" | "failed" | "cancelled" | string;
}

/** One traced tool-call span resolved to the exact attack path it hit (#3898). */
export interface TraceSpanAttackPath {
  trace_id: string;
  span_id: string;
  tool_name: string;
  server_name: string;
  package_name: string;
  match_basis: "tool" | "server" | "package" | string;
  vulnerability_id: string;
  severity: string;
  cvss_score: number;
  epss_score: number;
  is_kev: boolean;
  exposed_credentials: string[];
  exposed_nhi: Array<Record<string, unknown>>;
  affected_agents: string[];
  affected_servers: string[];
  blast_radius_score: number;
}

export interface TraceAttackPathsResponse {
  schema_version: "observability.trace_attack_paths.v1" | string;
  tenant_id: string;
  spans: number;
  count: number;
  attack_paths: TraceSpanAttackPath[];
}

/** A privacy-safe Shield detection on opt-in-screened trace content (#3899). */
export interface TraceContentFinding {
  trace_id: string;
  span_id: string;
  tool_name: string;
  channel: string;
  detector: string;
  severity: string;
  message: string;
}

export interface TraceConnectorDescriptor {
  name: string;
  kind: string;
  auth_fields: string[];
  supports_content: boolean;
}

export type TraceConnectorsResponse = ApiSchemas["TraceConnectorsResponse"];

export interface TraceConnectorPullResponse {
  schema_version: "observability.trace_connectors.v1" | string;
  tenant_id: string;
  provider: string;
  pulled_spans: number;
  content_screened: boolean;
  attack_paths: TraceSpanAttackPath[];
  content_findings: TraceContentFinding[];
  import?: {
    import_id: string;
    revision: number;
    complete: boolean;
    status: string;
    coverage: string;
    window_start: string;
    window_end: string;
    counts_scope: string;
    counts: { fetched: number; imported: number; updated?: number; unchanged: number; rejected: number; committed_pages: number; failed_pages: number };
    rejected_reasons: Record<string, number>;
    total_rejected: number;
    error: { code: string; retryable: boolean } | null;
    content_retained: false;
  };
}

// ── Governance: persisted AI-system blueprints (versioning + approval) ────────

/** The approved entities a blueprint version composes. */
export interface BlueprintComposition {
  agents: string[];
  models: string[];
  tools: string[];
  datasets: string[];
  identities: string[];
  owners: string[];
  guardrails: string[];
}

/** One immutable-once-approved blueprint version and its approval state. */
export interface BlueprintVersion {
  version_id: string;
  blueprint_id: string;
  tenant_id: string;
  version: number;
  status: "draft" | "pending" | "approved" | "rejected" | string;
  composition: BlueprintComposition;
  created_at: string;
  created_by: string;
  submitted_at: string;
  submitted_by: string;
  decided_at: string;
  approver: string;
  decision_note: string;
  seeded_from: string;
}

/** A persisted AI-system blueprint header. */
export interface BlueprintRecord {
  blueprint_id: string;
  tenant_id: string;
  name: string;
  owner: string;
  owner_type: string;
  description: string;
  created_at: string;
  updated_at: string;
  current_version: number;
  latest_version: number;
  approval_status: "draft" | "pending" | "approved" | "rejected" | string;
  seeded_from: string;
}

/** Response from `GET /v1/governance/blueprints`. */
export interface BlueprintListResponse {
  schema_version: string;
  tenant_id: string;
  count: number;
  next_offset: number | null;
  blueprints: BlueprintRecord[];
}

/** Response from `GET /v1/governance/blueprints/{id}`. */
export interface BlueprintDetailResponse {
  schema_version: string;
  tenant_id: string;
  blueprint: BlueprintRecord;
  versions: BlueprintVersion[];
}

/** Response from a blueprint create / approval-workflow action. */
export interface BlueprintVersionResponse {
  schema_version: string;
  tenant_id: string;
  blueprint?: BlueprintRecord;
  version: BlueprintVersion;
}

/** Response from `POST /v1/governance/blueprints/seed`. */
export interface BlueprintSeedResponse {
  schema_version: string;
  tenant_id: string;
  seeded_count: number;
  blueprints: BlueprintRecord[];
}

/** Request body for `POST /v1/governance/blueprints`. */
export interface BlueprintCreateRequest {
  name: string;
  owner: string;
  owner_type?: string;
  description?: string;
  composition?: Partial<BlueprintComposition>;
}

// ── Governance: ABAC device/group/client + delegation + served MCP-config ───────

/** Verified claims of a scoped delegation token (issue/verify/propagate). */
export interface DelegationClaims {
  jti: string;
  tenant_id: string;
  delegator: string;
  delegatee: string;
  scopes: string[];
  chain: string[];
  remaining_depth: number;
  issued_at: number;
  expires_at: number;
}

/** Response from issuing/propagating a delegation token. */
export interface DelegationTokenResponse {
  schema_version: string;
  token: string;
  delegation: DelegationClaims;
}

/** Response from `POST /v1/delegations/verify`. */
export interface DelegationVerifyResponse {
  schema_version: string;
  valid: boolean;
  reason?: string;
  delegation?: DelegationClaims;
}

/** One tenant-scoped MCP-client-config assignment. */
export interface McpClientConfigAssignment {
  config_id: string;
  tenant_id: string;
  name: string;
  profile_id: string;
  connector_ids: string[];
  connection_ids: string[];
  created_at: string;
  created_by: string;
  updated_at: string;
  revoked: boolean;
  identity_id: string;
  issuer: string;
  environment: string;
  allowed_tools: string[];
  required_scopes: string[];
  policy_ids: string[];
  owner: string;
  status: "active" | "disabled" | "revoked";
  revision: number;
  expires_at: string;
  config_url?: string;
}

/** Response from assigning a profile → one distributable read-only config URL. */
export interface McpConfigAssignmentResponse {
  schema_version: string;
  assignment: McpClientConfigAssignment;
  config_url: string;
}

/** One credential reference in a served MCP-client-config — never a secret value. */
export interface McpServerCredentialReference {
  value: string;
  handle: string;
  source: "reference";
}

/** The served, read-only `.mcp.json` document. References connectors/secrets by
 *  handle only; it never embeds secret material. */
export interface ServedMcpClientConfig {
  schema_version: string;
  config_id: string;
  tenant_id: string;
  name: string;
  profile_id: string;
  profile?: Record<string, unknown> | null;
  mcpServers: Record<string, {
    connector_id: string;
    name: string;
    transport: string;
    publisher?: string | null;
    risk_level?: string | null;
    packages: unknown[];
    env: Record<string, McpServerCredentialReference>;
    credential_references: string[];
  }>;
  connections: Array<{
    connection_id?: string;
    provider?: string;
    display_name?: string;
    has_secret: boolean;
    handle: string;
  }>;
  unknown_connectors: string[];
  generated_at: string;
  read_only: boolean;
}
