import type { GraphCompleteness,JobStatus } from "./scan-inventory";
import type { ApiSchemas,ContractEnvelope } from "./shared";

// ─── Operations & Integrations ──────────────────────────────────────────────
// Webhook subscriptions, SIEM connectors, threat-intel, async reports. Each
// contract mirrors an existing REST surface so the UI reaches human↔agent
// parity without new backend routes.

/** A governance webhook destination. The signing secret is never returned in
 *  list/detail views — only a non-reversible `secret_fingerprint` handle. */
export interface WebhookSubscription {
  subscription_id: string;
  tenant_id: string;
  url: string;
  event_types: string[];
  status: string;
  description: string;
  created_at: string;
  updated_at: string;
  allow_private_networks: boolean;
  secret_fingerprint: string;
}

export interface WebhookSubscriptionsResponse {
  schema_version: string;
  tenant_id: string;
  event_catalog: string[];
  count: number;
  subscriptions: WebhookSubscription[];
}

export interface WebhookCreateRequest {
  url: string;
  event_types?: string[];
  description?: string;
  signing_secret?: string | undefined;
  allow_private_networks?: boolean;
}

/** Registration response. `signing_secret` is present ONLY here, exactly once,
 *  and is unrecoverable afterward (mirrors the API-key one-time reveal). */
export interface WebhookCreateResponse {
  schema_version: string;
  subscription: WebhookSubscription;
  signing_secret: string;
  secret_notice: string;
}

export interface WebhookMutationResponse {
  schema_version: string;
  subscription?: WebhookSubscription;
  deleted?: boolean;
  queued?: boolean;
  subscription_id?: string;
  event_id?: string;
}

export interface WebhookOutboxResponse {
  schema_version: string;
  tenant_id: string;
  status: string | null;
  count: number;
  records: Array<Record<string, unknown>>;
  stats: Record<string, number>;
}

export type SiemConnectorsResponse = ApiSchemas["SiemConnectorsResponse"];

export type SiemFormatsResponse = ApiSchemas["SiemFormatsResponse"];

export interface SiemTestResponse {
  siem_type: string;
  healthy: boolean;
  error?: string;
}

export interface IntelFeedRun {
  sync_meta_source: string;
  last_synced: string | null;
  record_count: number;
  status: string;
  validation_status: string;
  parse_errors: number;
  validation_failures: number;
  cap_hit: boolean;
  /** Set with `status: "partial"` when the last sync was rate-limited, timed out or capped. */
  partial_reason?: string | null | undefined;
}

export interface IntelSource {
  source_id: string;
  display_name: string;
  tier: string;
  kind: string;
  validation_status: string;
  support_status: string;
  enabled: boolean;
  owner: string;
  description: string;
  feed_run: IntelFeedRun;
}

export type IntelSourcesResponse = ContractEnvelope<ApiSchemas["IntelSourcesResponse"], { sources: IntelSource[] }>;

export interface IntelAdvisory {
  id: string;
  summary: string;
  severity: string;
  cvss_score: number | null;
  cvss_vector: string | null;
  fixed_version: string | null;
  source: string;
  published_at: string | null;
  modified_at: string | null;
  epss_probability: number | null;
  epss_percentile: number | null;
  is_kev: boolean;
  kev_date_added: string | null;
  affected: Array<Record<string, unknown>>;
  canonical_ids: { cves: string[]; ghsas: string[]; osv: string[]; cwes: string[] };
  evidence_links: Array<{ label?: string; url: string }>;
}

export interface IntelAdvisoryResponse {
  schema_version: string;
  found: boolean;
  query: string;
  advisory: IntelAdvisory | null;
}

export interface IntelMatchPackageInput {
  ecosystem: string;
  name: string;
  version?: string | undefined;
}

export interface IntelMatchItem {
  ecosystem?: string;
  name?: string;
  version?: string;
  match_count: number;
  advisories?: Array<Record<string, unknown>>;
  [key: string]: unknown;
}

export interface IntelMatchResponse {
  schema_version: string;
  submitted: number;
  matched_packages: number;
  match_count: number;
  matches: IntelMatchItem[];
}

export interface IntelDailyBriefResponse {
  schema_version: string;
  generated_at: string;
  inputs: Record<string, unknown>;
  sections: {
    kev_last_24h: unknown[];
    high_epss_inventory: unknown[];
    vendor_advisories: unknown[];
    ioc_telemetry_hits: unknown[];
    campaign_matches: unknown[];
    ransomware_sector_matches: unknown[];
  };
  limitations: string[];
}

export type ReportSort = "effective_reach" | "cvss" | "severity" | "ordinal";

export interface ReportJobRecord {
  job_id: string;
  tenant_id: string;
  status: JobStatus;
  format: string;
  sort: string;
  severity: string | null;
  created_at: string;
  started_at: string | null;
  completed_at: string | null;
  row_count: number | null;
  byte_count: number | null;
  error: string | null;
  download_url?: string;
  download_token?: string;
  download_token_header?: string;
  artifact_backend?: "local" | "s3" | null;
  artifact_uri?: string | null;
}

export interface ReportCreateRequest {
  format?: "ndjson";
  sort?: ReportSort;
  severity?: string | null;
}

// ── ITSM ticketing (connect-once) ─────────────────────────────────────────────
// Shapes mirror src/agent_bom/api/routes/ticketing.py + ticketing/service.py.
// Credentials never appear here: a connection is created once in the Connections
// hub, and every ticket action runs through the stored, encrypted connection.

export type TicketProvider = "jira" | "servicenow" | "generic" | string;

export type TicketTransport = "mcp" | "rest" | string;

export type TicketConnectionStatus = "pending" | "active" | "error" | string;

/** Canonical, provider-neutral ticket status (models.py TicketStatus). */
export type TicketStatus = "open" | "in_progress" | "done" | "unknown" | string;

/** Non-secret metadata for a stored ticketing connection. */
export interface TicketingConnection {
  id: string;
  tenant_id: string;
  provider: TicketProvider;
  transport: TicketTransport;
  auth_method: string;
  display_name: string;
  endpoint: string;
  auth_params: Record<string, string>;
  status: TicketConnectionStatus;
  status_detail: string;
  created_at: string;
  updated_at: string;
  has_secret: boolean;
}

export type TicketingConnectionsResponse = ContractEnvelope<ApiSchemas["TicketingConnectionsResponse"], { connections: TicketingConnection[] }>;

/** A finding→ticket link (also the idempotency ledger row). */
export interface TicketLink {
  id: string;
  tenant_id: string;
  connection_id: string;
  dedupe_key: string;
  provider: TicketProvider;
  status: TicketStatus;
  external_id: string;
  key: string;
  url: string;
  created_at: string;
  updated_at: string;
}

export interface TicketsListResponse {
  schema_version: string;
  tenant_id: string;
  tickets: TicketLink[];
  count: number;
}

/** Result of creating or syncing a ticket (service.py _result). */
export interface TicketActionResult {
  schema_version: string;
  ticket: TicketLink;
  connection_id: string;
  provider: TicketProvider;
  transport: TicketTransport;
  deduplicated: boolean;
  audit_metadata: {
    connect_once: boolean;
    per_action_credential: boolean;
    note: string;
  };
}

/**
 * Body for POST /v1/ticketing/tickets. Carries NO credential, token, or
 * base-URL: auth + endpoint resolve only from the stored connection. Title and
 * description are derived server-side from `finding` (TicketDraft.from_finding).
 */
export interface TicketCreateBody {
  connection_id?: string;
  finding_id?: string;
  project?: string;
  issue_type?: string;
  source_url?: string;
  finding: Record<string, unknown>;
}

// ── Risk campaigns ───────────────────────────────────────────────────────────
// Server-authored remediation priorities. The browser renders these values but
// never recomputes priority or expected risk reduction.

export type RiskCampaignState = "open" | "in_progress" | "blocked" | "done";

export type RiskCampaignVerificationStatus =
  | "unverified"
  | "pending"
  | "verified"
  | "failed";

export interface RiskCampaignSeverityFactor {
  value: string;
  status: "observed";
  bands_present: string[];
}

export type RiskCampaignExploitabilityFactor =
  | { value: "known_exploited"; status: "observed"; signals: ["kev"] }
  | { value: number; status: "modeled"; signals: ["epss"] }
  | { value: null; status: "unknown"; signals?: never };

export interface RiskCampaignReachabilityFactor {
  value: boolean | null;
  status: "observed" | "unknown";
}

export interface RiskCampaignBusinessContextFactor {
  value: string | null;
  status: "observed" | "unknown";
}

export interface RiskCampaignCrownJewelFactor {
  value: boolean | null;
  status: "observed" | "unknown";
  signals?: string[];
}

export interface RiskCampaignScoreFactors {
  severity: RiskCampaignSeverityFactor;
  exploitability: RiskCampaignExploitabilityFactor;
  reachability: RiskCampaignReachabilityFactor;
  business_context: RiskCampaignBusinessContextFactor;
  crown_jewel: RiskCampaignCrownJewelFactor;
}

export interface RiskCampaignPriorityScoreComponents {
  base_risk: number;
  exploitability_boost: number;
  reachability_boost: number;
  crown_jewel_boost: number;
  cap: number;
}

export interface RiskCampaignExpectedReduction {
  modeled_window_percent: number;
  modeled_risk_points: number;
  assumption: string;
  method: string;
  scope: string;
  portfolio_complete: boolean;
}

export interface RiskCampaign {
  finding_ids_truncated?: boolean;
  id: string;
  tenant_id: string;
  title: string;
  finding_ids: string[];
  finding_count: number;
  severity: string;
  priority_score: number;
  priority_score_method: string;
  priority_score_components: RiskCampaignPriorityScoreComponents;
  score_factors: RiskCampaignScoreFactors;
  expected_risk_reduction: RiskCampaignExpectedReduction;
  owner: string | null;
  sla_due_at: string | null;
  state: RiskCampaignState;
  verification_status: RiskCampaignVerificationStatus;
  updated_at: string | null;
  source: string;
  membership_fingerprint: string;
  generation: number;
  version: number;
  active: boolean;
  membership_complete: boolean;
  membership_provisional: boolean;
}

export interface RiskCampaignsResponse {
  total_campaigns?: number;
  limit?: number;
  has_more?: boolean;
  next_cursor?: string | null;
  schema_version: "risk-campaigns.v1";
  tenant_id: string;
  campaigns: RiskCampaign[];
  count: number;
  finding_window_days: 90;
  finding_limit: number;
  truncated: boolean;
  total_findings: number | null;
  total_approximate: boolean;
  membership_complete: boolean;
}

export interface RiskCampaignUpdate {
  version: number;
  owner?: string | null;
  sla_due_at?: string | null;
  state?: RiskCampaignState;
}

export interface RiskCampaignVerificationRequest {
  version: number;
}

export interface RiskCampaignVerificationResult {
  schema_version: "risk-campaign-verification.v1";
  campaign_id: string;
  verification_status: "verified" | "failed";
  state: RiskCampaignState;
  remaining_finding_ids: string[];
  remaining_count: number;
  original_member_count: number;
  evidence_scope: {
    source: "canonical_findings_spine";
    finding_window_days: 90;
    finding_limit: number;
    membership_complete: true;
  };
  version: number;
  verified_at: string;
}

export interface RiskCampaignVerificationQueueEntry {
  campaign_id: string;
  title: string;
  original_member_count: number;
  owner: string | null;
  sla_due_at: string | null;
  state: RiskCampaignState;
  verification_status: "unverified" | "failed";
  active: false;
  version: number;
  updated_at: string | null;
}

export interface RiskCampaignVerificationQueueResponse {
  schema_version: "risk-campaign-verification-queue.v1";
  tenant_id: string;
  entries: RiskCampaignVerificationQueueEntry[];
  count: number;
  has_more: boolean;
  next_cursor: string | null;
  limit: number;
}

export interface RiskCampaignTicketRequest {
  connection_id: string;
  project?: string;
  issue_type?: string;
  cursor?: string | null;
  limit?: number;
}

export interface RiskCampaignTicketCreateError {
  finding_id: string;
  code: string;
  detail: string;
}

export interface RiskCampaignTicketSyncError {
  ticket_id: string;
  code: string;
  detail: string;
}

export interface RiskCampaignTicketCreateResult {
  schema_version: string;
  campaign_id: string;
  created: number;
  failed: number;
  tickets: TicketActionResult[];
  errors: RiskCampaignTicketCreateError[];
  per_action_credential: false;
  total: number;
  processed: number;
  next_cursor: string | null;
  has_more: boolean;
  action_limit: number;
}

export interface RiskCampaignTicketSyncResult {
  schema_version: string;
  campaign_id: string;
  synced: number;
  failed: number;
  tickets: TicketActionResult[];
  errors: RiskCampaignTicketSyncError[];
  per_action_credential: false;
  total: number;
  processed: number;
  next_cursor: string | null;
  has_more: boolean;
  action_limit: number;
}

/** A page of recorded relationships; totals and source coverage remain unknown. */
export interface GraphIncidentPage {
  evidence_scope?: "current_estate" | "historical_scan" | null;
  scan_id: string;
  snapshot_generation: string | null;
  node_id: string;
  found: boolean;
  direction: "in" | "out" | "both";
  limit: number;
  node: import("../graph-schema").UnifiedNode | null;
  nodes: import("../graph-schema").UnifiedNode[];
  edges: import("../graph-schema").UnifiedEdge[];
  next_cursor: string | null;
  completeness: Omit<GraphCompleteness, "total"> & { total: null; scope: "incident_edge_page"; missing_endpoint_count: number };
}

export type TraceCollectionReceipt = ApiSchemas["CollectionReceipt"];
