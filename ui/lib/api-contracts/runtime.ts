import type { GatewayFeedHealth,ProducerAssurance,ProducerAssuranceSummary } from "./overview";
import type { ApiSchemas,ContractEnvelope } from "./shared";

// ── Operator self-posture (GET /v1/self-posture) ────────────────────────────
// agent-bom auditing its OWN control-plane hardening. Honest four-way per-check
// status; `unknown` is a first-class outcome (never a silent pass). Mirrors
// agent_bom.self_posture.self_posture — see src/agent_bom/self_posture.py.
export type SelfPostureStatus = "pass" | "fail" | "warn" | "unknown";

export type SelfPostureOverall =
  | "hardened"
  | "action_advised"
  | "needs_review"
  | "at_risk";

export interface SelfPostureCheck {
  id: string;
  category: string;
  title: string;
  status: SelfPostureStatus;
  detail: string;
  remediation?: string;
}

export interface SelfPostureCounts {
  pass: number;
  fail: number;
  warn: number;
  unknown: number;
}

export interface SelfPostureReport {
  schema_version: number;
  overall_status: SelfPostureOverall;
  hardened: boolean;
  deployment_env: string;
  counts: SelfPostureCounts;
  checks: SelfPostureCheck[];
}

// ── Skills scan (#4790 REST parity — the CLI/MCP skills scanner over REST) ──

/** Per-file threat-intel status (never an implied clean pass). */
export type SkillsScanFileStatus =
  | "clean"
  | "suspicious"
  | "malicious"
  | "pending"
  | "unavailable";

/** Behavioural content verdict, split from provenance per the trust two-axis model. */
export type SkillsContentVerdict = "benign" | "suspicious" | "malicious";

/** Handling recommendation derived from content + provenance together. */
export type SkillsReviewVerdict = "clean" | "review" | "high_risk" | "blocked";

export interface SkillsScanFinding {
  severity: string;
  category: string;
  title: string;
  detail: string;
  source_file?: string | null;
  package?: string | null;
  server?: string | null;
  recommendation?: string | null;
  confidence?: string | null;
  source_line?: number | null;
  source_column?: number | null;
}

export interface SkillsScanTrust {
  verdict: SkillsContentVerdict;
  content_verdict: SkillsContentVerdict;
  provenance_verdict: string;
  review_verdict: SkillsReviewVerdict;
  confidence: string;
  recommendations: string[];
  review_reasons: string[];
}

export interface SkillsScanProvenance {
  status: "verified" | "unsigned" | "bundle_found_but_invalid" | "missing";
  reason?: string | null;
  sha256?: string | null;
  signer?: string | null;
  has_sigstore_bundle?: boolean;
}

export interface SkillsScanFileReport {
  path: string;
  status: SkillsScanFileStatus;
  credential_env_vars: string[];
  packages: Array<{ name: string; version?: string | null; ecosystem: string }>;
  servers: Array<{ name: string; command?: string | null; transport: string }>;
  audit: {
    passed: boolean;
    behavioral_summary?: string | null;
    findings: SkillsScanFinding[];
  };
  trust: SkillsScanTrust;
  provenance: SkillsScanProvenance;
}

export interface SkillsScanSummary {
  files_scanned: number;
  bundles: number;
  packages_found: number;
  servers_found: number;
  credential_env_vars: number;
  findings: number;
  verified_files: number;
  suspicious_files: number;
  malicious_files: number;
  blocked_files: number;
  high_risk_files: number;
  clean_files: number;
  suspicious_status_files: number;
  malicious_status_files: number;
  pending_status_files: number;
  unavailable_status_files: number;
}

export interface SkillsScanReport {
  scan_type: "skills";
  report_type: "skills_scan";
  status: "completed" | "no_data";
  run_id: string | null;
  created_at: string | null;
  summary: SkillsScanSummary;
  files: SkillsScanFileReport[];
  note?: string;
}

export interface SkillsScanRequest {
  directories?: string[];
  files?: string[];
}

/** One activity source and whether it is actually contributing events.
 *
 * `not_configured` is deliberately distinct from `empty`: "nothing happened"
 * and "nothing is wired up" need different next steps from the operator, and
 * collapsing them into one empty state is what makes a dashboard read as broken.
 */
export interface ActivitySource {
  source: string;
  status: "active" | "empty" | "not_configured" | "unavailable";
  event_count: number;
  detail: string;
  /** Present only for Snowflake, carrying its full query-history payload. */
  timeline?: SnowflakeActivityTimeline | undefined;
}

/** A source-agnostic activity event — the shape every source normalises into. */
export interface ActivityEvent {
  observed_at: string;
  source: string;
  event_type: string;
  agent_name: string;
  tool_name: string;
  severity: string;
  verdict: string;
  session_id?: string | undefined;
  trace_id?: string | undefined;
}

/** The Activity surface: agent/MCP runtime activity from every wired source.
 *
 * Snowflake used to BE this endpoint, so an install without a data warehouse
 * saw a "configure Snowflake" wall instead of the runtime activity it already
 * had. Snowflake is now one source among several.
 */
export interface ActivityTimeline {
  schema_version: string;
  tenant_id: string;
  window_days: number;
  event_count: number;
  events: ActivityEvent[];
  truncated: boolean;
  sources: ActivitySource[];
  status: "active" | "empty" | "no_sources_configured";
}

export interface SnowflakeActivityTimeline {
  account: string;
  discovered_at: string;
  summary: {
    total_queries: number;
    agent_queries: number;
    observability_events: number;
    unique_agents: number;
    tool_calls: number;
  };
  query_history: Array<{
    query_id: string;
    query_text: string;
    user_name: string;
    role_name: string;
    start_time: string;
    execution_status: string;
    query_type: string;
    is_agent_query: boolean;
    agent_pattern: string;
    execution_time_ms: number;
  }>;
  observability_events: Array<{
    event_id: string;
    event_type: string;
    agent_name: string;
    timestamp: string;
    duration_ms: number;
    status: string;
    model_name: string;
    tool_name: string;
    trace_id: string;
    input_tokens: number;
    output_tokens: number;
  }>;
  warnings: string[];
}

export interface TraceFlaggedCall {
  tool_name: string;
  server: string;
  package_name?: string | undefined;
  cve_ids: string[];
  severity: string;
  reason: string;
  span_id: string;
}

export interface TraceIngestResponse {
  traces: number;
  flagged: TraceFlaggedCall[];
  message?: string | undefined;
}

export interface TraceExplorerSpan {
  cloud_trace?: { basis: "source_reported"; execution_proven: false; scope_state: "consistent" | "conflict" | "invalid"; attributes: Record<string, string> } | null;
  surface?: string;
  parent_span_id?: string;
  parent_state?: "root" | "resolved" | "missing" | "cycle";
  depth?: number;
  logical_root?: boolean | null;
  native_type?: string;
  native_name?: string;
  event_time_missing?: boolean;
  collected_at?: string | null;
  end_time_unix_nano?: string | null;
  correlation_state?: string;
  inventory_binding?: { state: string; basis?: string; node_id?: string; scan_id?: string; snapshot_generation?: string; execution_proven: false; inventory_paths?: Array<{ node_ids: string[]; edge_ids: string[]; node_labels: string[]; finding_node_id: string; basis: "recorded_inventory_relationships"; execution_proven: false }>; paths_truncated?: boolean } | null;
  source_scope?: Record<string, string>;

  span_id: string;
  timestamp?: string | undefined;
  agent: string;
  tool: string;
  action_type: string;
  verdict: string;
  detail?: string | undefined;
  linked_findings: Array<{
    finding_id?: string | undefined;
    vulnerability_id?: string | undefined;
    severity?: string | undefined;
    effective_reach_band?: string | undefined;
    framework_tags?: string[] | undefined;
    policy_state?: string | undefined;
  }>;
  compliance_controls: string[];
}

export interface TraceExplorerSession {
  session_id: string;
  agent?: string | undefined;
  trace_id?: string | undefined;
  blocked_count: number;
  observed_count: number;
  spans: TraceExplorerSpan[];
}

export interface TraceExplorerResponse {
  retained_total?: number;
  source_counts?: Record<string, number>;
  offset?: number;
  limit?: number;
  has_more?: boolean;
  feed_included?: boolean;
  counts_scope?: string;
  schema_version: string;
  tenant_id: string;
  session_count: number;
  span_count: number;
  blocked_count: number;
  sessions: TraceExplorerSession[];
}

export interface HitlApprovalQueueItem {
  item_id: string;
  tenant_id: string;
  span_id: string;
  session_id: string;
  agent: string;
  tool: string;
  timestamp?: string | undefined;
  detail?: string | undefined;
  source?: string | undefined;
  status: "pending" | "approved" | "denied" | string;
  linked_findings: TraceExplorerSpan["linked_findings"];
  linked_finding_ids: string[];
  compliance_controls: string[];
  decided_by?: string | undefined;
  decided_at?: string | undefined;
  note?: string | undefined;
}

export interface HitlApprovalQueueResponse {
  schema_version: string;
  tenant_id: string;
  count: number;
  pending_count: number;
  items: HitlApprovalQueueItem[];
}

export interface ProxyStatusResponse extends ProducerAssuranceSummary {
  health?: GatewayFeedHealth;
  status: string;
  message?: string | undefined;
  total_tool_calls?: number | undefined;
  total_blocked?: number | undefined;
  uptime_seconds?: number | undefined;
  calls_by_tool?: Record<string, number> | undefined;
  blocked_by_reason?: Record<string, number> | undefined;
  latency?: { p50_ms?: number; p95_ms?: number; p99_ms?: number };
  detectors_active?: string[] | undefined;
  proxy_pid?: number | undefined;
}

export interface ProxyAlert {
  producer_assurance?: ProducerAssurance;
  /** ISO-8601 timestamp string (e.g. "2026-07-06T15:10:00+00:00"). */
  ts: string;
  severity: string;
  detector: string;
  tool_name: string;
  message: string;
  details?: Record<string, unknown> | undefined;
  event_id?: string | undefined;
  agent_name?: string | undefined;
  event_type?: string | undefined;
  decision?: string | undefined;
  effective_decision?: string | undefined;
  reason_code?: string | undefined;
  source_id?: string | undefined;
  session_id?: string | undefined;
  request_id?: string | undefined;
  trace_id?: string | undefined;
}

export type ProxyAlertsResponse = ContractEnvelope<ApiSchemas["ProxyAlertsResponse"], { alerts: ProxyAlert[] }>;

export interface AuditEntry {
  entry_id: string;
  timestamp: string;
  action: string;
  actor: string;
  resource: string;
  details: Record<string, unknown>;
  hmac_signature: string;
}

export interface AuditLogResponse {
  entries: AuditEntry[];
  total: number;
}

export interface AuditIntegrityResponse {
  verified: number;
  tampered: number;
  checked: number;
}
