import type { IssueSeverityCounts,PostureCountsResponse } from "./findings";
import type { ApiSchemas,ContractEnvelope } from "./shared";

// ─── Gateway Live Feed (unified fleet event stream) ─────────────────────

export type GatewayFeedActionType =
  | "tool_call_authorized"
  | "tool_call_blocked"
  | "data_filter_applied"
  | "llm_call";

/** Producer identity is independent from receipt freshness and retention. */
export type ProducerAssurance = "unknown" | "caller_asserted";

export interface ProducerAssuranceSummary {
  producer_assurance_count_basis?: "classified_events" | "submissions";
  producer_assurance?: ProducerAssurance;
  producer_assurance_counts?: { unknown: number; caller_asserted: number };
}

export interface GatewayFeedEvent {
  producer_assurance?: ProducerAssurance;
  event_id?: string;
  decision_id?: string;
  ts: string;
  agent: string;
  identity_id?: string;
  profile_id?: string;
  profile_revision?: number;
  blueprint_id?: string;
  blueprint_revision?: number;
  policy_ids?: string[];
  reason_code?: string;
  development_mode?: boolean;
  action_type: GatewayFeedActionType;
  target: string;
  upstream?: string;
  decision?: string;
  data_action?: string;
  policy_source?: string;
  trace_id?: string;
  detail: string;
  tenant: string;
  shadow: boolean;
  source: string;
  ingest_ordinal?: number | null;
  input_tokens?: number | null;
  output_tokens?: number | null;
  cost_usd?: number | null;
}

export interface GatewayFeedCompleteness {
  status: "complete" | "partial";
  reasons: string[];
  server_ordered: boolean;
  retention_floor_ordinal: number;
  latest_ordinal: number;
  max_events_per_tenant: number;
  dedupe_window_events: number;
}

export type GatewayFeedHealthState = "live" | "stale" | "unavailable" | "sample";

export interface GatewayFeedHealth {
  assurance_basis?: "transport_receipt";
  producer_assurance?: ProducerAssurance;
  state: GatewayFeedHealthState;
  live: boolean;
  heartbeat_at: string | null;
  age_seconds: number | null;
  stale_after_seconds: number;
  reason: string;
}

export interface GatewayFeedResponse extends ProducerAssuranceSummary {
  schema_version: string;
  tenant_id: string;
  generated_at: string;
  count: number;
  events: GatewayFeedEvent[];
  next_cursor: string | null;
  has_more: boolean;
  source: "gateway_activity_ledger" | "degraded_single_process";
  completeness: GatewayFeedCompleteness;
  health: GatewayFeedHealth;
}

export interface GatewayFeedKpis extends ProducerAssuranceSummary {
  source?: "gateway_activity_ledger" | "degraded_single_process";
  completeness?: {
    status: "complete" | "partial";
    reasons: string[];
    retention_floor_ordinal?: number;
    latest_ordinal?: number;
  };
  window?: { start: string; end: string; timezone: "UTC"; exact: boolean };
  schema_version: string;
  tenant_id: string;
  generated_at: string;
  calls_today: number;
  blocked_today: number;
  shadow_ai_blocked: number;
  data_filters_applied: number;
  tool_calls_authorized: number;
  llm_calls: number;
  uptime_seconds?: number;
  health: GatewayFeedHealth;
}

// ─── Inter-agent firewall (#982) ────────────────────────────────────────

export interface FirewallPairTally {
  source_agent: string;
  target_agent: string;
  allow: number;
  warn: number;
  deny: number;
}

export interface FirewallDecisionRecord {
  timestamp: number;
  source_agent: string;
  target_agent: string;
  decision: "allow" | "deny" | "warn";
  effective_decision: "allow" | "deny" | "warn";
  matched_rule: {
    source: string;
    target: string;
    decision: "allow" | "deny" | "warn";
    description: string;
  } | null;
  enforcement_mode: "enforce" | "dry_run" | null;
}

export interface FirewallRuntimeStats {
  total_decisions: number;
  allow: number;
  warn: number;
  deny: number;
  last_seen_ts: number | null;
  top_pairs: FirewallPairTally[];
  recent: FirewallDecisionRecord[];
}

export interface GatewayPolicyRuntimeSummary {
  source: string;
  source_kind: string;
  enabled_policies: number;
  rollout_mode:
    "disabled" | "advisory_only" | "mixed" | "default_deny" | "blocking";
  summary: string;
  total_rules: number;
  blocking_rules: number;
  advisory_rules: number;
  allowlist_rules: number;
  default_deny_rules: number;
  read_only_rules: number;
  secret_path_rules: number;
  unknown_egress_rules: number;
  denied_tool_classes: string[];
  blocks_requests: boolean;
  advisory_only: boolean;
  default_deny: boolean;
  protects_secret_paths: boolean;
  restricts_unknown_egress: boolean;
}

export interface EvaluateResult {
  allowed: boolean;
  reason: string;
  policy_id: string | null;
  policies_evaluated: number;
}

export type PostureResponse = ApiSchemas["PostureResponse"];

export interface TrendPointResponse {
  scope_id?: string | null;
  collection_coverage?: "complete" | "partial" | "unknown";
  measurement_version?: number | null;
  comparison?: { status: "comparable" | "unavailable"; reason: string | null; previous_scan_id: string | null; new_findings: number | null; still_open: number | null; no_longer_detected: number | null };
  open_finding_age_days?: number | null;
  evidence_age_days?: number | null;
  age_sample_count?: number;
  evidence_sample_count?: number;
  /** Open issue groups the posture headline counted when this point was recorded; null on older points. */
  issues?: { critical: number; high: number; medium: number; low: number; total: number; basis: string } | null;
  scan_id?: string | null;
  timestamp: string;
  total_vulns: number;
  /** Active KEV issue occurrences; null when the snapshot did not measure KEV. */
  kev_count?: number | null;
  critical: number;
  high: number;
  medium: number;
  low: number;
  posture_score: number;
  posture_grade: string;
}

export type TrendsResponse = ContractEnvelope<ApiSchemas["TrendsResponse"], { data_points: TrendPointResponse[] }>;

// ─── Cross-domain overview (landing page) ────────────────────────────────────

export type OverviewDomainStatus = "ok" | "warn" | "critical" | "idle" | "unavailable" | "unknown";

export interface OverviewDomain {
  label: string;
  href: string;
  graph_href?: string | undefined;
  metric: number | null;
  metric_label: string;
  /** False when the metric is a lower bound over retained findings. */
  count_exact?: boolean;
  evidence_status?: "complete" | "partial" | "unavailable";
  status: OverviewDomainStatus;
  detail: Record<string, unknown>;
}

/** Per-domain severity histogram — includes the honest ``unrated`` bucket so
 * ``sum(values) === count`` for the lane (issue #3946). */
export interface CoverageSeverity {
  critical: number;
  high: number;
  medium: number;
  low: number;
  unrated: number;
}

/** One security-posture coverage lane (CSPM / Vuln mgmt / ASPM / DSPM / AISPM). */
export interface OverviewCoverageLane {
  domain: "cspm" | "vuln" | "aspm" | "dspm" | "aispm";
  label: string;
  href: string;
  count: number;
  severity: CoverageSeverity;
  /** Counts describe current open findings, not assessment coverage. */
  evidence_status?: "complete" | "partial" | "unavailable";
  /** False means count/severity are lower bounds from a bounded read. */
  count_exact?: boolean;
}

export interface OverviewTopRisk {
  impact_category?: string | null;
  fixed_version?: string | null;
  vulnerability_id: string;
  canonical_id?: string | null | undefined;
  asset_id?: string | null | undefined;
  affected_servers?: string[] | undefined;
  package: string | null;
  severity: string;
  risk_score: number;
  is_kev: boolean;
  cvss_score: number | null;
  epss_score: number | null;
  affected_agents: string[];
  owner?: string | null | undefined;
  sla_due_at?: string | null | undefined;
  sla_due_at_source?: string | null | undefined;
}

/** One weighted input into the configurable exec risk score (#3940). */
export interface ExecScoreDriver {
  driver: string;
  label: string;
  count: number;
  weight: number;
  contribution: number;
}

/** How the exec risk score is displayed. */
export type ExecScoreDisplayFormat = "grade" | "percent" | "points";

/** The configurable exec risk-score posture block on the overview payload. */
export interface OverviewPosture {
  grade: string;
  score: number | null;
  summary: string;
  points?: number;
  percent?: number;
  display?: string | null;
  display_format?: ExecScoreDisplayFormat;
  policy_source?: string;
  penalty_total?: number;
  floored?: boolean;
  finding_total?: number;
  weights?: Record<string, number>;
  grade_thresholds?: Record<string, number>;
  breakdown?: ExecScoreDriver[];
}

/** GET/PUT /v1/overview/score-config — tenant exec-score model + display config. */
export interface ScoreConfigRuntime {
  active_override: boolean;
  source: string;
  override_endpoint: string;
  display_format: ExecScoreDisplayFormat;
  display_formats: ExecScoreDisplayFormat[];
  weights: Record<string, number>;
  grade_thresholds: Record<string, number>;
  drivers: {
    driver: string;
    label: string;
    default_weight: number;
    weight: number;
    overridden: boolean;
  }[];
  defaults: {
    weights: Record<string, number>;
    grade_thresholds: Record<string, number>;
    display_format: ExecScoreDisplayFormat;
  };
  overrides: Record<string, unknown>;
  message: string;
}

/** Body for PUT /v1/overview/score-config (all fields optional, clamped server-side). */
export interface ScoreConfigUpdate {
  weights?: Record<string, number>;
  grade_thresholds?: Record<string, number>;
  display_format?: ExecScoreDisplayFormat;
}

export interface OverviewResponse {
  /** True while a demo-estate server is still seeding its first evidence. */
  demo_estate_seeding?: boolean;
  /** Counts from the same evidence snapshot as posture and top_risks. */
  finding_counts?: Pick<PostureCountsResponse, "critical" | "high" | "medium" | "low" | "unrated" | "total" | "kev">;
  /** Open issue-group counts shared with /v1/posture/counts; null when unavailable. */
  issue_counts?: (Omit<IssueSeverityCounts, "kev"> & { kev?: number | null | undefined }) | null;
  schema_version: string;
  tenant_id: string;
  posture: OverviewPosture;
  headline: {
    /** The one unit every headline count uses; occurrences stay in finding_counts. */
    basis?: "issue_groups" | "occurrences";
    critical: number;
    high: number;
    critical_high: number;
    kev: number;
    credential_exposed: number;
    scans: number;
    latest_scan_at: string | null;
    hub_findings?: number;
  };
  coverage?: OverviewCoverageLane[];
  domains: {
    cloud: OverviewDomain;
    vuln: OverviewDomain;
    code: OverviewDomain;
    runtime: OverviewDomain;
    cost: OverviewDomain;
    identity: OverviewDomain;
    ops: OverviewDomain;
  };
  top_risks: OverviewTopRisk[];
}

/** Stable counts shared by the enterprise-demo CLI, API, and dashboard. */
export interface EnterpriseDemoSummary {
  assets: number;
  observations: number;
  evidence_sources: number;
  complete_sources: number;
  partial_sources: number;
  /** Correlation rows, which are trace groups — most hold a single event. */
  correlations: number;
  /** Of `correlations`, the rows that join evidence from more than one source.
   * The cross-vendor claim reconciles against this, never against the row count. */
  cross_source_correlations: number;
  snapshots: number;
  /** Whole-estate finding count. The rendered list is bounded; this is not. */
  findings: number;
}

/** Whole-estate posture totals. `by_severity` always carries every display
 * bucket including `unrated`, and always sums to `total` — an unevaluable
 * control is counted, never dropped. */
export interface EstateFindingSummary {
  schema_version: string;
  total: number;
  by_severity: Record<string, number>;
  assets_affected: number;
  assets_total: number;
  controls_evidenced: number;
  frameworks_evidenced: string[];
  attack_paths_evidenced: number;
  identities_implicated: number;
}

/** One finding rendered as the chain it belongs to: asset → identity →
 * configuration → attack path → compliance control. */
export interface EstateFindingView {
  finding_id: string;
  finding_type: string;
  severity: string;
  severity_bucket: string;
  title: string;
  security_domain: string;
  provider: string;
  account_ref: string;
  region: string;
  environment: string;
  asset_id: string;
  asset_canonical_id: string;
  asset_display_name: string;
  identity_asset_id: string;
  identity_display_name: string;
  identity_actor_id: string;
  configuration_setting: string;
  configuration_observed: string;
  configuration_expected: string;
  controls: string[];
  correlation_id: string;
  attack_path: string[];
}

export interface EnterpriseDemoEvent {
  normalization_version: string;
  event_id: string;
  tenant_id: string;
  stage: string;
  source: string;
  event_type: string;
  observed_at: string;
  trace_id: string;
  actor_id: string;
  resource_ids: string[];
  evidence_hash: string;
  source_run_id: string;
  event_relationships: Record<string, unknown>;
  graph_projection: Record<string, unknown>;
}

export interface EnterpriseDemoCorrelation {
  correlation_version: string;
  correlation_id: string;
  tenant_id: string;
  trace_id: string;
  kind: string;
  outcome: string;
  started_at: string;
  ended_at: string;
  event_ids: string[];
  sources: string[];
  asset_ids: string[];
  asset_path: string[];
  data_classifications: string[];
  evidence_hashes: string[];
  evidence_quality: string;
  incomplete_sources: string[];
}

export interface EnterpriseDemoCollectionHealth {
  source: string;
  status: "complete" | "partial" | "unavailable";
  records_read: number;
  watermark: string;
  source_schema: string;
  schema_url: string;
  failure_code: string;
}

/** What one truncated story list holds, and what it was truncated out of. */
export interface EnterpriseDemoListBound {
  returned: number;
  total: number;
  limit: number;
  truncated: boolean;
}

/** The bound on every list the story returns. `events` and `correlations` are
 * single-digit percentages of the estate, so the payload names each limit
 * rather than leaving a consumer to read a page size as a total. */
export interface EnterpriseDemoBounds {
  events: EnterpriseDemoListBound;
  correlations: EnterpriseDemoListBound;
  findings: EnterpriseDemoListBound;
}

/** Definition and completeness carried beside an otherwise ambiguous count. */
export interface EnterpriseDemoCountMetadata {
  definition: string;
  source: string;
  scope: string;
  window: string;
  filters: string[];
  returned: number;
  total: number;
  completeness: "complete" | "partial" | "unknown";
}

/** GET /v1/demo-estate/story — normalized, fictional enterprise evidence. */
export interface EnterpriseDemoStory {
  schema_version: string;
  synthetic: true;
  fictional: true;
  disclosure: string;
  estate_id: string;
  estate_name: string;
  tenant_id: string;
  scenario: string;
  estate_content_hash: string;
  story_content_hash: string;
  /** Persisted graph snapshot that carries this exact synthetic estate. */
  graph_snapshot_id: string;
  summary: EnterpriseDemoSummary;
  /** Limit + true total for each bounded list below. */
  bounds: EnterpriseDemoBounds;
  count_metadata: Record<string, EnterpriseDemoCountMetadata>;
  primary_correlation: EnterpriseDemoCorrelation;
  events: EnterpriseDemoEvent[];
  correlations: EnterpriseDemoCorrelation[];
  collection_health: EnterpriseDemoCollectionHealth[];
  /** Unbounded posture totals for the whole estate. */
  finding_summary: EstateFindingSummary;
  /** Bounded page of findings, incident first. `finding_summary.total` is the
   * real total — never `findings.length`. */
  findings: EstateFindingView[];
}

/** GET /v1/demo-estate/status — persisted graph ownership for demo routing. */
export interface DemoEstateStatus {
  schema_version: "demo_estate_status.v1";
  showcase_snapshot_id: string;
  showcase_available: boolean;
  graph_owner_scan_id: string | null;
  graph_alignment: "aligned" | "blocked" | "unavailable";
  reason: string | null;
  /** Whether the tenant's story is already built and will be served immediately. */
  story_ready?: boolean | undefined;
}

/** One security-domain lane on the per-account drill summary (#3931). Its
 * severity strip sums to ``count`` (same honest invariant as the overview). */
export interface AccountSummaryDomain {
  domain: "cspm" | "vuln" | "aspm" | "dspm" | "aispm";
  label: string;
  count: number;
  severity: CoverageSeverity;
  /** Pre-filtered /findings deep-link (provider + account + domain). */
  href: string;
}

/** One stored CIS benchmark run folded into the account's compliance health. */
export interface AccountSummaryBenchmark {
  provider: string;
  benchmark: string;
  passed: number;
  failed: number;
  evaluated: number;
  pass_rate: number | null;
}

/** GET /v1/cloud/accounts/{account_ref}/summary — per-account end-to-end drill. */
export interface AccountSummaryResponse {
  schema_version: string;
  tenant_id: string;
  account_ref: string;
  provider: string;
  account: string;
  regions: string[];
  environments: string[];
  findings_total: number;
  severity: CoverageSeverity;
  domains: AccountSummaryDomain[];
  compliance: {
    evaluated: number;
    passed: number;
    failed: number;
    pass_rate: number | null;
    benchmarks: AccountSummaryBenchmark[];
    href: string;
  };
  assets: { count: number; href: string; note: string };
  identities: { count: number; roles: number; note: string };
  drill: { findings_href: string; graph_href: string };
  truncated: boolean;
  empty: boolean;
  note: string;
}

export interface EnrichmentSourcePosture {
  source: string;
  status: "ok" | "stale" | "degraded" | "unknown" | string;
  last_success_at: string | null;
  last_failure_at: string | null;
  last_cache_at: string | null;
  age_seconds: number | null;
  slo_seconds: number;
  success_count: number;
  failure_count: number;
  cache_hit_count: number;
  message: string;
}

export interface EnrichmentPostureResponse {
  status: "ok" | "stale" | "degraded" | "unknown" | string;
  sources: EnrichmentSourcePosture[];
  operator_message: string;
}

export interface GovernanceFinding {
  category: string;
  severity: string;
  title: string;
  description: string;
  agent_or_role: string;
  object_name: string;
  details: Record<string, unknown>;
}

export interface GovernanceReport {
  account: string;
  discovered_at: string;
  summary: {
    access_records: number;
    privilege_grants: number;
    data_classifications: number;
    agent_usage_records: number;
    findings: number;
    critical_findings: number;
    high_findings: number;
  };
  findings: GovernanceFinding[];
  access_records: Array<{
    query_id: string;
    user_name: string;
    role_name: string;
    query_start: string;
    object_name: string;
    object_type: string;
    columns: string[];
    operation: string;
    is_write: boolean;
    /** ACCESS_HISTORY array; legacy records may omit this field. */
    source_field?: string;
    base_objects?: string[];
  }>;
  privilege_grants: Array<{
    grantee: string;
    grantee_type: string;
    privilege: string;
    granted_on: string;
    object_name: string;
    is_elevated: boolean;
  }>;
  data_classifications: Array<{
    object_name: string;
    object_type: string;
    column_name: string | null;
    tag_name: string;
    tag_value: string;
  }>;
  agent_usage: Array<{
    agent_name: string;
    user_name: string;
    role_name: string;
    start_time: string;
    total_tokens: number;
    credits_used: number;
    model_name: string;
    tool_calls: number;
    status: string;
  }>;
  warnings: string[];
}
