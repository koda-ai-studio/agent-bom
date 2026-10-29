import type { SourceKind,Summary } from "./auth";
import type { Agent,AttackFlowEdge,AttackFlowNode,BlastRadius } from "./findings";
import type { FirewallRuntimeStats,GatewayPolicyRuntimeSummary } from "./overview";
import type { JobStatus,ScanJob,ScanRequest } from "./scan-inventory";
import type { ApiSchemas,ContractEnvelope } from "./shared";

export type SourceStatus = "configured" | "healthy" | "degraded" | "disabled";

export type SourceCredentialMode = "none" | "reference";

export interface SourceRecord {
  source_id: string;
  tenant_id: string;
  display_name: string;
  kind: SourceKind;
  description: string;
  owner: string;
  connector_name: string | null;
  credential_mode: SourceCredentialMode;
  credential_ref: string | null;
  enabled: boolean;
  status: SourceStatus;
  config: Record<string, unknown>;
  last_tested_at: string | null;
  last_test_status: string | null;
  last_test_message: string | null;
  last_run_at: string | null;
  last_run_status: string | null;
  last_job_id: string | null;
  created_at: string;
  updated_at: string;
}

export type SourcesResponse = ContractEnvelope<ApiSchemas["SourcesResponse"], { sources: SourceRecord[] }>;

export interface DiscoveryProviderCapabilities {
  scan_modes: string[];
  required_scopes: string[];
  permissions_used: string[];
  outbound_destinations: string[];
  network_destinations?: string[] | undefined;
  data_boundary: string;
  writes: boolean;
  network_access: boolean;
  guarantees: string[];
}

export interface DiscoveryProviderTrustContract {
  read_only: boolean;
  agentless: boolean;
  entrypoints_opt_in: boolean;
  redaction_status: string;
  scope_control: string;
  data_residency: string;
  supports_scope_zero: boolean;
}

export interface DiscoverySdkReadiness {
  distribution: string;
  installed_version: string | null;
  recommended_floor: string;
  status: "ok" | "outdated" | "not_installed" | "unknown";
}

export interface DiscoveryProviderContract {
  sdk_readiness?: DiscoverySdkReadiness[];
  name: string;
  module: string;
  source: string;
  discover_attr: string;
  capabilities: DiscoveryProviderCapabilities;
  trust_contract: DiscoveryProviderTrustContract;
}

export type DiscoveryProvidersResponse = ContractEnvelope<ApiSchemas["DiscoveryProvidersResponse"], { providers: DiscoveryProviderContract[] }>;

export interface SourceCreateRequest {
  display_name: string;
  kind: SourceKind;
  description?: string | undefined;
  owner?: string | undefined;
  connector_name?: string | null | undefined;
  credential_mode?: SourceCredentialMode | undefined;
  credential_ref?: string | null | undefined;
  enabled?: boolean | undefined;
  config?: Record<string, unknown> | undefined;
  tenant_id?: string | undefined;
}

export interface SourceUpdateRequest {
  display_name?: string | undefined;
  description?: string | undefined;
  owner?: string | undefined;
  connector_name?: string | null | undefined;
  credential_mode?: SourceCredentialMode | null | undefined;
  credential_ref?: string | null | undefined;
  enabled?: boolean | undefined;
  status?: SourceStatus | undefined;
  config?: Record<string, unknown> | undefined;
}

export interface SourceCheckResponse {
  source_id: string;
  status: SourceStatus;
  message: string;
  tested_at: string;
}

export interface SourceRunResponse {
  source_id: string;
  job_id: string;
  status: JobStatus;
}

export interface SourceJobsResponse {
  source_id: string;
  jobs: ScanJob[];
  count: number;
}

export type JobsResponse = ContractEnvelope<ApiSchemas["JobsResponse"], { jobs: JobListItem[]; status_counts: Partial<Record<JobStatus, number>> }>;

export interface JobListItem {
  job_id: string;
  status: JobStatus;
  created_at: string;
  tenant_id?: string | undefined;
  source_id?: string | undefined;
  completed_at?: string | undefined;
  request?: ScanRequest | undefined;
  summary?: Summary | undefined;
  scan_timestamp?: string | undefined;
  generated_at?: string | undefined;
  scan_run?: Record<string, unknown> | undefined;
  scan_outcome?: "complete" | "partial" | "failed" | undefined;
  warning_count?: number | undefined;
  warnings_preview?: string[] | undefined;
  pushed?: boolean | undefined;
  error?: string | undefined;
}

export type ScanJobStatus = JobListItem & { graph_scan_id?: string | null | undefined };

export type AgentsResponse = ContractEnvelope<ApiSchemas["AgentsResponse"], { agents: Agent[] }>;

export interface RegistryServer {
  id: string;
  name: string;
  publisher: string;
  verified: boolean;
  transport: string;
  risk_level: "low" | "medium" | "high";
  packages: Array<{ name: string; ecosystem: string }>;
  source_url: string;
  description?: string | undefined;
  sigstore_bundle: string | null;
  tools?: string[] | undefined;
  credential_env_vars?: string[] | undefined;
  category?: string | undefined;
  license?: string | undefined;
  latest_version?: string | undefined;
  known_cves?: string[] | undefined;
  command_patterns?: string[] | undefined;
  risk_justification?: string | undefined;
}

export interface RegistryMeta {
  updated?: string | null;
  total_servers?: number | null;
  sources?: string[];
  source_url?: string | null;
  schema_version?: string | null;
}

export type RegistryResponse = ContractEnvelope<ApiSchemas["RegistryResponse"], { servers: RegistryServer[] }>;

export interface ControlNarrative {
  control_id: string;
  title: string;
  status: "pass" | "warning" | "fail";
  narrative: string;
  affected_packages: string[];
  affected_agents: string[];
  affected_findings: string[];
  remediation_steps: string[];
}

export interface FrameworkNarrative {
  framework: string;
  slug: string;
  status: "passing" | "at_risk" | "failing";
  score: number;
  narrative: string;
  recommendations: string[];
  failing_controls: ControlNarrative[];
}

export interface RemediationImpact {
  package: string;
  current_version: string;
  fix_version: string;
  controls_fixed: string[];
  frameworks_impacted: string[];
  narrative: string;
}

export type ComplianceNarrativeResponse = ApiSchemas["ComplianceNarrativeResponse"];

export interface ComplianceControl {
  code: string;
  name: string;
  /** Mapped finding occurrences (one advisory on N assets counts N). */
  findings: number;
  /** Distinct issue groups those occurrences collapse to — what the findings view lists. */
  issue_count?: number | undefined;
  // Additional unscored states are normalized by compliance-status helpers at
  // render boundaries; the legacy matrix row contract remains scored-only.
  status: "pass" | "warning" | "fail";
  // Provenance for the status: WHY a control landed where it did (e.g.
  // "no_completed_scan", "no_mapped_finding", "no_observed_signal"). Drives the
  // "Not evaluated — <reason>" label and the next-step CTA in the UI.
  evidence_reason?: string | undefined;
  // Evaluation mode that produced the status: "detective" | "corrective" | "overlay".
  evaluation_mode?: string | undefined;
  severity_breakdown: Record<string, number>;
  affected_packages: string[];
  affected_agents: string[];
}

export interface AISVSCheck {
  check_id: string;
  title?: string | undefined;
  status: "pass" | "fail" | "error" | "not_applicable";
  severity: string;
  evidence?: string | undefined;
  recommendation?: string | undefined;
  cis_section?: string | undefined;
  maestro_layer?: string | undefined;
}

export interface AISVSBenchmark {
  benchmark: string;
  benchmark_version: string;
  passed: number;
  failed: number;
  total: number;
  pass_rate: number;
  checks: AISVSCheck[];
  metadata: Record<string, unknown>;
}

export interface AISVSComplianceResponse {
  framework: "aisvs";
  framework_key: "aisvs_benchmark";
  framework_label: string;
  source: "scan_jobs";
  scan_id: string | null;
  measured_at: string | null;
  representation: "benchmark";
  score: number;
  summary: {
    pass: number;
    fail: number;
    error: number;
    not_applicable: number;
    total: number;
    score: number;
  };
  benchmark: AISVSBenchmark;
}

/** Structured remediation attached to a single cloud CIS benchmark check. */
export interface CISBenchmarkRemediation {
  priority?: number | undefined;
  effort?: string | undefined;
  guardrails?: string[] | undefined;
  fix_cli?: string | null | undefined;
  fix_console?: string | undefined;
  requires_human_review?: boolean | undefined;
  docs?: string | undefined;
}

/**
 * One normalized cloud CIS benchmark check row, as emitted by the backend
 * `analytics_contract.build_cis_benchmark_check_rows` and served by
 * `GET /v1/cis/checks`. Top-level `fix_cli` / `fix_console` / `priority` /
 * `guardrails` / `requires_human_review` are flattened copies of the matching
 * `remediation` fields for cheap indexing/filtering.
 */
export interface CISBenchmarkCheck {
  scan_id: string;
  measured_at: string;
  cloud: string;
  check_id: string;
  title: string;
  status: string;
  severity: string;
  cis_section: string;
  evidence: string;
  resource_ids: string[];
  remediation: CISBenchmarkRemediation;
  fix_cli: string;
  fix_console: string;
  effort: string;
  priority: number;
  guardrails: string[];
  requires_human_review: boolean;
  /** "graph" when the failing result and its resources come from the current graph. */
  evidence_source?: "graph" | "scan";
  /** The graph node of this check's result, when the current graph holds one. */
  graph_node_id?: string;
  graph_scan_id?: string;
  /** Failing resource graph node id -> the finding ids recorded on it. */
  resource_finding_ids?: Record<string, string[]>;
  unevaluated_resource_ids?: string[];
}

export interface CISBenchmarkChecksResponse {
  checks: CISBenchmarkCheck[];
  count: number;
  source: string;
}

/** One scored control on the catalog-backed NIST SP 800-53 line. */
export interface NistCatalogControl {
  control_id: string;
  title: string | null;
  status: "pass" | "fail" | "warning" | "error" | "not_evaluated";
  findings: number;
  evidencing_checks: string[];
  iso_27001_derived: string[];
}

/** Family rollup partitioning the full vendored catalog for scale-aware nav. */
export interface NistCatalogFamily {
  family: string;
  total: number;
  evaluated: number;
  pass: number;
  fail: number;
  warning: number;
  error: number;
  not_evaluated: number;
}

export interface NistCatalogSummary {
  pass: number;
  fail: number;
  warning: number;
  error: number;
  evaluated: number;
  not_evaluated: number;
  catalog_size: number;
  coverage_pct: number;
  score: number;
}

export interface NistCatalogIsoDerived {
  source: string;
  note: string;
  controls: string[];
}

/**
 * Catalog-backed NIST SP 800-53 Rev 5 line — the same shape the `/v1/compliance`
 * `nist_800_53_catalog` field carries and the `/v1/compliance/nist-800-53` drill
 * returns (one source of truth). Scored over EVALUATED controls only; ERROR and
 * not_evaluated are explicit buckets; ISO attribution is by identifier only.
 */
export interface NistCatalogLine {
  framework: "nist-800-53";
  framework_key: "nist_800_53_catalog";
  framework_label: string;
  representation: "catalog";
  source: string;
  vendor_asserted: boolean;
  status: "pass" | "fail" | "warning" | "no_data";
  score: number;
  summary: NistCatalogSummary;
  controls: NistCatalogControl[];
  iso_27001_derived: NistCatalogIsoDerived;
}

/** The `/v1/compliance/nist-800-53` drill: catalog line + family rollup. */
export interface NistCatalogDrill extends NistCatalogLine {
  families: NistCatalogFamily[];
}

export interface ComplianceResponse {
  /**
   * Percentage of EVALUATED controls that pass — not of the whole catalog.
   * Never render this without `evaluated_controls` / `total_controls`: a scan
   * that evaluated 8 of 931 controls and passed all 8 is "100%" of a very small
   * denominator, and a bare percentage reads as "the estate is 100% compliant".
   */
  overall_score: number;
  overall_status: "pass" | "warning" | "fail" | "no_data";
  /** Controls that produced a pass/warning/fail — the `overall_score` denominator. */
  evaluated_controls: number;
  /** Every control in every scored framework, evaluated or not. */
  total_controls: number;
  /** `evaluated_controls` / `total_controls`, as a percentage. */
  coverage_pct: number;
  scan_count: number;
  latest_scan: string | null;
  has_mcp_context?: boolean | undefined;
  has_agent_context?: boolean | undefined;
  scan_sources?: string[] | undefined;
  /** Server-owned measurement semantics; UI consumers must not infer from labels. */
  framework_kinds: Record<string, "scored" | "applicability">;
  owasp_llm_top10: ComplianceControl[];
  owasp_mcp_top10: ComplianceControl[];
  mitre_atlas: ComplianceControl[];
  nist_ai_rmf: ComplianceControl[];
  owasp_agentic_top10: ComplianceControl[];
  eu_ai_act: ComplianceControl[];
  nist_csf: ComplianceControl[];
  iso_27001: ComplianceControl[];
  soc2: ComplianceControl[];
  cis_controls: ComplianceControl[];
  cmmc: ComplianceControl[];
  nist_800_53: ComplianceControl[];
  fedramp: ComplianceControl[];
  pci_dss: ComplianceControl[];
  /**
   * Catalog-backed NIST SP 800-53 Rev 5 line, scored INDEPENDENTLY over the full
   * vendored catalog. Optional so a response predating the catalog scorer still
   * types; the UI falls back to the drill endpoint as the source of truth.
   */
  nist_800_53_catalog?: NistCatalogLine | undefined;
  aisvs_benchmark: AISVSComplianceResponse;
  summary: {
    owasp_applicable?: number | undefined;
    owasp_not_applicable?: number | undefined;
    owasp_mcp_applicable?: number | undefined;
    owasp_mcp_not_applicable?: number | undefined;
    /**
     * ATLAS and ATT&CK are technique catalogs, so they report which techniques
     * the evidence puts in play — never pass/fail. #4709 removed the scored
     * form from the API; the page kept reading `atlas_pass` and rendered
     * `NaN` across every tile until the fields here matched the response.
     */
    atlas_applicable?: number | undefined;
    atlas_not_applicable?: number | undefined;
    attack_applicable?: number | undefined;
    attack_not_applicable?: number | undefined;
    nist_pass: number;
    nist_warn: number;
    nist_fail: number;
    owasp_agentic_applicable?: number | undefined;
    owasp_agentic_not_applicable?: number | undefined;
    eu_ai_act_pass: number;
    eu_ai_act_warn: number;
    eu_ai_act_fail: number;
    nist_csf_pass: number;
    nist_csf_warn: number;
    nist_csf_fail: number;
    iso_27001_pass: number;
    iso_27001_warn: number;
    iso_27001_fail: number;
    soc2_pass: number;
    soc2_warn: number;
    soc2_fail: number;
    cis_pass: number;
    cis_warn: number;
    cis_fail: number;
    cmmc_pass: number;
    cmmc_warn: number;
    cmmc_fail: number;
    nist_800_53_pass: number;
    nist_800_53_warn: number;
    nist_800_53_fail: number;
    nist_800_53_catalog_pass?: number | undefined;
    nist_800_53_catalog_fail?: number | undefined;
    nist_800_53_catalog_warning?: number | undefined;
    nist_800_53_catalog_error?: number | undefined;
    nist_800_53_catalog_evaluated?: number | undefined;
    nist_800_53_catalog_not_evaluated?: number | undefined;
    fedramp_pass: number;
    fedramp_warn: number;
    fedramp_fail: number;
    pci_dss_pass: number;
    pci_dss_warn: number;
    pci_dss_fail: number;
    aisvs_pass: number;
    aisvs_fail: number;
    aisvs_error: number;
    aisvs_not_applicable: number;
    /** Benchmark evidence, counted by `evaluated_controls` like a framework row. */
    cis_foundations_pass?: number | undefined;
    cis_foundations_fail?: number | undefined;
    cis_foundations_error?: number | undefined;
    cis_foundations_not_applicable?: number | undefined;
    cis_foundations_evaluated?: number | undefined;
  };
}

export interface FrameworkCatalogMetadata {
  schema_version: number;
  catalog_id: string;
  catalog_type: string;
  source: string;
  attack_version: string;
  updated_at: string;
  fetched_at: number;
  normalized_sha256: string;
  sources: Record<string, unknown>;
  technique_count: number;
  cwe_mapping_count: number;
  path?: string | undefined;
}

export interface MitreAtlasCatalogMetadata {
  schema_version: number;
  catalog_id: string;
  catalog_type: string;
  source: string;
  atlas_version: string;
  updated_at: string;
  fetched_at: number;
  normalized_sha256: string;
  sources: Record<string, unknown>;
  technique_count: number;
  tactic_count: number;
  curated_count?: number;
  path?: string | undefined;
}

export type FrameworkCatalogsResponse = ContractEnvelope<ApiSchemas["FrameworkCatalogsResponse"], { frameworks: { mitre_attack: FrameworkCatalogMetadata; mitre_atlas?: MitreAtlasCatalogMetadata } }>;

export interface AgentDetailResponse {
  agent: Agent;
  summary: {
    total_servers: number;
    total_packages: number;
    total_tools: number;
    total_credentials: number;
    total_vulnerabilities: number;
    severity_breakdown: Record<string, number>;
  };
  blast_radius: BlastRadius[];
  credentials: string[];
  fleet?: FleetAgent | null | undefined;
}

export interface AgentLifecycleResponse {
  graph?: import("@/lib/graph-schema").UnifiedGraphData;
  nodes: AttackFlowNode[];
  edges: AttackFlowEdge[];
  stats: Record<string, number>;
}

export type FleetLifecycleState =
  | "discovered"
  | "pending_review"
  | "approved"
  | "quarantined"
  | "decommissioned";

export interface FleetAgent {
  agent_id: string;
  name: string;
  agent_type: string;
  config_path: string;
  lifecycle_state: FleetLifecycleState;
  owner: string | null;
  environment: string | null;
  tags: string[];
  trust_score: number;
  trust_factors: Record<string, number>;
  server_count: number;
  package_count: number;
  credential_count: number;
  vuln_count: number;
  last_discovery: string | null;
  last_scan: string | null;
  created_at: string;
  updated_at: string;
  notes: string;
}

export type FleetResponse = ContractEnvelope<ApiSchemas["FleetResponse"], { agents: FleetAgent[] }>;

export type FleetStatsResponse = ApiSchemas["FleetStatsResponse"];

export interface FleetEndpoint {
  endpoint_id: string;
  tenant_id: string;
  platform: Record<string, string>;
  counts: Record<string, number | null>;
  collector_status: Record<string, string>;
  collector_messages: Record<string, string>;
  privacy: Record<string, boolean>;
  completeness: "complete" | "partial";
  last_scan_id: string;
  observed_at: string;
  updated_at: string;
}

export interface FleetEndpointsResponse {
  endpoints: FleetEndpoint[];
  count: number;
  total: number;
  limit: number;
  offset: number;
  has_more: boolean;
}

export interface FleetSyncResult {
  synced: number;
  new: number;
  updated: number;
}

export interface FleetQuarantineResult {
  agent_id: string;
  lifecycle_state: string;
  gateway_policy: {
    policy_id: string;
    name: string;
    mode: string;
    enabled: boolean;
    bound_agents: string[];
    created: boolean;
  };
}

export interface ScanSchedule {
  schedule_id: string;
  name: string;
  cron_expression: string;
  scan_config: Record<string, unknown>;
  enabled: boolean;
  last_run: string | null;
  next_run: string | null;
  last_job_id: string | null;
  created_at: string;
  updated_at: string;
  tenant_id: string;
}

export interface ScheduleCreateRequest {
  name: string;
  cron_expression: string;
  scan_config?: Record<string, unknown> | undefined;
  enabled?: boolean | undefined;
  tenant_id?: string | undefined;
}

export type PolicyMode = "audit" | "enforce";

export interface GatewayRule {
  id: string;
  description: string;
  action: string;
  block_tools: string[];
  tool_name: string | null;
  tool_name_pattern: string | null;
  arg_pattern: Record<string, string>;
  rate_limit: number | null;
  require_registry_verified: boolean;
}

export interface GatewayPolicy {
  policy_id: string;
  name: string;
  description: string;
  mode: PolicyMode;
  rules: GatewayRule[];
  bound_agents: string[];
  bound_agent_types: string[];
  bound_environments: string[];
  created_at: string;
  updated_at: string;
  enabled: boolean;
}

export type GatewayPolicyResponse = ContractEnvelope<ApiSchemas["GatewayPoliciesResponse"], { policies: GatewayPolicy[] }>;

export interface PolicyAuditEntry {
  entry_id: string;
  policy_id: string;
  policy_name: string;
  rule_id: string;
  agent_name: string;
  tool_name: string;
  arguments_preview: Record<string, unknown>;
  action_taken: string;
  reason: string;
  timestamp: string;
}

export interface GatewayAuditResponse {
  entries: PolicyAuditEntry[];
  count: number;
}

export interface GatewayStatsResponse {
  total_policies: number;
  enforce_count: number;
  audit_count: number;
  enabled_count: number;
  total_rules: number;
  audit_entries: number;
  blocked_count: number;
  alerted_count: number;
  policy_runtime: GatewayPolicyRuntimeSummary;
  firewall_runtime: FirewallRuntimeStats;
}
