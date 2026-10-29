import type { Tool } from "./auth";

export type DeploymentMode = "local" | "fleet" | "cluster" | "hybrid" | "ci" | "ingest" | "unknown";

export type ServiceState = "locked" | "connected" | "live";

export type ServiceId =
  | "cloud_accounts"
  | "data_sources"
  | "local_agents"
  | "fleet"
  | "runtime_proxy"
  | "runtime_gateway"
  | "runtime_traces"
  | "ai_spend"
  | "compliance";

export interface ServiceEntry {
  state: ServiceState;
  count: number;
  requires?: string[] | undefined;
  detail?: string | undefined;
  /** cloud_accounts only: newest completed cloud scan (connection or push). */
  last_scan_at?: string | null | undefined;
  /** cloud_accounts only: brokered connections vs scopes seen in scan results. */
  connections?: number | undefined;
  scanned_scopes?: number | undefined;
}

export interface IssueSeverityCounts {
  critical: number;
  high: number;
  medium: number;
  low: number;
  unrated: number;
  total: number;
  /** Known-exploited issues, on the same issue-group unit as the severity counts. */
  kev?: number | undefined;
  approximate: boolean;
  basis: "issue_groups";
  window?: unknown;
}

export interface EstateAgentCounts {
  /** Distinct agents in the tenant's current graph snapshot; null when the graph backend cannot count them. */
  total: number | null;
  scan_id: string | null;
  basis: "graph_agents";
}

export interface PostureCountsResponse {
  /** Open issue groups, identical to the findings page default query. */
  issues?: IssueSeverityCounts | undefined;
  /** Agent population shared by every surface; equals the /v1/inventory/assets?type=agent total. */
  agents?: EstateAgentCounts | undefined;
  critical: number;
  high: number;
  medium: number;
  low: number;
  /** Findings whose source severity is unknown or unscored. */
  unrated?: number | undefined;
  total: number;
  kev: number;
  compound_issues: number;
  deployment_mode?: DeploymentMode | undefined;
  has_mcp_context?: boolean | undefined;
  has_agent_context?: boolean | undefined;
  has_local_scan?: boolean | undefined;
  has_fleet_ingest?: boolean | undefined;
  has_cluster_scan?: boolean | undefined;
  has_ci_cd_scan?: boolean | undefined;
  has_mesh?: boolean | undefined;
  has_gateway?: boolean | undefined;
  has_proxy?: boolean | undefined;
  has_traces?: boolean | undefined;
  has_registry?: boolean | undefined;
  scan_sources?: string[] | undefined;
  scan_count?: number | undefined;
  services?: Partial<Record<ServiceId, ServiceEntry>> | undefined;
}

export interface RemediationItem {
  package: string;
  ecosystem: string;
  current_version: string;
  fixed_version: string | null;
  severity: string;
  is_kev: boolean;
  /** Normalized 0-10 remediation risk derived from grouped blast-radius risk. */
  impact_score: number;
  priority?: number | undefined;
  action?: string | undefined;
  reason?: string | null | undefined;
  command?: string | null | undefined;
  verify_command?: string | null | undefined;
  vulnerabilities: string[];
  affected_agents: string[];
  agents_pct: number;
  exposed_credentials: string[];
  credentials_pct: number;
  /** Credential names the hosting servers hold; null when the evidence did not record them. */
  server_credentials?: string[] | null | undefined;
  server_credential_count?: number | null | undefined;
  reachable_tools: string[];
  tools_pct: number;
  owasp_tags: string[];
  atlas_tags: string[];
  nist_ai_rmf_tags?: string[] | undefined;
  owasp_mcp_tags?: string[] | undefined;
  owasp_agentic_tags?: string[] | undefined;
  eu_ai_act_tags?: string[] | undefined;
  nist_csf_tags?: string[] | undefined;
  iso_27001_tags?: string[] | undefined;
  soc2_tags?: string[] | undefined;
  cis_tags?: string[] | undefined;
  references?: string[] | undefined;
  risk_narrative: string;
}

export type FindingTriageQueueState =
  "open" | "assigned" | "reviewing" | "decided";

export type FindingTriageDecision =
  "not_affected" | "affected" | "under_investigation";

export type FindingTriageJustification =
  | "component_not_present"
  | "vulnerable_code_not_present"
  | "vulnerable_code_not_in_execute_path"
  | "vulnerable_code_cannot_be_controlled_by_adversary"
  | "inline_mitigations_already_exist";

export interface FindingTriageRequest {
  vulnerability_id: string;
  package?: string | undefined;
  server_name?: string | undefined;
  assignee?: string | undefined;
  queue_state?: FindingTriageQueueState | undefined;
  decision?: FindingTriageDecision | undefined;
  justification?: FindingTriageJustification | null | undefined;
  decision_reason?: string | undefined;
  expires_at?: string | undefined;
}

export interface FindingTriageDecisionRequest {
  decision: FindingTriageDecision;
  justification?: FindingTriageJustification | null | undefined;
  decision_reason?: string | undefined;
  assignee?: string | null | undefined;
  expires_at?: string | null | undefined;
}

export interface FindingTriageItem {
  id: string;
  vulnerability_id: string;
  package: string;
  server_name: string;
  queue_state: FindingTriageQueueState | string;
  decision: FindingTriageDecision | string;
  justification?: FindingTriageJustification | string | null | undefined;
  decision_reason: string;
  assignee: string;
  created_by: string;
  created_at: string;
  reviewed_at: string;
  expires_at: string;
  tenant_id: string;
  vex_eligible: boolean;
}

export interface FindingTriageResponse {
  schema_version: "findings.triage.v1" | string;
  triage: FindingTriageItem[];
  total: number;
  limit: number;
  offset: number;
}

export interface FindingTriageVexResponse {
  schema_version: "findings.triage.vex.v1" | string;
  tenant_id: string;
  count: number;
  format: "openvex" | string;
  filters?: Record<string, string> | undefined;
  finding_scope?: {
    count: number;
    total: number | null;
    warnings: string[];
    completeness: { status: string; reason: string };
  } | undefined;
  vex: Record<string, unknown>;
  signature: {
    algorithm: string;
    signature_hex: string;
    key_id: string;
  };
}

export type AgentStatus = "configured" | "installed-not-configured";

export interface Agent {
  canonical_id?: string;
  stable_id?: string;
  name: string;
  /** The one resolved name the API serves for this agent (recorded name, else the formatted id). */
  display_name?: string | undefined;
  agent_type: string;
  /** Display class from the API: "client" | "background" | "synthetic" (additive). */
  agent_class?: string | undefined;
  config_path?: string | undefined;
  source?: string | undefined;
  source_id?: string | undefined;
  enrollment_name?: string | undefined;
  owner?: string | undefined;
  environment?: string | undefined;
  mdm_provider?: string | undefined;
  tags?: string[] | undefined;
  status?: AgentStatus | undefined;
  discovered_at?: string | undefined;
  last_seen?: string | undefined;
  metadata?: Record<string, unknown> | undefined;
  discovery_provenance?: DiscoveryProvenance | undefined;
  // Per-run discovery envelope (#2083). Trust contract for the scan run that
  // produced this Agent record: scan_mode, discovery_scope, permissions_used,
  // redaction_status. Optional because legacy records pre-envelope don't carry it.
  discovery_envelope?: DiscoveryEnvelope | null | undefined;
  mcp_servers: MCPServer[];
  automation_settings?: string[] | undefined;
}

export interface DiscoveryEnvelope {
  envelope_version: number;
  scan_mode: string;
  discovery_scope: string[];
  permissions_used: string[];
  redaction_status: string;
  captured_at: string;
}

export interface MCPServer {
  name: string;
  /** "mcp-server" for a real MCP server; manifests, SBOMs, and AI-inventory wrappers carry other surfaces. */
  surface?: string | undefined;
  command?: string | undefined;
  args?: string[] | undefined;
  transport?: string | undefined;
  url?: string | undefined;
  auth_mode?: string | undefined;
  config_path?: string | undefined;
  security_warnings?: string[] | undefined;
  security_intelligence?: SecurityIntelligenceEntry[] | undefined;
  packages: Package[];
  tools?: Tool[] | undefined;
  env?: Record<string, string> | undefined;
  vulnerabilities?: Vulnerability[] | undefined;
  has_credentials?: boolean | undefined;
  credential_env_vars?: string[] | undefined;
  security_blocked?: boolean | undefined;
  provenance?: MCPProvenance | undefined;
  discovery_provenance?: DiscoveryProvenance | undefined;
}

export interface DiscoveryProvenance {
  source_type?: string | undefined;
  observed_via?: string | string[] | undefined;
  source?: string | undefined;
  collector?: string | undefined;
  provider?: string | undefined;
  service?: string | undefined;
  resource_type?: string | undefined;
  resource_id?: string | undefined;
  resource_name?: string | undefined;
  location?: string | undefined;
  mapping_method?: string | undefined;
  version_source?: string | undefined;
  version_provenance?: VersionProvenance | undefined;
  confidence?: string | number | undefined;
  discovered_via?: string | undefined;
  resolved_from_registry?: boolean | undefined;
}

export interface VersionProvenance {
  declared_name?: string | undefined;
  declared_version?: string | undefined;
  resolved_version?: string | undefined;
  version_source?: string | undefined;
  confidence?: string | undefined;
  observed_at?: string | undefined;
  version_resolved_at?: string | undefined;
  resolved_from_registry?: boolean | undefined;
  floating_reference?: boolean | undefined;
  floating_reference_reason?: string | undefined;
  pinned?: boolean | undefined;
  pinned_version?: string | undefined;
  evidence?: Record<string, unknown>[] | undefined;
  version_conflicts?: Record<string, unknown>[] | undefined;
}

export interface SecurityIntelligenceEntry {
  entry_id: string;
  title: string;
  severity?: string | undefined;
  confidence: string;
  default_recommendation: string;
  source_type?: string | undefined;
  source?: string | undefined;
  match_type?: string | undefined;
  matched_value?: string | undefined;
  ecosystem?: string | undefined;
  package?: string | undefined;
  affected_versions?: string | undefined;
  first_seen?: string | undefined;
  references?: string[] | undefined;
  last_verified?: string | undefined;
  remediation_actions?: string[] | undefined;
}

export interface MCPProvenance {
  observed_via: string[];
  observed_scopes: string[];
  scan_sources: string[];
  source_agents: string[];
  configured_locally: boolean;
  fleet_present: boolean;
  gateway_registered: boolean;
  runtime_observed: boolean;
  first_seen?: string | null | undefined;
  last_seen?: string | null | undefined;
  last_synced?: string | null | undefined;
}

export interface Package {
  name: string;
  version: string;
  ecosystem: string;
  purl?: string | undefined;
  version_source?: string | undefined;
  version_confidence?: string | undefined;
  version_provenance?: VersionProvenance | undefined;
  discovery_provenance?: DiscoveryProvenance | undefined;
  vulnerabilities?: Vulnerability[] | undefined;
}

export interface Vulnerability {
  id: string;
  severity: "critical" | "high" | "medium" | "low" | "none";
  /** API v2 field — same as description */
  summary?: string | undefined;
  description?: string | undefined;
  cwe_ids?: string[] | undefined;
  references?: string[] | undefined;
  advisory_sources?: string[] | undefined;
  aliases?: string[] | undefined;
  cvss_score?: number | null | undefined;
  cvss_vector?: string | undefined;
  epss_score?: number | null | undefined;
  epss_percentile?: number | undefined;
  /** API v2 field — same as cisa_kev */
  is_kev?: boolean | undefined;
  cisa_kev?: boolean | undefined;
  kev_date_added?: string | undefined;
  kev_due_date?: string | undefined;
  fixed_version?: string | undefined;
  /** API v2 field — same as published */
  published_at?: string | undefined;
  modified_at?: string | undefined;
  nvd_published?: string | undefined;
  published?: string | undefined;
  /** Phase 2 fields */
  severity_source?: string | undefined;
  confidence?: number | undefined;
  match_confidence_tier?: string | undefined;
}

/** An incomplete attempt does not replace the original observation's provenance. */
export interface FindingReconfirmation {
  scan_id: string | null;
  attempted_at: string | null;
  reason_codes: Array<"scan_partial" | "scan_failed" | "scan_not_executed" | "scope_partial" | "scope_permission_denied" | "scope_unavailable" | "scope_unsupported" | "scope_skipped" | "scope_incomplete" | "coverage_issue">;
}

export interface FindingOccurrenceSummary {
  observation_status?: "observed" | "unreconfirmed" | undefined;
  reconfirmation?: FindingReconfirmation | undefined;
  finding_id?: string | undefined;
  occurrence_id?: string | undefined;
  canonical_id?: string | undefined;
  asset?: {
    name?: string | undefined;
    asset_type?: string | undefined;
    stable_id?: string | undefined;
  } | undefined;
  severity?: string | undefined;
  package_version?: string | null | undefined;
  scan_id?: string | undefined;
  status?: string | undefined;
  owner?: string | null | undefined;
  sla_due_at?: string | null | undefined;
  sla_due_at_source?: "severity-kev/v1" | "explicit" | "unknown" | "unavailable" | undefined;
  last_seen?: string | null | undefined;
  last_observed?: string | null | undefined;
  graph_reachable?: boolean | null | undefined;
  graph_min_hop_distance?: number | null | undefined;
}

export interface UnifiedFinding {
  lane?: string | undefined;
  provider?: string | undefined;
  account_ref?: string | undefined;
  environment?: string | undefined;
  observation_status?: "observed" | "unreconfirmed" | undefined;
  reconfirmation?: FindingReconfirmation | undefined;
  unreconfirmed_occurrence_count?: number | undefined;
  id: string;
  finding_id?: string | undefined;
  occurrence_id?: string | undefined;
  finding_group_id?: string | undefined;
  finding_group_key?: string | undefined;
  finding_class: "vulnerability" | "misconfiguration" | "secret" | "pii" | "identity" | "unclassified";
  canonical_id?: string | undefined;
  finding_type?: string | undefined;
  source?: string | undefined;
  /** Estate / asset UnifiedNode id this finding attaches to (graph FK). */
  node_id?: string | null | undefined;
  /** Vulnerability/misconfiguration node id (e.g. vuln:CVE-…). */
  finding_node_id?: string | null | undefined;
  /** EntityType.value for the estate node when known. */
  entity_type?: string | null | undefined;
  asset?: {
    name?: string | undefined;
    asset_type?: string | undefined;
    identifier?: string | null | undefined;
    location?: string | null | undefined;
    stable_id?: string | undefined;
  } | undefined;
  severity: string;
  effective_severity?: string | undefined;
  cvss_severity?: string | null | undefined;
  vendor_severity?: string | null | undefined;
  title?: string | undefined;
  description?: string | undefined;
  cve_id?: string | null | undefined;
  cwe_ids?: string[] | undefined;
  references?: string[] | undefined;
  advisory_sources?: string[] | undefined;
  advisory_aliases?: string[] | undefined;
  aliases?: string[] | undefined;
  cvss_score?: number | null | undefined;
  cvss_version?: string | null | undefined;
  cvss_vector?: string | null | undefined;
  attack_vector?: string | null | undefined;
  attack_complexity?: string | null | undefined;
  privileges_required?: string | null | undefined;
  user_interaction?: string | null | undefined;
  network_exploitable?: boolean | undefined;
  epss_score?: number | null | undefined;
  epss_percentile?: number | null | undefined;
  is_kev?: boolean | null | undefined;
  kev_date_added?: string | null | undefined;
  kev_due_date?: string | null | undefined;
  published_at?: string | null | undefined;
  modified_at?: string | null | undefined;
  severity_source?: string | null | undefined;
  confidence?: number | null | undefined;
  match_confidence_tier?: string | null | undefined;
  package?: string | null | undefined;
  package_name?: string | null | undefined;
  package_version?: string | null | undefined;
  ecosystem?: string | null | undefined;
  fixed_version?: string | null | undefined;
  remediation_guidance?: string | null | undefined;
  compliance_tags?: string[] | undefined;
  /** Full mappings are returned only with `?include=controls`; list rows carry `controls_count`. */
  controls?: Array<Record<string, unknown>> | undefined;
  controls_count?: number | undefined;
  evidence?: Record<string, unknown> | undefined;
  /** `null` when no scorer assessed the finding — render "Not assessed", never 0. */
  risk_score?: number | null | undefined;
  impact_category?: string | null | undefined;
  affected_servers?: string[] | undefined;
  /** `<framework>:<control>` tags stamped on the finding; the basis of every compliance count. */
  framework_tags?: string[] | undefined;
  affected_agents?: string[] | undefined;
  exposed_credentials?: string[] | undefined;
  exposed_tools?: string[] | undefined;
  /** Persisted graph path evidence for this asset-specific finding. */
  graph_reachable?: boolean | null | undefined;
  graph_min_hop_distance?: number | null | undefined;
  graph_reachable_from_agents?: string[] | undefined;
  graph_reachable_from?: string[] | undefined;
  graph_reachable_from_count?: number | null | undefined;
  /** Dependency lineage of a package-backed finding (absent otherwise). */
  is_direct?: boolean | null | undefined;
  dependency_depth?: number | null | undefined;
  /** Parent package the vulnerable dependency was pulled in through. */
  introduced_via?: string | null | undefined;
  scan_id?: string | undefined;
  scan_sources?: string[] | undefined;
  status?: string | undefined;
  first_seen?: string | null | undefined;
  last_seen?: string | null | undefined;
  resolved_at?: string | null | undefined;
  reopened_at?: string | null | undefined;
  scan_count?: number | undefined;
  last_observed?: string | null | undefined;
  occurrence_count?: number | null | undefined;
  occurrences?: FindingOccurrenceSummary[] | undefined;
  occurrences_truncated?: boolean | undefined;
  /** Grouped rows: distinct installed versions across occurrences (first 20) and their full count. */
  package_versions?: string[] | undefined;
  package_version_count?: number | undefined;
  remediation_versions?: string[] | null | undefined;
  provenance?: Record<string, unknown> | string | null | undefined;
  owner?: string | null | undefined;
  sla_due_at?: string | null | undefined;
  sla_due_at_source?: "severity-kev/v1" | "explicit" | "unknown" | "unavailable" | undefined;
  triage_id?: string | null | undefined;
  triage_decision?: "not_affected" | "affected" | "under_investigation" | null | undefined;
  triage_queue_state?: string | null | undefined;
  /** CWPP runtime/EDR workload evidence (additive; never a clean-workload claim). */
  workload_runtime_evidence?: WorkloadRuntimeEvidence | undefined;
}

/**
 * Canonical finding-list envelope (#3666). Every finding-list surface
 * (`/v1/findings`, `/v1/compliance/hub/findings`, `/v1/governance/findings`)
 * returns this shape, generic over the finding row type, so consumers learn
 * one contract. Keyset `cursor` / `next_cursor` is the scale pagination path;
 * `limit` / `offset` stay for backward compatibility.
 */
export interface FindingListEnvelope<T> {
  schema_version: string;
  findings: T[];
  count: number;
  /** Null on continuation pages whose first-page count may no longer be current. */
  total: number | null;
  total_approximate?: boolean | undefined;
  limit: number;
  offset: number;
  sort: string | null;
  scan_id?: string | null | undefined;
  cursor: string;
  next_cursor: string;
  has_more: boolean;
  warnings: string[];
  grouping?: {
    status: "complete" | "partial";
    scanned_occurrences: number;
    scan_budget: number;
    occurrence_total: number | null;
    occurrence_sample_limit: number;
    unit?: "control_groups" | undefined;
    canonical_issue_total?: number | undefined;
  } | undefined;
  count_metadata: {
    definition: string;
    source: string;
    scope: string;
    window: ReadWindow | { days: number } | null;
    filters: Record<string, unknown>;
    returned: number;
    total: number | null;
    total_kind: "exact" | "lower_bound" | "unknown";
    completeness: {
      status: "complete" | "partial" | "unknown";
      reason: string;
    };
  };
  /** Applied default read-window (#4009); present on `/v1/findings`. */
  window?: ReadWindow | undefined;
  /** Canonical server-applied facets echoed for pagination/debugging. */
  filters?: {
    finding_class?: "vulnerability" | "misconfiguration" | "secret" | "pii" | "identity" | "unclassified";
  } | undefined;
  /** Exact only when `facets_approximate` is false. */
  facets?: FindingFacets | undefined;
  lane_counts_approximate?: boolean;
  facets_approximate?: boolean | undefined;
  facet_metadata?: {
    domain?: { basis: "multi_label"; sums_to_total: false };
    freshness: {
      basis: string[];
      thresholds_hours: number[];
      missing_or_invalid: "unavailable";
    };
  } | undefined;
  /**
   * Completeness of the server-side scope walk. Present only when a scope
   * filter (`provider` / `account` / `environment` / `domain` / `q`) is
   * applied. `partial` means the walk hit its row budget or deadline: the page
   * is a prefix, not the whole matching set — continue with `next_cursor`.
   */
  scope_completeness?: ScopeCompleteness | undefined;
}

export interface ScopeCompleteness {
  status: "complete" | "partial";
  reason: string;
  scanned_rows: number;
  scan_budget: number;
}

export interface FindingFacets {
  lane?: Record<string, number>;
  finding_class: Record<"vulnerability" | "misconfiguration" | "secret" | "pii" | "identity" | "unclassified", number>;
  severity: Record<"critical" | "high" | "medium" | "low" | "info" | "unknown", number>;
  status: Record<"open" | "resolved", number>;
  domain: Record<"cspm" | "vuln" | "aspm" | "dspm" | "aispm", number>;
  freshness: Record<"last_24_hours" | "last_7_days" | "last_30_days" | "older" | "unavailable", number>;
  reachability?: Record<"reachable" | "unreachable" | "unassessed", number>;
  exploit_intelligence?: Record<"kev_and_epss" | "kev_only" | "epss_only" | "unavailable", number>;
  fixability?: Record<"fix_available" | "no_fix_available", number>;
  ownership?: Record<"owned" | "unowned", number>;
  disposition?: Record<"affected" | "not_affected" | "under_investigation" | "untriaged", number>;
}

/** Applied time-window echoed by windowed read surfaces (#4009). */
export interface ReadWindow {
  days: number;
  since: string | null;
  applied: boolean;
  label: string;
}

export type FindingsResponse = FindingListEnvelope<UnifiedFinding>;

/** CWPP runtime/EDR evidence fused onto a workload-scoped finding. */
export interface WorkloadRuntimeEvidence {
  schema_version?: string;
  state?:
    | "runtime_ioc_observed"
    | "runtime_alert_observed"
    | "runtime_activity_observed"
    | "no_runtime_signal"
    | string;
  signal_count?: number;
  signal_types?: Record<string, number>;
  severity_counts?: Record<string, number>;
  source_kinds?: string[];
  latest_observed_at?: string;
  clean_workload_assertion?: boolean;
  note?: string;
}

/** Frozen catalog association, not an execution observation. */
export interface AtlasMappingReceipt {
  basis: "catalog_weakness_association";
  execution_proven: false;
  cwe_ids: string[];
  attack_reference: string;
  atlas_catalog_sha256: string;
  attack_catalog_sha256: string;
  atlas_version: string;
  technique_url: string;
}

export interface BlastRadius {
  vulnerability_id: string;
  canonical_id?: string | undefined;
  asset?: { canonical_id?: string; stable_id?: string } | undefined;
  severity: string;
  package?: string | undefined;
  ecosystem?: string | undefined;
  affected_agents: string[];
  affected_servers?: string[] | undefined;
  exposed_credentials: string[];
  /** API v2 field — same as reachable_tools */
  exposed_tools?: string[] | undefined;
  reachable_tools: string[];
  /** API v2 field — same as blast_score (0-100); `null` when not assessed. */
  risk_score?: number | null | undefined;
  blast_score: number;
  cvss_score?: number | null | undefined;
  epss_score?: number | null | undefined;
  is_kev?: boolean | undefined;
  cisa_kev?: boolean | undefined;
  fixed_version?: string | undefined;
  owasp_tags?: string[] | undefined;
  atlas_tags?: string[] | undefined;
  atlas_mapping_evidence?: Record<string, AtlasMappingReceipt> | undefined;
  nist_ai_rmf_tags?: string[] | undefined;
  owasp_mcp_tags?: string[] | undefined;
  owasp_agentic_tags?: string[] | undefined;
  eu_ai_act_tags?: string[] | undefined;
  /** CWE-derived impact category: code-execution, credential-access, etc. */
  impact_category?: string | undefined;
  /** Full credential set before CWE filtering (for reference) */
  all_server_credentials?: string[] | undefined;
  /** Human-readable attack vector description */
  attack_vector_summary?: string | undefined;
  /** Registry-only tools (not confirmed in runtime inventory). */
  phantom_tools?: string[] | undefined;
  /** Flattened compliance framework tags for chips. */
  framework_tags?: string[] | undefined;
  /** Effective reach band from blast-radius scoring. */
  effective_reach_band?: string | undefined;
  /** Effective reach score (0-100). */
  effective_reach_score?: number | undefined;
  /** Runtime observation/blocking evidence fused onto the finding. */
  runtime_evidence?: {
    state?: "static" | "observed" | "blocked" | "replay_only" | string;
    blocked_count?: number;
    observed_count?: number;
  } | undefined;
  /** CWPP runtime/EDR workload evidence (distinct from proxy/gateway runtime_evidence). */
  workload_runtime_evidence?: WorkloadRuntimeEvidence | undefined;
  /** Graph-walk reachability (populated by the unified-graph dependency
   *  reach engine). `true` when an agent's USES/DEPENDS_ON closure
   *  reaches the vulnerable package; `false` when the package is in
   *  inventory but no agent traversal reaches it; `undefined` when the
   *  engine did not run for this scan. */
  graph_reachable?: boolean | null | undefined;
  /** Smallest hop count from any reaching agent. `null` / `undefined`
   *  when graph_reachable is not `true`. */
  graph_min_hop_distance?: number | null | undefined;
  /** Agent node ids whose dependency closure reaches the vulnerable
   *  package (e.g. ["agent:cursor", "agent:claude-desktop"]). */
  graph_reachable_from_agents?: string[] | undefined;
  graph_reachable_from?: string[] | undefined;
  graph_reachable_from_count?: number | null | undefined;
}

export interface AttackFlowNodeData {
  [key: string]: unknown;
  nodeType: "cve" | "package" | "server" | "agent" | "credential" | "tool";
  label: string;
  severity?: string | undefined;
  cvss_score?: number | undefined;
  epss_score?: number | undefined;
  is_kev?: boolean | undefined;
  risk_score?: number | undefined;
  fixed_version?: string | undefined;
  owasp_tags?: string[] | undefined;
  atlas_tags?: string[] | undefined;
  nist_ai_rmf_tags?: string[] | undefined;
  owasp_mcp_tags?: string[] | undefined;
  owasp_agentic_tags?: string[] | undefined;
  eu_ai_act_tags?: string[] | undefined;
  version?: string | undefined;
  ecosystem?: string | undefined;
  agent_type?: string | undefined;
  status?: string | undefined;
  description?: string | undefined;
}

export interface AttackFlowNode {
  id: string;
  type: string;
  position: { x: number; y: number };
  data: AttackFlowNodeData;
}

export interface AttackFlowEdge {
  id: string;
  source: string;
  target: string;
  type: string;
  animated?: boolean | undefined;
  style?: { stroke: string } | undefined;
}

export interface AttackFlowStats {
  total_cves: number;
  total_packages: number;
  total_servers: number;
  total_agents: number;
  total_credentials: number;
  total_tools: number;
  severity_counts: Record<string, number>;
}

export interface AttackFlowResponse {
  nodes: AttackFlowNode[];
  edges: AttackFlowEdge[];
  stats: AttackFlowStats;
}

export interface ContextGraphResponse {
  nodes: Array<{
    id: string;
    kind: string;
    label: string;
    metadata: Record<string, unknown>;
  }>;
  edges: Array<{
    source: string;
    target: string;
    kind: string;
    weight: number;
    metadata: Record<string, unknown>;
  }>;
  lateral_paths: Array<{
    source: string;
    target: string;
    hops: string[];
    edges: string[];
    composite_risk: number;
    summary: string;
    credential_exposure: string[];
    tool_exposure: string[];
    vuln_ids: string[];
    finding_ids?: string[];
  }>;
  interaction_risks: Array<{
    pattern: string;
    agents: string[];
    risk_score: number;
    description: string;
    owasp_agentic_tag?: string | undefined;
  }>;
  stats: {
    total_nodes: number;
    total_edges: number;
    agent_count: number;
    shared_server_count: number;
    shared_credential_count: number;
    lateral_path_count: number;
    max_lateral_depth: number;
    highest_path_risk: number;
    interaction_risk_count: number;
  };
}
