import type { ExposurePath } from "../exposure-path";
import type { GraphPathFocus } from "../graph-path-focus";
import type {
AttackPath,
UnifiedEdge,
UnifiedGraphData,
UnifiedNode,
} from "../graph-schema";
import type { PostureScorecard,ScorecardSummary,Summary } from "./auth";
import type { Agent,BlastRadius,RemediationItem,UnifiedFinding } from "./findings";
import type { ApiSchemas,ContractEnvelope } from "./shared";

export type GraphConsequenceRequest = ApiSchemas["GraphConsequenceRequest"];

export type GraphConsequenceResponse = ApiSchemas["GraphConsequenceResponse"];

export type GraphCompromiseRequest = ApiSchemas["GraphCompromiseRequest"];

export type GraphCompromiseResponse = ApiSchemas["GraphCompromiseResponse"];

export type JobStatus = "pending" | "running" | "done" | "failed" | "cancelled";

export interface ScanRequest {
  source_id?: string | undefined;
  inventory?: string | undefined;
  images?: string[] | undefined;
  k8s?: boolean | undefined;
  k8s_namespace?: string | undefined;
  tf_dirs?: string[] | undefined;
  gha_path?: string | undefined;
  repo_url?: string | undefined;
  agent_projects?: string[] | undefined;
  sbom?: string | undefined;
  enrich?: boolean | undefined;
  format?: string | undefined;
  dynamic_discovery?: boolean | undefined;
  dynamic_max_depth?: number | undefined;
}

export type StepStatus = "pending" | "running" | "done" | "failed" | "skipped";

export interface StepEvent {
  type: "step";
  step_id: string;
  status: StepStatus;
  message: string;
  started_at?: string | undefined;
  completed_at?: string | undefined;
  stats?: Record<string, number> | undefined;
  sub_step?: string | undefined;
  progress_pct?: number | undefined;
}

export interface ProgressEvent {
  type: "progress";
  message: string;
}

export interface DoneEvent {
  type: "done";
  status: string;
  job_id: string;
}

export type SSEEvent = StepEvent | ProgressEvent | DoneEvent;

export interface ScanJob {
  job_id: string;
  status: JobStatus;
  created_at: string;
  tenant_id?: string | undefined;
  source_id?: string | undefined;
  triggered_by?: string | undefined;
  schedule_id?: string | undefined;
  started_at?: string | undefined;
  completed_at?: string | undefined;
  request: ScanRequest;
  progress: string[];
  result?: ScanResult | undefined;
  result_document?: Record<string, unknown> | string | undefined;
  result_format?: string | undefined;
  error?: string | undefined;
}

export interface ScanResult {
  findings?: UnifiedFinding[];
  enforcement?: { coverage?: import("../mcp-audit").McpAuditCoverage[] };
  scan_id?: string | undefined;
  finding_summary?: { total: number; by_severity: Record<string, number> } | undefined;
  agents: Agent[];
  blast_radius: BlastRadius[];
  remediation_plan?: RemediationItem[] | undefined;
  scorecard_summary?: ScorecardSummary | undefined;
  scan_performance?: Record<string, number> | undefined;
  posture_scorecard?: PostureScorecard | undefined;
  summary?: Summary | undefined;
  warnings?: string[] | undefined;
  scan_timestamp?: string | undefined;
  generated_at?: string | undefined;
  scan_run?: ScanRunEvidence | undefined;
  vuln_data_freshness?: VulnDataFreshness | undefined;
  tool_version?: string | undefined;
  /** Context metadata — auto-detected from scan sources */
  has_mcp_context?: boolean | undefined;
  has_agent_context?: boolean | undefined;
  scan_sources?: string[] | undefined;
  /** Cloud estate evidence persisted by cloud connection and CLI cloud scans. */
  cloud_inventory?: unknown | undefined;
  cis_benchmark?: unknown | undefined;
  azure_cis_benchmark?: unknown | undefined;
  gcp_cis_benchmark?: unknown | undefined;
  snowflake_cis_benchmark?: unknown | undefined;
  databricks_cis_benchmark?: unknown | undefined;
  /** Static repo extras (API clone / CLI project path). */
  ai_inventory?: Record<string, unknown> | undefined;
  project_inventory?: Record<string, unknown> | undefined;
  skill_audit?: Record<string, unknown> | undefined;
  iac_findings?: unknown | undefined;
  sast?: Record<string, unknown> | undefined;
}

export interface ScanRunIssue {
  code: string;
  stage: string;
  source: string;
  message: string;
  severity: "warning" | "error";
  affects_coverage: boolean;
}

export interface ScanRunEvidence extends Record<string, unknown> {
  outcome?: "complete" | "partial" | "failed" | undefined;
  issues?: ScanRunIssue[] | undefined;
  warning_count?: number | undefined;
  requested_scope_count?: number | undefined;
  complete_scope_count?: number | undefined;
  incomplete_scope_count?: number | undefined;
  scopes?: Record<string, unknown>[] | undefined;
}

export interface VulnDataFreshness {
  status?: string | undefined;
  source?: string | undefined;
  last_updated?: string | null | undefined;
  age_hours?: number | null | undefined;
  age_days?: number | null | undefined;
  stale?: boolean | undefined;
}

export interface GraphPagination {
  total: number;
  offset: number;
  limit: number;
  has_more: boolean;
  cursor?: string | undefined;
  next_cursor?: string | undefined;
}

/**
 * Shared evidence coverage contract. `truncated` means the response is a
 * bounded page; clients must follow the cursor before treating the lens as
 * exhaustive. `sampled` is reserved for deterministic representative views.
 */
export interface GraphCompleteness {
  edges_truncated?: boolean;
  edge_limit?: number;
  edge_returned?: number;
  edge_expansion_endpoint?: string;
  status: "complete" | "truncated" | "sampled";
  complete: boolean;
  sampled: boolean;
  truncated: boolean;
  returned: number;
  total?: number | undefined;
  reason?: string | undefined;
}

export interface GraphSnapshot {
  scan_id: string;
  created_at: string;
  node_count: number;
  edge_count: number;
  risk_summary: Record<string, number>;
  analysis_status?: import("../graph-schema").GraphStats["analysis_status"] | undefined;
  snapshot_kind?: "scan" | "correlation" | undefined;
  correlation_id?: string | undefined;
  evidence_manifest_sha256?: string | undefined;
}

export interface GraphCorrelationReceipt {
  scan_id: string;
  created_at?: string | undefined;
  digest?: string | undefined;
  node_count?: number | undefined;
  edge_count?: number | undefined;
  source_kinds?: string[] | undefined;
  freshness?: "fresh" | "stale_allowed" | undefined;
  age_hours?: number | undefined;
}

export interface GraphCorrelationRun {
  correlation_id: string;
  tenant_id: string;
  name: string;
  status: "pending" | "running" | "complete" | "failed";
  max_age_hours: number;
  allow_stale: boolean;
  input_manifest: GraphCorrelationReceipt[];
  result_manifest: {
    correlation_merge?: {
      node_conflict_count?: number | undefined;
      edge_conflict_count?: number | undefined;
      conflict_count?: number | undefined;
    } | undefined;
    output?: {
      scan_id?: string | undefined;
      node_count?: number | undefined;
      edge_count?: number | undefined;
      attack_path_count?: number | undefined;
      exposure_path_count?: number | undefined;
    } | undefined;
    analysis_bounds?: Record<string, unknown> | undefined;
  };
  manifest_sha256: string;
  output_scan_id: string;
  failure_code: string;
  created_at: string;
  started_at: string;
  completed_at: string;
}

export interface GraphCorrelationCreate {
  name: string;
  scan_ids: string[];
  max_age_hours: number;
  allow_stale: boolean;
}

export interface GraphCorrelationList {
  items: GraphCorrelationRun[];
  count: number;
}

export type GraphScenarioChange =
  | {
      kind: "add_node";
      key: string;
      entity_type: string;
      label: string;
      presentation?: Record<string, unknown> | undefined;
    }
  | { kind: "remove_node"; node_id: string }
  | {
      kind: "patch_node";
      node_id: string;
      patch: {
        label?: string | undefined;
        status?: string | undefined;
        risk_score?: number | undefined;
        severity?: string | undefined;
        attributes?: Partial<
          Record<
            | "description"
            | "environment"
            | "owner"
            | "provider"
            | "region"
            | "account_id"
            | "repository"
            | "fix_status"
            | "disposition"
            | "reachability",
            unknown
          >
        > | undefined;
        compliance_tags?: string[] | undefined;
        data_sources?: string[] | undefined;
      };
    }
  | {
      kind: "add_edge";
      source: string;
      target: string;
      relationship: string;
      direction: "directed" | "bidirectional";
      weight: number;
      traversable: boolean;
      confidence: number;
    }
  | {
      kind: "remove_edge";
      source: string;
      target: string;
      relationship: string;
    };

/** Persisted, snapshot-pinned proposed architecture. Never observed state. */
export interface GraphScenario {
  scenario_id: string;
  tenant_id: string;
  name: string;
  description: string;
  base_scan_id: string;
  assumptions: string[];
  changes: GraphScenarioChange[];
  revision: number;
  created_by: string;
  created_at: string;
  updated_at: string;
}

export type GraphScenariosResponse = ContractEnvelope<ApiSchemas["GraphScenariosResponse"], { scenarios: GraphScenario[] }>;

export interface GraphScenarioResponse {
  schema: "graph.scenarios.v1" | string;
  scenario: GraphScenario;
}

export interface GraphScenarioComparisonCounts {
  scan_id?: string | undefined;
  node_count: number;
  edge_count: number;
  completeness?: GraphCompleteness | undefined;
  base_status?: "available" | "stale" | "unavailable" | string | undefined;
  latest_scan_id?: string | null | undefined;
}

export interface GraphScenarioProposedGraph
  extends GraphScenarioComparisonCounts {
  modeled: true;
  nodes: UnifiedNode[];
  edges: UnifiedEdge[];
}

export interface GraphScenarioDifference {
  nodes_added: unknown[];
  nodes_removed: unknown[];
  nodes_changed: unknown[];
  edges_added: unknown[];
  edges_removed: unknown[];
  touched_observed_path_count: number;
  touched_observed_path_ids: string[];
}

export interface GraphScenarioComparisonResponse {
  schema: "graph.scenario-comparison.v1" | string;
  scenario: GraphScenario;
  current: GraphScenarioComparisonCounts;
  proposed: GraphScenarioProposedGraph;
  difference: GraphScenarioDifference;
  available: boolean;
  unavailable_reason?: string | null | undefined;
  base_status?: string | undefined;
  stale?: boolean | undefined;
}

/** Adjacent-pair entry from GET /v1/graph/history */
export interface GraphHistoryDiffSummary {
  nodes_added?: number;
  nodes_removed?: number;
  nodes_changed?: number;
  edges_added?: number;
  edges_removed?: number;
  [key: string]: unknown;
}

export interface GraphHistorySnapshot {
  scan_id: string;
  created_at?: string;
  node_count?: number;
  edge_count?: number;
  diff_baseline_scan_id?: string;
  diff_summary?: GraphHistoryDiffSummary;
}

export interface GraphHistoryResponse {
  schema_version?: string;
  snapshots: GraphHistorySnapshot[];
  window?: Record<string, unknown>;
}

export interface GraphAttackPath extends AttackPath {
  exposure_path?: ExposurePath | undefined;
}

export interface GraphVendorFacets {
  unit: "paths";
  snapshot_paths: number;
  cross_vendor_paths: number;
  pairs: Array<{ source_vendor: string; target_vendor: string; paths: number }>;
  selected: { source_vendor?: string; target_vendor?: string } | null;
  covers_all_paths: boolean;
}

export interface UnifiedGraphResponse extends Omit<
  UnifiedGraphData,
  "attack_paths"
> {
  attack_paths: GraphAttackPath[];
  pagination: GraphPagination;
  completeness?: GraphCompleteness | undefined;
  focus?: GraphPathFocus | undefined;
  /** Present on the cross-vendor queue: path counts per (source vendor, target vendor) over the whole snapshot. */
  vendor_facets?: GraphVendorFacets | undefined;
  count_metadata?: {
    source?: "persisted_graph_paths" | "derived_graph_paths" | string;
    returned?: number;
    total?: number;
    snapshot_total?: number;
    materialized_paths?: number;
    derived_paths?: number;
    returned_rows?: number;
    scope?: string;
    /** Paths in the matching queue whose every occurrence is suppressed; null when not enumerated (focused reads). */
    suppressed_paths?: number | null;
    /** total minus suppressed_paths: the open paths. */
    open_paths?: number | null;
    suppression_basis?: "approved_exception";
    suppression_complete?: boolean;
    [key: string]: unknown;
  } | undefined;
}

/** Shared HTTP/MCP inventory projection over the tenant-scoped graph store. */
export interface InventorySummaryFilters {
  type?: string[] | undefined;
  search?: string | undefined;
  environment?: string | undefined;
  provider?: string | undefined;
  source?: string | undefined;
  severity?: string | undefined;
  minSeverity?: string | undefined;
}

export interface InventorySummaryResponse {
  evidence_scope?: "current_estate" | "scan_snapshot" | "no_snapshot";
  snapshot_generation?: string | null;
  schema_version: string;
  status?: "no_snapshot" | undefined;
  count_exact?: boolean | undefined;
  count_basis?: string | undefined;
  finding_count_scope?: "selected_snapshot" | "current_estate" | undefined;
  filters?: Partial<{
    type: string[];
    search: string;
    environment: string;
    provider: string;
    source: string;
    severity: string;
    min_severity: string;
  }> | undefined;
  collection_coverage?: { status: "unknown" | "partial"; reason: string; reason_codes?: string[] } | undefined;
  tenant_id: string;
  scan_id: string;
  created_at?: string | undefined;
  total_assets: number;
  by_type: Record<string, number>;
  by_group: Record<string, number>;
  finding_count: number;
  facets: InventoryFacets;
  facet_metadata: InventoryFacetMetadata;
  completeness: GraphCompleteness;
}

export interface InventoryFacetBucket {
  value: string | null;
  count: number;
}

export interface InventoryFacet {
  buckets: InventoryFacetBucket[];
}

export interface InventoryFacets {
  type: InventoryFacet;
  source: InventoryFacet;
  provider: InventoryFacet;
  environment: InventoryFacet;
  severity: InventoryFacet;
}

export interface InventoryFacetMetadata {
  basis: string;
  mode: "self_excluding" | string;
  exact: boolean;
  scan_id: string;
  dimensions?: Record<string, string> | undefined;
}

export interface InventoryFindingSummary {
  total: number;
  by_severity: Record<string, number>;
  ids: string[];
  top_severity: string;
}

export interface InventoryAssetBase {
  risk_assessment?: import("@/lib/node-risk-assessment").NodeRiskAssessment | undefined;
  id: string;
  type: string;
  name: string;
  environment: string;
  provider: string;
  risk: number;
  severity: string;
  status: string;
  source: string;
  sources: string[];
  first_seen: string;
  last_seen: string;
  attributes: Record<string, unknown>;
  compliance_tags: string[];
  ecosystem: string;
  version: string;
}

export interface InventoryAsset extends InventoryAssetBase {
  finding_summary: InventoryFindingSummary;
  relationship_count: number;
}

export interface InventoryPagination {
  total: number;
  offset: number;
  limit: number;
  cursor?: string | undefined;
  next_cursor?: string | undefined;
  has_more: boolean;
  facet_filtered: boolean;
}

export interface InventoryAssetsResponse {
  evidence_scope?: "current_estate" | "scan_snapshot" | "no_snapshot";
  snapshot_generation?: string | null;
  schema_version: string;
  tenant_id: string;
  scan_id: string;
  created_at: string;
  assets: InventoryAsset[];
  filters: Record<string, string | string[]>;
  pagination: InventoryPagination;
  facets: InventoryFacets;
  facet_metadata: InventoryFacetMetadata;
  completeness: GraphCompleteness;
}

export interface InventoryAssetDetailResponse {
  evidence_scope?: "current_estate" | "scan_snapshot";
  schema_version: string;
  tenant_id: string;
  scan_id: string;
  snapshot_generation: string;
  next_cursor: string | null;
  nodes: Record<string, unknown>[];
  evidence_sources: string[];
  impact_status: "not_evaluated";
  asset: InventoryAssetBase;
  node: Record<string, unknown>;
  edges_out: Record<string, unknown>[];
  edges_in: Record<string, unknown>[];
  neighbors: string[];
  sources: string[];
  impact: Record<string, unknown>;
  completeness: GraphCompleteness;
}

export interface AgentBomManifestNode {
  id: string;
  entity_type: string;
  label: string;
  attributes: Record<string, unknown>;
}

export interface AgentBomManifestEdge {
  id: string;
  source: string;
  target: string;
  relationship: string;
  attributes: Record<string, unknown>;
}

export interface AgentBomManifestServer extends Record<string, unknown> {
  server_stable_id?: string;
  identity_basis?: "server_identity" | "observation";
  agent_names?: string[];
  agent_ids?: string[];
  agent_binding?: "inventory_identity" | "unbound";
  observation_ids?: string[];
  observations?: Array<Record<string, unknown>>;
}

export interface AgentBomManifestResponse {
  schema_version: "agent-bom.manifest/v1" | string;
  generated_at: string;
  source: "local-discovery" | "control-plane" | string;
  tenant_id?: string | undefined;
  summary: {
    agents: number;
    mcp_servers: number;
    tools: number;
    credential_refs: number;
    runtime_observed_servers: number;
    gateway_registered_servers: number;
  };
  visibility: {
    owners: number;
    unowned_agents: number;
    shadow_runtime_servers: number;
    untracked_runtime_servers: number;
    servers_with_warnings: number;
    risky_credential_refs: number;
    risk_signals: {
      unowned_agent_ids: string[];
      shadow_runtime_server_ids: string[];
      untracked_runtime_server_ids: string[];
      risky_credential_refs: string[];
    };
  };
  blueprint_drift: {
    status: "not_observed" | "aligned" | "needs_review" | string;
    mode: "observation_only" | string;
    fail_behavior: "report_only" | string;
    signal_count: number;
    signals: Array<{
      kind: string;
      entity_id: string;
      severity: string;
      message: string;
    }>;
  };
  agents: Array<Record<string, unknown>>;
  mcp_servers: AgentBomManifestServer[];
  graph: {
    nodes: AgentBomManifestNode[];
    edges: AgentBomManifestEdge[];
    stats: {
      nodes: number;
      edges: number;
      relationships: string[];
    };
  };
  boundaries: {
    stores_credential_values: boolean;
    stores_raw_prompts: boolean;
    credential_value_policy: string;
  };
}
