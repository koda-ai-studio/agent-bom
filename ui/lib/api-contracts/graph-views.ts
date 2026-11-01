import type { ExposurePath } from "../exposure-path";
import type {
UnifiedEdge,
UnifiedGraphData,
UnifiedNode
} from "../graph-schema";
import type { GraphAttackPath,GraphCompleteness,GraphPagination } from "./scan-inventory";
import type { ApiSchemas,ContractEnvelope } from "./shared";

export interface FixFirstRiskReason {
  kind: string;
  label: string;
  detail: string;
}

export interface FixFirstAction {
  title: string;
  detail: string;
  href: string;
}

export interface FixFirstRankMeta {
  reachability?: "confirmed" | "likely" | "unknown" | "unlikely" | string;
  raw_severity?: string;
  environment_weight?: number;
  environments?: string[];
  tool_capabilities?: string[];
}

export interface FixFirstPathCard {
  id: string;
  semantic_key?: string;
  occurrence_count?: number;
  occurrence_path_ids?: string[];
  rank: number;
  title: string;
  summary: string;
  attack_path: GraphAttackPath;
  exposure_path?: ExposurePath | undefined;
  nodes?: UnifiedNode[] | undefined;
  sequence_labels: string[];
  risk_reasons: FixFirstRiskReason[];
  next_actions: FixFirstAction[];
  rank_meta?: FixFirstRankMeta | undefined;
  affected: {
    agents: string[];
    servers: string[];
    packages: string[];
    findings: string[];
    finding_labels?: string[];
    credentials: string[];
    tools: string[];
  };
}

/** Fusion crown-jewel path cluster (not a remediation ticket campaign). */
export interface GraphAttackCampaign {
  campaign_id: string;
  crown_jewel: string;
  crown_jewel_label: string;
  partition?: string;
  owner?: string;
  business_impact?: string;
  exploitability?: number | null;
  expected_risk_reduction?: number | null;
  path_count: number;
  top_path_summary?: string;
  cross_partition?: boolean;
  evidence?: string[];
  member_paths?: string[];
  priority_score?: number | null;
  priority_method?: string | null;
  exploitability_evidence?: { status: string; basis?: string; evidence_refs: string[]; reason_codes?: string[] };
  expected_risk_reduction_evidence?: { status: string; basis?: string; evidence_refs: string[]; reason_codes?: string[] };
}

export interface GraphRemediationPriority {
  id: string;
  rank: number;
  asset_node_id: string;
  asset_label: string;
  finding_node_id: string;
  finding_label: string;
  finding_id: string;
  fixed_version: string | null;
  guidance: string;
  covered_paths: number;
  newly_covered_paths: number;
  critical_paths: number;
  high_paths: number;
  unknown_reachability_paths: number;
  remaining_paths_after_selection: number;
  path_ids: string[];
  path_sample_complete: boolean;
}

export interface GraphRemediationPriorities {
  schema_version: "graph-remediation-priorities.v1";
  coverage_basis: "recorded_paths_touching_selected_findings";
  source_coverage: "not_assessed";
  method: string;
  assessed_paths: number;
  candidate_count: number;
  covered_paths: number;
  remaining_paths: number;
  complete: boolean;
  limitations: string[];
  path_budget: number;
  recommendation_limit: number;
  remediation_verified: false;
  recommendations: GraphRemediationPriority[];
}

export interface FixFirstGraphViewResponse {
  scan_id: string;
  snapshot_generation?: string | null;
  tenant_id: string;
  created_at: string;
  cards: FixFirstPathCard[];
  remediation_priorities?: GraphRemediationPriorities;
  attack_campaigns?: GraphAttackCampaign[];
  summary: {
    total_paths: number;
    matched_paths: number;
    returned_paths: number;
    highest_risk: number;
    covered_findings: number;
    campaign_count?: number;
    node_count: number;
    edge_count: number;
  };
  focus: {
    cve: string;
    package: string;
    agent: string;
  };
}

export interface NhiGovernanceIdentity {
  node_id?: string;
  label?: string;
  risk_score?: number;
  status?: string;
  [key: string]: unknown;
}

export interface NhiGovernancePosture {
  generated_from?: string;
  scan_id?: string;
  tenant_id?: string;
  counts?: Record<string, number>;
  identities?: NhiGovernanceIdentity[];
  [key: string]: unknown;
}

export interface GraphQueryRequest {
  snapshot_generation?: string | undefined;
  roots: string[];
  scan_id?: string | undefined;
  direction?: "forward" | "reverse" | "both" | undefined;
  max_depth?: number | undefined;
  max_nodes?: number | undefined;
  max_edges?: number | undefined;
  timeout_ms?: number | undefined;
  traversable_only?: boolean | undefined;
  static_only?: boolean | undefined;
  dynamic_only?: boolean | undefined;
  include_roots?: boolean | undefined;
  include_attack_paths?: boolean | undefined;
  min_severity?: string | undefined;
  entity_types?: string[] | undefined;
  relationship_types?: string[] | undefined;
  compliance_prefixes?: string[] | undefined;
  data_sources?: string[] | undefined;
}

export interface GraphQueryResponse extends Omit<UnifiedGraphData, "snapshot_generation"> {
  snapshot_generation?: string | null | undefined;
  roots: string[];
  direction: "forward" | "reverse" | "both";
  max_depth: number;
  max_nodes: number;
  max_edges: number;
  timeout_ms: number;
  budget: Record<string, number>;
  truncated: boolean;
  missing_roots: string[];
  depth_by_node: Record<string, number>;
  filters: Record<string, unknown>;
  completeness: GraphCompleteness;
}

export interface GraphImpactResponse {
  scan_id?: string | undefined;
  tenant_id?: string | undefined;
  snapshot_generation?: string | null | undefined;
  interpretation?: { basis: "recorded_reverse_reachability" | "recorded_forward_reachability"; execution: "not_established"; collection_coverage: "unknown"; traversable_only: false; max_depth: number } | undefined;
  completeness?: GraphCompleteness | undefined;
  node_id: string;
  affected_nodes: string[];
  affected_by_type: Record<string, number>;
  affected_count: number;
  max_depth_reached: number;
  max_depth?: number | null | undefined;
  depth_basis?: "requested" | "default" | "longest_materialized_path" | null | undefined;
  direction?: "reverse" | "forward" | undefined;
  /** The nodes behind each count, nearest first (bounded server-side). */
  affected_nodes_detail?: { id: string; label: string; entity_type: string; depth: number }[] | undefined;
}

/** Saved tenant graph filter preset from GET/POST /v1/graph/presets */
export interface GraphFilterPreset {
  name: string;
  description?: string;
  filters: Record<string, unknown>;
  created_at?: string;
  tenant_id?: string;
}

export interface GraphFilterPresetCreate {
  name: string;
  description?: string;
  filters: Record<string, unknown>;
}

export interface GraphNodeDetailResponse {
  scan_id?: string | undefined;
  tenant_id?: string | undefined;
  snapshot_generation?: string | null | undefined;
  completeness?: GraphCompleteness | undefined;
  node: UnifiedNode;
  edges_out: UnifiedEdge[];
  edges_in: UnifiedEdge[];
  neighbors: string[];
  sources: string[];
  impact: GraphImpactResponse;
}

export type GraphNeighborDirection = "out" | "in" | "both";

export type GraphNodeNeighborsResponse = Pick<ApiSchemas["GraphNodeNeighborsResponse"],
  "node_id" | "scan_id" | "found" | "limit" | "total_neighbors" | "truncated"
> & {
  direction: GraphNeighborDirection;
  neighbors: UnifiedNode[];
  edges: UnifiedEdge[];
};

export interface GraphRollupAggregate {
  descendant_count: number;
  by_type: Record<string, number>;
  severity_counts: Record<string, number>;
  worst_severity: string;
  worst_severity_rank: number;
  internet_exposed: boolean;
  toxic_combo: boolean;
  exposed_count: number;
  toxic_count: number;
  /** Distinct open issues among descendants (the severity_counts basis). */
  issue_count?: number | undefined;
  /** Every place those issues were found. */
  finding_occurrence_count?: number | undefined;
}

export interface GraphRollupContainer {
  context?: { workload?: string; image?: string; environment?: string; account?: string };
  id: string;
  label: string;
  entity_type: string;
  severity: string;
  is_container: boolean;
  has_children: boolean;
  direct_child_count: number;
  aggregate: GraphRollupAggregate;
  /** Other top-level scopes linked by non-containment edges, counted server-side before any row cap. */
  connections?: { connected_entry_count: number; relationship_count: number };  /** Effective provider: declared on the scope or inherited over a recorded containment/hosting edge. */
  cloud_provider?: string;
  /** `declared`, `inherited:<relationship>`, or empty when no provider is recorded. */
  cloud_provider_basis?: string;
}

export interface GraphRollupSummary {
  total_nodes?: number;
  /** Estate node count before the loader bounded the snapshot. Equals
   * `total_nodes` on an unbounded load; larger when the load was truncated. */
  total_nodes_source?: number;
  total_edges?: number;
  top_level_count?: number;
  container_count?: number;
  orphan_count?: number;
  orphan_shown_count?: number;
  orphan_truncated_count?: number;
  direct_child_count?: number;
  /** Direct children left after filters; the pageable drill-down total. */
  matching_child_count?: number;
  returned_child_count?: number;
  /** Estate-wide distinct open issues; equals the overview's issue total. */
  issue_count?: number;
  finding_occurrence_count?: number;
  /** Estate-wide open issues by severity, the same basis as `issue_count`. */
  issue_severity_counts?: Partial<Record<"critical" | "high" | "medium" | "low" | "info" | "none", number>>;
}

/** Offset page over a drill-down's ranked direct children. */
export interface GraphRollupPagination {
  offset: number;
  limit: number | null;
  returned: number;
  total: number;
  has_more: boolean;
  next_offset: number | null;
}

export interface GraphRollupOrphanSummarySample {
  id: string;
  label: string;
  entity_type: string;
  severity: string;
}

export interface GraphRollupOrphanSummary {
  total: number;
  shown: number;
  truncated: number;
  by_type: Record<string, number>;
  severity_counts: Record<string, number>;
  worst_severity: string;
  worst_severity_rank: number;
  internet_exposed: boolean;
  toxic_combo: boolean;
  exposed_count: number;
  toxic_count: number;
  sample: GraphRollupOrphanSummarySample[];
}

export interface GraphRollupResponse {
  snapshot_generation?: string;
  scan_id: string;
  tenant_id: string;
  created_at: string;
  mode: "rollup" | "drilldown" | "attack_path";
  filters: Record<string, unknown>;
  top_level?: GraphRollupContainer[];
  orphan_summary?: GraphRollupOrphanSummary;
  children?: GraphRollupContainer[];
  /** Container-to-container relationships, aggregated. Containment is excluded
   *  — that is the nesting the roll-up already expresses. */
  edges?: GraphRollupEdge[];
  /** Counts for the aggregated relationship rows, independent from node
   * completeness. `source_total` is exact for the graph used to build this
   * roll-up; `source_truncated` says when that source graph was already bounded. */
  edge_count_metadata?: GraphRollupEdgeCountMetadata;
  /** Reconciles returned-entry descendant counts when containment scopes overlap. */
  aggregate_count_metadata?: GraphRollupAggregateCountMetadata;
  node?: {
    id: string;
    label: string;
    entity_type: string;
    severity: string;
    cloud_provider?: string;
    cloud_provider_basis?: string;
  } | null;
  summary: GraphRollupSummary;
  /** Present on drill-down responses. */
  pagination?: GraphRollupPagination;
  /** Completeness of the returned roll-up nodes/containers. */
  completeness: GraphCompleteness;
}

export interface GraphRollupAggregateCountMetadata {
  basis: "returned_entry_descendants";
  definition: string;
  distinct_descendants: number;
  descendant_memberships: number;
  shared_descendants: number;
  extra_memberships: number;
  /** True only for the returned entries over the loaded source, not the whole estate. */
  additive: boolean;
  /** Distinct finding occurrences across every evaluated entry; entries sharing a server each count its occurrences. */
  distinct_finding_occurrences?: number;
  finding_occurrence_memberships?: number;
  occurrences_additive?: boolean;
  source_truncated: boolean;
  reason: string;
}

export interface GraphRollupEdgeCountMetadata {
  definition: string;
  source_total: number;
  returned: number;
  truncated: boolean;
  source_truncated: boolean;
  reason: string;
}

export interface GraphRollupEdge {
  source: string;
  target: string;
  /** How many underlying edges collapsed into this one. */
  count: number;
  relationships: string[];
  /** Absent on older servers; never infer direction from a relationship name. */
  directions?: string[] | null;
  relationship_counts?: Record<string, number> | null;
}

export interface GraphSearchResponse {
  snapshot_generation?: string;
  query: string;
  results: UnifiedNode[];
  pagination: GraphPagination;
}

export type GraphSemanticClusterKind =
  | "package_family"
  | "cve_family"
  | "agent_fleet"
  | "server_fleet"
  | "credential_family"
  | "tool_capability"
  | "source_environment";

export type GraphSemanticClusterExpansion = Required<ApiSchemas["SemanticClusterExpansion"]>;

export type GraphSemanticCluster = Omit<ApiSchemas["SemanticCluster"], "kind" | "expansion"> & {
  kind: GraphSemanticClusterKind;
  expansion: GraphSemanticClusterExpansion;
};

export type GraphSemanticClustersResponse = Pick<ApiSchemas["GraphClustersResponse"],
  "scan_id" | "tenant_id" | "created_at" | "stats"
> & {
  clusters: GraphSemanticCluster[];
  available_kinds: GraphSemanticClusterKind[];
};

export type GraphAgentSelectorItem = Pick<ApiSchemas["GraphAgentRecord"],
  "id" | "label" | "risk_score" | "severity" | "status" | "data_sources" | "first_seen" | "last_seen"
> & {
  risk_assessment?: import("@/lib/node-risk-assessment").NodeRiskAssessment | undefined;
};

export type GraphAgentsResponse = Pick<ApiSchemas["GraphAgentsResponse"], "scan_id" | "tenant_id" | "created_at"> & {
  snapshot_generation?: string;
  agents: GraphAgentSelectorItem[];
  pagination: GraphPagination;
};

/** Lifecycle classification the drift lens paints onto graph nodes/edges. */
export type GraphChangeKind = "new" | "removed" | "changed" | "unchanged";

/**
 * Server-computed map from node id / `source|target|relationship` edge key to
 * its change kind between two snapshots. Entries absent from the map are
 * treated as `unchanged`. Populated by `/v1/graph/diff`.
 */
export interface GraphChangeKindIndex {
  nodes: Record<string, GraphChangeKind>;
  edges: Record<string, GraphChangeKind>;
}

/**
 * Rich node record emitted by `/v1/graph/diff` for added/removed nodes.
 * Shape mirrors the backend `node_diff_metadata`, plus a `change_kind` tag
 * the route attaches for the drift lens.
 */
export interface GraphDiffNode {
  id: string;
  entity_type: string;
  label: string;
  status: string;
  severity: string;
  severity_id: number;
  risk_score: number;
  attributes?: Record<string, unknown> | undefined;
  compliance_tags?: string[] | undefined;
  change_kind?: string | undefined;
}

export interface GraphDiffResponse {
  /** Added/removed nodes are full node objects. */
  nodes_added: GraphDiffNode[];
  nodes_removed: GraphDiffNode[];
  /** Changed nodes are emitted as bare node-id strings. */
  nodes_changed: string[];
  edges_added: [string, string, string][];
  edges_removed: [string, string, string][];
  change_kind_index?: GraphChangeKindIndex | undefined;
  attribute_deltas?: Record<string, GraphAttributeDelta[]> | undefined;
  /** Exact counts; the lists above stop at the server's row/byte cap when `truncated`. */
  summary?: { totals: Record<"nodes" | "edges", GraphDiffChangeCounts> } | undefined;
  truncated?: boolean | undefined;
  total_changes?: number | undefined;
  returned_changes?: number | undefined;
}

export interface GraphEstateSnapshotRef {
  scan_id: string;
  job_id: string;
  captured_at: string;
}

/** A changed node named by the diff summary's highlights. */
export interface GraphEstateHighlightNode {
  kind: "node" | "edge";
  change: "added" | "removed" | "changed";
  id?: string;
  entity_type?: string;
  label?: string;
  severity?: string;
  source?: string;
  target?: string;
  /** Endpoint display names for a highlighted edge, from the snapshot that holds it. */
  source_label?: string;
  target_label?: string;
  relationship?: string;
  /** Vendor the changed node (or a relationship's target) recorded; absent when none was recorded. */
  vendor?: string;
}

/** A stored attack path present on one side of the comparison only. */
export interface GraphEstatePathChange {
  source: string;
  target: string;
  /** Endpoint display names from the snapshot that holds the path; absent on older servers. */
  source_label?: string;
  target_label?: string;
  hops: string[];
  /** The path's unique exposure_path_id; absent on older servers. */
  exposure_path_id?: string;
  composite_risk: number;
  summary: string;
  /** Vendor the path's target (else source) recorded; absent when none was recorded. */
  vendor?: string;
}

export interface GraphChangeAttribution {
  unit: "nodes";
  sources: Array<{ vendor: string; account: string } & GraphDiffChangeCounts>;
  omitted_sources: number;
  unattributed: GraphDiffChangeCounts;
}

export interface GraphEstateHighlights {
  new_critical_findings?: { count: number; top: GraphEstateHighlightNode[] };
  new_credential_reach?: { count: number; top: GraphEstateHighlightNode[] };
  removed_controls?: { count: number; top: GraphEstateHighlightNode[] };
  new_attack_paths?: { status: string; count: number; count_is_lower_bound?: boolean; top: GraphEstatePathChange[] };
  removed_attack_paths?: { status: string; count: number; count_is_lower_bound?: boolean; top: GraphEstatePathChange[] };
}

/** One target scope compared with its comparable previous snapshot. */
export interface GraphEstateChangeSource {
  scope_id: string;
  label: string;
  /** `default_scan_request`: the label is only the unnamed-request fallback, not a vendor source. */
  label_basis?: "default_scan_request" | "scan_target";
  old: GraphEstateSnapshotRef;
  new: GraphEstateSnapshotRef;
  /** The scope's own earlier scan, or the store's declared earlier snapshot for a scope scanned once. */
  baseline?: "scope_history" | "snapshot_continuity";
  counts: Record<"nodes" | "edges", GraphDiffChangeCounts>;
  total_changes: number;
  nodes_by_entity_type: Record<string, GraphDiffChangeCounts>;
  /** Changed nodes per vendor and account recorded on each node; absent on older servers. */
  changes_by_source?: GraphChangeAttribution | undefined;
  highlights: GraphEstateHighlights;
  /** Open issue groups the posture trend recorded for both scans; null when either scan has no recorded point. */
  issue_change?: GraphEstateIssueChange | null | undefined;
  skipped_snapshots: number;
}

export type IssueSnapshotCounts = Record<"critical" | "high" | "medium" | "low" | "total", number>;

export interface GraphEstateIssueChange {
  basis: string;
  old: IssueSnapshotCounts;
  new: IssueSnapshotCounts;
}

/** A scope with no earlier snapshot to compare: never counted as additions. */
export interface GraphEstateFirstObservation {
  scope_id: string;
  label: string;
  new: GraphEstateSnapshotRef;
  reason: "first_observation" | "previous_graph_unavailable";
  node_count: number;
  edge_count: number;
  skipped_snapshots: number;
}

export type GraphEstateChangesResponse = ContractEnvelope<
  ApiSchemas["GraphEstateChangesResponse"],
  {
    sources: GraphEstateChangeSource[];
    new_sources: GraphEstateFirstObservation[];
    totals: Record<"nodes" | "edges", GraphDiffChangeCounts> & {
      changed_sources: number;
      unchanged_sources: number;
      new_sources: number;
    };
  }
>;

export interface GraphDiffChangeCounts {
  added: number;
  removed: number;
  changed: number;
}

export interface GraphAttributeDelta {
  field: string;
  before: unknown;
  after: unknown;
  summary: string;
}

/** Rich edge record returned by `/v1/graph/edges/changes` and `/v1/graph/edges/active`. */
export interface GraphEdgeHistoryRecord {
  source_id: string;
  target_id: string;
  relationship: string;
  direction: string;
  weight: number;
  traversable: boolean;
  confidence: number;
  provenance: Record<string, unknown>;
  evidence: Record<string, unknown>;
  valid_from?: string | undefined;
  valid_to?: string | null | undefined;
  first_seen?: string | undefined;
  last_seen?: string | undefined;
  scan_id?: string | undefined;
}

export interface GraphEdgeChangePair {
  before: GraphEdgeHistoryRecord;
  after: GraphEdgeHistoryRecord;
}

export interface GraphEdgeChangesSummary {
  added: number;
  removed: number;
  changed: number;
  unchanged: number;
}

export interface GraphEdgeChangesResponse {
  scan_id_old: string;
  scan_id_new: string;
  edges_added: GraphEdgeHistoryRecord[];
  edges_removed: GraphEdgeHistoryRecord[];
  edges_changed: GraphEdgeChangePair[];
  edges_unchanged: GraphEdgeHistoryRecord[];
  summary: GraphEdgeChangesSummary;
}

export type GraphExportFormat =
  "json" | "dot" | "mermaid" | "graphml" | "cypher";
