/**
 * Unified Graph Schema — TypeScript surface for the Python graph schema.
 *
 * As of #2255 the canonical taxonomy (entity types + relationship types)
 * is generated from the Python source via `npm run codegen:graph-schema`
 * into ./graph-schema.generated.ts. This file re-exports the generated
 * kind enums. Wire fields come from the generated OpenAPI contract; legacy
 * snapshot compatibility and shared display constants remain here.
 *
 * When adding a new entity / edge type:
 *   1. Add it to agent_bom.graph.types in Python.
 *   2. Run `cd ui && npm run codegen:graph-schema` to refresh
 *      graph-schema.generated.ts.
 *   3. Extend the display color maps in this file to cover the new key.
 */

import type { components } from "./api-schema.generated";

type GraphApiSchemas = components["schemas"];

// Re-export the codegen output so consumers can keep the
// `from "@/lib/graph-schema"` import path while still resolving the
// generated, drift-checked enum/union types.
export {
  GRAPH_SCHEMA_VERSION,
  GraphNodeKind,
  GraphEdgeKind,
  GRAPH_NODE_KINDS,
  GRAPH_EDGE_KINDS,
  GRAPH_NODE_KIND_META,
  GRAPH_EDGE_KIND_META,
  isGraphNodeKind,
  isGraphEdgeKind,
} from "./graph-schema.generated";
export type {
  GraphNodeKindKey,
  GraphEdgeKindKey,
  GraphNodeKindMeta,
  GraphEdgeKindMeta,
} from "./graph-schema.generated";

// ═══════════════════════════════════════════════════════════════════════════
// Enums
// ═══════════════════════════════════════════════════════════════════════════

export enum EntityType {
  // Inventory entities (OCSF Category 5)
  AGENT = "agent",
  SERVER = "server",
  PACKAGE = "package",
  TOOL = "tool",
  TOOL_CALL = "tool_call",
  MODEL = "model",
  FRAMEWORK = "framework",
  DATASET = "dataset",
  CONTAINER = "container",
  RESOURCE = "resource",
  CLOUD_RESOURCE = "cloud_resource",
  SOURCE_FILE = "source_file",
  CODE_MODULE = "code_module",
  CONFIG_FILE = "config_file",
  EXTERNAL_IMPORT = "external_import",
  DIRECTORY = "directory",
  CI_JOB = "ci_job",
  // Finding entities (OCSF Category 2)
  VULNERABILITY = "vulnerability",
  MISCONFIGURATION = "misconfiguration",
  // Inventory but security-relevant (OCSF Category 5)
  CREDENTIAL = "credential",
  CREDENTIAL_REF = "credential_ref",
  // Identity & governance (OCSF Category 3)
  ORG = "org",
  ACCOUNT = "account",
  USER = "user",
  GROUP = "group",
  ROLE = "role",
  POLICY = "policy",
  SERVICE_ACCOUNT = "service_account",
  SERVICE_PRINCIPAL = "service_principal",
  FEDERATED_IDENTITY = "federated_identity",
  // Agent-identity governance control plane
  MANAGED_IDENTITY = "managed_identity",
  ACCESS_GRANT = "access_grant",
  ACCESS_POLICY = "access_policy",
  BLUEPRINT = "blueprint",
  // Behavioral drift (detection finding)
  DRIFT_INCIDENT = "drift_incident",
  // Cloud-CNAPP primitives
  DATA_STORE = "data_store",
  API_GATEWAY = "api_gateway",
  // Application Security Posture Management (ASPM)
  APPLICATION = "application",
  // Organizational hierarchy
  PROVIDER = "provider",
  ENVIRONMENT = "environment",
  FLEET = "fleet",
  CLUSTER = "cluster",
}

export enum RelationshipType {
  // Static inventory
  HOSTS = "hosts",
  HOSTED_ON = "hosted_on",
  USES = "uses",
  USES_FRAMEWORK = "uses_framework",
  DEPENDS_ON = "depends_on",
  PROVIDES_TOOL = "provides_tool",
  EXPOSES_CRED = "exposes_cred",
  REACHES_TOOL = "reaches_tool",
  SERVES_MODEL = "serves_model",
  CONTAINS = "contains",
  IMPORTS = "imports",
  DEFINES = "defines",
  RUNS = "runs",
  CONFIGURES = "configures",
  OBSERVES = "observes",
  // Vulnerability
  AFFECTS = "affects",
  VULNERABLE_TO = "vulnerable_to",
  EXPLOITABLE_VIA = "exploitable_via",
  REMEDIATES = "remediates",
  TRIGGERS = "triggers",
  // Lateral movement
  SHARES_SERVER = "shares_server",
  SHARES_CRED = "shares_cred",
  LATERAL_PATH = "lateral_path",
  // Ownership & governance
  MANAGES = "manages",
  OWNS = "owns",
  PART_OF = "part_of",
  MEMBER_OF = "member_of",
  ASSUMES = "assumes",
  TRUSTS = "trusts",
  ATTACHED = "attached",
  INHERITS = "inherits",
  CAN_ACCESS = "can_access",
  CROSS_ACCOUNT_TRUST = "cross_account_trust",
  // Runtime
  ACTED_AS = "acted_as",
  INVOKED = "invoked",
  CALLED = "called",
  ACCESSED = "accessed",
  TRACE_STEP = "trace_step",
  USED_CREDENTIAL = "used_credential",
  DELEGATED_TO = "delegated_to",
  // Cross-environment correlation (#1892)
  CORRELATES_WITH = "correlates_with",
  POSSIBLY_CORRELATES_WITH = "possibly_correlates_with",

  // Agent-identity governance
  AUTHENTICATES_AS = "authenticates_as",
  SCOPED_TO = "scoped_to",
  GOVERNS = "governs",
  EXHIBITS_DRIFT = "exhibits_drift",

  // Cloud-CNAPP: exposure, data reachability, effective permissions
  EXPOSED_TO = "exposed_to",
  STORES = "stores",
  HAS_PERMISSION = "has_permission",
  PROTECTS = "protects",

  // Application Security Posture Management (ASPM)
  BELONGS_TO = "belongs_to",
}

export enum NodeStatus {
  ACTIVE = "active",
  INACTIVE = "inactive",
  VULNERABLE = "vulnerable",
  REMEDIATED = "remediated",
}

// Compile-time parity guard — fails the typecheck if the hand-rolled
// EntityType / RelationshipType enums above drift from the generated
// GraphNodeKind / GraphEdgeKind. The generated file is the source of
// truth (#2255); this guard turns drift into a tsc error rather than a
// silent runtime miss.
import type {
  GraphNodeKindKey as _GraphNodeKindKey,
  GraphEdgeKindKey as _GraphEdgeKindKey,
} from "./graph-schema.generated";
type _AssertExtends<T extends U, U> = T;
type _EntityTypeValue = `${EntityType}`;
type _RelationshipTypeValue = `${RelationshipType}`;
type _NodeParity = _AssertExtends<_EntityTypeValue, _GraphNodeKindKey>;
type _EdgeParity = _AssertExtends<_RelationshipTypeValue, _GraphEdgeKindKey>;
type _GeneratedNodeParity = _AssertExtends<_GraphNodeKindKey, _EntityTypeValue>;
type _GeneratedEdgeParity = _AssertExtends<
  _GraphEdgeKindKey,
  _RelationshipTypeValue
>;
// Surface the helper aliases so they aren't pruned as unused imports.
export type _GraphSchemaParity = [
  _NodeParity,
  _EdgeParity,
  _GeneratedNodeParity,
  _GeneratedEdgeParity,
];

/** String severity → numeric rank for sorting (0-5, higher = worse) */
export const SEVERITY_RANK: Record<string, number> = {
  critical: 5,
  high: 4,
  medium: 3,
  low: 2,
  info: 1,
  informational: 1,
  none: 0,
  unknown: 0,
};

// ═══════════════════════════════════════════════════════════════════════════
// Core interfaces
// ═══════════════════════════════════════════════════════════════════════════

export type NodeDimensions = Pick<GraphApiSchemas["GraphNodeDimensions"],
  "ecosystem" | "cloud_provider" | "agent_type" | "surface" | "environment"
>;

/** Current wire fields, with provenance optional for legacy snapshots. */
export type UnifiedNode = Pick<GraphApiSchemas["GraphNodeRecord"],
  "id" | "entity_type" | "label" |
  "status" | "risk_score" | "severity" | "first_seen" | "last_seen" |
  "attributes" | "compliance_tags" | "data_sources"
> & {
  category_uid?: GraphApiSchemas["GraphNodeRecord"]["category_uid"];
  class_uid?: GraphApiSchemas["GraphNodeRecord"]["class_uid"];
  type_uid?: GraphApiSchemas["GraphNodeRecord"]["type_uid"];
  severity_id?: GraphApiSchemas["GraphNodeRecord"]["severity_id"];
  dimensions: NodeDimensions;
  evidence_provenance?: GraphApiSchemas["GraphNodeRecord"]["evidence_provenance"];
  risk_assessment?: import("@/lib/node-risk-assessment").NodeRiskAssessment | undefined;
};

export type UnifiedEdge = Pick<GraphApiSchemas["GraphEdgeRecord"],
  "id" | "source" | "target" | "relationship" | "weight" | "traversable" |
  "first_seen" | "last_seen" | "evidence"
> & {
  activity_id?: GraphApiSchemas["GraphEdgeRecord"]["activity_id"];
  direction: "directed" | "bidirectional";
  source_scan_id?: GraphApiSchemas["GraphEdgeRecord"]["source_scan_id"] | null | undefined;
};

/**
 * A typed MITRE ATT&CK / ATLAS technique mapped to one hop of an attack path.
 *
 * These are *potential* techniques derived from the graph's observed evidence
 * (the hop's edge relationship + target entity type + edge evidence), NOT a
 * claim that the technique was detected being used. A hop whose evidence maps
 * to no known technique is simply left without a mapping (fail-closed). Mirrors
 * the Python `TechniqueMapping` (agent_bom.graph.container).
 */
export type TechniqueMapping = Required<Pick<GraphApiSchemas["TechniqueMapping"],
  "hop_index" | "technique_id" | "technique_name" | "catalog" | "tactics" | "provenance" | "confidence"
>> & {
  evidence_basis?: "observed" | "runtime_observed" | "inferred" | "modeled" | null;
};

export type HopAuthorityEvidence = {
  status: "recorded" | "partial";
  decisions: Array<{
    source: "authorization-evidence";
    provider: "azure" | "gcp";
    decision: "allow" | "explicit_deny" | "implicit_deny" | "indeterminate";
    action: string;
    principal_id: string | null;
    resource: string | null;
    binding_ids: string[];
    observed_at: string | null;
  }>;
  native_grants?: Array<{
    source: "snowflake-objects";
    privilege: string;
    account: string | null;
    role: string | null;
    object_fqn: string | null;
    object_type: string | null;
  }>;
  derivation: {
    basis: "recorded_graph_connections";
    source_scan_id: string;
    path_selection: "one_shortest_path_per_grant_and_access";
    paths: Array<{
      access: "direct" | "group" | "assume_chain";
      grant_principal_id: string;
      grant_edge_id: string;
      source_edge_ids: string[];
    }>;
    truncated: boolean;
  } | null;
  reason_codes: string[];
};

export interface GraphHopEvidence {
  canonical_edge_id?: string | null;
  runtime_references?: Array<{ event_id?: string; trace_id?: string }> | undefined;
  source_node_id: string;
  target_node_id: string;
  relationship: string;
  source_snapshot_ids: string[];
  relationship_provenance?: "recorded" | "unavailable";
  correlation_identity_status?: "current" | "recomputation_required" | "unavailable";
  evidence_tier: "static_scan" | "modeled_infrastructure" | "runtime_observed" | "recorded" | "derived" | "legacy_unrecorded" | "unknown" | string;
  confidence: number | null;
  freshness: "fresh" | "stale_allowed" | "unknown" | string;
  runtime_observed_state: "observed" | "blocked" | "not_observed" | string;
  direction: string;
  traversable: boolean;
  complete: boolean;
  truncated: boolean;
  runtime_outcome?: "blocked" | "failed" | "unknown" | undefined;
  reason_codes?: string[] | undefined;
  authority?: HopAuthorityEvidence | null;
}

/** Stored paths may predate reachability, technique and finding-ID evidence. */
export type AttackPath = Pick<GraphApiSchemas["GraphAttackPathRecord"],
  "source" | "target" | "hops" | "edges" | "composite_risk" | "summary" |
  "credential_exposure" | "tool_exposure" | "vuln_ids"
> & Partial<Pick<GraphApiSchemas["GraphAttackPathRecord"],
  "finding_ids" | "reachability" | "reachability_basis" | "mitre_technique_ids"
>> & {
  /** Server-ranked finding severity; never inferred from composite_risk. */
  severity?: string;
  /** Immutable source receipts for every directed hop in correlated snapshots. */
  hop_evidence?: GraphHopEvidence[];
  /** Completeness and limits for the analysis that produced this path. */
  analysis?: {
    status?: GraphAnalysisState | string;
    reason_codes?: string[];
    limits?: Record<string, number>;
    observed?: Record<string, number>;
  };
  /** Potential mapped techniques, not observed attacker activity. */
  technique_mappings?: TechniqueMapping[];
  /** Server queue sort values; absent on legacy payloads. */
  ranking_factors?: AttackPathRankingFactors;
};

export type AttackPathEvidenceConfidence = "verified" | "likely" | "structural" | "unassessed" | "disproven";

export interface AttackPathRankingFactors {
  order: string[];
  evidence_tier: number;
  is_kev: boolean;
  /** Worst finding severity on the path; "unknown" means no scored finding (unscored). */
  severity: string;
  severity_scored: boolean;
  /** Hop-receipt support, separate from composite_risk. */
  evidence_confidence: AttackPathEvidenceConfidence | string;
  composite_risk: number;
  credential_count: number;
  /** Tie-breakers after credential_count; read from path evidence, never added to composite_risk. */
  max_epss?: number;
  internet_exposed?: boolean;
  environment_weight?: number;
  hop_count?: number;
  reasons: string[];
}

export interface InteractionRisk {
  pattern: string;
  agents: string[];
  risk_score: number;
  description: string;
  owasp_agentic_tag?: string;
}

export type GraphAnalysisState =
  | "complete"
  | "limited"
  | "skipped"
  | "failed"
  | "not_recorded";

export interface GraphAnalysisStatus {
  status: GraphAnalysisState;
  reason_codes: string[];
  limits: Record<string, number>;
  observed: Record<string, number>;
}

export interface GraphStats {
  total_nodes: number;
  /** Estate node count before any load-time node budget. Equals `total_nodes`
   * on an unbounded load; reconciles with `completeness.total` when truncated. */
  total_nodes_source?: number;
  total_edges: number;
  node_types: Record<string, number>;
  severity_counts: Record<string, number>;
  /** What `severity_counts` counts: finding-bearing graph nodes, not issues or occurrences. */
  severity_basis?: "graph_nodes";
  relationship_types: Record<string, number>;
  attack_path_count: number;
  interaction_risk_count: number;
  max_attack_path_risk: number;
  highest_interaction_risk: number;
  analysis_status?: Record<string, GraphAnalysisStatus>;
}

export interface UnifiedGraphData {
  snapshot_generation?: string;
  scan_id: string;
  tenant_id: string;
  created_at: string;
  nodes: UnifiedNode[];
  edges: UnifiedEdge[];
  attack_paths: AttackPath[];
  interaction_risks: InteractionRisk[];
  stats: GraphStats;
}

// ═══════════════════════════════════════════════════════════════════════════
// Display constants
// ═══════════════════════════════════════════════════════════════════════════

/** Canonical node colors by entity type */
export const ENTITY_COLOR_MAP: Record<string, string> & Record<EntityType, string> = {
  [EntityType.AGENT]: "#10b981", // emerald
  [EntityType.SERVER]: "#3b82f6", // blue
  [EntityType.PACKAGE]: "#52525b", // zinc
  [EntityType.TOOL]: "#a855f7", // purple
  [EntityType.TOOL_CALL]: "#9333ea", // purple
  [EntityType.MODEL]: "#8b5cf6", // violet
  [EntityType.FRAMEWORK]: "#06b6d4", // cyan
  [EntityType.DATASET]: "#06b6d4", // cyan
  [EntityType.CONTAINER]: "#6366f1", // indigo
  [EntityType.RESOURCE]: "#3b82f6", // blue
  [EntityType.CLOUD_RESOURCE]: "#0ea5e9", // sky
  [EntityType.SOURCE_FILE]: "#22d3ee", // cyan
  [EntityType.CODE_MODULE]: "#06b6d4", // cyan
  [EntityType.CONFIG_FILE]: "#f97316", // orange
  [EntityType.EXTERNAL_IMPORT]: "#f59e0b", // amber
  [EntityType.DIRECTORY]: "#0d9488", // teal
  [EntityType.CI_JOB]: "#a855f7", // purple
  [EntityType.VULNERABILITY]: "#ef4444", // red
  [EntityType.CREDENTIAL]: "#f59e0b", // amber
  [EntityType.CREDENTIAL_REF]: "#facc15", // yellow
  [EntityType.MISCONFIGURATION]: "#f97316", // orange
  [EntityType.ORG]: "#115e59", // teal
  [EntityType.ACCOUNT]: "#0f766e", // teal
  [EntityType.USER]: "#14b8a6", // teal
  [EntityType.GROUP]: "#0d9488", // teal
  [EntityType.ROLE]: "#ea580c", // orange
  [EntityType.POLICY]: "#d97706", // amber
  [EntityType.SERVICE_ACCOUNT]: "#0f766e", // teal
  [EntityType.SERVICE_PRINCIPAL]: "#0f766e", // teal
  [EntityType.FEDERATED_IDENTITY]: "#0e7490", // cyan
  [EntityType.MANAGED_IDENTITY]: "#0891b2", // cyan
  [EntityType.ACCESS_GRANT]: "#ca8a04", // amber
  [EntityType.ACCESS_POLICY]: "#a16207", // amber
  [EntityType.BLUEPRINT]: "#7c3aed", // violet
  [EntityType.DRIFT_INCIDENT]: "#fb923c", // orange
  [EntityType.DATA_STORE]: "#0284c7", // sky
  [EntityType.API_GATEWAY]: "#2563eb", // blue
  [EntityType.APPLICATION]: "#7c3aed", // violet
  [EntityType.PROVIDER]: "#6b7280", // gray
  [EntityType.ENVIRONMENT]: "#6b7280", // gray
  [EntityType.FLEET]: "#475569", // slate
  [EntityType.CLUSTER]: "#4f46e5", // indigo
};

/** Canonical edge colors by relationship type */
export const RELATIONSHIP_COLOR_MAP: Record<string, string> & Record<RelationshipType, string> = {
  [RelationshipType.HOSTS]: "#6b7280",
  [RelationshipType.HOSTED_ON]: "#78716c",
  [RelationshipType.USES]: "#10b981",
  [RelationshipType.USES_FRAMEWORK]: "#06b6d4",
  [RelationshipType.DEPENDS_ON]: "#52525b",
  [RelationshipType.PROVIDES_TOOL]: "#a855f7",
  [RelationshipType.EXPOSES_CRED]: "#f59e0b",
  [RelationshipType.REACHES_TOOL]: "#fbbf24",
  [RelationshipType.SERVES_MODEL]: "#8b5cf6",
  [RelationshipType.CONTAINS]: "#6366f1",
  [RelationshipType.IMPORTS]: "#22d3ee",
  [RelationshipType.DEFINES]: "#06b6d4",
  [RelationshipType.RUNS]: "#a855f7",
  [RelationshipType.CONFIGURES]: "#f97316",
  [RelationshipType.OBSERVES]: "#22d3ee",
  [RelationshipType.AFFECTS]: "#ef4444",
  [RelationshipType.VULNERABLE_TO]: "#ef4444",
  [RelationshipType.EXPLOITABLE_VIA]: "#dc2626",
  [RelationshipType.SHARES_SERVER]: "#22d3ee",
  [RelationshipType.SHARES_CRED]: "#f97316",
  [RelationshipType.LATERAL_PATH]: "#ea580c",
  [RelationshipType.ACTED_AS]: "#14b8a6",
  [RelationshipType.INVOKED]: "#10b981",
  [RelationshipType.CALLED]: "#a855f7",
  [RelationshipType.ACCESSED]: "#3b82f6",
  [RelationshipType.TRACE_STEP]: "#6366f1",
  [RelationshipType.USED_CREDENTIAL]: "#facc15",
  [RelationshipType.DELEGATED_TO]: "#a855f7",
  [RelationshipType.CORRELATES_WITH]: "#0ea5e9",
  [RelationshipType.POSSIBLY_CORRELATES_WITH]: "#7dd3fc",
  // Vulnerability lifecycle relations (audit-4 P1: missing UI colors).
  [RelationshipType.REMEDIATES]: "#22c55e",
  [RelationshipType.TRIGGERS]: "#f97316",
  // Ownership / governance relations.
  [RelationshipType.MANAGES]: "#14b8a6",
  [RelationshipType.OWNS]: "#0d9488",
  [RelationshipType.PART_OF]: "#6b7280",
  [RelationshipType.MEMBER_OF]: "#4b5563",
  [RelationshipType.ASSUMES]: "#ea580c",
  [RelationshipType.TRUSTS]: "#0891b2",
  [RelationshipType.ATTACHED]: "#d97706",
  [RelationshipType.INHERITS]: "#a16207",
  [RelationshipType.CAN_ACCESS]: "#dc2626",
  [RelationshipType.CROSS_ACCOUNT_TRUST]: "#be123c",
  // Agent-identity governance relations.
  [RelationshipType.AUTHENTICATES_AS]: "#0891b2",
  [RelationshipType.SCOPED_TO]: "#22d3ee",
  [RelationshipType.GOVERNS]: "#a16207",
  [RelationshipType.EXHIBITS_DRIFT]: "#fb923c",
  // Cloud-CNAPP relations.
  [RelationshipType.EXPOSED_TO]: "#e11d48",
  [RelationshipType.STORES]: "#0284c7",
  [RelationshipType.HAS_PERMISSION]: "#dc2626",
  [RelationshipType.PROTECTS]: "#2563eb",
  // ASPM relations.
  [RelationshipType.BELONGS_TO]: "#7c3aed",
};

// ═══════════════════════════════════════════════════════════════════════════
// Layout options
// ═══════════════════════════════════════════════════════════════════════════

export enum GraphLayout {
  DAGRE = "dagre",
  FORCE = "force",
  RADIAL = "radial",
  SANKEY = "sankey",
  HIERARCHICAL = "hierarchical",
  GRID = "grid",
}

/** Entity types that represent actual security findings (for SIEM export) */
export const FINDING_ENTITY_TYPES: Set<EntityType> = new Set([
  EntityType.VULNERABILITY,
  EntityType.MISCONFIGURATION,
  EntityType.DRIFT_INCIDENT,
]);
