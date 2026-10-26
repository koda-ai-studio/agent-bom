// ─── Surface-parity types (#4014) ─────────────────────────────────────────────
// Human UIs for three flagship API/MCP-only surfaces: signed audit export/verify
// (P1-2), the "should I deploy" gate, and the ExposurePath lens (P1-3). Response
// shapes mirror the backend contracts in api/routes/enterprise.py + routes/graph.py.

/** Signed audit evidence packet: JSON body + its detached HMAC signature header. */
export interface AuditExportPacket {
  /** The export body returned by GET /v1/audit/export. */
  payload: unknown;
  /** X-Agent-Bom-Audit-Export-Signature header value (empty if the server omitted it). */
  signature: string;
}

/** Result of POST /v1/audit/export/verify — tamper-evident PASS/FAIL, no key material. */
export interface AuditExportVerifyResult {
  valid: boolean;
  payload_bytes: number;
}

export interface GraphExposureEntityRef {
  entityType?: string | undefined;
  rawLabel?: string | undefined;
  id: string;
  label: string;
  role: string;
  severity?: string | undefined;
  riskScore?: number | undefined;
}

export interface GraphExposureRelationshipRef {
  id: string;
  source: string;
  target: string;
  relationship: string;
  confidence?: number | undefined;
  direction?: "directed" | "bidirectional" | undefined;
  traversable?: boolean | undefined;
}

/** One ranked ExposurePath as returned by the MCP-compatible REST surface. */
export interface GraphExposurePath {
  evidence?: import("@/lib/exposure-path").ExposureEvidenceSummary | undefined;
  dependencyContext?: import("@/lib/exposure-path").ExposureDependencyContext | undefined;
  id: string;
  rank?: number | undefined;
  label: string;
  summary?: string | undefined;
  riskScore: number;
  severity: string;
  source: GraphExposureEntityRef;
  target: GraphExposureEntityRef;
  hops: GraphExposureEntityRef[];
  relationships: GraphExposureRelationshipRef[];
  nodeIds: string[];
  edgeIds: string[];
  findings: string[];
  reachableTools: string[];
  exposedCredentials: string[];
  reachability?: string | undefined;
  reachabilityBasis?: string[] | undefined;
  evidenceDimensions?: import("@/lib/exposure-path").ExposureEvidenceDimensions | undefined;
  hopEvidence?: import("@/lib/graph-schema").GraphHopEvidence[] | undefined;
  provenance?: { source: string; scanId?: string | undefined } | undefined;
}

export interface GraphExposurePathsResponse {
  schema_version: string;
  tool: string;
  tenant_id: string;
  scan_id: string;
  created_at?: string | null | undefined;
  count: number;
  total: number;
  filters: { limit: number; min_risk: number };
  paths: GraphExposurePath[];
  message?: string | undefined;
  count_metadata?: { source: string; total_is_lower_bound: boolean } | undefined;
  completeness?: { complete: boolean; truncated?: boolean; reason?: string } | undefined;
  pagination?: { offset: number; limit: number; returned: number; has_more: boolean; next_cursor: string | null } | undefined;
}

/** ``not_found``: no exposure path names the candidate exactly; it was not evaluated. */
export type DeployDecision = "allow" | "warn" | "block" | "not_found";

/** allow/warn/block/not_found deploy gate decision from POST /v1/graph/should-i-deploy. */
export interface GraphDeployDecisionResponse {
  schema_version: string;
  tool: string;
  tenant_id: string;
  scan_id: string;
  candidate: { value: string };
  decision: DeployDecision;
  /** Null when no path matched the candidate. */
  maxRisk: number | null;
  thresholds: { warnRisk: number; blockRisk: number };
  reasons: string[];
  matchedPathCount: number;
  matchedPaths: GraphExposurePath[];
  provenance?: { source: string; basis: string } | undefined;
}

// ─── CWPP agentless side-scan (Azure/GCP) ───────────────────────────────────

export type SideScanProvider = "aws" | "azure" | "gcp";

/** Honest per-provider side-scan executor capability (from the lifecycle module). */
export interface SideScanProviderCapability {
  provider: SideScanProvider;
  target_discovery: boolean;
  lifecycle_contract: boolean;
  executor: string;
  cli_available: boolean;
  credentialed_smoke: boolean;
}

/** Metadata-only, non-negative evidence counts for one execution. */
export interface SideScanCounts {
  package_count: number;
  vulnerability_count: number;
  secret_count: number;
  config_finding_count: number;
  ioc_finding_count: number;
}

/** One durable side-scan execution record (never a clean-workload assertion). */
export interface SideScanExecutionRecord {
  execution_id: string;
  provider: SideScanProvider;
  account_id: string;
  target_id: string;
  status: string;
  phase: string;
  cleanup_status: string;
  counts: SideScanCounts;
  failure_code: string;
  warning_codes: string[];
  updated_at: string;
  created_at: string;
}

/** GET /v1/cloud/side-scan — recent executions + capabilities for the tenant. */
export interface SideScanListResponse {
  tenant_id: string;
  executions: SideScanExecutionRecord[];
  page?: {
    limit: number;
    offset: number;
    returned: number;
    total: number;
    has_more: boolean;
    completeness: "complete";
  } | undefined;
  capabilities: SideScanProviderCapability[];
  credentialed_smoke: boolean;
}

/** POST/GET side-scan execution envelope (status can be disabled/unavailable). */
export interface SideScanExecutionResponse {
  status: string;
  execution_id: string;
  provider: SideScanProvider;
  tenant_id: string;
  execution?: SideScanExecutionRecord;
  evidence?: Record<string, unknown>;
  result?: Record<string, unknown>;
  reason?: string;
  message?: string;
  enable?: string;
}

/** Body for POST /v1/cloud/side-scan (no credential is ever sent). */
export interface SideScanTriggerRequest {
  provider: "azure" | "gcp";
  target_id: string;
  /** "image" scans a GCE image; Azure managed images are not supported. */
  target_type?: "disk" | "image";
  account_id: string;
  location: string;
  collector_id: string;
  collector_resource_group?: string;
  region?: string;
  idempotency_key?: string;
  scan_secrets_enabled?: boolean;
}

export interface AgentLifecycleRecord {
  record_id: string;
  agent_id: string;
  snapshot_id: string | null;
  recorded_at: string;
  observed_at: string | null;
  composition_digest: string | null;
  assurance: "operator_recorded";
}

export interface AgentLifecyclePage {
  history_limit_reached?: boolean;
  items: AgentLifecycleRecord[];
  next_offset: number | null;
}
