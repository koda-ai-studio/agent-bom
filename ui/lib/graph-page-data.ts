import { graphAgentContext } from "@/lib/graph-agent-context";
import type { Edge } from "@xyflow/react";

import type { FilterState } from "@/components/lineage-filter";
import type { LineageNodeData, LineageNodeType } from "@/components/lineage-nodes";
import type { GraphNodeDetailResponse, GraphQueryResponse, UnifiedGraphResponse } from "@/lib/api";
import { mergeGraphNodeDetail } from "@/lib/graph-entity-detail";
import { lineageNodeTypeForEntity } from "@/lib/graph-entity-mapping";
import { RelationshipType, type UnifiedNode } from "@/lib/graph-schema";
import { nodeRiskAssessment } from "@/lib/node-risk-assessment";

import { LARGE_GRAPH_OVERVIEW_MAX_RENDERED_NODES } from "@/lib/large-graph-overview";

// Start with a small ranked selection. The API also returns supporting ancestors;
// this request limit is not a promise about returned or rendered node counts.
// Full-estate search and scope summaries remain independent of this selection.
export function graphFetchLimitForSnapshot(scanId: string, expandedScanId: string | null): number {
  return scanId && scanId === expandedScanId ? LARGE_GRAPH_OVERVIEW_MAX_RENDERED_NODES : 50;
}

const FOCUS_NEIGHBORHOOD_DEPTH = 2;
const FOCUS_NEIGHBORHOOD_NODE_LIMIT = 80;

export function getLocalNeighborhoodIds(
  nodeId: string,
  edges: Edge[],
  maxDepth = FOCUS_NEIGHBORHOOD_DEPTH,
  maxNodes = FOCUS_NEIGHBORHOOD_NODE_LIMIT,
): Set<string> {
  const adjacency = new Map<string, Set<string>>();
  for (const edge of edges) {
    addNeighbor(adjacency, edge.source, edge.target);
    addNeighbor(adjacency, edge.target, edge.source);
  }

  const visited = new Set<string>([nodeId]);
  const queue = [{ id: nodeId, depth: 0 }];
  while (queue.length > 0) {
    const current = queue.shift()!;
    if (current.depth >= maxDepth) continue;
    for (const neighbor of adjacency.get(current.id) ?? []) {
      if (visited.has(neighbor)) continue;
      visited.add(neighbor);
      if (visited.size >= maxNodes) return visited;
      queue.push({ id: neighbor, depth: current.depth + 1 });
    }
  }

  return visited;
}

function addNeighbor(
  map: Map<string, Set<string>>,
  source: string,
  target: string,
): void {
  const existing = map.get(source);
  if (existing) {
    existing.add(target);
  } else {
    map.set(source, new Set([target]));
  }
}

export const RELATIONSHIP_SCOPE_MAP: Record<
  FilterState["relationshipScope"],
  RelationshipType[] | undefined
> = {
  all: undefined,
  inventory: [
    RelationshipType.HOSTS,
    RelationshipType.HOSTED_ON,
    RelationshipType.USES,
    RelationshipType.DEPENDS_ON,
    RelationshipType.PROVIDES_TOOL,
    RelationshipType.EXPOSES_CRED,
    RelationshipType.REACHES_TOOL,
    RelationshipType.SERVES_MODEL,
    RelationshipType.USES_FRAMEWORK,
    RelationshipType.CONTAINS,
  ],
  attack: [
    RelationshipType.AFFECTS,
    RelationshipType.VULNERABLE_TO,
    RelationshipType.EXPLOITABLE_VIA,
    RelationshipType.REMEDIATES,
    RelationshipType.TRIGGERS,
    RelationshipType.SHARES_SERVER,
    RelationshipType.SHARES_CRED,
    RelationshipType.LATERAL_PATH,
    RelationshipType.EXPLOITABLE_VIA,
    RelationshipType.EXPOSED_TO,
    RelationshipType.HAS_PERMISSION,
  ],
  runtime: [
    RelationshipType.INVOKED,
    RelationshipType.ACCESSED,
    RelationshipType.TRACE_STEP,
    RelationshipType.RECORDED_ACTIVITY,
    RelationshipType.CALLED,
    RelationshipType.USED_CREDENTIAL,
    RelationshipType.DELEGATED_TO,
  ],
  governance: [
    RelationshipType.MANAGES,
    RelationshipType.OWNS,
    RelationshipType.PART_OF,
    RelationshipType.MEMBER_OF,
    RelationshipType.AUTHENTICATES_AS,
    RelationshipType.SCOPED_TO,
    RelationshipType.GOVERNS,
    RelationshipType.EXHIBITS_DRIFT,
    RelationshipType.ASSUMES,
    RelationshipType.TRUSTS,
    RelationshipType.ATTACHED,
    RelationshipType.INHERITS,
    RelationshipType.CAN_ACCESS,
    RelationshipType.CROSS_ACCOUNT_TRUST,
    RelationshipType.STORES,
    RelationshipType.HAS_PERMISSION,
  ],
};

export function emptyGraphResponse(scanId: string): UnifiedGraphResponse {
  return {
    scan_id: scanId,
    tenant_id: "",
    created_at: "",
    nodes: [],
    edges: [],
    attack_paths: [],
    interaction_risks: [],
    stats: {
      total_nodes: 0,
      total_edges: 0,
      node_types: {},
      severity_counts: {},
      relationship_types: {},
      attack_path_count: 0,
      interaction_risk_count: 0,
      max_attack_path_risk: 0,
      highest_interaction_risk: 0,
      analysis_status: {},
    },
    pagination: {
      total: 0,
      offset: 0,
      limit: 0,
      has_more: false,
    },
  };
}

function lineageTypeForEntity(entityType: string): LineageNodeType {
  return lineageNodeTypeForEntity(entityType) ?? "server";
}

function stringAttribute(
  attributes: Record<string, unknown> | undefined,
  key: string,
): string | undefined {
  const value = attributes?.[key];
  return typeof value === "string" ? value : undefined;
}

function versionProvenanceAttribute(
  attributes: Record<string, unknown> | undefined,
  key: string,
): string | undefined {
  const value = attributes?.version_provenance;
  if (!value || typeof value !== "object" || Array.isArray(value))
    return undefined;
  const nested = (value as Record<string, unknown>)[key];
  return typeof nested === "string" ? nested : undefined;
}

export function buildFallbackNodeData(node: UnifiedNode, graph?: Pick<UnifiedGraphResponse, "nodes" | "edges">): LineageNodeData {
  const attributes = { ...(node.attributes ?? {}), node_id: node.id };
  return {
    label: node.label,
    nodeType: lineageTypeForEntity(String(node.entity_type)),
    entityType: String(node.entity_type),
    status: String(node.status ?? ""),
    riskScore: node.risk_score,
    riskAssessment: nodeRiskAssessment(node.risk_assessment),
    severity: node.severity,
    firstSeen: node.first_seen,
    lastSeen: node.last_seen,
    dataSources: node.data_sources ?? [],
    complianceTags: node.compliance_tags ?? [],
    attributes,
    description:
      stringAttribute(attributes, "description") ||
      stringAttribute(attributes, "recommendation") ||
      stringAttribute(attributes, "framework") ||
      stringAttribute(attributes, "source"),
    version:
      stringAttribute(attributes, "version") ||
      stringAttribute(attributes, "hash"),
    ecosystem: stringAttribute(attributes, "ecosystem"),
    versionSource:
      versionProvenanceAttribute(attributes, "version_source") ||
      stringAttribute(attributes, "version_source"),
    versionConfidence:
      versionProvenanceAttribute(attributes, "confidence") ||
      stringAttribute(attributes, "version_confidence"),
    command:
      stringAttribute(attributes, "command") ||
      stringAttribute(attributes, "transport") ||
      stringAttribute(attributes, "url"),
    ...(node.entity_type === "agent" ? { agentContext: graphAgentContext(node,
      graph?.edges.filter(edge => edge.source === node.id) ?? [], graph?.edges.filter(edge => edge.target === node.id) ?? [],
      new Map((graph?.nodes ?? [node]).map(item => [item.id, item]))) } : {}),
    agentType: stringAttribute(attributes, "agent_type"),
    agentStatus: stringAttribute(attributes, "status"),
  };
}

export function mergeNodeDetail(
  base: LineageNodeData,
  detail: GraphNodeDetailResponse,
): LineageNodeData {
  const fallback = buildFallbackNodeData({ ...detail.node, attributes: { ...base.attributes, ...detail.node.attributes } });
  const merged = mergeGraphNodeDetail(base, detail);
  for (const key of ["description", "version", "ecosystem", "versionSource", "versionConfidence", "command", "agentType", "agentStatus"] as const) {
    merged[key] = base[key] || fallback[key];
  }
  return merged;
}


export function graphErrorState(message: string): {
  title: string;
  detail: string;
  suggestions: string[];
} {
  const lowered = message.toLowerCase();
  if (
    lowered.includes("budget") ||
    lowered.includes("limit") ||
    lowered.includes("too large")
  ) {
    return {
      title: "Graph query budget reached",
      detail: message,
      suggestions: [
        "Reduce depth or page size before retrying.",
        "Switch back to Relevant paths for operator triage.",
        "Narrow the graph by agent, severity, or relationship scope.",
      ],
    };
  }
  if (lowered.includes("timeout") || lowered.includes("timed out")) {
    return {
      title: "Graph query timed out",
      detail: message,
      suggestions: [
        "Retry with a smaller page size.",
        "Reduce max depth for the current graph window.",
        "Use search or selectors before expanding topology.",
      ],
    };
  }
  if (
    lowered.includes("permission") ||
    lowered.includes("tenant") ||
    lowered.includes("forbidden") ||
    lowered.includes("unauthorized")
  ) {
    return {
      title: "Graph is unavailable for this tenant or session",
      detail: message,
      suggestions: [
        "Confirm the selected tenant has access to this snapshot.",
        "Refresh the session before retrying.",
        "Use a snapshot generated by the current tenant.",
      ],
    };
  }
  return {
    title: "Graph query failed",
    detail: message,
    suggestions: [
      "Retry the request.",
      "Reduce the graph scope if the snapshot is large.",
      "Check API logs for the rejected query.",
    ],
  };
}

export type InvestigationMode = {
  rootId: string;
  rootLabel: string;
  truncated: boolean;
  nodeCount: number;
  edgeCount: number;
};

export function queryResponseToGraphResponse(
  response: GraphQueryResponse,
): UnifiedGraphResponse {
  const completeness = response.completeness ?? {
    status: response.truncated ? "truncated" : "complete",
    complete: !response.truncated,
    sampled: false,
    truncated: response.truncated,
    returned: response.nodes.length,
    ...(response.truncated ? { reason: "traversal_budget" } : { total: response.nodes.length }),
  };
  return {
    scan_id: response.scan_id,
    tenant_id: response.tenant_id,
    created_at: response.created_at,
    nodes: response.nodes,
    edges: response.edges,
    attack_paths: response.attack_paths,
    interaction_risks: response.interaction_risks,
    stats: response.stats,
    completeness,
    pagination: {
      total: completeness.total ?? response.nodes.length,
      offset: 0,
      limit: response.nodes.length,
      has_more: response.truncated,
    },
  };
}

/** Return only an exhaustive total; truncated traversals intentionally have none. */
export function knownGraphTotal(response: UnifiedGraphResponse): number | null {
  if (response.completeness) return response.completeness.total ?? null;
  return response.pagination.total;
}
