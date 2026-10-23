import type { Edge, Node } from "@xyflow/react";
import type { LineageNodeData, LineageNodeType } from "@/components/lineage-nodes";

const IDENTITIES = new Set<LineageNodeType>([
  "role", "user", "group", "policy", "serviceAccount", "servicePrincipal",
  "federatedIdentity", "managedIdentity", "accessGrant", "accessPolicy",
]);
const ACCESS_RELATIONSHIPS = new Set([
  "can_access", "acted_as", "authenticates_as", "assumes", "has_permission",
  "member_of", "inherits", "governs", "scoped_to",
]);
const DEPENDENCY_EVIDENCE = new Set<LineageNodeType>([
  "sourceFile", "configFile", "codeModule", "directory", "container", "package",
]);
const FINDINGS = new Set<LineageNodeType>(["vulnerability", "misconfiguration"]);
const FINDING_RELATIONSHIPS = new Set(["vulnerable_to", "affects"]);

export interface InvestigationContextGroup {
  id: "identity" | "connections" | "dependency" | "workload";
  label: string;
  nodeIds: string[];
}

/** Presentation membership only; never adds facts, drops edges or reverses evidence. */
export function graphInvestigationContext(
  nodes: Node<LineageNodeData>[],
  edges: Edge[],
  options: { rootId?: string | undefined; correlation?: boolean; pathSelected?: boolean },
): { anchorId?: string; nodes: Node<LineageNodeData>[]; edges: Edge[]; groups: InvestigationContextGroup[] } | null {
  if (!nodes.length || nodes.length > 24 || options.pathSelected) return null;
  const byId = new Map(nodes.map(node => [node.id, node]));
  if (options.rootId) {
    if (byId.get(options.rootId)?.data.nodeType !== "agent") return null;
    const identityIds = new Set<string>();
    for (const edge of edges) {
      const neighbor = edge.source === options.rootId ? edge.target : edge.target === options.rootId ? edge.source : undefined;
      if (neighbor && IDENTITIES.has(byId.get(neighbor)?.data.nodeType as LineageNodeType)
        && ACCESS_RELATIONSHIPS.has(String(edge.data?.relationship))) identityIds.add(neighbor);
    }
    if (!identityIds.size) return null;
    return {
      anchorId: options.rootId,
      nodes: [byId.get(options.rootId)!, ...nodes.filter(node => node.id !== options.rootId)], edges,
      groups: [
        { id: "connections", label: "Agent connections", nodeIds: nodes.filter(node => !identityIds.has(node.id)).map(node => node.id) },
        { id: "identity", label: "Identity and access context", nodeIds: nodes.filter(node => identityIds.has(node.id)).map(node => node.id) },
      ],
    };
  }
  if (!options.correlation || !nodes.some(node => node.data.nodeType === "package")) return null;
  const artifactIds = new Set(nodes.filter(node => DEPENDENCY_EVIDENCE.has(node.data.nodeType)).map(node => node.id));
  const dependencyIds = new Set(artifactIds);
  for (const edge of edges) {
    if (!FINDING_RELATIONSHIPS.has(String(edge.data?.relationship))) continue;
    const findingId = artifactIds.has(edge.source) ? edge.target : artifactIds.has(edge.target) ? edge.source : undefined;
    if (findingId && FINDINGS.has(byId.get(findingId)?.data.nodeType as LineageNodeType)) dependencyIds.add(findingId);
  }
  // Deployment occurrences sit beside their recorded workload. Package links
  // remain visible bridges to dependency evidence; identities are never merged.
  for (const edge of edges) {
    if (["contains", "hosts", "runs"].includes(String(edge.data?.relationship))
      && byId.get(edge.source)?.data.nodeType === "container"
      && byId.get(edge.target)?.data.nodeType === "agent") dependencyIds.delete(edge.source);
  }
  if (!dependencyIds.size || dependencyIds.size === nodes.length) return null;
  return {
    nodes, edges,
    groups: [
      { id: "dependency", label: "Dependency evidence", nodeIds: nodes.filter(node => dependencyIds.has(node.id)).map(node => node.id) },
      { id: "workload", label: "Workload and access context", nodeIds: nodes.filter(node => !dependencyIds.has(node.id)).map(node => node.id) },
    ],
  };
}

export function selectInvestigationContext(
  context: NonNullable<ReturnType<typeof graphInvestigationContext>>,
  groupId: string,
) {
  const group = context.groups.find(item => item.id === groupId);
  if (!group) return { nodes: context.nodes, edges: context.edges, omittedNodes: 0, crossContextEdges: 0 };
  const visible = new Set(group.nodeIds);
  if (context.anchorId) visible.add(context.anchorId);
  return {
    nodes: context.nodes.filter(node => visible.has(node.id)),
    edges: context.edges.filter(edge => visible.has(edge.source) && visible.has(edge.target)),
    omittedNodes: context.nodes.filter(node => !visible.has(node.id)).length,
    crossContextEdges: context.edges.filter(edge => visible.has(edge.source) !== visible.has(edge.target)).length,
  };
}

/** Rank incoming identity context after the anchor, without changing the drawn edge. */
export function investigationRankEdges(
  context: NonNullable<ReturnType<typeof graphInvestigationContext>>,
  edges: Edge[],
): Edge[] {
  if (!context.anchorId) return edges;
  const identities = new Set(context.groups.find(group => group.id === "identity")?.nodeIds);
  return edges.map(edge => edge.target === context.anchorId && identities.has(edge.source)
    ? { ...edge, source: edge.target, target: edge.source } : edge);
}

export function restoreInvestigationEdges(original: Edge[], ranked: Edge[], vertical = false): Edge[] {
  const byId = new Map(original.map(edge => [edge.id, edge]));
  return ranked.map(edge => {
    const source = byId.get(edge.id);
    if (!source || source.source === edge.source) return edge;
    return { ...edge, source: source.source, target: source.target,
      sourceHandle: vertical ? "context-up" : "context", targetHandle: "context" };
  });
}

export interface InvestigationLane extends InvestigationContextGroup {
  x: number;
  y: number;
  width: number;
  height: number;
}

/** Visual evidence groups, never containment or inferred attack-path edges. */
export function layoutInvestigationLanes(
  context: NonNullable<ReturnType<typeof graphInvestigationContext>>,
  nodes: Node<LineageNodeData>[],
  edges: Edge[],
): { nodes: Node<LineageNodeData>[]; edges: Edge[]; lanes: InvestigationLane[] } | null {
  if (context.anchorId || nodes.length > 16 || edges.length > 24) return null;
  const visible = new Set(nodes.map(node => node.id));
  const groups = ["workload", "dependency"].map(id => context.groups.find(group => group.id === id))
    .filter((group): group is InvestigationContextGroup => Boolean(group))
    .map(group => ({ ...group, nodeIds: group.nodeIds.filter(id => visible.has(id)) }));
  if (groups.length !== 2 || groups.some(group => !group.nodeIds.length)) return null;
  const x = Math.min(...nodes.map(node => node.position.x)) - 40;
  const width = Math.max(...nodes.map(node => node.position.x + 360)) - x + 40;
  const placed = new Map<string, Node<LineageNodeData>>();
  const lanes: InvestigationLane[] = [];
  let y = 0;
  for (const group of groups) {
    const members = new Set(group.nodeIds);
    const ranks = new Map<number, Node<LineageNodeData>[]>();
    for (const node of nodes.filter(node => members.has(node.id))) {
      ranks.set(node.position.x, [...(ranks.get(node.position.x) ?? []), node]);
    }
    const rows = Math.max(...[...ranks.values()].map(rank => rank.length));
    const nodeHeight = 300, rowStep = 320, header = 64;
    const height = header + (rows - 1) * rowStep + nodeHeight + 48;
    for (const rank of ranks.values()) {
      rank.sort((a, b) => a.position.y - b.position.y || a.id.localeCompare(b.id));
      rank.forEach((node, index) => placed.set(node.id, { ...node,
        style: { ...node.style, minHeight: nodeHeight },
        position: { x: node.position.x, y: y + header + ((rows - rank.length) / 2 + index) * rowStep },
      }));
    }
    lanes.push({ ...group, x, y, width, height });
    y += height + 64;
  }
  return {
    nodes: nodes.map(node => placed.get(node.id) ?? node),
    edges: edges.map(edge => ({ ...edge, data: { ...edge.data, quietLabel: false, directionEmphasis: true } })),
    lanes,
  };
}
