import { graphEdgeEvidence } from "@/lib/graph-edge-evidence";
import type { AttackPath, UnifiedEdge, UnifiedGraphData, UnifiedNode } from "@/lib/graph-schema";
import { GRAPH_NODE_KIND_META } from "@/lib/graph-schema.generated";
import { relationshipEdgeLabelText } from "@/lib/graph-utils";
import { nodeContextMarkers, type NodeContextMarker } from "@/lib/attack-path-graph-markers";

/** Findings attach to the asset they affect; they are badges, not hops. */
export const FINDING_ENTITY_TYPES = new Set(["vulnerability", "misconfiguration", "drift_incident", "finding"]);
const SEVERITY_ORDER = ["critical", "high", "medium", "low"];
/** Bound the number of other recorded paths drawn as branches. */
const MAX_CONNECTED_PATHS = 8;

export type EdgeEvidenceStyle = "recorded" | "inferred" | "unrecorded";
export type PathGraphFinding = { id: string; label: string; severity: string };
export type PathGraphNode = {
  id: string;
  kind: "entity" | "group";
  role: "entry" | "path" | "target" | "branch";
  label: string;
  typeLabel: string;
  entityType: string;
  findings: PathGraphFinding[];
  markers: NodeContextMarker[];
  /** Collapsed sibling groups only. */
  count?: number;
  parentId?: string;
};
export type PathGraphEdge = {
  id: string;
  source: string;
  target: string;
  relationship: string;
  relationshipLabel: string;
  evidence: EdgeEvidenceStyle;
  onPath: boolean;
  bidirectional: boolean;
};
export type AttackPathGraphModel = {
  nodes: PathGraphNode[];
  edges: PathGraphEdge[];
  pathNodeIds: string[];
  /** Other recorded paths in this snapshot that share a node or edge with the selected one. */
  connectedPathCount: number;
  omittedConnectedPaths: number;
};

export function typeLabel(entityType: string): string {
  return (GRAPH_NODE_KIND_META as Record<string, { label?: string }>)[entityType]?.label ?? entityType.replaceAll("_", " ");
}

function pluralType(entityType: string, count: number): string {
  const label = typeLabel(entityType).toLowerCase();
  if (count === 1) return label;
  return label.endsWith("y") && !/[aeiou]y$/.test(label) ? `${label.slice(0, -1)}ies` : label.endsWith("s") ? `${label}es` : `${label}s`;
}

function severityRank(severity: string): number {
  const index = SEVERITY_ORDER.indexOf(severity.toLowerCase());
  return index < 0 ? SEVERITY_ORDER.length : index;
}

function evidenceStyle(edge: UnifiedEdge): EdgeEvidenceStyle {
  const { mode } = graphEdgeEvidence(edge.evidence ?? {});
  return mode === "inferred" ? "inferred" : mode === "unknown" ? "unrecorded" : "recorded";
}

function pairKey(a: string, b: string): string {
  return a < b ? `${a}\u0000${b}` : `${b}\u0000${a}`;
}

/** The recorded edge for one hop, honouring direction unless the edge is bidirectional. */
function hopEdge(edges: UnifiedEdge[], source: string, target: string, relationship?: string): UnifiedEdge | undefined {
  const matches = edges.filter(edge => (edge.source === source && edge.target === target)
    || (edge.direction === "bidirectional" && edge.source === target && edge.target === source));
  return matches.find(edge => edge.relationship === relationship || edge.id === relationship) ?? matches[0];
}

/** Trailing finding hops fold into the asset before them; a finding mid-chain stays a node. */
function assetHops(path: AttackPath, nodes: Map<string, UnifiedNode>): string[] {
  const hops = [...new Set(path.hops)].filter(id => nodes.has(id));
  let end = hops.length;
  while (end > 1 && FINDING_ENTITY_TYPES.has(nodes.get(hops[end - 1]!)!.entity_type)) end -= 1;
  return hops.slice(0, end);
}

function pathKey(path: AttackPath): string {
  return path.hops.join("\u0000");
}

type Draft = { nodes: Set<string>; edges: Map<string, UnifiedEdge>; onPath: Set<string> };

function addPathEdges(draft: Draft, hops: string[], path: AttackPath, edges: UnifiedEdge[], onPath: boolean) {
  for (let index = 0; index < hops.length - 1; index += 1) {
    const hopIndex = path.hops.indexOf(hops[index]!);
    const edge = hopEdge(edges, hops[index]!, hops[index + 1]!, path.edges[hopIndex]);
    if (!edge) continue;
    draft.edges.set(edge.id, edge);
    if (onPath) draft.onPath.add(edge.id);
  }
}

/** Other recorded paths that share a node with the selected path or are one recorded edge away. */
function connectedPaths(graph: UnifiedGraphData, selected: AttackPath, selectedHops: Set<string>, nodes: Map<string, UnifiedNode>) {
  const adjacency = new Map<string, Set<string>>();
  for (const edge of graph.edges) {
    for (const [a, b] of [[edge.source, edge.target], [edge.target, edge.source]] as const) {
      if (!adjacency.has(a)) adjacency.set(a, new Set());
      adjacency.get(a)!.add(b);
    }
  }
  const selectedKey = pathKey(selected);
  return (graph.attack_paths ?? [])
    .filter(other => pathKey(other) !== selectedKey)
    .map(other => ({ other, hops: assetHops(other, nodes) }))
    .filter(({ hops }) => hops.some(id => selectedHops.has(id) || [...(adjacency.get(id) ?? [])].some(next => selectedHops.has(next))))
    .sort((a, b) => (b.other.composite_risk ?? 0) - (a.other.composite_risk ?? 0));
}

function findingsFor(id: string, graph: UnifiedGraphData, nodes: Map<string, UnifiedNode>, drawn: Set<string>): PathGraphFinding[] {
  const seen = new Map<string, PathGraphFinding>();
  for (const edge of graph.edges) {
    const other = edge.source === id ? edge.target : edge.target === id ? edge.source : null;
    const finding = other ? nodes.get(other) : undefined;
    if (!finding || drawn.has(finding.id) || !FINDING_ENTITY_TYPES.has(finding.entity_type)) continue;
    seen.set(finding.id, { id: finding.id, label: finding.label, severity: String(finding.severity ?? "unknown").toLowerCase() });
  }
  return [...seen.values()].sort((a, b) => severityRank(a.severity) - severityRank(b.severity) || a.id.localeCompare(b.id));
}

/** Breadth-first parent of every branch node, seeded from the selected path. */
function branchParents(draft: Draft, pathIds: string[]): Map<string, string> {
  const parents = new Map<string, string>();
  const visited = new Set(pathIds);
  const queue = [...pathIds];
  const links = [...draft.edges.values()];
  while (queue.length) {
    const current = queue.shift()!;
    for (const edge of links) {
      const next = edge.source === current ? edge.target : edge.target === current ? edge.source : null;
      if (!next || visited.has(next) || !draft.nodes.has(next)) continue;
      visited.add(next);
      parents.set(next, current);
      queue.push(next);
    }
  }
  return parents;
}

function descendants(root: string, parents: Map<string, string>): Set<string> {
  const out = new Set([root]);
  let grew = true;
  while (grew) {
    grew = false;
    for (const [child, parent] of parents) if (out.has(parent) && !out.has(child)) { out.add(child); grew = true; }
  }
  return out;
}

export function buildAttackPathGraphModel(
  graph: UnifiedGraphData,
  path: AttackPath,
  options: { expandedGroups?: ReadonlySet<string>; collapseThreshold?: number } = {},
): AttackPathGraphModel {
  const nodes = new Map(graph.nodes.map(node => [node.id, node]));
  const pathNodeIds = assetHops(path, nodes);
  const selectedHops = new Set(pathNodeIds);
  const draft: Draft = { nodes: new Set(pathNodeIds), edges: new Map(), onPath: new Set() };
  addPathEdges(draft, pathNodeIds, path, graph.edges, true);

  const connected = connectedPaths(graph, path, selectedHops, nodes);
  const drawnPaths = connected.slice(0, MAX_CONNECTED_PATHS);
  for (const { other, hops } of drawnPaths) {
    hops.forEach(id => draft.nodes.add(id));
    addPathEdges(draft, hops, other, graph.edges, false);
  }
  // Recorded links between the selected path and the branches it touches.
  const pathPairs = new Set([...draft.onPath].map(id => { const edge = draft.edges.get(id)!; return pairKey(edge.source, edge.target); }));
  for (const edge of graph.edges) {
    if (!draft.nodes.has(edge.source) || !draft.nodes.has(edge.target) || draft.edges.has(edge.id)) continue;
    if (!selectedHops.has(edge.source) && !selectedHops.has(edge.target)) continue;
    if (pathPairs.has(pairKey(edge.source, edge.target))) continue;
    draft.edges.set(edge.id, edge);
  }

  const threshold = options.collapseThreshold ?? 3;
  const parents = branchParents(draft, pathNodeIds);
  const groups = new Map<string, string[]>();
  for (const [child, parent] of parents) {
    const key = `group:${parent}:${nodes.get(child)!.entity_type}`;
    groups.set(key, [...(groups.get(key) ?? []), child]);
  }
  const hidden = new Map<string, string>();
  const collapsed: PathGraphNode[] = [];
  for (const [key, members] of groups) {
    if (members.length <= threshold || options.expandedGroups?.has(key)) continue;
    for (const member of members) for (const id of descendants(member, parents)) hidden.set(id, key);
    const entityType = nodes.get(members[0]!)!.entity_type;
    collapsed.push({
      id: key, kind: "group", role: "branch", entityType,
      label: `${members.length} ${pluralType(entityType, members.length)}`,
      typeLabel: "Collapsed siblings", count: members.length, parentId: parents.get(members[0]!)!,
      findings: [], markers: [],
    });
  }

  const drawnFindings = new Set([...draft.nodes].filter(id => FINDING_ENTITY_TYPES.has(nodes.get(id)!.entity_type)));
  const lastIndex = pathNodeIds.length - 1;
  const entityNodes: PathGraphNode[] = [...draft.nodes].filter(id => !hidden.has(id)).map(id => {
    const node = nodes.get(id)!;
    const index = pathNodeIds.indexOf(id);
    return {
      id, kind: "entity", label: node.label || id, entityType: node.entity_type, typeLabel: typeLabel(node.entity_type),
      role: index < 0 ? "branch" : index === 0 && lastIndex > 0 ? "entry" : index === lastIndex ? "target" : "path",
      findings: findingsFor(id, graph, nodes, drawnFindings),
      markers: nodeContextMarkers(node.attributes ?? {}),
    };
  });
  for (const group of collapsed) {
    const members = groups.get(group.id)!;
    group.findings = [...new Map(members.flatMap(id => findingsFor(id, graph, nodes, drawnFindings)).map(finding => [finding.id, finding])).values()]
      .sort((a, b) => severityRank(a.severity) - severityRank(b.severity) || a.id.localeCompare(b.id));
  }

  const edges: PathGraphEdge[] = [];
  const groupEdges = new Map<string, PathGraphEdge>();
  for (const edge of draft.edges.values()) {
    const sourceGroup = hidden.get(edge.source), targetGroup = hidden.get(edge.target);
    const base = {
      relationship: edge.relationship,
      relationshipLabel: relationshipEdgeLabelText(edge.relationship),
      evidence: evidenceStyle(edge),
      onPath: draft.onPath.has(edge.id),
      bidirectional: edge.direction === "bidirectional",
    };
    if (!sourceGroup && !targetGroup) {
      edges.push({ id: edge.id, source: edge.source, target: edge.target, ...base });
      continue;
    }
    // Only the link from the visible parent into the group stands in for its members.
    const group = sourceGroup ?? targetGroup!;
    const parent = collapsed.find(item => item.id === group)!.parentId!;
    if (!(edge.source === parent || edge.target === parent)) continue;
    const existing = groupEdges.get(group);
    const weakest = !existing ? base.evidence : [existing.evidence, base.evidence].includes("unrecorded") ? "unrecorded"
      : [existing.evidence, base.evidence].includes("inferred") ? "inferred" : "recorded";
    groupEdges.set(group, {
      id: `${group}:link`, source: edge.source === parent ? parent : group, target: edge.source === parent ? group : parent,
      ...base, evidence: weakest,
      relationshipLabel: existing && existing.relationship !== edge.relationship ? "Recorded relationships" : base.relationshipLabel,
    });
  }
  return {
    nodes: [...entityNodes, ...collapsed],
    edges: [...edges, ...groupEdges.values()],
    pathNodeIds,
    connectedPathCount: connected.length,
    omittedConnectedPaths: Math.max(0, connected.length - drawnPaths.length),
  };
}

/**
 * Every node the graph can show (collapsed siblings included) plus the
 * findings on them, so node and finding details resolve to recorded data.
 */
export function attackPathEvidenceGraph(graph: UnifiedGraphData, path: AttackPath): UnifiedGraphData {
  const model = buildAttackPathGraphModel(graph, path, { collapseThreshold: Number.POSITIVE_INFINITY });
  const ids = new Set(model.nodes.flatMap(node => [node.id, ...node.findings.map(finding => finding.id)]));
  const nodes = graph.nodes.filter(node => ids.has(node.id));
  const edges = graph.edges.filter(edge => ids.has(edge.source) && ids.has(edge.target));
  return {
    ...graph, nodes, edges, attack_paths: [path], interaction_risks: [],
    stats: { ...graph.stats, total_nodes: nodes.length, total_edges: edges.length, attack_path_count: 1, interaction_risk_count: 0 },
  };
}
