import type { Edge, Node } from "@xyflow/react";
import type { LineageNodeData } from "@/components/lineage-nodes";
import { INTERNET_ANCHOR_ID } from "@/lib/graph-internet-context";
import { semanticLayer } from "@/lib/graph-semantic-columns";

const SEVERITY_RANK: Record<string, number> = { critical: 5, high: 4, medium: 3, low: 2, info: 1 };
/** Links that lead away from what they connect: a finding is read last, never walked through. */
const BACKWARD = new Set(["part_of", "hosted_on", "belongs_to", "member_of", "affects"]);

function severityOf(node: Node<LineageNodeData> | undefined): number {
  const value = String(node?.data.severity ?? (node?.data.attributes as Record<string, unknown> | undefined)?.severity ?? "").toLowerCase();
  return SEVERITY_RANK[value] ?? 0;
}

/**
 * The exposure story a view tells when nothing is selected: the Internet, the asset it reaches,
 * and the forward links from there to the most severe finding reachable. Only recorded links are
 * walked, so the chain never claims a hop the graph does not hold. ``[]`` without an Internet anchor.
 */
export function exposureSpine(nodes: readonly Node<LineageNodeData>[], edges: readonly Edge[]): string[] {
  const byId = new Map(nodes.filter(node => !node.hidden).map(node => [node.id, node]));
  if (!byId.has(INTERNET_ANCHOR_ID)) return [];
  const next = new Map<string, string[]>();
  for (const edge of edges) {
    if (edge.hidden || (edge.data?.traversable === false && !(edge.source === INTERNET_ANCHOR_ID && edge.data?.displayOnly === true)) || edge.source === edge.target || !byId.has(edge.source) || !byId.has(edge.target)) continue;
    if (BACKWARD.has(String(edge.data?.relationship ?? ""))) continue;
    next.set(edge.source, [...(next.get(edge.source) ?? []), edge.target].sort());
  }
  const entries = next.get(INTERNET_ANCHOR_ID) ?? [];
  let best: string[] = [];
  let bestScore = -1;
  for (const entry of entries) {
    // Breadth first, so the first route to a finding is its shortest; a node is never revisited.
    const parent = new Map<string, string>([[entry, INTERNET_ANCHOR_ID]]);
    const queue = [entry];
    let candidate: string[] = [INTERNET_ANCHOR_ID, entry], score = 0;
    while (queue.length) {
      const id = queue.shift()!;
      const node = byId.get(id);
      if (semanticLayer(node!) === "finding") {
        const rank = severityOf(node);
        if (rank + 1 > score) {
          const chain = [id];
          for (let at = parent.get(id); at; at = parent.get(at)) chain.unshift(at);
          candidate = chain; score = rank + 1;
        }
        continue;
      }
      for (const target of next.get(id) ?? []) if (!parent.has(target) && target !== INTERNET_ANCHOR_ID) { parent.set(target, id); queue.push(target); }
    }
    if (score > bestScore || (score === bestScore && candidate.length < best.length)) { best = candidate; bestScore = score; }
  }
  return best;
}

/** The one environment every other drawn node belongs to: drawn as a boundary around them, not as a root. */
export function enclosingEnvironment(nodes: readonly Node<LineageNodeData>[], edges: readonly Edge[]): Node<LineageNodeData> | null {
  const visible = nodes.filter(node => !node.hidden && node.id !== INTERNET_ANCHOR_ID);
  // An environment or a cloud account: scopes a security map draws as a boundary.
  const scope = (value: unknown) => value === "environment" || value === "account";
  const environments = visible.filter(node => node.type === "environmentNode" || scope(node.data.nodeType) || scope(node.data.entityType));
  if (environments.length !== 1) return null;
  const environment = environments[0]!;
  // It must be the only root: nothing but the Internet leads into it, and every other node is connected to it.
  if (edges.some(edge => !edge.hidden && edge.target === environment.id && edge.source !== INTERNET_ANCHOR_ID)) return null;
  const reached = new Set([environment.id]);
  const queue = [environment.id];
  while (queue.length) {
    const id = queue.shift()!;
    // Membership follows links either way: a finding that affects a role belongs to the role's account.
    for (const edge of edges) {
      if (edge.hidden || edge.source === INTERNET_ANCHOR_ID) continue;
      const other = edge.source === id ? edge.target : edge.target === id ? edge.source : null;
      if (other && !reached.has(other)) { reached.add(other); queue.push(other); }
    }
  }
  return visible.every(node => reached.has(node.id)) && visible.length > 2 ? environment : null;
}

/** A layout's input without the boundary frame a previous pass drew, and with what framing hid shown again. */
export function withoutFrames(nodes: Node<LineageNodeData>[], edges: Edge[]): { nodes: Node<LineageNodeData>[]; edges: Edge[] } {
  return {
    nodes: nodes.filter(node => node.type !== "boundaryFrame").map(node => node.data.framed ? { ...node, hidden: false, data: { ...node.data, framed: undefined } } : node),
    edges: edges.map(edge => edge.data?.framed ? { ...edge, hidden: false, data: { ...edge.data, framed: undefined } } : edge),
  };
}
