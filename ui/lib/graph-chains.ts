import { COLUMN_MAX_NODES } from "@/lib/path-card-column";

export interface GraphChain {
  /** Node ids from a root to a leaf, in edge direction, at most COLUMN_MAX_NODES long. */
  ids: string[];
  /** Relationship between consecutive ids; `relationships[i]` links `ids[i]` to `ids[i + 1]`. */
  relationships: string[];
  /** Hops beyond the phone column, reached from the last listed node. */
  hiddenHops: number;
}

type Link = { source: string; target: string; data?: Record<string, unknown> | undefined };

/** Upper bound on listed chains; a broad graph keeps its canvas and Fit all. */
export const GRAPH_CHAIN_LIMIT = 60;

/**
 * Root-to-leaf chains through the visible graph, for a phone's list reading.
 * Every node appears in at least one chain; a cycle is cut at the first repeat.
 */
export function graphChains(nodes: { id: string }[], edges: Link[], limit = GRAPH_CHAIN_LIMIT): { chains: GraphChain[]; truncated: boolean } {
  const ids = new Set(nodes.map(node => node.id));
  const out = new Map<string, { target: string; relationship: string }[]>();
  const incoming = new Map<string, number>();
  for (const edge of edges) {
    if (!ids.has(edge.source) || !ids.has(edge.target) || edge.source === edge.target) continue;
    const relationship = typeof edge.data?.relationship === "string" ? edge.data.relationship : "";
    out.set(edge.source, [...(out.get(edge.source) ?? []), { target: edge.target, relationship }]);
    incoming.set(edge.target, (incoming.get(edge.target) ?? 0) + 1);
  }
  const chains: GraphChain[] = [];
  const covered = new Set<string>();
  let truncated = false;
  const walk = (path: string[], relationships: string[]) => {
    if (chains.length >= limit) { truncated = true; return; }
    const last = path.at(-1)!;
    const next = (out.get(last) ?? []).filter(link => !path.includes(link.target));
    if (next.length === 0) {
      const shown = path.slice(0, COLUMN_MAX_NODES);
      shown.forEach(id => covered.add(id));
      path.forEach(id => covered.add(id));
      chains.push({ ids: shown, relationships: relationships.slice(0, shown.length - 1), hiddenHops: path.length - shown.length });
      return;
    }
    for (const link of next) walk([...path, link.target], [...relationships, link.relationship]);
  };
  const order = nodes.map(node => node.id);
  for (const id of order) if (!incoming.get(id)) walk([id], []);
  // Nodes only reachable through a cycle have no root; start from the first uncovered one.
  for (const id of order) if (!covered.has(id) && chains.length < limit) walk([id], []);
  if (order.some(id => !covered.has(id))) truncated = true;
  return { chains, truncated };
}
