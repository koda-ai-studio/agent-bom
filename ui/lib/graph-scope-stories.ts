import type { Edge, Node } from "@xyflow/react";
import type { LineageNodeData } from "@/components/lineage-nodes";
import { enclosingEnvironment, withoutFrames } from "@/lib/graph-exposure-spine";
import { INTERNET_ANCHOR_ID } from "@/lib/graph-internet-context";

type ScopeStories = { scopeId: string; stories: { id: string; label: string; nodeIds: Set<string> }[] };
/** Partition only where the recorded scope is the sole connection. Real links,
 * including blocked access and reverse findings, always keep a branch together. */
export function scopeStories(input: Node<LineageNodeData>[], inputEdges: Edge[]): ScopeStories | null {
  const restored = withoutFrames(input, inputEdges);
  const nodes = restored.nodes.filter(n => !n.hidden);
  if (nodes.length > 24 || nodes.some(n => n.data.rollup || n.data.attributes?.rollup_is_container === true)) return null;
  const byId = new Map(nodes.map(n => [n.id, n]));
  if (!byId.has(INTERNET_ANCHOR_ID)) return null;
  const edges = restored.edges.filter(e => !e.hidden && byId.has(e.source) && byId.has(e.target));
  const scope = enclosingEnvironment(nodes, edges);
  if (!scope) return null;
  const links = edges.filter(e => e.source !== scope.id && e.target !== scope.id);
  const seen = new Set([scope.id]), stories: ScopeStories["stories"] = [];
  for (const start of [...byId.keys()].sort()) {
    if (seen.has(start)) continue;
    const nodeIds = new Set<string>(), pending = [start];
    while (pending.length) {
      const id = pending.pop()!;
      if (seen.has(id)) continue;
      seen.add(id); nodeIds.add(id);
      for (const e of links) {
        const next = e.source === id ? e.target : e.target === id ? e.source : null;
        if (next && !seen.has(next)) pending.push(next);
      }
    }
    const roots = edges.filter(e => e.source === scope.id && nodeIds.has(e.target)).map(e => e.target).sort();
    if (!roots.length) return null;
    const exposed = nodeIds.has(INTERNET_ANCHOR_ID);
    stories.push({ id: exposed ? INTERNET_ANCHOR_ID : roots[0]!, label: exposed ? "Internet exposure" : byId.get(roots[0]!)!.data.label, nodeIds });
  }
  stories.sort((a, b) => Number(b.nodeIds.has(INTERNET_ANCHOR_ID)) - Number(a.nodeIds.has(INTERNET_ANCHOR_ID)) || a.label.localeCompare(b.label));
  return stories.length > 1 ? { scopeId: scope.id, stories } : null;
}

/** Reversible view projection. IDs, relationships, direction and evidence are
 * retained; choosing another flow never claims it is reachable from Internet. */
export function selectScopeStory(input: Node<LineageNodeData>[], inputEdges: Edge[], stories: ScopeStories, id: string) {
  const story = stories.stories.find(s => s.id === id);
  if (!story) return { nodes: input, edges: inputEdges };
  const { nodes, edges } = withoutFrames(input, inputEdges);
  const kept = new Set([...story.nodeIds, stories.scopeId]);
  return {
    nodes: nodes.map(n => ({ ...n, hidden: n.hidden || !kept.has(n.id), data: { ...n.data, connectedScope: true } })),
    edges: edges.map(e => ({ ...e, hidden: e.hidden || !kept.has(e.source) || !kept.has(e.target) })),
  };
}
