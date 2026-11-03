import { isClusterPillNode } from "@/lib/sibling-aggregator";
import type { Edge, Node } from "@xyflow/react";
import type { LineageNodeData } from "@/components/lineage-nodes";

/** A connected window over loaded evidence; never invents or reverses a link. */
export function graphConnectionPreview<N extends Node<LineageNodeData>, E extends Edge>(
  nodes: N[], edges: E[], rootId?: string, limit = 6,
) {
  const byId = new Map(nodes.map(node => [node.id, node]));
  const neighbors = new Map(nodes.map(node => [node.id, new Set<string>()]));
  for (const edge of edges) {
    if (!byId.has(edge.source) || !byId.has(edge.target) || edge.source === edge.target) continue;
    neighbors.get(edge.source)!.add(edge.target);
    neighbors.get(edge.target)!.add(edge.source);
  }
  const rank = (node: N) => node.data.nodeType === "agent" ? 0
    : node.data.attributes?.is_repo_root === true ? 1
    : ["misconfiguration", "vulnerability", "credential"].includes(node.data.nodeType) ? 3 : 2;
  const compare = (a: N, b: N) => rank(a) - rank(b) || a.data.label.localeCompare(b.data.label) || a.id.localeCompare(b.id);
  // Include every loaded node in the picker, including disconnected components.
  const roots = nodes.filter(node => !isClusterPillNode(node)).sort(compare);
  const root = roots.find(node => node.id === rootId) ?? roots.find(node => neighbors.get(node.id)!.size) ?? roots[0];
  if (!root) return null;
  const selected = new Set([root.id]);
  const queue = [root.id];
  const budget = Math.max(1, Math.min(6, Math.floor(limit) || 6));
  while (queue.length && selected.size < budget) {
    const next = [...neighbors.get(queue.shift()!)!].map(id => byId.get(id)!).sort(compare);
    for (const node of next) {
      if (selected.has(node.id)) continue;
      selected.add(node.id); queue.push(node.id);
      if (selected.size >= budget) break;
    }
  }
  return { root, roots, nodes: nodes.filter(node => selected.has(node.id)),
    edges: edges.filter(edge => selected.has(edge.source) && selected.has(edge.target)),
    totalNodes: nodes.length, totalEdges: edges.length };
}
