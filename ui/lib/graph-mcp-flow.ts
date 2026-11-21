import type { Edge, Node } from "@xyflow/react";
import type { LineageNodeData } from "@/components/lineage-nodes";
import { semanticGraphLayout, SEMANTIC_COLUMN_GAP, SEMANTIC_ROW_GAP } from "@/lib/graph-semantic-layout";

export const MCP_FLOW_FOOTPRINT = { width: 240, height: 216, cardMaxHeight: 216, column: SEMANTIC_COLUMN_GAP, row: SEMANTIC_ROW_GAP };
export const mcpEvidenceFlow = semanticGraphLayout;

/** Recorded upstream evidence for a finding, including reverse `affects` edges.
 * Associations do not turn unrelated branches into a supporting path. */
export function findingEvidenceContext(id: string, nodes: Node<LineageNodeData>[], edges: Edge[]): Set<string> | null {
  if (!nodes.some(n => n.id === id && n.data.evidenceFlow && ["vulnerability", "misconfiguration"].includes(n.data.nodeType))) return null;
  const visible = new Set(nodes.map(n => n.id));
  const parents = new Map<string, string[]>();
  for (const e of edges) {
    if (e.hidden || !visible.has(e.source) || !visible.has(e.target) || ["correlates_with", "associated_with"].includes(String(e.data?.relationship))) continue;
    const [source, target] = e.data?.relationship === "affects" ? [e.target, e.source] : [e.source, e.target];
    parents.set(target, [...(parents.get(target) ?? []), source]);
  }
  const visited = new Set([id]), queue = [id];
  for (let i = 0; i < queue.length; i++) for (const parent of parents.get(queue[i]!) ?? []) {
    if (!visited.has(parent)) { visited.add(parent); queue.push(parent); }
  }
  return visited;
}
