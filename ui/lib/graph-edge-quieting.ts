import type { Edge, Node } from "@xyflow/react";
import type { LineageNodeData } from "@/components/lineage-nodes";

export interface QuietInput {
  showAll: boolean;
  focusNodes: readonly (string | null)[];
  focusEdge: string | null;
}

/**
 * A long connection across a map too large for one screen explains nothing until someone asks about
 * either end, so it waits for a hover or a selection. Display only: the edge stays in the page's data,
 * every count is taken from the recorded total, and `held` is what the canvas must say it left out.
 * A selected relationship stays drawn so its inspector never describes a line that has vanished.
 */
export function quietContextEdges(edges: Edge[], { showAll, focusNodes, focusEdge }: QuietInput) {
  let drawn = 0, held = 0, total = 0;
  const output = edges.map(edge => {
    if (edge.data?.displayOnly) return edge;
    total++;
    if (edge.hidden) return edge;
    const quiet = edge.data?.quietUntilFocus === true && !showAll && edge.id !== focusEdge && !focusNodes.includes(edge.source) && !focusNodes.includes(edge.target);
    if (!quiet) { drawn++; return edge; }
    held++;
    return { ...edge, hidden: true };
  });
  return { edges: output, drawn, held, total };
}

/** Stable across hover, so looking at one node does not rebuild every card. */
export function withHeldConnections(nodes: Node<LineageNodeData>[], edges: Edge[], showAll: boolean) {
  if (showAll) return nodes;
  const held = new Map<string, number>();
  for (const edge of edges) {
    if (edge.hidden || edge.data?.quietUntilFocus !== true) continue;
    held.set(edge.source, (held.get(edge.source) ?? 0) + 1);
    held.set(edge.target, (held.get(edge.target) ?? 0) + 1);
  }
  return held.size ? nodes.map(node => held.has(node.id) ? { ...node, data: { ...node.data, heldConnections: held.get(node.id) } } : node) : nodes;
}
