import type { Node } from "@xyflow/react";
import type { LineageNodeData } from "@/components/lineage-nodes";

type FlowNode = Node<LineageNodeData>;
export interface WrapOptions {
  maxRows: number;
  columnGap: number;
  rowGap: number;
  /** Re-space every rank, not just the tall ones. */
  respace: boolean;
}

/**
 * A left-to-right layout turns a fan-out into one tall column, which only fits at an unreadable
 * zoom. Wrapping a tall rank into neighbouring columns keeps rank order and every edge's direction
 * while keeping the map as wide as a canvas is.
 */
export function wrappedRankLayout(nodes: FlowNode[], { maxRows, columnGap, rowGap, respace }: WrapOptions): FlowNode[] {
  const ranks = new Map<number, FlowNode[]>();
  for (const node of nodes) if (!node.hidden) {
    const key = Math.round(node.position.x);
    ranks.set(key, [...(ranks.get(key) ?? []), node]);
  }
  if (!respace && ![...ranks.values()].some(rank => rank.length > maxRows)) return nodes;
  const placed = new Map<string, { x: number; y: number }>();
  let column = 0;
  for (const key of [...ranks.keys()].sort((a, b) => a - b)) {
    const rank = ranks.get(key)!.sort((a, b) => a.position.y - b.position.y || a.id.localeCompare(b.id));
    if (!respace && rank.length <= maxRows) {
      for (const node of rank) placed.set(node.id, { x: column * columnGap, y: node.position.y });
      column++;
      continue;
    }
    const rows = respace ? maxRows : Math.max(maxRows, Math.ceil(Math.sqrt(rank.length / 2.4)));
    const middle = respace ? 0 : (rank[0]!.position.y + rank.at(-1)!.position.y) / 2;
    for (let start = 0; start < rank.length; start += rows) {
      const chunk = rank.slice(start, start + rows);
      chunk.forEach((node, row) => placed.set(node.id, { x: column * columnGap, y: middle + (row - (chunk.length - 1) / 2) * rowGap }));
      column++;
    }
  }
  return nodes.map(node => placed.has(node.id) ? { ...node, position: placed.get(node.id)! } : node);
}
