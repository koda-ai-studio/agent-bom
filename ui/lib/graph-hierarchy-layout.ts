import { semanticGraphLayout } from "@/lib/graph-semantic-layout";
import type { Edge, Node } from "@xyflow/react";
import type { LineageNodeData } from "@/components/lineage-nodes";
import { countStraightCrossings, reduceRankCrossings, type LayoutOptions } from "@/lib/dagre-layout";


/** Coordinate adjacent layers, so branches that converge stay together.
 * Individual rank swaps can get stuck when both a directory and its file
 * need to move. Whole sweeps preserve rank/spacing and never add crossings. */
export function orderHierarchyBranches(nodes: Node[], edges: Edge[]): Node[] {
  let best = reduceRankCrossings(nodes, edges);
  const score = (items: Node[]) => {
    const y = new Map(items.map(node => [node.id, node.position.y]));
    return [countStraightCrossings(items, edges), edges.reduce((sum, edge) =>
      sum + (y.has(edge.source) && y.has(edge.target) ? Math.abs(y.get(edge.source)! - y.get(edge.target)!) : 0), 0)];
  };
  let bestScore = score(best);
  for (const reverse of [true, false, true, false]) {
    const positions = new Map(best.map(node => [node.id, node.position]));
    const ranks = new Map<number, Node[]>();
    for (const node of best) ranks.set(node.position.x, [...(ranks.get(node.position.x) ?? []), node]);
    const xs = [...ranks.keys()].sort((a, b) => reverse ? b - a : a - b);
    for (const x of xs) {
      const rank = ranks.get(x)!;
      const slots = rank.map(node => node.position.y).sort((a, b) => a - b);
      const center = (node: Node) => {
        const neighbors = edges.flatMap(edge => {
          const id = reverse ? (edge.source === node.id ? edge.target : null) : (edge.target === node.id ? edge.source : null);
          const at = id ? positions.get(id) : undefined;
          return at && (reverse ? at.x > x : at.x < x) ? [at.y] : [];
        });
        return neighbors.length ? neighbors.reduce((a, b) => a + b, 0) / neighbors.length : node.position.y;
      };
      rank.sort((a, b) => center(a) - center(b) || a.position.y - b.position.y || a.id.localeCompare(b.id));
      rank.forEach((node, index) => positions.set(node.id, { x, y: slots[index]! }));
    }
    const candidate = reduceRankCrossings(best.map(node => ({ ...node, position: positions.get(node.id)! })), edges);
    const next = score(candidate);
    if (next[0]! < bestScore[0]! || (next[0] === bestScore[0] && next[1]! < bestScore[1]!)) {
      best = candidate;
      bestScore = next;
    }
  }
  return best;
}

/** Semantic layers and the server-selected path share one layout in every view. */
export function graphHierarchyLayout(nodes: Node<LineageNodeData>[], edges: Edge[], _options: LayoutOptions = {}): { nodes: Node[]; edges: Edge[] } {
  void _options;
  return semanticGraphLayout(nodes, edges);
}
