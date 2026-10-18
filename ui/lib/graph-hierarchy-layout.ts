import type { Edge, Node } from "@xyflow/react";
import type { LineageNodeData } from "@/components/lineage-nodes";
import { applyDagreLayout, reduceRankCrossings, type LayoutOptions } from "@/lib/dagre-layout";

const FINDINGS = new Set(["vulnerability", "misconfiguration", "driftIncident"]);

/** Source-rooted levels keep repository sibling directories in the same rank.
 * Cycles retain Dagre's cycle-aware ordering instead of inventing a root. */
function sourceRanks(nodes: Node[], edges: Edge[]): Map<string, number> | null {
  const incoming = new Map(nodes.map(node => [node.id, 0]));
  const outgoing = new Map<string, string[]>();
  for (const edge of edges) {
    if (!incoming.has(edge.source) || !incoming.has(edge.target)) continue;
    incoming.set(edge.target, incoming.get(edge.target)! + 1);
    outgoing.set(edge.source, [...(outgoing.get(edge.source) ?? []), edge.target]);
  }
  const queue = nodes.filter(node => incoming.get(node.id) === 0).map(node => node.id).sort();
  const ranks = new Map(queue.map(id => [id, 0]));
  let visited = 0;
  for (let index = 0; index < queue.length; index++) {
    const id = queue[index]!;
    visited++;
    for (const target of outgoing.get(id) ?? []) {
      ranks.set(target, Math.max(ranks.get(target) ?? 0, ranks.get(id)! + 1));
      incoming.set(target, incoming.get(target)! - 1);
      if (incoming.get(target) === 0) queue.push(target);
    }
  }
  return visited === nodes.length ? ranks : null;
}

/** Rank by recorded relationships; finding arrows retain their original direction. */
export function graphHierarchyLayout(nodes: Node<LineageNodeData>[], edges: Edge[], options: LayoutOptions = {}) {
  const byId = new Map(nodes.map(node => [node.id, node]));
  const contextEdges = new Set(edges.filter(edge => {
    const source = byId.get(edge.source), target = byId.get(edge.target);
    return source && target && !source.data.rollup && !target.data.rollup
      && source.type !== "clusterPillNode" && target.type !== "clusterPillNode"
      && edge.data?.relationship === "affects" && FINDINGS.has(source.data.nodeType) && !FINDINGS.has(target.data.nodeType);
  }).map(edge => edge.id));
  const rankedEdges = edges.map(edge => contextEdges.has(edge.id) ? { ...edge, source: edge.target, target: edge.source } : edge)
    .sort((a,b) => a.id.localeCompare(b.id));
  // At overview zoom the native glyph and text grow independently of the
  // camera. Reserve their full three-line caption plus finding footer so
  // stacked findings cannot run into the next entity's glyph.
  const nodeHeight = Math.max(300, options.nodeHeight ?? 0);
  const compact = nodes.length <= 24;
  const layout = applyDagreLayout([...nodes].sort((a,b) => a.id.localeCompare(b.id)), rankedEdges, {
    direction: "LR", nodeWidth: 240, nodeHeight: 224, nodeSep: 40, ...options,
    ...(compact ? { nodeHeight, rankSep: Math.min(options.rankSep ?? 96, 96), fitAspect: undefined,
      minSeparation: { width: 240, gap: 24, ...options.minSeparation, height: nodeHeight } } : {}),
  });
  // Dagre's dummy edge ranks can leave empty vertical slots. Pack each real
  // rank in its existing order, keeping the evidence-derived horizontal
  // levels and enough room for captions rather than shrinking the canvas.
  const ranks = new Map<number, typeof layout.nodes>();
  const levels = compact ? sourceRanks(layout.nodes, rankedEdges) : null;
  const rankStep = (options.nodeWidth ?? 240) + Math.min(options.rankSep ?? 96, 96);
  const rankedNodes = levels ? layout.nodes.map(node => ({ ...node, position: { ...node.position, x: levels.get(node.id)! * rankStep } })) : layout.nodes;
  for (const node of rankedNodes) {
    const x = Math.round(node.position.x);
    ranks.set(x, [...(ranks.get(x) ?? []), node]);
  }
  const rowStep = nodeHeight + Math.max(24, options.minSeparation?.gap ?? 0, options.nodeSep ?? 32);
  const rows = Math.max(0, ...[...ranks.values()].map(rank => rank.length));
  const packed = [...ranks.values()].flatMap(rank => rank.sort((a,b) => a.position.y - b.position.y).map((node, index) => ({
    ...node, style: { ...node.style, minHeight: nodeHeight },
    position: { x: node.position.x, y: ((rows - rank.length) / 2 + index) * rowStep },
  })));
  const span = Math.max(0, ...packed.map(node => node.position.x));
  const height = Math.max(0, rows - 1) * rowStep + nodeHeight;
  const stretch = span > 0 ? Math.max(1, Math.min(2, ((options.fitAspect ?? 2.2) * height - (options.nodeWidth ?? 240)) / span)) : 1;
  const spaced = packed.map(node => ({ ...node, position: { ...node.position, x: node.position.x * stretch } }));
  // Large contexts retain the established wrapped-rank layout. Packing all
  // siblings into one column would recreate the tall fan-out problem.
  const positioned = new Map((compact ? reduceRankCrossings(spaced, rankedEdges) : layout.nodes).map(node => [node.id, node]));
  return {
    nodes: nodes.map(node => positioned.get(node.id)!),
    edges: edges.map((edge): Edge => ({ ...edge,
      ...(contextEdges.has(edge.id) ? { sourceHandle: "context", targetHandle: "context" } : {}),
      data: { ...edge.data, quietLabel: true },
    })),
  };
}
