import type { Edge, Node } from "@xyflow/react";
import type { LineageNodeData } from "@/components/lineage-nodes";
import { applyDagreLayout, reduceRankCrossings, type LayoutOptions } from "@/lib/dagre-layout";

const FINDINGS = new Set(["vulnerability", "misconfiguration", "driftIncident"]);
const STRUCTURAL_LABELS = new Set(["contains", "hosts", "vulnerable_to", "has_finding"]);

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
  const layout = applyDagreLayout([...nodes].sort((a,b) => a.id.localeCompare(b.id)), rankedEdges, {
    direction: "LR", nodeWidth: 240, nodeSep: 40, ...options, nodeHeight,
    rankSep: Math.min(options.rankSep ?? 96, 96), fitAspect: undefined,
    minSeparation: { width: 240, gap: 24, ...options.minSeparation, height: nodeHeight },
  });
  // Dagre's dummy edge ranks can leave empty vertical slots. Pack each real
  // rank in its existing order, keeping the evidence-derived horizontal
  // levels and enough room for captions rather than shrinking the canvas.
  const ranks = new Map<number, typeof layout.nodes>();
  for (const node of layout.nodes) {
    const x = Math.round(node.position.x);
    ranks.set(x, [...(ranks.get(x) ?? []), node]);
  }
  const rowStep = nodeHeight + Math.max(24, options.minSeparation?.gap ?? 0, options.nodeSep ?? 32);
  const rows = Math.max(0, ...[...ranks.values()].map(rank => rank.length));
  const packed = [...ranks.values()].flatMap(rank => rank.sort((a,b) => a.position.y - b.position.y).map((node, index) => ({
    ...node, position: { x: node.position.x, y: ((rows - rank.length) / 2 + index) * rowStep },
  })));
  const positioned = new Map(reduceRankCrossings(packed, rankedEdges).map(node => [node.id, node]));
  return {
    nodes: nodes.map(node => positioned.get(node.id)!),
    edges: edges.map((edge): Edge => ({ ...edge,
      ...(contextEdges.has(edge.id) ? { sourceHandle: "context", targetHandle: "context" } : {}),
      data: { ...edge.data, quietLabel: STRUCTURAL_LABELS.has(String(edge.data?.relationship)) },
    })),
  };
}
