import type { Edge, Node } from "@xyflow/react";
import type { LineageNodeData } from "@/components/lineage-nodes";
import { graphRepositoryContext } from "@/lib/graph-repository-context";
import { applyDagreLayout, countStraightCrossings, reduceRankCrossings, type LayoutOptions } from "@/lib/dagre-layout";

const FINDINGS = new Set(["vulnerability", "misconfiguration", "driftIncident"]);

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

/** Keep single-parent chains level and leave room for long links between them. */
function alignHierarchyBranches(nodes: Node[], edges: Edge[], minGap: number): Node[] {
  const positions = new Map(nodes.map(node => [node.id, node.position]));
  const ranks = new Map<number, Node[]>();
  for (const node of nodes) ranks.set(node.position.x, [...(ranks.get(node.position.x) ?? []), node]);
  for (const x of [...ranks.keys()].sort((a, b) => a - b)) {
    const rank = ranks.get(x)!.sort((a, b) => a.position.y - b.position.y);
    const desired = rank.map(node => {
      const parents = edges.filter(edge => edge.target === node.id).flatMap(edge => {
        const parent = positions.get(edge.source);
        return parent && parent.x < x ? [parent.y] : [];
      }).sort((a, b) => a - b);
      return parents.length ? parents[Math.floor(parents.length / 2)]! : node.position.y;
    });
    const ys: number[] = [];
    desired.forEach((y, i) => ys.push(i ? Math.max(y, ys[i - 1]! + minGap) : y));
    // Centre siblings around a shared parent rather than pushing the whole
    // branch down; already-separated chains keep their exact parent row.
    const shift = desired.reduce((sum, y, i) => sum + y - ys[i]!, 0) / rank.length;
    rank.forEach((node, i) => positions.set(node.id, { x, y: ys[i]! + shift }));
  }
  return nodes.map(node => ({ ...node, position: positions.get(node.id)! }));
}

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
  const repository = nodes.some(node => graphRepositoryContext(node.data));
  const fanIn = new Map<string, number>(), fanOut = new Map<string, number>();
  for (const edge of rankedEdges) {
    fanIn.set(edge.target, (fanIn.get(edge.target) ?? 0) + 1);
    fanOut.set(edge.source, (fanOut.get(edge.source) ?? 0) + 1);
  }
  // Compact correlations can still be wide fan-ins/fan-outs. Keep their
  // aspect-aware wrapping so a small evidence set does not become a tall
  // column that the adaptive camera can only show one node at a time.
  const compact = nodes.length <= 24 && (repository || Math.max(0, ...fanIn.values(), ...fanOut.values()) <= 2);
  const captionRanks = sourceRanks(nodes, rankedEdges);
  const stackedFinding = nodes.some(node => FINDINGS.has(node.data.nodeType) &&
    (!captionRanks || nodes.some(peer => peer.id !== node.id && captionRanks.get(peer.id) === captionRanks.get(node.id))));
  const tallCaptions = stackedFinding || nodes.some(node => node.data.occurrenceRole || (node.data.label?.length ?? 0) > 32);
  const layout = applyDagreLayout([...nodes].sort((a,b) => a.id.localeCompare(b.id)), rankedEdges, {
    direction: "LR", nodeWidth: 240, nodeHeight: 224, nodeSep: 40, ...options,
    ...(nodes.length <= 24 && tallCaptions ? { nodeHeight,
      minSeparation: { width: 240, gap: 24, ...options.minSeparation, height: nodeHeight } } : {}),
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
  const ordered = compact ? orderHierarchyBranches(spaced, rankedEdges) : layout.nodes;
  const positioned = new Map((compact && repository ? alignHierarchyBranches(ordered, rankedEdges, rowStep) : ordered).map(node => [node.id, node]));
  return {
    nodes: nodes.map(node => positioned.get(node.id)!),
    edges: edges.map((edge): Edge => ({ ...edge,
      ...(contextEdges.has(edge.id) ? { sourceHandle: "context", targetHandle: "context" } : {}),
      data: { ...edge.data, quietLabel: !edge.data?.isClusterEdge },
    })),
  };
}
