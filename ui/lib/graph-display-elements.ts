import type { Edge, Node } from "@xyflow/react";

import type { LineageNodeData } from "@/components/lineage-nodes";
import type { BlastRadiusState } from "@/lib/graph-blast-investigation";
import type { ReachabilitySummary } from "@/lib/graph-reachability";
import type { DriftLensFilter, EvidenceLensFilter } from "@/lib/filter-algebra";
import { driftFilterPasses, evidenceLensPasses, isCriticalChange } from "@/lib/filter-algebra";
import { CHANGE_KIND_META, changeKindForEdge, changeKindForNode, graphNodeDisplayLabels, readableGraphEdges, type buildDriftIndex, type ChangeKind } from "@/lib/graph-utils";
import { serpentinePositions } from "@/lib/path-serpentine-layout";

type LineageNode = Node<LineageNodeData>;
type DriftIndex = ReturnType<typeof buildDriftIndex>;
type RenderBand = LineageNodeData["renderBand"];

// Keep relationship captions useful on focused graphs without letting a
// medium-sized topology turn into a wall of overlapping badges. Above this
// count labels follow the selected neighborhood; the relationship inspector
// and legend remain available for the full evidence.
export const GRAPH_EDGE_LABEL_BUDGET = 24;

/**
 * Compose the existing className (e.g. `node-critical-pulse`) with the
 * focus-mode classes. The data-driven `dimmed`/`highlighted` flags are kept
 * too, so dimming works in tests that read `data.dimmed` directly.
 */
function composeFocusClass(base: string | undefined, focused: boolean, dimmed: boolean): string {
  return [base, focused ? "lineage-node-focus" : "", dimmed ? "lineage-node-dim" : ""].filter(Boolean).join(" ") || "";
}

const emphasize = (node: LineageNode, focused: boolean, included: boolean, band: RenderBand): LineageNode => ({
  ...node,
  className: composeFocusClass(node.className, focused, !included),
  data: { ...node.data, renderBand: band, dimmed: !included, highlighted: included },
});

/** One emphasis owner at a time: blast radius, then a selected path, then reachability, then hover/pin focus. */
export function focusDisplayNodes({ nodes, band, blastRadius, pathNodeIds, pathOrder, reachability, neighborhood, focusId }: {
  nodes: LineageNode[];
  band: RenderBand;
  blastRadius: BlastRadiusState | null;
  pathNodeIds: Set<string> | null;
  pathOrder: Map<string, number> | null;
  reachability: ReachabilitySummary | null;
  neighborhood: Set<string> | null;
  focusId: string | null;
}): LineageNode[] {
  if (blastRadius) return nodes.map(node => emphasize(node, node.id === blastRadius.rootId, blastRadius.nodeIds.has(node.id), band));
  if (pathNodeIds) {
    const slots = serpentinePositions([...(pathOrder?.keys() ?? [])], 4, { column: 460, row: 220 });
    return nodes.filter(node => pathNodeIds.has(node.id)).map(node => {
      const slot = slots.get(node.id) ?? { x: 0, y: 0, reverse: false };
      const placed = emphasize({ ...node, position: { x: slot.x, y: slot.y } }, true, true, "detail");
      // A focused path always renders full cards, whatever the zoom band.
      return { ...placed, data: { ...placed.data, renderBand: "detail", reverseFlow: slot.reverse } };
    });
  }
  if (reachability) return nodes.map(node => emphasize(node, node.id === reachability.rootId, reachability.nodeIds.has(node.id), band));
  if (!neighborhood) return nodes.map(node => ({ ...node, data: { ...node.data, renderBand: band } }));
  return nodes.map(node => {
    const connected = neighborhood.has(node.id);
    const dimmed = !connected && node.type !== "clusterPillNode";
    return { ...node, className: composeFocusClass(node.className, node.id === focusId, dimmed), data: { ...node.data, renderBand: band, dimmed, highlighted: connected } };
  });
}

/** Drift rings and evidence dimming over the focused nodes; group pills stay legible navigation controls. */
export function lensDisplayNodes({ nodes, driftEngaged, driftIndex, driftFilter, evidenceActive, evidenceFilter }: {
  nodes: LineageNode[];
  driftEngaged: boolean;
  driftIndex: DriftIndex;
  driftFilter: DriftLensFilter;
  evidenceActive: boolean;
  evidenceFilter: EvidenceLensFilter;
}): LineageNode[] {
  let result = nodes;
  if (driftEngaged) {
    result = result.map(node => {
      const kind = changeKindForNode(node.id, driftIndex);
      const critical = isCriticalChange(kind, node.data.severity);
      const ringClass = driftFilter === "critical" && critical ? "drift-ring-critical" : CHANGE_KIND_META[kind].ringClass;
      return {
        ...node,
        className: [node.className, ringClass].filter(Boolean).join(" "),
        data: { ...node.data, dimmed: Boolean(node.data.dimmed) || !driftFilterPasses(kind, driftFilter, critical) },
      };
    });
  }
  if (evidenceActive) {
    result = result.map(node => ({ ...node, data: { ...node.data, dimmed: Boolean(node.data.dimmed) || !evidenceLensPasses(node.data.runtimeEvidenceTier, evidenceFilter) } }));
  }
  return result.map(node => node.type === "clusterPillNode" ? {
    ...node,
    className: (node.className ?? "").replace(/\blineage-node-dim\b/g, ""),
    data: { ...node.data, dimmed: false },
  } : node);
}

/** Change-kind tallies over what the canvas renders; `unchanged` is derived here, `removed` comes from the diff. */
export function driftTally(nodes: LineageNode[], driftIndex: DriftIndex): { counts: Record<ChangeKind, number>; critical: number } {
  const counts: Record<ChangeKind, number> = { new: 0, changed: 0, removed: driftIndex.counts.removed, unchanged: 0 };
  let critical = 0;
  for (const node of nodes) {
    const kind = changeKindForNode(node.id, driftIndex);
    if (kind === "new" || kind === "changed" || kind === "unchanged") counts[kind] += 1;
    if (isCriticalChange(kind, node.data.severity)) critical += 1;
  }
  return { counts, critical };
}

export function evidenceTally(nodes: LineageNode[]): Record<EvidenceLensFilter, number> {
  const counts: Record<EvidenceLensFilter, number> = { all: nodes.length, runtime_observed: 0, runtime_blocked: 0, static_scan: 0 };
  for (const node of nodes) {
    const tier = node.data.runtimeEvidenceTier ?? "static_scan";
    if (tier === "runtime_observed") counts.runtime_observed += 1;
    else if (tier === "runtime_blocked") counts.runtime_blocked += 1;
    else counts.static_scan += 1;
  }
  return counts;
}

const widthAtLeast = (edge: Edge, fallback: number, minimum: number) =>
  Math.max(typeof edge.style?.strokeWidth === "number" ? edge.style.strokeWidth : fallback, minimum);

/** Edge emphasis for the same owner order as the nodes: selected path, blast radius, reachability, focus. */
export function emphasizedDisplayEdges({ edges, nodes, neighborhood, pathEdgeIds, blastRadius, reachability, captureMode, zoom }: {
  edges: Edge[];
  nodes: LineageNode[];
  neighborhood: Set<string> | null;
  pathEdgeIds: Set<string> | null;
  blastRadius: BlastRadiusState | null;
  reachability: ReachabilitySummary | null;
  captureMode: boolean;
  zoom: number;
}): Edge[] {
  const readable = readableGraphEdges(edges, neighborhood, {
    baseOpacity: 1, highSignalOpacity: 1, inactiveOpacity: 0.06, captureMode, zoom,
    nodeLabels: graphNodeDisplayLabels(nodes),
    // Past this many edges the captions overlap into noise, so they follow
    // the selection instead of blanketing the canvas. A capture keeps them.
    maxLabeledEdges: captureMode ? Number.POSITIVE_INFINITY : GRAPH_EDGE_LABEL_BUDGET,
  });
  if (pathEdgeIds) {
    return readable.filter(edge => pathEdgeIds.has(edge.id)).map((edge): Edge => ({
      ...edge,
      labelShowBg: true,
      labelBgPadding: [8, 4],
      labelBgBorderRadius: 6,
      labelBgStyle: { fill: "var(--surface)", fillOpacity: 1 },
      labelStyle: { fill: "var(--foreground)", fontSize: Math.max(12, Math.min(20, 13 / Math.max(zoom, 0.2))), fontWeight: 650 },
      data: { ...edge.data, directionEmphasis: true, pathEmphasis: true },
      animated: !captureMode,
      style: { ...edge.style, opacity: 1, strokeWidth: widthAtLeast(edge, 2, 3.2), filter: undefined },
    }));
  }
  const glow = (included: boolean, edge: Edge, inactive: number, shadow: string): Edge => ({
    ...edge,
    data: { ...edge.data, directionEmphasis: included },
    animated: captureMode ? false : Boolean(included || edge.animated),
    style: { ...edge.style, opacity: included ? 0.95 : inactive, strokeWidth: included ? widthAtLeast(edge, 2, 3) : 1, ...(included ? { filter: shadow } : {}) },
  });
  if (blastRadius) {
    return readable.map(edge => glow(blastRadius.nodeIds.has(edge.source) && blastRadius.nodeIds.has(edge.target), edge, 0.06, "drop-shadow(0 0 6px rgba(139,92,246,0.55))"));
  }
  if (reachability) {
    return readable.map(edge => glow(reachability.edgeKeys.has(`${edge.source}=>${edge.target}`) || reachability.edgeKeys.has(`${edge.target}=>${edge.source}`),
      edge, 0.07, "drop-shadow(0 0 6px rgba(244,63,94,0.5))"));
  }
  return readable.map(edge => ({
    ...edge,
    // ReactFlow measures label backgrounds when label content changes.
    // A stable group font prevents Fit/zoom from outgrowing that background.
    ...(edge.data?.isClusterEdge ? { labelStyle: { ...edge.labelStyle, fontSize: 18 } } : {}),
    // Unselected links keep their labels and evidence with one legible
    // theme-aware stroke. Focus restores semantic emphasis.
    ...(!neighborhood || neighborhood.size > 13 ? { style: { ...edge.style,
      stroke: edge.data?.boundedOverview ? "var(--text-secondary)" : "var(--text-tertiary)",
      ...(edge.data?.boundedOverview ? { strokeWidth: 1.6, vectorEffect: "non-scaling-stroke" } : {}),
    } } : {}),
  }));
}

/** New and changed edges adopt their change-kind colour so the drift lens reads as one system with the node rings. */
export function driftDisplayEdges(edges: Edge[], engaged: boolean, driftIndex: DriftIndex): Edge[] {
  if (!engaged) return edges;
  return edges.map((edge): Edge => {
    const relationship = typeof edge.data?.relationship === "string" ? edge.data.relationship : "";
    const kind = changeKindForEdge(edge.source, edge.target, relationship, driftIndex);
    if (kind === "unchanged") return edge;
    const opacity = typeof edge.style?.opacity === "number" ? edge.style.opacity : 0.4;
    return {
      ...edge,
      style: {
        ...edge.style,
        stroke: CHANGE_KIND_META[kind].color,
        opacity: Math.max(opacity, 0.85),
        strokeWidth: widthAtLeast(edge, 1.4, 2.2),
        transition: "stroke 0.2s ease, opacity 0.2s ease, stroke-width 0.2s ease",
      },
    };
  });
}
