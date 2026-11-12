import { Graph, layout } from "@dagrejs/dagre";

import type { AttackPathGraphModel } from "@/lib/attack-path-graph-model";

export type AttackPathDirection = "LR" | "TB";
export type AttackPathLayout = {
  direction: AttackPathDirection;
  /** Top-left corner of every node box. */
  positions: Map<string, { x: number; y: number }>;
  width: number;
  height: number;
  nodeWidth: number;
  nodeHeight: number;
};

export const ATTACK_PATH_NODE = { width: 150, height: 116 } as const;
export const ATTACK_PATH_CANVAS_BOUNDS = { min: 240, max: 560 } as const;
/** Room for the fitted frame's padding and the zoom controls row. */
const CANVAS_CHROME_PX = 112;
const SPACING = { LR: { rank: 34, cross: 28 }, TB: { rank: 44, cross: 24 } } as const;

/** Lane per node: 0 for the selected path, ±n for branches on the side dagre chose. */
function branchLanes(model: AttackPathGraphModel, main: (id: string) => number, cross: (id: string) => number): Map<string, number> {
  const spine = new Set(model.pathNodeIds);
  const spineCross = model.pathNodeIds.reduce((sum, id) => sum + cross(id), 0) / Math.max(1, model.pathNodeIds.length);
  const lanes = new Map<string, number>(model.pathNodeIds.map(id => [id, 0]));
  const columns = new Map<number, string[]>();
  for (const node of model.nodes) {
    if (spine.has(node.id)) continue;
    const key = Math.round(main(node.id));
    columns.set(key, [...(columns.get(key) ?? []), node.id]);
  }
  for (const ids of columns.values()) {
    const ordered = [...ids].sort((a, b) => Math.abs(cross(a) - spineCross) - Math.abs(cross(b) - spineCross) || a.localeCompare(b));
    let above = 0, below = 0;
    for (const id of ordered) lanes.set(id, cross(id) < spineCross ? -(++above) : ++below);
  }
  return lanes;
}

/**
 * Layered DAG: dagre ranks every node into columns (rows on a phone), then the
 * selected path is pinned to one straight line and each branch node takes the
 * nearest free lane above or below it.
 */
export function layoutAttackPathGraph(model: AttackPathGraphModel, direction: AttackPathDirection): AttackPathLayout {
  const graph = new Graph({ multigraph: true });
  const spacing = SPACING[direction];
  graph.setGraph({ rankdir: direction, ranksep: spacing.rank, nodesep: spacing.cross, marginx: 0, marginy: 0, ranker: "network-simplex" });
  graph.setDefaultEdgeLabel(() => ({}));
  for (const node of model.nodes) graph.setNode(node.id, { width: ATTACK_PATH_NODE.width, height: ATTACK_PATH_NODE.height });
  for (const edge of model.edges) graph.setEdge(edge.source, edge.target, { weight: edge.onPath ? 8 : 1, minlen: 1 }, edge.id);
  layout(graph);

  const row = direction === "LR";
  const main = (id: string) => row ? graph.node(id).x : graph.node(id).y;
  const cross = (id: string) => row ? graph.node(id).y : graph.node(id).x;
  const pitch = (row ? ATTACK_PATH_NODE.height : ATTACK_PATH_NODE.width) + spacing.cross;
  const lanes = branchLanes(model, main, cross);
  const minLane = Math.min(0, ...lanes.values());
  const minMain = Math.min(...model.nodes.map(node => main(node.id)));
  const positions = new Map<string, { x: number; y: number }>();
  let width = 0, height = 0;
  for (const node of model.nodes) {
    const along = main(node.id) - minMain;
    const across = (lanes.get(node.id)! - minLane) * pitch;
    const x = row ? along : across, y = row ? across : along;
    positions.set(node.id, { x, y });
    width = Math.max(width, x + ATTACK_PATH_NODE.width);
    height = Math.max(height, y + ATTACK_PATH_NODE.height);
  }
  return { direction, positions, width, height, nodeWidth: ATTACK_PATH_NODE.width, nodeHeight: ATTACK_PATH_NODE.height };
}

/** Phones keep text readable: the column fits the width down to 0.7, then the page scrolls. */
export const NARROW_MIN_ZOOM = 0.7;
const NARROW_SIDE_PX = 8;

export function narrowFitZoom(layout: Pick<AttackPathLayout, "width">, containerWidth: number): number {
  if (!(containerWidth > 0) || !(layout.width > 0)) return 1;
  return Math.min(1, Math.max(NARROW_MIN_ZOOM, (containerWidth - 2 * NARROW_SIDE_PX) / layout.width));
}

/**
 * The canvas grows with the laid-out graph. Desktop stays within fixed bounds
 * and fits to view; a phone shows the whole column at a readable zoom.
 */
export function attackPathCanvasHeight(layout: Pick<AttackPathLayout, "height" | "width">, narrow: boolean, containerWidth = 0): number {
  if (narrow) {
    const height = layout.height * narrowFitZoom(layout, containerWidth) + CANVAS_CHROME_PX;
    return Math.round(Math.max(ATTACK_PATH_CANVAS_BOUNDS.min, height));
  }
  // A wide graph fits at a smaller zoom; reserve only the height it will occupy.
  const zoom = containerWidth > 0 && layout.width > 0
    ? Math.min(1, Math.max(DESKTOP_MIN_ZOOM, (containerWidth * (1 - 2 * DESKTOP_FIT_PADDING)) / layout.width)) : 1;
  const height = layout.height * zoom + CANVAS_CHROME_PX;
  return Math.round(Math.min(ATTACK_PATH_CANVAS_BOUNDS.max, Math.max(ATTACK_PATH_CANVAS_BOUNDS.min, height)));
}

/**
 * What the camera frames: the whole graph when it fits at `minZoom`, else the
 * selected path's own extent so the spine stays readable and branches pan in.
 */
export function attackPathFitBounds(
  layout: Pick<AttackPathLayout, "positions" | "width" | "height" | "nodeWidth" | "nodeHeight">,
  spineIds: readonly string[], paneWidth: number, paneHeight: number, minZoom: number,
): { x: number; y: number; width: number; height: number } {
  const whole = { x: 0, y: 0, width: layout.width, height: layout.height };
  const fits = layout.width * minZoom <= paneWidth && layout.height * minZoom <= paneHeight;
  const spine = spineIds.map(id => layout.positions.get(id)).filter((point): point is { x: number; y: number } => Boolean(point));
  if (fits || spine.length === 0) return whole;
  const x = Math.min(...spine.map(point => point.x)), y = Math.min(...spine.map(point => point.y));
  return {
    x, y,
    width: Math.max(...spine.map(point => point.x)) + layout.nodeWidth - x,
    height: Math.max(...spine.map(point => point.y)) + layout.nodeHeight - y,
  };
}

export const DESKTOP_MIN_ZOOM = 0.6;
export const DESKTOP_FIT_PADDING = 0.04;
