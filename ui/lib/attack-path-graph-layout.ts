import { Graph, layout } from "@dagrejs/dagre";

import type { AttackPathGraphModel } from "@/lib/attack-path-graph-model";
import { ATTACK_PATH_FIT_PADDING } from "@/lib/attack-path-graph-viewport";
import { legibleZoomForText } from "@/lib/graph-adaptive-frame";

export type AttackPathDirection = "LR" | "TB";
export type AttackPathLayout = {
  direction: AttackPathDirection;
  /** Top-left corner of every node box. */
  positions: Map<string, { x: number; y: number }>;
  /** Layer index along the reading direction, and lane across it (0 = selected path). */
  columns: Map<string, number>;
  lanes: Map<string, number>;
  minLane: number;
  maxLane: number;
  /** Gap between layers and between lanes, and the margin kept outside the outer lanes for routed edges. */
  rankGap: number;
  laneGap: number;
  margin: number;
  width: number;
  height: number;
  nodeWidth: number;
  nodeHeight: number;
};

/** Room for a two-line name under a 56px glyph. */
export const ATTACK_PATH_NODE = { width: 168, height: 136 } as const;
/** The path graph's node: a glyph over a two-line name, narrow enough that a seven-hop path fits a desktop canvas legibly. */
export const PATH_NODE = { width: 152, height: 136 } as const;
export const ATTACK_PATH_CANVAS_BOUNDS = { min: 240, max: 640 } as const;
/**
 * Rows of branches sit 168px apart on a desktop; a phone keeps columns tight. The desktop gap
 * between layers holds a hop's relationship name and the turns of lines changing row, so no
 * line bends inside a node's column.
 */
const SPACING = { LR: { rank: 48, lane: 32 }, TB: { rank: 40, lane: 20 } } as const;

/** Layer per node from dagre's ranking, re-indexed 0..n along the reading direction. */
function rankColumns(model: AttackPathGraphModel, direction: AttackPathDirection): Map<string, number> {
  const graph = new Graph({ multigraph: true });
  graph.setGraph({ rankdir: direction, ranksep: 40, nodesep: 20, ranker: "network-simplex" });
  graph.setDefaultEdgeLabel(() => ({}));
  for (const node of model.nodes) graph.setNode(node.id, { width: PATH_NODE.width, height: PATH_NODE.height });
  for (const edge of model.edges) graph.setEdge(edge.source, edge.target, { weight: edge.onPath ? 8 : 1, minlen: 1 }, edge.id);
  layout(graph);
  const main = (id: string) => Math.round(direction === "LR" ? graph.node(id).x : graph.node(id).y);
  const ranks = [...new Set(model.nodes.map(node => main(node.id)))].sort((a, b) => a - b);
  return new Map(model.nodes.map(node => [node.id, ranks.indexOf(main(node.id))]));
}

/**
 * Lanes by barycenter, layer by layer: a branch node sits at the distance of
 * the neighbours already placed, closest to the spine first. The selected path
 * is always the first lane (the top row on a desktop, the left column on a
 * phone) so it is what a first frame shows; every branch takes a lane after it.
 * Ordering branches by where their neighbours are keeps their edges from crossing.
 */
function assignLanes(model: AttackPathGraphModel, columns: Map<string, number>): Map<string, number> {
  const lanes = new Map<string, number>(model.pathNodeIds.map(id => [id, 0]));
  const neighbours = new Map<string, string[]>();
  for (const edge of model.edges) {
    neighbours.set(edge.source, [...(neighbours.get(edge.source) ?? []), edge.target]);
    neighbours.set(edge.target, [...(neighbours.get(edge.target) ?? []), edge.source]);
  }
  const byColumn = new Map<number, string[]>();
  for (const node of model.nodes) {
    if (lanes.has(node.id)) continue;
    const column = columns.get(node.id)!;
    byColumn.set(column, [...(byColumn.get(column) ?? []), node.id]);
  }
  for (const column of [...byColumn.keys()].sort((a, b) => a - b)) {
    const keyed = byColumn.get(column)!.map(id => {
      const placed = (neighbours.get(id) ?? []).filter(other => lanes.has(other)).map(other => lanes.get(other)!);
      const mean = placed.length ? placed.reduce((sum, lane) => sum + lane, 0) / placed.length : 0;
      return { id, key: Math.max(mean, 0.5) };
    });
    keyed.sort((a, b) => a.key - b.key || a.id.localeCompare(b.id));
    keyed.forEach((item, index) => lanes.set(item.id, index + 1));
  }
  return lanes;
}

/**
 * Layered DAG: the selected path is one straight line, every node sits in its
 * dagre layer, and branches take lanes above and below the path.
 */
export function layoutAttackPathGraph(model: AttackPathGraphModel, direction: AttackPathDirection): AttackPathLayout {
  const spacing = SPACING[direction];
  const columns = rankColumns(model, direction);
  const lanes = assignLanes(model, columns);
  const minLane = Math.min(0, ...lanes.values());
  const maxLane = Math.max(0, ...lanes.values());
  const row = direction === "LR";
  const mainSize = row ? PATH_NODE.width : PATH_NODE.height;
  const crossSize = row ? PATH_NODE.height : PATH_NODE.width;
  const margin = spacing.lane / 2;
  const positions = new Map<string, { x: number; y: number }>();
  let width = 0, height = 0;
  for (const node of model.nodes) {
    const along = columns.get(node.id)! * (mainSize + spacing.rank);
    const across = margin + (lanes.get(node.id)! - minLane) * (crossSize + spacing.lane);
    const x = row ? along : across, y = row ? across : along;
    positions.set(node.id, { x, y });
    width = Math.max(width, x + PATH_NODE.width + (row ? 0 : margin));
    height = Math.max(height, y + PATH_NODE.height + (row ? margin : 0));
  }
  return {
    direction, positions, columns, lanes, minLane, maxLane, rankGap: spacing.rank, laneGap: spacing.lane, margin,
    width, height, nodeWidth: PATH_NODE.width, nodeHeight: PATH_NODE.height,
  };
}

/** Phones keep text readable: the column fits the width down to where 15px names are 11px, then the page scrolls. */
export const NARROW_MIN_ZOOM = legibleZoomForText(15);
/** The path graph's desktop floor: its 15px names stay at least about 11px on screen. */
export const PATH_DESKTOP_MIN_ZOOM = 0.75;

function fittedZoom(layout: Pick<AttackPathLayout, "width">, containerWidth: number, floor: number): number {
  if (!(containerWidth > 0) || !(layout.width > 0)) return 1;
  const usable = containerWidth - ATTACK_PATH_FIT_PADDING.left - ATTACK_PATH_FIT_PADDING.right;
  return Math.min(1, Math.max(floor, usable / layout.width));
}

/**
 * A phone never hides a node: a graph wider than the frame at the legible floor gets a wider
 * canvas that scrolls sideways. A desktop canvas always matches its frame.
 */
export function attackPathCanvasWidth(layout: Pick<AttackPathLayout, "width">, narrow: boolean, containerWidth: number): number {
  if (!narrow || !(containerWidth > 0)) return containerWidth;
  const needed = layout.width * NARROW_MIN_ZOOM + ATTACK_PATH_FIT_PADDING.left + ATTACK_PATH_FIT_PADDING.right;
  return Math.max(containerWidth, Math.ceil(needed));
}

export function narrowFitZoom(layout: Pick<AttackPathLayout, "width">, containerWidth: number): number {
  return fittedZoom(layout, containerWidth, NARROW_MIN_ZOOM);
}

/**
 * The canvas grows with the laid-out graph at the zoom it will be shown at:
 * desktop within fixed bounds, a phone the whole column so the page scrolls.
 */
export function attackPathCanvasHeight(layout: Pick<AttackPathLayout, "height" | "width">, narrow: boolean, containerWidth = 0): number {
  const zoom = fittedZoom(layout, containerWidth, narrow ? NARROW_MIN_ZOOM : PATH_DESKTOP_MIN_ZOOM);
  const height = layout.height * zoom + ATTACK_PATH_FIT_PADDING.top + ATTACK_PATH_FIT_PADDING.bottom;
  if (narrow) return Math.round(Math.max(ATTACK_PATH_CANVAS_BOUNDS.min, height));
  return Math.round(Math.min(ATTACK_PATH_CANVAS_BOUNDS.max, Math.max(ATTACK_PATH_CANVAS_BOUNDS.min, height)));
}
