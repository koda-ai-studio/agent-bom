import { semanticColumns } from "@/lib/graph-semantic-columns";

import type { AttackPathGraphModel } from "@/lib/attack-path-graph-model";
import { ATTACK_PATH_FIT_PADDING, FINDING_BADGE_OVERHANG } from "@/lib/attack-path-graph-viewport";
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

/** The card tells one path: its hops read left to right in hop order, even where a hop's backend layer comes
 * before the hop it follows (a role that reaches an agent). A branch sits one column before, after or level with
 * the card it connects to, by their backend layer order; a node no branch reaches keeps its backend column. */
function rankColumns(model: AttackPathGraphModel): Map<string, number> {
  const layered = semanticColumns(model.nodes.map(node => ({ id: node.id, data: { entityType: node.entityType, semanticLayer: node.semanticLayer } })),
    model.edges.map(edge => ({ ...edge, data: { relationship: edge.relationship } })), model.pathNodeIds);
  const columns = new Map(layered);
  const placed = new Set<string>();
  let previous = -Infinity;
  for (const id of model.pathNodeIds) {
    if (!columns.has(id) || placed.has(id)) continue;
    previous = Math.max(layered.get(id)!, previous + 1);
    columns.set(id, previous);
    placed.add(id);
  }
  for (let frontier = [...placed]; frontier.length;) {
    const next: string[] = [];
    for (const edge of model.edges) for (const [from, to] of [[edge.source, edge.target], [edge.target, edge.source]] as const) {
      if (!frontier.includes(from) || placed.has(to) || !columns.has(to)) continue;
      columns.set(to, columns.get(from)! + Math.sign(layered.get(to)! - layered.get(from)!));
      placed.add(to);
      next.push(to);
    }
    frontier = next;
  }
  for (let pass = 0; pass < model.nodes.length; pass++) for (const node of model.nodes) {
    if (node.semanticOwner && columns.has(node.semanticOwner)) columns.set(node.id, columns.get(node.semanticOwner)!);
  }
  return columns;
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
    if (lanes.has(node.id) || node.semanticOwner) continue;
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
    keyed.forEach((item, index) => lanes.set(item.id, (Math.floor(index / 2) + 1) * (index % 2 ? -1 : 1)));
  }
  for (let pass = 0; pass < model.nodes.length; pass++) for (const node of model.nodes) {
    if (!node.semanticOwner || lanes.has(node.id) || !lanes.has(node.semanticOwner)) continue;
    let lane = lanes.get(node.semanticOwner)! + 1;
    while (model.nodes.some(other => columns.get(other.id) === columns.get(node.id) && lanes.get(other.id) === lane)) lane++;
    lanes.set(node.id, lane);
  }
  for (const node of model.nodes) if (!lanes.has(node.id)) lanes.set(node.id, 1);
  return lanes;
}

/** A card owned by a branch card (a server's package) sits in the next drawn column right of its owner, level with it, when that
 * cell is free and every link of the card is to its owner: the link is then one short forward line, not a loop round
 * the owner's name down the side of its column. Cards owned by a hop of the selected path keep their place below it. */
function besideBranchOwners(model: AttackPathGraphModel, columns: Map<string, number>, lanes: Map<string, number>) {
  const existing = new Set(columns.values());
  const path = new Set(model.pathNodeIds);
  for (const node of model.nodes) {
    const owner = node.semanticOwner;
    if (!owner || path.has(node.id) || path.has(owner) || !columns.has(owner) || !lanes.has(owner)) continue;
    const column = Math.min(...[...existing].filter(value => value > columns.get(owner)!)), lane = lanes.get(owner)!;
    if (!Number.isFinite(column) || model.nodes.some(other => other.id !== node.id && columns.get(other.id) === column && lanes.get(other.id) === lane)) continue;
    if (model.edges.some(edge => (edge.source === node.id || edge.target === node.id) && edge.source !== owner && edge.target !== owner)) continue;
    columns.set(node.id, column);
    lanes.set(node.id, lane);
  }
}

/** A phone reads the supplied path vertically; context occupies one adjacent
 * column, with additional rows instead of an off-screen third column. */
function portraitPathLayout(model: AttackPathGraphModel): AttackPathLayout {
  const columns = rankColumns(model), positions = new Map<string, { x: number; y: number }>();
  const lanes = new Map<string, number>();
  const spine = model.pathNodeIds.filter(id => model.nodes.some(node => node.id === id));
  const spineSet = new Set(spine), groups = new Map<string, string[]>();
  for (const node of model.nodes) {
    if (spineSet.has(node.id)) continue;
    const owner = node.semanticOwner && spineSet.has(node.semanticOwner) ? node.semanticOwner
      : spine.find(id => model.edges.some(edge => edge.source === id && edge.target === node.id || edge.target === id && edge.source === node.id)) ?? spine.at(-1) ?? "";
    groups.set(owner, [...(groups.get(owner) ?? []), node.id]);
  }
  let y = 0;
  for (const id of spine.length ? spine : [""]) {
    if (id) { positions.set(id, { x: 8, y }); lanes.set(id, 0); }
    const context = groups.get(id) ?? [];
    context.forEach((child, index) => { positions.set(child, { x: 120, y: y + (index + 1) * 168 }); lanes.set(child, 1); });
    y += (1 + context.length) * 168;
  }
  return { direction: "TB", positions, columns, lanes, minLane: 0, maxLane: groups.size ? 1 : 0,
    rankGap: 32, laneGap: 12, margin: 8, width: groups.size ? 280 : 168,
    height: Math.max(136, y - 32), nodeWidth: PATH_NODE.width, nodeHeight: PATH_NODE.height };
}

/**
 * Layered DAG: the selected path is one straight line, every node sits in its
 * dagre layer, and branches take lanes above and below the path.
 */
export function layoutAttackPathGraph(model: AttackPathGraphModel, _requestedDirection: AttackPathDirection, hopColumns?: Map<string, number>): AttackPathLayout {
  if (_requestedDirection === "TB") return portraitPathLayout(model);
  // Desktop preserves the backend semantic columns.
  const direction: AttackPathDirection = "LR";
  const spacing = SPACING[direction];
  const columns = hopColumns ? new Map(hopColumns) : rankColumns(model);
  const lanes = assignLanes(model, columns);
  besideBranchOwners(model, columns, lanes);
  const occupiedColumns = [...new Set(columns.values())].sort((a, b) => a - b);
  const minLane = Math.min(0, ...lanes.values());
  const maxLane = Math.max(0, ...lanes.values());
  const row = direction === "LR";
  const mainSize = row ? PATH_NODE.width : PATH_NODE.height;
  const crossSize = row ? PATH_NODE.height : PATH_NODE.width;
  const margin = spacing.lane / 2;
  const positions = new Map<string, { x: number; y: number }>();
  let width = 0, height = 0;
  for (const node of model.nodes) {
    const along = occupiedColumns.indexOf(columns.get(node.id)!) * (mainSize + spacing.rank);
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
export const NARROW_MIN_ZOOM = Math.max(legibleZoomForText(15), 48 / 56);
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
export function attackPathCanvasWidth(layout: Pick<AttackPathLayout, "width"> & Partial<Pick<AttackPathLayout, "direction">>, narrow: boolean, containerWidth: number): number {
  if (!narrow || layout.direction === "TB" || !(containerWidth > 0)) return containerWidth;
  const needed = layout.width * NARROW_MIN_ZOOM + ATTACK_PATH_FIT_PADDING.left + ATTACK_PATH_FIT_PADDING.right + FINDING_BADGE_OVERHANG;
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
