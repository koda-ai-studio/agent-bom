import { ATTACK_PATH_NODE, PATH_DESKTOP_MIN_ZOOM, type AttackPathDirection, type AttackPathLayout } from "@/lib/attack-path-graph-layout";
import { routeAttackPathEdges, sampleRoute, type Point } from "@/lib/attack-path-graph-routes";
import { ATTACK_PATH_FIT_PADDING } from "@/lib/attack-path-graph-viewport";
import type { ArchitectureModel, ArchitectureNode } from "@/lib/agent-architecture-model";

/** The layout shares the attack-path geometry so its routing, camera and node boxes apply unchanged. */
export type ArchitectureLayout = AttackPathLayout;

/** Rows of a layered map sit 72px apart; flow columns 64px, so an eight-step flow fits a desktop at the readable zoom. */
const SPACING = { TB: { rank: 72, lane: 40 }, LR: { rank: 64, lane: 36 } } as const;
export const ARCHITECTURE_CANVAS_BOUNDS = { min: 320, max: 860 } as const;
const SWEEPS = 6;
const LOCAL_SEARCH_EDGES = 80;

function geometry(model: ArchitectureModel, direction: AttackPathDirection, columns: Map<string, number>, lanes: Map<string, number>): ArchitectureLayout {
  const spacing = SPACING[direction];
  const row = direction === "LR";
  const minLane = Math.min(0, ...lanes.values());
  const maxLane = Math.max(0, ...lanes.values());
  const mainSize = row ? ATTACK_PATH_NODE.width : ATTACK_PATH_NODE.height;
  const crossSize = row ? ATTACK_PATH_NODE.height : ATTACK_PATH_NODE.width;
  const margin = spacing.lane / 2;
  const positions = new Map<string, { x: number; y: number }>();
  let width = 0, height = 0;
  for (const node of model.nodes) {
    const along = columns.get(node.id)! * (mainSize + spacing.rank);
    const across = margin + (lanes.get(node.id)! - minLane) * (crossSize + spacing.lane);
    const x = row ? along : across, y = row ? across : along;
    positions.set(node.id, { x, y });
    width = Math.max(width, x + ATTACK_PATH_NODE.width + (row ? 0 : margin));
    height = Math.max(height, y + ATTACK_PATH_NODE.height + (row ? margin : 0));
  }
  return {
    direction, positions, columns, lanes, minLane, maxLane, rankGap: spacing.rank, laneGap: spacing.lane, margin,
    width, height, nodeWidth: ATTACK_PATH_NODE.width, nodeHeight: ATTACK_PATH_NODE.height,
  };
}

const byPlacement = (a: ArchitectureNode, b: ArchitectureNode) => Number(b.entry) - Number(a.entry) || a.order - b.order || a.id.localeCompare(b.id);

/**
 * Layered map as a tidy tree: leaves take consecutive slots, each parent is
 * centred over its children, so parent lines never cross.
 */
function layered(model: ArchitectureModel): ArchitectureLayout {
  const ids = new Set(model.nodes.map(node => node.id));
  const children = new Map<string, ArchitectureNode[]>();
  const roots: ArchitectureNode[] = [];
  for (const node of model.nodes) {
    if (node.parentId && ids.has(node.parentId) && node.parentId !== node.id) children.set(node.parentId, [...(children.get(node.parentId) ?? []), node]);
    else roots.push(node);
  }
  const columns = new Map<string, number>();
  const lanes = new Map<string, number>();
  let slot = 0;
  const place = (node: ArchitectureNode, depth: number): number => {
    columns.set(node.id, depth);
    const kids = (children.get(node.id) ?? []).sort(byPlacement);
    if (kids.length === 0) { lanes.set(node.id, slot); slot += 1; return lanes.get(node.id)!; }
    const placed = kids.map(kid => place(kid, depth + 1));
    lanes.set(node.id, (placed[0]! + placed[placed.length - 1]!) / 2);
    return lanes.get(node.id)!;
  };
  for (const root of roots.sort(byPlacement)) place(root, 0);
  return geometry(model, "TB", columns, lanes);
}

function flowColumns(model: ArchitectureModel): Map<string, number> {
  const incoming = new Map<string, string[]>();
  for (const edge of model.edges) incoming.set(edge.target, [...(incoming.get(edge.target) ?? []), edge.source]);
  const columns = new Map<string, number>();
  const rank = (id: string, seen: Set<string>): number => {
    if (columns.has(id)) return columns.get(id)!;
    if (seen.has(id)) return 0;
    seen.add(id);
    const value = Math.max(-1, ...(incoming.get(id) ?? []).map(source => rank(source, seen))) + 1;
    columns.set(id, value);
    return value;
  };
  for (const node of model.nodes) rank(node.id, new Set());
  // The harness's own finish is the last step.
  const end = `finish:${model.rootId}`;
  if (columns.has(end)) {
    const others = [...columns].filter(([id]) => id !== end).map(([, value]) => value);
    columns.set(end, Math.max(columns.get(end)!, Math.max(-1, ...others) + 1));
  }
  return columns;
}

/** Whole lanes centred on the main row: the router's channels sit between whole lanes. */
function centredLanes(order: Map<number, string[]>): Map<string, number> {
  const lanes = new Map<string, number>();
  for (const ids of order.values()) ids.forEach((id, index) => lanes.set(id, index - Math.floor((ids.length - 1) / 2)));
  return lanes;
}

type Order = Map<number, string[]>;
const copyOrder = (order: Order): Order => new Map([...order].map(([column, ids]) => [column, [...ids]]));

/** Barycentre sweeps: each row sorted by the mean lane of its neighbours in the previous (or next) column. */
function sweep(model: ArchitectureModel, order: Order, forward: boolean): Order {
  const next = copyOrder(order);
  const lanes = centredLanes(next);
  const keys = [...next.keys()].sort((a, b) => a - b);
  for (const column of forward ? keys : keys.reverse()) {
    const ids = next.get(column)!;
    const keyed = new Map(ids.map(id => {
      const placed = model.edges.filter(edge => (forward ? edge.target : edge.source) === id).map(edge => lanes.get(forward ? edge.source : edge.target)!);
      return [id, placed.length ? placed.reduce((sum, lane) => sum + lane, 0) / placed.length : lanes.get(id)!];
    }));
    next.set(column, [...ids].sort((a, b) => keyed.get(a)! - keyed.get(b)!));
    centredLanes(new Map([[column, next.get(column)!]])).forEach((lane, id) => lanes.set(id, lane));
  }
  return next;
}

/** Flow, left to right: longest-path columns; rows ordered by barycentre, then adjacent swaps while they remove crossings. */
function flow(model: ArchitectureModel): ArchitectureLayout {
  const columns = flowColumns(model);
  let order: Order = new Map();
  for (const node of [...model.nodes].sort(byPlacement)) {
    const column = columns.get(node.id)!;
    order.set(column, [...(order.get(column) ?? []), node.id]);
  }
  const score = (candidate: Order) => {
    const layout = geometry(model, "LR", columns, centredLanes(candidate));
    return { layout, crossings: countRouteCrossings(model, routeArchitecture(model, layout)) };
  };
  let best = score(order);
  for (let pass = 0; pass < SWEEPS && best.crossings > 0; pass += 1) {
    const candidateOrder = sweep(model, order, pass % 2 === 0);
    const candidate = score(candidateOrder);
    if (candidate.crossings < best.crossings) { best = candidate; order = candidateOrder; }
  }
  // Exhaustive scoring is quadratic in edges; large harnesses keep the sweep result.
  for (let improved = best.crossings > 0 && model.edges.length <= LOCAL_SEARCH_EDGES; improved;) {
    improved = false;
    for (const [column, ids] of order) for (let index = 0; index + 1 < ids.length && best.crossings > 0; index += 1) {
      const candidateOrder = copyOrder(order);
      const row = candidateOrder.get(column)!;
      [row[index], row[index + 1]] = [row[index + 1]!, row[index]!];
      const candidate = score(candidateOrder);
      if (candidate.crossings < best.crossings) { best = candidate; order = candidateOrder; improved = true; }
    }
  }
  return best.layout;
}

export function layoutArchitecture(model: ArchitectureModel): ArchitectureLayout {
  return model.mode === "layered" ? layered(model) : flow(model);
}

/** Routes come from the attack-path router: adjacent layers connect directly, longer edges run in free channels. */
export function routeArchitecture(model: ArchitectureModel, layout: ArchitectureLayout): Map<string, Point[]> {
  if (model.mode === "layered") {
    // A tidy tree only links adjacent rows with each parent centred over its children: one S-curve per line never crosses.
    const point = (id: string, bottom: boolean) => {
      const { x, y } = layout.positions.get(id)!;
      return { x: x + layout.nodeWidth / 2, y: bottom ? y + layout.nodeHeight : y };
    };
    return new Map(model.edges.map(edge => [edge.id, [point(edge.source, true), point(edge.target, false)]]));
  }
  return routeAttackPathEdges({ edges: model.edges.map(edge => ({ ...edge, bidirectional: false })) }, layout);
}

function segmentsCross(a: Point, b: Point, c: Point, d: Point): boolean {
  const cross = (p: Point, q: Point, r: Point) => (q.x - p.x) * (r.y - p.y) - (q.y - p.y) * (r.x - p.x);
  const d1 = cross(c, d, a), d2 = cross(c, d, b), d3 = cross(a, b, c), d4 = cross(a, b, d);
  if (d1 === 0 && d2 === 0 && d3 === 0 && d4 === 0) {
    // Collinear: overlapping runs merge two lines into one, which reads as a crossing.
    const overlap = (p: number, q: number, r: number, s: number) => Math.min(Math.max(p, q), Math.max(r, s)) > Math.max(Math.min(p, q), Math.min(r, s));
    return overlap(a.x, b.x, c.x, d.x) || overlap(a.y, b.y, c.y, d.y);
  }
  return d1 * d2 <= 0 && d3 * d4 <= 0;
}

/** Pairs of drawn connectors that cross, ignoring pairs that share an end (fan-out trunks meet by design). */
export function countRouteCrossings(model: Pick<ArchitectureModel, "edges">, routes: Map<string, Point[]>): number {
  const lines = model.edges.map(edge => ({ edge, points: sampleRoute(routes.get(edge.id) ?? []) }));
  let count = 0;
  for (let i = 0; i < lines.length; i += 1) for (let j = i + 1; j < lines.length; j += 1) {
    const a = lines[i]!, b = lines[j]!;
    if (new Set([a.edge.source, a.edge.target, b.edge.source, b.edge.target]).size < 4) continue;
    let crossed = false;
    for (let p = 1; p < a.points.length && !crossed; p += 1) for (let q = 1; q < b.points.length && !crossed; q += 1) {
      crossed = segmentsCross(a.points[p - 1]!, a.points[p]!, b.points[q - 1]!, b.points[q]!);
    }
    if (crossed) count += 1;
  }
  return count;
}

/** Canvas height from the laid-out content at the zoom it will be shown at, within readable bounds. */
export function architectureCanvasHeight(layout: Pick<ArchitectureLayout, "width" | "height">, containerWidth: number): number {
  const usable = containerWidth - ATTACK_PATH_FIT_PADDING.left - ATTACK_PATH_FIT_PADDING.right;
  const zoom = containerWidth > 0 && layout.width > 0 ? Math.min(1, Math.max(PATH_DESKTOP_MIN_ZOOM, usable / layout.width)) : 1;
  const height = layout.height * zoom + ATTACK_PATH_FIT_PADDING.top + ATTACK_PATH_FIT_PADDING.bottom;
  return Math.round(Math.min(ARCHITECTURE_CANVAS_BOUNDS.max, Math.max(ARCHITECTURE_CANVAS_BOUNDS.min, height)));
}
