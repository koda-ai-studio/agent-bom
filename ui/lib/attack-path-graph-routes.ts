import type { AttackPathLayout } from "@/lib/attack-path-graph-layout";
import type { PathGraphEdge } from "@/lib/attack-path-graph-model";

export type Point = { x: number; y: number };

/** Glyph geometry inside a node box: a 56px circle 6px below the top, centred across. */
export const GLYPH = { size: 56, top: 6 } as const;
export const GLYPH_CENTER_Y = GLYPH.top + GLYPH.size / 2;
/** Row layouts attach lines at the glyph rim, so connectors run circle to circle above the names. */
export function glyphInsetX(nodeWidth: number): number {
  return (nodeWidth - GLYPH.size) / 2 - 2;
}

type Geometry = Pick<AttackPathLayout, "direction" | "positions" | "columns" | "lanes" | "minLane" | "maxLane" | "rankGap" | "laneGap" | "margin" | "nodeWidth" | "nodeHeight">;

function frame(layout: Geometry) {
  const row = layout.direction === "LR";
  const mainSize = row ? layout.nodeWidth : layout.nodeHeight;
  const crossSize = row ? layout.nodeHeight : layout.nodeWidth;
  const colStart = (column: number) => column * (mainSize + layout.rankGap);
  const laneTop = (lane: number) => layout.margin + (lane - layout.minLane) * (crossSize + layout.laneGap);
  return {
    point: (main: number, cross: number): Point => row ? { x: main, y: cross } : { x: cross, y: main },
    gapAfter: (column: number) => colStart(column) + mainSize + layout.rankGap / 2,
    gapBefore: (column: number) => colStart(column) - layout.rankGap / 2,
    /** Cross coordinate of the free channel between `lane` and `lane + 1`. */
    channelBelow: (lane: number) => laneTop(lane) + crossSize + layout.laneGap / 2,
    outsideAbove: () => laneTop(layout.minLane) - layout.margin / 2,
    outsideBelow: () => laneTop(layout.maxLane) + crossSize + layout.margin / 2,
  };
}

function handles(layout: Geometry, id: string): { out: Point; in: Point } {
  const { x, y } = layout.positions.get(id)!;
  if (layout.direction === "TB") {
    return { out: { x: x + layout.nodeWidth / 2, y: y + layout.nodeHeight }, in: { x: x + layout.nodeWidth / 2, y } };
  }
  const inset = glyphInsetX(layout.nodeWidth);
  return { out: { x: x + layout.nodeWidth - inset, y: y + GLYPH_CENTER_Y }, in: { x: x + inset, y: y + GLYPH_CENTER_Y } };
}

type Leg = { gap: number; from: number; to: number; id: string; x?: number };

/** Spacing between the vertical legs of different lines that turn in one gap. */
const LEG_SPACING = 12;

/**
 * Lines changing row turn in the gap between layers. In one gap, a line that
 * goes down turns before one that goes less far down (and a line that comes up
 * after one that comes up less far), so lines fanning out of or into a node
 * leave and arrive side by side instead of crossing or sharing a trunk.
 */
function placeLegs(legs: Leg[], centreOf: (gap: number) => number, rankGap: number) {
  const byGap = new Map<number, Leg[]>();
  for (const leg of legs) byGap.set(leg.gap, [...(byGap.get(leg.gap) ?? []), leg]);
  for (const [gap, group] of byGap) {
    const down = group.filter(leg => leg.to > leg.from).sort((a, b) => b.to - a.to || b.from - a.from || a.id.localeCompare(b.id));
    const up = group.filter(leg => leg.to < leg.from).sort((a, b) => a.to - b.to || a.from - b.from || a.id.localeCompare(b.id));
    const ordered = [...down, ...up];
    const spacing = ordered.length > 1 ? Math.min(LEG_SPACING, (rankGap - 16) / (ordered.length - 1)) : 0;
    ordered.forEach((leg, index) => { leg.x = centreOf(gap) + (index - (ordered.length - 1) / 2) * spacing; });
  }
}

type Plan = { id: string; start: Point; end: Point; legs: Leg[]; alternatives: Leg[][] };

/**
 * Where two provisional routes meet or run along one row, other than a handle
 * they share. Turns in one gap are spread apart afterwards, so they never count.
 */
function conflicts(a: Point[], b: Point[], row: boolean): number {
  const shared = (x: number, y: number) => [a[0]!, a.at(-1)!].some(p => p.x === x && p.y === y && [b[0]!, b.at(-1)!].some(q => q.x === x && q.y === y));
  const lo = (p: number, q: number) => Math.min(p, q), hi = (p: number, q: number) => Math.max(p, q);
  let count = 0;
  for (let i = 1; i < a.length; i += 1) for (let j = 1; j < b.length; j += 1) {
    const [p, q, r, t] = [a[i - 1]!, a[i]!, b[j - 1]!, b[j]!];
    const vertical = p.x === q.x;
    if (vertical === (r.x === t.x)) {
      const along = vertical ? [p.x === r.x, hi(lo(p.y, q.y), lo(r.y, t.y)), lo(hi(p.y, q.y), hi(r.y, t.y))] as const
        : [p.y === r.y, hi(lo(p.x, q.x), lo(r.x, t.x)), lo(hi(p.x, q.x), hi(r.x, t.x))] as const;
      if (vertical !== row && along[0] && along[2] - along[1] > 2) count += 2;
      continue;
    }
    const [v, w, h, k] = vertical ? [p, q, r, t] : [r, t, p, q];
    if (v.x >= lo(h.x, k.x) && v.x <= hi(h.x, k.x) && h.y >= lo(v.y, w.y) && h.y <= hi(v.y, w.y) && !shared(v.x, h.y)) count += 1;
  }
  return count;
}

/**
 * A long edge between rows may change row next to its target, next to its
 * source, or run outside every row. Take the corridor that crosses the fewest
 * other lines; the nearest channel wins a tie.
 */
function chooseCorridors(plans: Plan[], centreOf: (gap: number) => number, point: (main: number, cross: number) => Point, row: boolean) {
  const draw = (plan: Plan, legs: Leg[]) => [plan.start, ...legs.flatMap(leg => [point(centreOf(leg.gap), leg.from), point(centreOf(leg.gap), leg.to)]), plan.end];
  for (const plan of plans) {
    const others = plans.filter(other => other !== plan).map(other => draw(other, other.legs));
    const score = (legs: Leg[]) => others.reduce((total, other) => total + conflicts(draw(plan, legs), other, row), 0);
    for (const candidate of plan.alternatives) {
      const legs = candidate.filter(leg => leg.from !== leg.to);
      if (score(legs) < score(plan.legs)) plan.legs = legs;
    }
  }
}

/**
 * One route per edge, leaving the source's trailing handle and entering the
 * target's leading handle. Every route is horizontal and vertical runs only:
 * it changes row only in the free gap between layers, and runs along a row
 * only at a glyph's centre line or in the free channel between rows. Nothing
 * bends inside a node's column, so no line passes through a glyph or a name.
 * An edge against the layer order runs outside the outermost rows.
 */
export function routeAttackPathEdges(model: { edges: readonly Pick<PathGraphEdge, "id" | "source" | "target" | "bidirectional">[] }, layout: Geometry): Map<string, Point[]> {
  const f = frame(layout);
  const row = layout.direction === "LR";
  const crossOf = (point: Point) => row ? point.y : point.x;
  const occupied = new Set([...layout.columns].map(([id, column]) => `${column}:${layout.lanes.get(id)}`));
  const plans: Plan[] = [];
  for (const edge of model.edges) {
    let source = edge.source, target = edge.target;
    // A two-way relationship carries no arrowheads; draw it in reading order.
    if (edge.bidirectional && layout.columns.get(target)! < layout.columns.get(source)!) [source, target] = [target, source];
    const cs = layout.columns.get(source)!, ct = layout.columns.get(target)!;
    const ls = layout.lanes.get(source)!, lt = layout.lanes.get(target)!;
    const start = handles(layout, source).out, end = handles(layout, target).in;
    const sCross = crossOf(start), eCross = crossOf(end);
    const through = (cross: number): Leg[] => [
      { gap: cs, from: sCross, to: cross, id: edge.id },
      { gap: ct - 1, from: cross, to: eCross, id: edge.id },
    ];
    let legs: Leg[];
    let alternatives: number[] = [];
    if (ct <= cs) legs = through(ls + lt < 0 ? f.outsideAbove() : f.outsideBelow());
    else if (ct === cs + 1) legs = lt === ls ? [] : [{ gap: cs, from: sCross, to: eCross, id: edge.id }];
    else if (lt !== ls) {
      legs = through(lt < ls ? f.channelBelow(lt) : f.channelBelow(lt - 1));
      alternatives = [lt < ls ? f.channelBelow(ls - 1) : f.channelBelow(ls), f.outsideAbove(), f.outsideBelow()];
    } else {
      const blocked = Array.from({ length: ct - cs - 1 }, (_, index) => cs + index + 1).some(column => occupied.has(`${column}:${ls}`));
      legs = blocked ? through(ls <= 0 ? f.channelBelow(ls - 1) : f.channelBelow(ls)) : [];
      if (blocked) alternatives = [f.channelBelow(ls - 1), f.outsideAbove(), f.outsideBelow()];
    }
    plans.push({ id: edge.id, start, end, legs: legs.filter(leg => leg.from !== leg.to), alternatives: alternatives.map(through) });
  }
  chooseCorridors(plans, gap => f.gapAfter(gap), f.point, row);
  placeLegs(plans.flatMap(plan => plan.legs), gap => f.gapAfter(gap), layout.rankGap);
  const routes = new Map<string, Point[]>();
  for (const { id, start, end, legs } of plans) {
    const points: Point[] = [start];
    for (const leg of legs) points.push(f.point(leg.x!, leg.from), f.point(leg.x!, leg.to));
    points.push(end);
    routes.set(id, points);
  }
  return routes;
}

const CORNER = 10;

/** Straight runs with rounded corners; every route is horizontal and vertical runs. */
export function routePath(points: Point[]): string {
  let d = `M ${points[0]!.x} ${points[0]!.y}`;
  for (let index = 1; index < points.length; index += 1) {
    const from = points[index - 1]!, to = points[index]!, next = points[index + 1];
    const incoming = Math.hypot(to.x - from.x, to.y - from.y), outgoing = next ? Math.hypot(next.x - to.x, next.y - to.y) : 0;
    const radius = Math.min(CORNER, incoming / 2, outgoing / 2);
    if (!next || radius <= 0) { d += ` L ${to.x} ${to.y}`; continue; }
    const at = (p: Point, length: number, r: number) => `${to.x + (p.x - to.x) * r / length} ${to.y + (p.y - to.y) * r / length}`;
    d += ` L ${at(from, incoming, radius)} Q ${to.x} ${to.y} ${at(next, outgoing, radius)}`;
  }
  return d;
}

/** The corners of the drawn route, for geometry checks. */
export function sampleRoute(points: Point[]): Point[] {
  return [...points];
}

/** Where a relationship name appears: the middle of the route's run. */
export function routeLabelPoint(points: Point[]): Point {
  const [a, b] = points.length > 2 ? [points[1]!, points[2]!] : [points[0]!, points[points.length - 1]!];
  return { x: (a.x + b.x) / 2, y: (a.y + b.y) / 2 };
}
