import type { AttackPathDirection, AttackPathLayout } from "@/lib/attack-path-graph-layout";
import type { AttackPathGraphModel } from "@/lib/attack-path-graph-model";

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

/**
 * One route per edge, leaving the source's trailing handle and entering the
 * target's leading handle. Adjacent layers connect directly; a longer forward
 * edge runs in the free channel between lanes next to its target; an edge
 * against the layer order runs outside the outermost lanes. Channels never
 * contain node boxes, so no line passes through a glyph or a name.
 */
export function routeAttackPathEdges(model: AttackPathGraphModel, layout: Geometry): Map<string, Point[]> {
  const f = frame(layout);
  const occupied = new Set([...layout.columns].map(([id, column]) => `${column}:${layout.lanes.get(id)}`));
  const routes = new Map<string, Point[]>();
  for (const edge of model.edges) {
    let source = edge.source, target = edge.target;
    // A two-way relationship carries no arrowheads; draw it in reading order.
    if (edge.bidirectional && layout.columns.get(target)! < layout.columns.get(source)!) [source, target] = [target, source];
    const cs = layout.columns.get(source)!, ct = layout.columns.get(target)!;
    const ls = layout.lanes.get(source)!, lt = layout.lanes.get(target)!;
    const start = handles(layout, source).out, end = handles(layout, target).in;
    const via = (cross: number) => [start, f.point(f.gapAfter(cs), cross), f.point(f.gapBefore(ct), cross), end];
    if (ct <= cs) {
      routes.set(edge.id, via(ls + lt <= 0 ? f.outsideAbove() : f.outsideBelow()));
    } else if (ct === cs + 1 && lt === ls) {
      routes.set(edge.id, [start, end]);
    } else if (ct === cs + 1) {
      // Edges leaving toward the same side share one trunk into the channel next to the source, then fan out.
      routes.set(edge.id, [start, f.point(f.gapAfter(cs), lt < ls ? f.channelBelow(ls - 1) : f.channelBelow(ls)), end]);
    } else if (lt !== ls) {
      routes.set(edge.id, via(lt < ls ? f.channelBelow(lt) : f.channelBelow(lt - 1)));
    } else {
      const blocked = Array.from({ length: ct - cs - 1 }, (_, index) => cs + index + 1).some(column => occupied.has(`${column}:${ls}`));
      routes.set(edge.id, !blocked ? [start, end] : via(ls <= 0 ? f.channelBelow(ls - 1) : f.channelBelow(ls)));
    }
  }
  return routes;
}

function along(direction: AttackPathDirection, point: Point) {
  return direction === "LR" ? { main: point.x, cross: point.y } : { main: point.y, cross: point.x };
}

function controls(direction: AttackPathDirection, from: Point, to: Point): [Point, Point] {
  const a = along(direction, from), b = along(direction, to);
  const half = (b.main - a.main) / 2;
  const at = (main: number, cross: number): Point => direction === "LR" ? { x: main, y: cross } : { x: cross, y: main };
  return [at(a.main + half, a.cross), at(b.main - half, b.cross)];
}

/** Smooth S-curves where a route changes lane, straight runs along a channel. */
export function routePath(points: Point[], direction: AttackPathDirection): string {
  let d = `M ${points[0]!.x} ${points[0]!.y}`;
  for (let index = 1; index < points.length; index += 1) {
    const from = points[index - 1]!, to = points[index]!;
    if (along(direction, from).cross === along(direction, to).cross) { d += ` L ${to.x} ${to.y}`; continue; }
    const [c1, c2] = controls(direction, from, to);
    d += ` C ${c1.x} ${c1.y} ${c2.x} ${c2.y} ${to.x} ${to.y}`;
  }
  return d;
}

/** Points along the drawn route, for geometry checks and label placement. */
export function sampleRoute(points: Point[], direction: AttackPathDirection, steps = 16): Point[] {
  const out: Point[] = [points[0]!];
  for (let index = 1; index < points.length; index += 1) {
    const from = points[index - 1]!, to = points[index]!;
    if (along(direction, from).cross === along(direction, to).cross) { out.push(to); continue; }
    const [c1, c2] = controls(direction, from, to);
    for (let step = 1; step <= steps; step += 1) {
      const t = step / steps, u = 1 - t;
      out.push({
        x: u * u * u * from.x + 3 * u * u * t * c1.x + 3 * u * t * t * c2.x + t * t * t * to.x,
        y: u * u * u * from.y + 3 * u * u * t * c1.y + 3 * u * t * t * c2.y + t * t * t * to.y,
      });
    }
  }
  return out;
}

/** Where a relationship name appears: the middle of the route's run. */
export function routeLabelPoint(points: Point[]): Point {
  const [a, b] = points.length > 2 ? [points[1]!, points[2]!] : [points[0]!, points[points.length - 1]!];
  return { x: (a.x + b.x) / 2, y: (a.y + b.y) / 2 };
}
