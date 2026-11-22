import { obstacleWaypoints } from "@/lib/relationship-obstacles";
import { getBezierPath, type EdgeProps } from "@xyflow/react";
import type { RelationshipLane } from "@/lib/relationship-lanes";

type Obstacle = { id: string; x: number; y: number; width: number; height: number };
type Endpoints = Pick<EdgeProps, "source" | "target" | "sourceX" | "sourceY" | "targetX" | "targetY" | "sourcePosition" | "targetPosition">;
type Point = [number, number];
export const ROUTED_NODE_LIMIT = 130;

/** Straight runs joined by rounded corners: the one line style every relationship uses. */
export function roundedRoute(points: Point[]): string {
  const distinct = points.filter((point, index) => !index || point[0] !== points[index - 1]![0] || point[1] !== points[index - 1]![1]);
  let path = `M${distinct[0]![0]},${distinct[0]![1]}`;
  for (let index = 1; index < distinct.length - 1; index++) {
    const previous = distinct[index - 1]!, point = distinct[index]!, next = distinct[index + 1]!;
    const incoming = Math.hypot(point[0] - previous[0], point[1] - previous[1]);
    const outgoing = Math.hypot(next[0] - point[0], next[1] - point[1]);
    const radius = Math.min(12, incoming / 2, outgoing / 2);
    const before = point.map((value, axis) => value + (previous[axis]! - value) * radius / incoming);
    const after = point.map((value, axis) => value + (next[axis]! - value) * radius / outgoing);
    path += ` L${before[0]},${before[1]} Q${point[0]},${point[1]} ${after[0]},${after[1]}`;
  }
  return `${path} L${distinct.at(-1)![0]},${distinct.at(-1)![1]}`;
}

type Cubic = [Point, Point, Point, Point];

function cubicPoint(curve: Cubic, t: number): Point {
  const u = 1 - t;
  return [0, 1].map(axis => u ** 3 * curve[0][axis]! + 3 * u ** 2 * t * curve[1][axis]!
    + 3 * u * t ** 2 * curve[2][axis]! + t ** 3 * curve[3][axis]!) as Point;
}

function curveHits(curve: Cubic, obstacles: Obstacle[]): boolean {
  for (let step = 1; step < 96; step++) {
    const [x, y] = cubicPoint(curve, step / 96);
    if (obstacles.some(box => x > box.x - 16 && x < box.x + box.width + 16
      && y > box.y - 16 && y < box.y + box.height + 16)) return true;
  }
  return false;
}

function followsPorts(curve: Cubic, edge: Endpoints): boolean {
  const outward = (position: string, point: Point, control: Point) => position === "right" ? control[0] > point[0]
    : position === "left" ? control[0] < point[0] : position === "bottom" ? control[1] > point[1] : control[1] < point[1];
  return outward(edge.sourcePosition, curve[0], curve[1]) && outward(edge.targetPosition, curve[3], curve[2]);
}
function portExit(point: Point, position: string): Point {
  return [point[0] + (position === "right" ? 32 : position === "left" ? -32 : 0),
    point[1] + (position === "bottom" ? 32 : position === "top" ? -32 : 0)];
}

/** Do not choose a distant single bend when the endpoints have a local corridor. */
function staysLocal(curve: Cubic, boxes: Obstacle[]): boolean {
  if (!boxes.length) return true;
  const left = Math.min(...boxes.map(box => box.x)) - 48;
  const right = Math.max(...boxes.map(box => box.x + box.width)) + 48;
  const top = Math.min(...boxes.map(box => box.y)) - 48;
  const bottom = Math.max(...boxes.map(box => box.y + box.height)) + 48;
  for (let step = 1; step < 96; step++) {
    const [x, y] = cubicPoint(curve, step / 96);
    if (x < left || x > right || y < top || y > bottom) return false;
  }
  return true;
}

/** Search nearby obstacle boundaries, not the envelope of the whole canvas. */
function clearCurve(curve: Cubic, obstacles: Obstacle[], edge: Endpoints, endpointBoxes: Obstacle[]): Cubic | null {
  if (!curveHits(curve, obstacles)) return curve;
  const candidates: { curve: Cubic; cost: number }[] = [];
  const budget = Math.max(160, Math.hypot(curve[3][0] - curve[0][0], curve[3][1] - curve[0][1]) * 2);
  for (const axis of [1, 0] as const) {
    const middle = (curve[0][axis] + curve[3][axis]) / 2;
    const boundaries = obstacles.flatMap(box => [32, 48, 64, 96].flatMap(gap => axis
      ? [box.y - gap, box.y + box.height + gap] : [box.x - gap, box.x + box.width + gap]));
    for (const control of new Set(boundaries)) {
      if (Math.abs(control - middle) > budget) continue;
      const first: Point = [...curve[1]], second: Point = [...curve[2]];
      first[axis] = control; second[axis] = control;
      const candidate: Cubic = [curve[0], first, second, curve[3]];
      if (followsPorts(candidate, edge) && staysLocal(candidate, endpointBoxes) && !curveHits(candidate, obstacles)) candidates.push({ curve: candidate, cost: Math.abs(control - middle) });
    }
  }
  return candidates.sort((a, b) => a.cost - b.cost)[0]?.curve ?? null;
}

/** A continuous curve through a local gap. The pair's channel shifts the gap
 * so unrelated connections do not acquire a common trunk. */
function corridorCurve(start: Point, end: Point, obstacles: Obstacle[], channel: number): Cubic[] | null {
  const candidates: { curves: Cubic[]; cost: number }[] = [];
  for (const axis of [0, 1] as const) {
    const boundaries = obstacles.flatMap(box => axis ? [box.y - 32, box.y + box.height + 32] : [box.x - 32, box.x + box.width + 32]);
    for (const boundary of new Set(boundaries)) {
      const middle = boundary + channel * 3;
      const first: Point = [...start], second: Point = [...end];
      first[axis] = middle; second[axis] = middle;
      const points = [start, first, second, end];
      const cost = points.slice(1).reduce((sum, point, i) => sum + Math.hypot(point[0] - points[i]![0], point[1] - points[i]![1]), 0);
      if (cost > Math.max(160, Math.hypot(end[0] - start[0], end[1] - start[1]) * 2)) continue;
      for (const tension of [0.15, 0.08, 0.03]) {
        const curves: Cubic[] = points.slice(1).map((point, i) => {
          const previous = points[i]!, before = points[Math.max(0, i - 1)]!, after = points[Math.min(3, i + 2)]!;
          return [previous,
            [previous[0] + (point[0] - before[0]) * tension, previous[1] + (point[1] - before[1]) * tension],
            [point[0] - (after[0] - previous[0]) * tension, point[1] - (after[1] - previous[1]) * tension], point];
        });
        if (curves.some(curve => curveHits(curve, obstacles))) continue;
        candidates.push({ curves, cost }); break;
      }
    }
  }
  return candidates.sort((a, b) => a.cost - b.cost)[0]?.curves ?? null;
}

function smoothWaypoints(points: Point[], obstacles: Obstacle[]): Cubic[] | null {
  for (const tension of [0.15, 0.05, 0.01, 0.002, 0]) {
    const curves: Cubic[] = points.slice(1).map((point, i) => {
      const previous = points[i]!, before = points[Math.max(0, i - 1)]!, after = points[Math.min(points.length - 1, i + 2)]!;
      return [previous,
        [previous[0] + (point[0] - before[0]) * tension, previous[1] + (point[1] - before[1]) * tension],
        [point[0] - (after[0] - previous[0]) * tension, point[1] - (after[1] - previous[1]) * tension], point];
    });
    if (!curves.some(curve => curveHits(curve, obstacles))) return curves;
  }
  return null;
}

/** Reserve endpoint labels and badges while leaving a tunnel through the glyph. */
function endpointGuards(edge: Endpoints, boxes: Obstacle[]): Obstacle[] {
  return (["source", "target"] as const).flatMap(side => {
    const box = boxes.find(item => item.id === edge[side]);
    if (!box) return [];
    const position = side === "source" ? edge.sourcePosition : edge.targetPosition;
    const x = side === "source" ? edge.sourceX : edge.targetX;
    const y = side === "source" ? edge.sourceY : edge.targetY;
    const horizontal = position === "left" || position === "right";
    const behind = position === "right" ? { ...box, width: x - box.x - 17 }
      : position === "left" ? { ...box, x: x + 17, width: box.x + box.width - x - 17 }
      : position === "bottom" ? { ...box, height: y - box.y - 17 }
      : { ...box, y: y + 17, height: box.y + box.height - y - 17 };
    return [behind, ...(horizontal ? [
      { ...box, height: y - 40 - box.y },
      { ...box, y: y + 40, height: box.y + box.height - y - 40 },
    ] : [
      { ...box, width: x - 40 - box.x },
      { ...box, x: x + 40, width: box.x + box.width - x - 40 },
    ])].filter(guard => guard.width > 0 && guard.height > 0);
  });
}

/** Every source-target pair owns a cubic curve and distinct endpoint offsets.
 * No shared horizontal/vertical trunk can imply a relationship to another source. */
export function relationshipPath(edge: Endpoints, obstacles: Obstacle[], lane?: RelationshipLane, clearance = 16): [string, number, number] {
  let [path] = getBezierPath({ ...edge,
    curvature: 0.25 + Math.abs(lane?.channel ?? 0) * 0.025,
  });
  const numbers = path.match(/-?\d+(?:\.\d+)?(?:e[+-]?\d+)?/gi)!.map(Number);
  const original = Array.from({ length: 4 }, (_, index) => [numbers[index * 2]!, numbers[index * 2 + 1]!] as Point) as Cubic;
  original[1][1] += lane?.source ?? 0;
  original[2][1] += lane?.target ?? 0;
  path = `M${original[0].join(",")} C${original.slice(1).map(point => point.join(",")).join(" ")}`;
  const [x, y] = cubicPoint(original, 0.5);
  const blockers = [...obstacles.filter(box => box.id !== edge.source && box.id !== edge.target), ...endpointGuards(edge, obstacles)]
    .map(box => ({ ...box, x: box.x + 16 - clearance, y: box.y + 16 - clearance, width: box.width - 2 * (16 - clearance), height: box.height - 2 * (16 - clearance) }))
    .filter(box => box.width > 0 && box.height > 0);
  if (!blockers.length || obstacles.length > ROUTED_NODE_LIMIT) return [path, x, y];
  const curve = clearCurve(original, blockers, edge, obstacles.filter(box => box.id === edge.source || box.id === edge.target));
  if (!curve) {
    let curves = corridorCurve(original[0], original[3], blockers, lane?.channel ?? 0);
    if (curves && !followsPorts([curves[0]![0], curves[0]![1], curves.at(-1)![2], curves.at(-1)![3]], edge)) curves = null;
    if (!curves) {
      const points = obstacleWaypoints(portExit(original[0], edge.sourcePosition), portExit(original[3], edge.targetPosition), blockers, lane?.channel ?? 0);
      if (points) curves = smoothWaypoints([original[0], ...points, original[3]], blockers);
    }
    if (!curves) return clearance === 16 ? relationshipPath(edge, obstacles, lane, 8) : [path, x, y];
    const label = cubicPoint(curves[Math.floor(curves.length / 2)]!, 0.5);
    return [`M${original[0].join(",")} ${curves.map(part => `C${part.slice(1).map(point => point.join(",")).join(" ")}`).join(" ")}`, ...label];
  }
  if (curve === original) return [path, x, y];
  const label = cubicPoint(curve, 0.5);
  return [`M${curve[0].join(",")} C${curve.slice(1).map(point => point.join(",")).join(" ")}`, ...label];
}

export function anchoredLabelPoint(edge: Pick<EdgeProps, "sourceX" | "sourceY" | "targetX" | "targetY">, side: "source" | "target"): { x: number; y: number } {
  const offset = Math.min(56, Math.max(24, Math.abs(edge.targetX - edge.sourceX) / 4));
  return side === "source" ? { x: edge.sourceX + offset, y: edge.sourceY } : { x: edge.targetX - offset, y: edge.targetY };
}
