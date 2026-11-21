type Point = [number, number];
type Box = { x: number; y: number; width: number; height: number };

/** Segment/rectangle intersection, including narrow blockers missed by sparse samples. */
function blocked(a: Point, b: Point, box: Box, padding = 16): boolean {
  let low = 0, high = 1;
  for (const axis of [0, 1] as const) {
    const min = (axis ? box.y : box.x) - padding;
    const max = min + (axis ? box.height : box.width) + padding * 2;
    const delta = b[axis] - a[axis];
    if (Math.abs(delta) < 0.000001) {
      if (a[axis] <= min || a[axis] >= max) return false;
      continue;
    }
    const from = (min - a[axis]) / delta, to = (max - a[axis]) / delta;
    low = Math.max(low, Math.min(from, to)); high = Math.min(high, Math.max(from, to));
    if (low >= high) return false;
  }
  return high > 0 && low < 1;
}

/** Shortest visible corner chain when one bend cannot clear alternating cards.
 * Bounded by the caller's canvas node limit; no topology or evidence is changed. */
export function obstacleWaypoints(start: Point, end: Point, boxes: Box[], channel = 0): Point[] | null {
  const margin = 32 + Math.min(12, Math.abs(channel) * 2);
  const corners: Point[] = boxes.flatMap(box => [
    [box.x - margin, box.y - margin], [box.x + box.width + margin, box.y - margin],
    [box.x - margin, box.y + box.height + margin], [box.x + box.width + margin, box.y + box.height + margin],
  ] as Point[]).filter(point => !boxes.some(box => blocked(point, point, box)));
  const points = [start, end, ...corners];
  const distances = points.map(() => Infinity), previous = points.map(() => -1), visited = new Set<number>();
  distances[0] = 0;
  for (let step = 0; step < points.length; step++) {
    let current = -1;
    for (let index = 0; index < points.length; index++) if (!visited.has(index)
      && (current < 0 || distances[index]! < distances[current]!)) current = index;
    if (current < 0 || !Number.isFinite(distances[current]!)) return null;
    if (current === 1) {
      const route: Point[] = [];
      for (let index = 1; index >= 0; index = previous[index]!) route.unshift(points[index]!);
      return route;
    }
    visited.add(current);
    for (let next = 0; next < points.length; next++) {
      if (visited.has(next)) continue;
      const a = points[current]!, b = points[next]!;
      const cost = distances[current]! + Math.hypot(b[0] - a[0], b[1] - a[1]);
      if (cost >= distances[next]! || boxes.some(box => blocked(a, b, box))) continue;
      distances[next] = cost; previous[next] = current;
    }
  }
  return null;
}
