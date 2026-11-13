import { getBezierPath, getSmoothStepPath, Position, type EdgeProps } from "@xyflow/react";

type Obstacle = { id: string; x: number; y: number; width: number; height: number };
type Endpoints = Pick<EdgeProps, "source" | "target" | "sourceX" | "sourceY" | "targetX" | "targetY" | "sourcePosition" | "targetPosition">;

type Point = [number, number];

/** A full canvas page plus the display nodes a flow can add. */
export const ROUTED_NODE_LIMIT = 130;
/** A corridor beyond this multiple of the direct distance reads as a stray line across the map, not a route. */
const MAX_DETOUR = 2;
/** How far below a glyph's centre row a caption-avoiding route runs. */
const EXIT_OFFSET = 18;

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

/** A vertical rank still uses glyph-side ports. Exit beside the full caption
 * before turning down, and reverse the route for an incoming relationship. */
function endpointCaptionRoute(edge: Endpoints, obstacles: Obstacle[], path: string): [string, number, number] | null {
  if (obstacles.length > ROUTED_NODE_LIMIT || Math.abs(edge.targetY - edge.sourceY) < 80) return null;
  const forward = edge.sourceY < edge.targetY;
  const upper = { id: forward ? edge.source : edge.target, x: forward ? edge.sourceX : edge.targetX, y: forward ? edge.sourceY : edge.targetY, position: forward ? edge.sourcePosition : edge.targetPosition };
  const lower = { id: forward ? edge.target : edge.source, x: forward ? edge.targetX : edge.sourceX, y: forward ? edge.targetY : edge.sourceY, position: forward ? edge.targetPosition : edge.sourcePosition };
  const upperNode = obstacles.find(node => node.id === upper.id);
  const lowerNode = obstacles.find(node => node.id === lower.id);
  if (!upperNode || !lowerNode || ![Position.Left, Position.Right, Position.Bottom].includes(upper.position)) return null;
  const captionTop = upper.position === Position.Bottom ? upper.y + 8 : 2 * upper.y - upperNode.y + 8;
  const bottom = upperNode.y + upperNode.height;
  if (captionTop >= bottom || lowerNode.y < bottom + 16) return null;
  const coordinates = path.match(/-?\d+(?:\.\d+)?(?:e[+-]?\d+)?/gi)?.map(Number) ?? [];
  if (coordinates.length !== 8) return null;
  let crossesCaption = false;
  for (let step = 1; step < 48 && !crossesCaption; step++) {
    const t = step / 48, u = 1 - t;
    const x = u ** 3 * coordinates[0]! + 3 * u ** 2 * t * coordinates[2]! + 3 * u * t ** 2 * coordinates[4]! + t ** 3 * coordinates[6]!;
    const y = u ** 3 * coordinates[1]! + 3 * u ** 2 * t * coordinates[3]! + 3 * u * t ** 2 * coordinates[5]! + t ** 3 * coordinates[7]!;
    crossesCaption = x > upperNode.x && x < upperNode.x + upperNode.width && y > captionTop && y < bottom;
  }
  if (!crossesCaption) return null;
  const upperX = upper.position === Position.Left ? upperNode.x - 24 : upperNode.x + upperNode.width + 24;
  const lowerX = lower.position === Position.Top ? lower.x : lower.position === Position.Left ? lowerNode.x - 24 : lowerNode.x + lowerNode.width + 24;
  const laneY = (bottom + lowerNode.y) / 2;
  // Run beside the glyph a little below its centre row: a sibling edge to a same-row neighbour
  // leaves the same handle along that row, and sharing it would read as one line splitting.
  const exitY = upper.y + Math.min(EXIT_OFFSET, Math.max(0, (captionTop - upper.y) / 2));
  const exit = (x: number): Point[] => exitY === upper.y ? [[x, upper.y]] : [[upper.x + Math.sign(x - upper.x) * 12, exitY], [x, exitY]];
  // The lower card's side handle gets the same treatment, a little above its row.
  const sideEntry = lower.position === Position.Left || lower.position === Position.Right;
  const enterY = sideEntry ? lower.y - Math.min(EXIT_OFFSET, Math.max(0, (lower.y - lowerNode.y) / 2)) : lower.y;
  const enter = (x: number): Point[] => enterY === lower.y ? [[x, lower.y]] : [[x, enterY], [lower.x + Math.sign(x - lower.x) * 12, enterY]];
  const points: Point[] = [[upper.x, upper.y], ...exit(upperX), [upperX, laneY], [lowerX, laneY], ...enter(lowerX), [lower.x, lower.y]];
  const intervening = obstacles.filter(node => node.id !== upper.id && node.id !== lower.id
    && node.y < lower.y && node.y + node.height > upper.y);
  // A skipped rank can contain another entity. Test every segment, reserving
  // room for rounded corners, before using an interior or exterior corridor.
  const clear = (route: Point[]) => route.slice(1).every((point, index) => {
    const previous = route[index]!;
    return intervening.every(node => Math.max(previous[0], point[0]) <= node.x - 16
      || Math.min(previous[0], point[0]) >= node.x + node.width + 16
      || Math.max(previous[1], point[1]) <= node.y - 16
      || Math.min(previous[1], point[1]) >= node.y + node.height + 16);
  });
  if (clear(points)) return [roundedRoute(forward ? points : points.reverse()), (upperX + lowerX) / 2, laneY];
  const gap = Math.min(24, (lowerNode.y - bottom) / 3);
  const firstLane = bottom + gap, lastLane = lowerNode.y - gap;
  const outerLanes = [Math.min(upperNode.x, lowerNode.x, ...intervening.map(node => node.x)) - 24,
    Math.max(upperNode.x + upperNode.width, lowerNode.x + lowerNode.width, ...intervening.map(node => node.x + node.width)) + 24];
  const candidates = outerLanes.map(x => ({ x, route: [
    [upper.x, upper.y], ...exit(upperX), [upperX, firstLane], [x, firstLane],
    [x, lastLane], [lowerX, lastLane], ...enter(lowerX), [lower.x, lower.y],
  ] as Point[] })).filter(candidate => clear(candidate.route));
  const length = (route: Point[]) => route.slice(1).reduce((total, point, index) => total + Math.abs(point[0] - route[index]![0]) + Math.abs(point[1] - route[index]![1]), 0);
  const direct = Math.abs(edge.targetX - edge.sourceX) + Math.abs(edge.targetY - edge.sourceY);
  const candidate = candidates.filter(item => length(item.route) <= direct * MAX_DETOUR).sort((a, b) => length(a.route) - length(b.route))[0];
  if (!candidate) return null;
  return [roundedRoute(forward ? candidate.route : candidate.route.reverse()), candidate.x, (firstLane + lastLane) / 2];
}

/** Route bounded relationships around captions and intervening entities. */
export function relationshipPath(edge: Endpoints, obstacles: Obstacle[]): [string, number, number] {
  // The caption check samples the direct curve between the ports; the drawn line is always right-angle runs.
  const [path] = getBezierPath(edge);
  const captionRoute = endpointCaptionRoute(edge, obstacles, path);
  if (captionRoute) return captionRoute;
  // A serpentine path changes rows on the same side of both circular glyphs.
  // Keep its turn and caption outside the wider name/metadata column.
  if (obstacles.length <= ROUTED_NODE_LIMIT && Math.abs(edge.targetX - edge.sourceX) < 8
      && Math.abs(edge.targetY - edge.sourceY) > 80
      && edge.sourcePosition === edge.targetPosition
      && [Position.Left, Position.Right].includes(edge.sourcePosition)) {
    const endpoints = obstacles.filter(node => node.id === edge.source || node.id === edge.target);
    const right = edge.sourcePosition === Position.Right;
    const laneX = right
      ? Math.max(edge.sourceX, ...endpoints.map(node => node.x + node.width)) + 48
      : Math.min(edge.sourceX, ...endpoints.map(node => node.x)) - 48;
    return [
      roundedRoute([[edge.sourceX, edge.sourceY], [laneX, edge.sourceY], [laneX, edge.targetY], [edge.targetX, edge.targetY]]),
      laneX, (edge.sourceY + edge.targetY) / 2,
    ];
  }
  // Every other relationship draws as right-angle runs with rounded corners, matching the attack-path graph.
  const [stepPath, stepX, stepY] = getSmoothStepPath({ ...edge, borderRadius: 12 });
  // Keep dense/vertical layouts on the standard renderer. This correction is
  // bounded to short investigations and does not change relationship direction.
  if (obstacles.length > ROUTED_NODE_LIMIT || edge.targetX - edge.sourceX < 240
      || edge.sourcePosition !== Position.Right || edge.targetPosition !== Position.Left) return [stepPath, stepX, stepY];
  const between = obstacles.filter(node => node.id !== edge.source && node.id !== edge.target
    && node.x > edge.sourceX + 24 && node.x + node.width < edge.targetX - 24);
  // The drawn route turns once, midway between the ends; test each of its runs, not its bounding box.
  const intersects = (x: number, y: number, padX: number, padY: number) => between.some(node =>
    x + padX > node.x && x - padX < node.x + node.width
    && y + padY > node.y && y - padY < node.y + node.height);
  const turnX = (edge.sourceX + edge.targetX) / 2;
  const runs: [Point, Point][] = [[[edge.sourceX, edge.sourceY], [turnX, edge.sourceY]], [[turnX, edge.sourceY], [turnX, edge.targetY]], [[turnX, edge.targetY], [edge.targetX, edge.targetY]]];
  let blocked = intersects(stepX, stepY, 48, 16);
  for (const [[ax, ay], [bx, by]] of runs) {
    const steps = Math.max(1, Math.ceil(Math.hypot(bx - ax, by - ay) / 8));
    for (let step = 0; step <= steps && !blocked; step++) blocked = intersects(ax + (bx - ax) * step / steps, ay + (by - ay) * step / steps, 2, 2);
  }
  if (!blocked) return [stepPath, stepX, stepY];
  // A fixed 40-unit offset can skip a clear gap between sibling rows and send
  // the connector outside the fitted node envelope. Include those interior
  // lanes before choosing the shortest clear route.
  const rows = [...between].sort((a, b) => a.y - b.y);
  const gaps = rows.slice(1).flatMap((node, index) => {
    const previous = rows[index]!;
    const bottom = previous.y + previous.height;
    return node.y - bottom > 32 ? [(bottom + node.y) / 2] : [];
  });
  // A card that only partly overlaps the corridor still sits under the lane's straight run.
  const corridor = obstacles.filter(node => node.id !== edge.source && node.id !== edge.target
    && node.x < edge.targetX - 24 && node.x + node.width > edge.sourceX + 24);
  const clearOf = (y: number) => corridor.every(node => y < node.y - 16 || y > node.y + node.height + 16);
  const candidates = [...gaps, ...corridor.flatMap(node => [node.y - 40, node.y + node.height + 40])];
  const lanes = candidates.filter(clearOf);
  const top = Math.min(...obstacles.map(node => node.y));
  const bottom = Math.max(...obstacles.map(node => node.y + node.height));
  const outside = (y: number) => Number(y < top || y > bottom);
  lanes.sort((a, b) => outside(a) - outside(b) || (Math.abs(edge.sourceY - a) + Math.abs(edge.targetY - a))
    - (Math.abs(edge.sourceY - b) + Math.abs(edge.targetY - b)) || a - b);
  const baseLane = lanes[0] ?? Math.min(edge.sourceY, edge.targetY, ...corridor.map(node => node.y)) - 40;
  const branchLane = baseLane + Math.sign(edge.targetY - edge.sourceY) * 16;
  const lane = clearOf(branchLane) ? branchLane : baseLane;
  const sourceNode = obstacles.find(node => node.id === edge.source);
  const targetNode = obstacles.find(node => node.id === edge.target);
  const start = Math.max(edge.sourceX + 32, sourceNode ? sourceNode.x + sourceNode.width + 24 : edge.sourceX + 32);
  const end = Math.min(edge.targetX - 32, targetNode ? targetNode.x - 24 : edge.targetX - 32);
  // Turn into and out of the lane in the clear space beside each end, with rounded corners.
  const entry = Math.max(start, Math.min(start + 64, ...between.map(node => node.x - 24)));
  const exit = Math.min(end, Math.max(end - 64, ...between.map(node => node.x + node.width + 24)));
  return [
    roundedRoute([[edge.sourceX, edge.sourceY], [entry, edge.sourceY], [entry, lane], [exit, lane], [exit, edge.targetY], [edge.targetX, edge.targetY]]),
    entry + (exit - entry) * (edge.targetY < edge.sourceY ? 0.3 : edge.targetY > edge.sourceY ? 0.7 : 0.5), lane,
  ];
}

/**
 * Where a counted caption ("Depends On ×3") sits: beside the port its lines
 * split from (or join at), on that node's row, rather than mid-canvas.
 */
export function anchoredLabelPoint(edge: Pick<EdgeProps, "sourceX" | "sourceY" | "targetX" | "targetY">, side: "source" | "target"): { x: number; y: number } {
  const offset = Math.min(56, Math.max(24, Math.abs(edge.targetX - edge.sourceX) / 4));
  return side === "source" ? { x: edge.sourceX + offset, y: edge.sourceY } : { x: edge.targetX - offset, y: edge.targetY };
}
