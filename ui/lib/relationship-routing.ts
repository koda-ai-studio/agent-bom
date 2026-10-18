import { getBezierPath, Position, type EdgeProps } from "@xyflow/react";

type Obstacle = { id: string; x: number; y: number; width: number; height: number };
type Endpoints = Pick<EdgeProps, "source" | "target" | "sourceX" | "sourceY" | "targetX" | "targetY" | "sourcePosition" | "targetPosition">;

/** Detour long left-to-right links around intervening entities in bounded views. */
export function relationshipPath(edge: Endpoints, obstacles: Obstacle[]): [string, number, number] {
  const [path, labelX, labelY] = getBezierPath(edge);
  // A serpentine path changes rows on the same side of both circular glyphs.
  // Keep its turn and caption outside the wider name/metadata column.
  if (obstacles.length <= 80 && Math.abs(edge.targetX - edge.sourceX) < 8
      && Math.abs(edge.targetY - edge.sourceY) > 80
      && edge.sourcePosition === edge.targetPosition
      && [Position.Left, Position.Right].includes(edge.sourcePosition)) {
    const endpoints = obstacles.filter(node => node.id === edge.source || node.id === edge.target);
    const right = edge.sourcePosition === Position.Right;
    const laneX = right
      ? Math.max(edge.sourceX, ...endpoints.map(node => node.x + node.width)) + 48
      : Math.min(edge.sourceX, ...endpoints.map(node => node.x)) - 48;
    const step = Math.sign(edge.targetY - edge.sourceY) * 24;
    return [
      `M${edge.sourceX},${edge.sourceY} Q${laneX},${edge.sourceY} ${laneX},${edge.sourceY + step} L${laneX},${edge.targetY - step} Q${laneX},${edge.targetY} ${edge.targetX},${edge.targetY}`,
      laneX, (edge.sourceY + edge.targetY) / 2,
    ];
  }
  // Keep dense/vertical layouts on the standard renderer. This correction is
  // bounded to short investigations and does not change relationship direction.
  if (obstacles.length > 80 || edge.targetX - edge.sourceX < 240
      || edge.sourcePosition !== Position.Right || edge.targetPosition !== Position.Left) return [path, labelX, labelY];
  const between = obstacles.filter(node => node.id !== edge.source && node.id !== edge.target
    && node.x > edge.sourceX + 24 && node.x + node.width < edge.targetX - 24);
  // React Flow supplies a single cubic curve. Sample it rather than treating
  // its entire bounding box as an obstruction (which reroutes clear diagonals).
  const coordinates = path.match(/-?\d+(?:\.\d+)?(?:e[+-]?\d+)?/gi)?.map(Number) ?? [];
  const intersects = (x: number, y: number, padX: number, padY: number) => between.some(node =>
    x + padX > node.x && x - padX < node.x + node.width
    && y + padY > node.y && y - padY < node.y + node.height);
  let blocked = intersects(labelX, labelY, 48, 16);
  if (coordinates.length === 8) {
    for (let step = 1; step < 24 && !blocked; step++) {
      const t = step / 24;
      const u = 1 - t;
      const x = u ** 3 * coordinates[0]! + 3 * u ** 2 * t * coordinates[2]! + 3 * u * t ** 2 * coordinates[4]! + t ** 3 * coordinates[6]!;
      const y = u ** 3 * coordinates[1]! + 3 * u ** 2 * t * coordinates[3]! + 3 * u * t ** 2 * coordinates[5]! + t ** 3 * coordinates[7]!;
      blocked = intersects(x, y, 2, 2);
    }
  }
  if (!blocked) return [path, labelX, labelY];
  // A fixed 40-unit offset can skip a clear gap between sibling rows and send
  // the connector outside the fitted node envelope. Include those interior
  // lanes before choosing the shortest clear route.
  const rows = [...between].sort((a, b) => a.y - b.y);
  const gaps = rows.slice(1).flatMap((node, index) => {
    const previous = rows[index]!;
    const bottom = previous.y + previous.height;
    return node.y - bottom > 32 ? [(bottom + node.y) / 2] : [];
  });
  const candidates = [...gaps, ...between.flatMap(node => [node.y - 40, node.y + node.height + 40])];
  const lanes = candidates.filter(y => between.every(node => y < node.y - 16 || y > node.y + node.height + 16));
  const top = Math.min(...obstacles.map(node => node.y));
  const bottom = Math.max(...obstacles.map(node => node.y + node.height));
  const outside = (y: number) => Number(y < top || y > bottom);
  lanes.sort((a, b) => outside(a) - outside(b) || (Math.abs(edge.sourceY - a) + Math.abs(edge.targetY - a))
    - (Math.abs(edge.sourceY - b) + Math.abs(edge.targetY - b)) || a - b);
  const baseLane = lanes[0] ?? Math.min(edge.sourceY, edge.targetY, ...between.map(node => node.y)) - 40;
  const branchLane = baseLane + Math.sign(edge.targetY - edge.sourceY) * 16;
  const lane = between.every(node => branchLane < node.y - 16 || branchLane > node.y + node.height + 16)
    ? branchLane : baseLane;
  const sourceNode = obstacles.find(node => node.id === edge.source);
  const targetNode = obstacles.find(node => node.id === edge.target);
  const start = Math.max(edge.sourceX + 32, sourceNode ? sourceNode.x + sourceNode.width + 24 : edge.sourceX + 32);
  const end = Math.min(edge.targetX - 32, targetNode ? targetNode.x - 24 : edge.targetX - 32);
  // Ease into and out of the horizontal lane over the available clear space.
  // Keep both transition endpoints outside every intervening node, with
  // horizontal tangents where each cubic meets the straight segment.
  const entry = Math.max(start + 32, Math.min(start + 96, ...between.map(node => node.x - 24)));
  const exit = Math.min(end - 32, Math.max(end - 96, ...between.map(node => node.x + node.width + 24)));
  return [
    `M${edge.sourceX},${edge.sourceY} C${start},${edge.sourceY} ${start + (entry - start) / 2},${lane} ${entry},${lane} L${exit},${lane} C${exit + (end - exit) / 2},${lane} ${end},${edge.targetY} ${edge.targetX},${edge.targetY}`,
    entry + (exit - entry) * (edge.targetY < edge.sourceY ? 0.3 : edge.targetY > edge.sourceY ? 0.7 : 0.5), lane,
  ];
}
