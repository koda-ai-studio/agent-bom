import { getBezierPath, Position, type EdgeProps } from "@xyflow/react";

type Obstacle = { id: string; x: number; y: number; width: number; height: number };
type Endpoints = Pick<EdgeProps, "source" | "target" | "sourceX" | "sourceY" | "targetX" | "targetY" | "sourcePosition" | "targetPosition">;

/** Detour long left-to-right links around intervening entities in bounded views. */
export function relationshipPath(edge: Endpoints, obstacles: Obstacle[]): [string, number, number] {
  const [path, midpointX, midpointY] = getBezierPath(edge);
  let [labelX, labelY] = [midpointX, midpointY];
  const coordinates = path.match(/-?\d+(?:\.\d+)?(?:e[+-]?\d+)?/gi)?.map(Number) ?? [];
  // Opposite slopes can cross at their midpoints. Keep their captions on the
  // actual curve, on different sides of that crossing.
  if (coordinates.length === 8 && Math.abs(edge.targetY - edge.sourceY) > 80) {
    const t = edge.targetY > edge.sourceY ? 0.65 : 0.35;
    const u = 1 - t;
    const candidateX = u ** 3 * coordinates[0]! + 3 * u ** 2 * t * coordinates[2]! + 3 * u * t ** 2 * coordinates[4]! + t ** 3 * coordinates[6]!;
    const candidateY = u ** 3 * coordinates[1]! + 3 * u ** 2 * t * coordinates[3]! + 3 * u * t ** 2 * coordinates[5]! + t ** 3 * coordinates[7]!;
    // Moving away from a crossing must not move the caption into an endpoint.
    if (!obstacles.some(node => candidateX + 48 > node.x && candidateX - 48 < node.x + node.width
      && candidateY + 16 > node.y && candidateY - 16 < node.y + node.height)) {
      labelX = candidateX;
      labelY = candidateY;
    }
  }
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
  const candidates = between.flatMap(node => [node.y - 40, node.y + node.height + 40]);
  const lanes = candidates.filter(y => between.every(node => y < node.y - 16 || y > node.y + node.height + 16));
  lanes.sort((a, b) => (Math.abs(edge.sourceY - a) + Math.abs(edge.targetY - a))
    - (Math.abs(edge.sourceY - b) + Math.abs(edge.targetY - b)) || a - b);
  const baseLane = lanes[0] ?? Math.min(edge.sourceY, edge.targetY, ...between.map(node => node.y)) - 40;
  const branchLane = baseLane + Math.sign(edge.targetY - edge.sourceY) * 16;
  const lane = between.every(node => branchLane < node.y - 16 || branchLane > node.y + node.height + 16)
    ? branchLane : baseLane;
  const sourceNode = obstacles.find(node => node.id === edge.source);
  const targetNode = obstacles.find(node => node.id === edge.target);
  const start = Math.max(edge.sourceX + 32, sourceNode ? sourceNode.x + sourceNode.width + 24 : edge.sourceX + 32);
  const end = Math.min(edge.targetX - 32, targetNode ? targetNode.x - 24 : edge.targetX - 32);
  return [
    `M${edge.sourceX},${edge.sourceY} C${start},${edge.sourceY} ${start},${lane} ${start + 32},${lane} L${end - 32},${lane} C${end},${lane} ${end},${edge.targetY} ${edge.targetX},${edge.targetY}`,
    edge.targetY < edge.sourceY ? end - 32 : edge.targetY > edge.sourceY ? start + 32 : (start + end) / 2, lane,
  ];
}
