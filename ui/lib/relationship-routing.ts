import { getBezierPath, type EdgeProps } from "@xyflow/react";

type Obstacle = { id: string; x: number; y: number; width: number; height: number };
type Endpoints = Pick<EdgeProps, "source" | "target" | "sourceX" | "sourceY" | "targetX" | "targetY" | "sourcePosition" | "targetPosition">;

/** Detour long horizontal links around intervening entities in bounded views. */
export function relationshipPath(edge: Endpoints, obstacles: Obstacle[]): [string, number, number] {
  const [path, labelX, labelY] = getBezierPath(edge);
  // Keep dense/vertical layouts on the standard renderer. This correction is
  // bounded to short investigations and does not change relationship direction.
  if (obstacles.length > 80 || edge.targetX - edge.sourceX < 240
      || Math.abs(edge.targetY - edge.sourceY) > 48) return [path, labelX, labelY];
  const between = obstacles.filter(node => node.id !== edge.source && node.id !== edge.target
    && node.x > edge.sourceX + 24 && node.x + node.width < edge.targetX - 24);
  const blocked = between.some(node => node.y - 16 <= Math.max(edge.sourceY, edge.targetY)
    && node.y + node.height + 16 >= Math.min(edge.sourceY, edge.targetY));
  if (!blocked) return [path, labelX, labelY];
  const lane = Math.min(edge.sourceY, edge.targetY, ...between.map(node => node.y)) - 40;
  const start = edge.sourceX + 32;
  const end = edge.targetX - 32;
  return [
    `M${edge.sourceX},${edge.sourceY} C${start},${edge.sourceY} ${start},${lane} ${start + 32},${lane} L${end - 32},${lane} C${end},${lane} ${end},${edge.targetY} ${edge.targetX},${edge.targetY}`,
    (edge.sourceX + edge.targetX) / 2, lane,
  ];
}
