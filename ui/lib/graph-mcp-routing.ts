import type { EdgeProps } from "@xyflow/react";
import { roundedRoute } from "@/lib/relationship-routing";

type Box = { x: number; y: number; width: number; height: number };
type Link = Pick<EdgeProps, "sourceX" | "sourceY" | "targetX" | "targetY">;

/** Bounded MCP branches in the shared right-angle style. The canonical arrow and evidence dash stay intact. */
export function mcpBranchPath(edge: Link, source: Box, target: Box, obstacles: Box[] = []): [string, number, number] | null {
  const { sourceX: sx, sourceY: sy, targetX: tx, targetY: ty } = edge;
  if (![sx, sy, tx, ty, source.x, source.y, source.width, target.x, target.y].every(Number.isFinite)
    || target.x <= source.x || tx <= sx) return null;
  const leave = source.x + source.width, arrive = target.x;
  const skipsAnEntity = obstacles.some(box => box.x >= leave && box.x + box.width <= arrive
    && box.y <= Math.max(sy, ty) && box.y + box.height >= Math.min(sy, ty));
  // A direct finding link bypasses the intermediate entities above their glyphs,
  // rather than sharing their ports or looping below the whole estate.
  const top = Math.min(source.y, target.y) - 64;
  const turn = Math.max(sx + 24, (leave + arrive) / 2);
  const points: [number, number][] = target.x - source.x > 500 && skipsAnEntity
    ? [[sx, sy], [Math.max(sx + 24, leave + 24), sy], [Math.max(sx + 24, leave + 24), top], [Math.min(tx - 24, arrive - 24), top], [Math.min(tx - 24, arrive - 24), ty], [tx, ty]]
    : [[sx, sy], [turn, sy], [turn, ty], [tx, ty]];
  for (let index = 1; index < points.length; index++) {
    const [ax, ay] = points[index - 1]!, [bx, by] = points[index]!;
    const steps = Math.max(1, Math.ceil(Math.hypot(bx - ax, by - ay) / 8));
    for (let step = 1; step < steps; step++) {
      const x = ax + (bx - ax) * step / steps, y = ay + (by - ay) * step / steps;
      // More complex topologies retain the shared obstacle-aware router.
      if (obstacles.some(box => x > box.x - 4 && x < box.x + box.width + 4 && y > box.y - 4 && y < box.y + box.height + 4)) return null;
    }
  }
  const middle = Math.floor((points.length - 1) / 2);
  const [mx, my] = points[middle]!, [nx, ny] = points[middle + 1]!;
  return [roundedRoute(points), (mx + nx) / 2, (my + ny) / 2];
}
