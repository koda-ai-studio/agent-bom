import type { EdgeProps } from "@xyflow/react";

type Box = { x: number; y: number; width: number; height: number };
type Link = Pick<EdgeProps, "sourceX" | "sourceY" | "targetX" | "targetY">;

/** Smooth bounded MCP branches. The canonical arrow and evidence dash stay intact. */
export function mcpBranchPath(edge: Link, source: Box, target: Box, obstacles: Box[] = []): [string, number, number] | null {
  const { sourceX: sx, sourceY: sy, targetX: tx, targetY: ty } = edge;
  if (![sx, sy, tx, ty, source.x, source.y, source.width, target.x, target.y].every(Number.isFinite)
    || target.x <= source.x || tx <= sx) return null;
  const span = tx - sx;
  const gap = target.x - source.x - source.width;
  const reach = Math.max(48, gap * 0.7);
  let c1x = Math.max(sx + span * 0.45, source.x + source.width + reach), c1y = sy;
  let c2x = Math.min(tx - span * 0.45, target.x - reach), c2y = ty;
  if (target.x - source.x > 500) {
    // A direct finding link bypasses the intermediate entities above their
    // glyphs, rather than sharing their ports or looping below the whole estate.
    const top = Math.min(source.y, target.y) - 64;
    c1x = sx + span * 0.22; c2x = tx - span * 0.22; c1y = c2y = top;
  }
  const point = (t: number) => {
    const u = 1 - t;
    return { x: u ** 3 * sx + 3 * u ** 2 * t * c1x + 3 * u * t ** 2 * c2x + t ** 3 * tx,
      y: u ** 3 * sy + 3 * u ** 2 * t * c1y + 3 * u * t ** 2 * c2y + t ** 3 * ty };
  };
  for (let step = 1; step < 64; step++) {
    const p = point(step / 64);
    // More complex topologies retain the shared obstacle-aware router.
    if (obstacles.some(box => p.x > box.x - 4 && p.x < box.x + box.width + 4
      && p.y > box.y - 4 && p.y < box.y + box.height + 4)) return null;
  }
  const mid = point(0.5);
  return [`M${sx},${sy} C${c1x},${c1y} ${c2x},${c2y} ${tx},${ty}`, mid.x, mid.y];
}
