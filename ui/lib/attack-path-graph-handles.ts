import type { AttackPathLayout } from "@/lib/attack-path-graph-layout";

/** Which handles a link uses. A phone column joins neighbouring cards top to bottom and side columns from the side.
 * On a row, a forward link runs right-out to left-in and a backward link left-out to right-in; two cards of one
 * column join on their right rims, so the link is one curve beside the column rather than a hook round it. */
export function pathEdgeHandles(layout: Pick<AttackPathLayout, "direction" | "positions">, source: string, target: string) {
  const from = layout.positions.get(source)!, to = layout.positions.get(target)!;
  if (layout.direction === "TB") {
    if (from.x !== to.x) return { sourceHandle: from.x < to.x ? "context-right" : "context-left", targetHandle: from.x < to.x ? "context-left" : "context-right" };
    return { sourceHandle: from.y > to.y ? "reverse" : null, targetHandle: from.y > to.y ? "reverse" : null };
  }
  if (from.x === to.x && from.y !== to.y) return { sourceHandle: "side", targetHandle: "context" };
  return { sourceHandle: from.x > to.x ? "context" : null, targetHandle: from.x > to.x ? "context" : null };
}
