import { Position } from "@xyflow/react";
import type { AttackPathLayout } from "@/lib/attack-path-graph-layout";
import { BRANCH_DROP, BRANCH_INSET, GLYPH_CENTER_Y, glyphInsetX } from "@/lib/attack-path-graph-routes";

/** Which handles a link uses. A phone column joins neighbouring cards top to bottom and side columns from the side.
 * On a row, a forward link runs right-out to left-in and a backward link left-out to right-in; two cards of one
 * column join on their right rims, so the link is one curve beside the column rather than a hook round it. A forward
 * link between rows meets the upper card low on its rim. */
export function pathEdgeHandles(layout: Pick<AttackPathLayout, "direction" | "positions">, source: string, target: string) {
  const from = layout.positions.get(source)!, to = layout.positions.get(target)!;
  if (layout.direction === "TB") {
    if (from.x !== to.x) return { sourceHandle: from.x < to.x ? "context-right" : "context-left", targetHandle: from.x < to.x ? "context-left" : "context-right" };
    return { sourceHandle: from.y > to.y ? "reverse" : null, targetHandle: from.y > to.y ? "reverse" : null };
  }
  if (from.x === to.x && from.y !== to.y) return { sourceHandle: "side", targetHandle: "context" };
  // A forward link changing row leaves or enters the upper card low on its rim, so it never runs along that card's row line.
  if (from.x < to.x && from.y !== to.y) return from.y < to.y ? { sourceHandle: "branch", targetHandle: null } : { sourceHandle: null, targetHandle: "branch" };
  return { sourceHandle: from.x > to.x ? "context" : null, targetHandle: from.x > to.x ? "context" : null };
}

/** Every handle a card renders, declared up front so React Flow can draw links before it measures the cards. Each id
 * an edge names through pathEdgeHandles must be here, or React Flow drops that edge. */
export function declaredHandles(layout: Pick<AttackPathLayout, "direction" | "nodeWidth" | "nodeHeight">) {
  const inset = glyphInsetX(layout.nodeWidth);
  return layout.direction === "TB"
    ? [{ type: "target" as const, position: Position.Top, x: layout.nodeWidth / 2, y: 0, width: 1, height: 1, id: null },
      { type: "source" as const, position: Position.Bottom, x: layout.nodeWidth / 2, y: layout.nodeHeight, width: 1, height: 1, id: null },
      { type: "source" as const, position: Position.Top, x: layout.nodeWidth / 2, y: 0, width: 1, height: 1, id: "reverse" },
      { type: "target" as const, position: Position.Bottom, x: layout.nodeWidth / 2, y: layout.nodeHeight, width: 1, height: 1, id: "reverse" },
      ...([Position.Left, Position.Right] as const).flatMap(position => (["source", "target"] as const).map(type => ({ type, position,
        x: position === Position.Left ? inset : layout.nodeWidth - inset, y: GLYPH_CENTER_Y, width: 1, height: 1, id: `context-${position}` })))]
    : [{ type: "target" as const, position: Position.Left, x: inset, y: GLYPH_CENTER_Y, width: 1, height: 1, id: null },
      { type: "source" as const, position: Position.Right, x: layout.nodeWidth - inset, y: GLYPH_CENTER_Y, width: 1, height: 1, id: null },
      { type: "source" as const, position: Position.Left, x: inset, y: GLYPH_CENTER_Y, width: 1, height: 1, id: "context" },
      { type: "target" as const, position: Position.Right, x: layout.nodeWidth - inset, y: GLYPH_CENTER_Y, width: 1, height: 1, id: "context" },
      { type: "source" as const, position: Position.Right, x: layout.nodeWidth - inset, y: GLYPH_CENTER_Y, width: 1, height: 1, id: "side" },
      { type: "source" as const, position: Position.Right, x: layout.nodeWidth - inset - BRANCH_INSET(), y: GLYPH_CENTER_Y + BRANCH_DROP(), width: 1, height: 1, id: "branch" },
      { type: "target" as const, position: Position.Left, x: inset + BRANCH_INSET(), y: GLYPH_CENTER_Y + BRANCH_DROP(), width: 1, height: 1, id: "branch" }];
}
