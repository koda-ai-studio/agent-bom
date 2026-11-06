import { describe, expect, it } from "vitest";
import { Position } from "@xyflow/react";
import { relationshipPath } from "@/lib/relationship-routing";

const card = (id: string, x: number, y: number) => ({ id, x, y, width: 220, height: 224 });

describe("relationshipPath", () => {
  it("never sends a connection around the whole map to avoid the cards in its way", () => {
    // Three full rows between two cards one column apart: the only clear exterior corridor is beyond the grid.
    const obstacles = [card("source", 1480, 340), card("target", 1110, 1360)];
    for (let row = 1; row <= 3; row++) for (let column = 0; column < 7; column++) {
      if (column * 370 === 1480 && row === 1) continue;
      obstacles.push(card(`r${row}c${column}`, column * 370, row * 340));
    }
    const [path] = relationshipPath({
      source: "source", target: "target", sourceX: 1590, sourceY: 376, targetX: 1220, targetY: 1396,
      sourcePosition: Position.Left, targetPosition: Position.Top,
    }, obstacles);
    const xs = [...path.matchAll(/[MLQC ](-?\d+(?:\.\d+)?),/g)].map(match => Number(match[1]));
    expect(Math.min(...xs)).toBeGreaterThan(0);
    expect(Math.max(...xs)).toBeLessThan(6 * 370 + 220);
  });
});
