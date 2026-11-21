import { Position } from "@xyflow/react";
import { describe, expect, it } from "vitest";
import { relationshipPath } from "@/lib/relationship-routing";

const pairs = (path: string) => {
  const numbers = path.match(/-?\d+(?:\.\d+)?/g)!.map(Number);
  return Array.from({ length: numbers.length / 2 }, (_, index) => ({ x: numbers[index * 2]!, y: numbers[index * 2 + 1]! }));
};

describe("relationship lanes", () => {
  it("does not leave a captioned card along the row a sibling edge already runs on", () => {
    // A wide caption under the glyph: the direct curve would cut through it, so the route exits beside it.
    const upper = { id: "agent", x: 0, y: 0, width: 300, height: 200 };
    const lower = { id: "server", x: 420, y: 420, width: 220, height: 200 };
    const edge = { source: "agent", target: "server", sourceX: 182, sourceY: 36, targetX: 494, targetY: 456,
      sourcePosition: Position.Right, targetPosition: Position.Left };
    const [path] = relationshipPath(edge, [upper, lower], { source: 14, target: -14 });
    const alongRow = pairs(path).filter(point => point.x > edge.sourceX + 4 && Math.abs(point.y - edge.sourceY) < 6);
    expect(alongRow).toEqual([]);
  });

  it("does not reach a lower card along the row its own sibling edge leaves on", () => {
    // Reverse direction: the lower card is the source and also has a same-row neighbour edge.
    const upper = { id: "server", x: 300, y: 0, width: 400, height: 200 };
    const lower = { id: "agent", x: 0, y: 420, width: 300, height: 200 };
    const edge = { source: "agent", target: "server", sourceX: 182, sourceY: 456, targetX: 472, targetY: 36,
      sourcePosition: Position.Right, targetPosition: Position.Left };
    const [path] = relationshipPath(edge, [upper, lower], { source: 14, target: -14 });
    expect(path).toContain("C");
    const alongRow = pairs(path).filter(point => point.x > edge.sourceX + 14 && Math.abs(point.y - edge.sourceY) < 6);
    expect(alongRow).toEqual([]);
  });

  it("keeps a detour lane clear of a card that only partly overlaps the corridor", () => {
    const edge = { source: "a", target: "b", sourceX: 72, sourceY: 36, targetX: 672, targetY: 36,
      sourcePosition: Position.Right, targetPosition: Position.Left };
    const between = { id: "between", x: 260, y: 0, width: 220, height: 180 };
    const partial = { id: "partial", x: 560, y: -200, width: 220, height: 180 };
    const [path, labelX, lane] = relationshipPath(edge, [between, partial, { id: "a", x: 0, y: 0, width: 144, height: 180 }, { id: "b", x: 600, y: 0, width: 144, height: 180 }]);
    const clear = (y: number, node: typeof partial) => y < node.y - 16 || y > node.y + node.height + 16;
    expect(labelX <= partial.x - 16 || labelX >= partial.x + partial.width + 16 || clear(lane, partial)).toBe(true);
    expect(labelX <= between.x - 16 || labelX >= between.x + between.width + 16 || clear(lane, between)).toBe(true);
    const values = path.match(/-?\d+(?:\.\d+)?(?:e[+-]?\d+)?/gi)!.map(Number);
    for (let index = 0; index < values.length - 2; index += 6) for (let step = 0; step <= 200; step++) {
      const t = step / 200, u = 1 - t;
      const [x, y] = [0, 1].map(axis => u ** 3 * values[index + axis]! + 3 * u ** 2 * t * values[index + axis + 2]!
        + 3 * u * t ** 2 * values[index + axis + 4]! + t ** 3 * values[index + axis + 6]!);
      expect([between, partial].some(box => x! > box.x - 12 && x! < box.x + box.width + 12 && y! > box.y - 12 && y! < box.y + box.height + 12)).toBe(false);
    }
  });
});
