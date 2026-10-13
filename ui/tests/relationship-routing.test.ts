import { Position } from "@xyflow/react";
import { describe, expect, it } from "vitest";
import { relationshipPath } from "@/lib/relationship-routing";

const edge = { source: "finding", target: "data", sourceX: 72, sourceY: 36, targetX: 672, targetY: 36,
  sourcePosition: Position.Right, targetPosition: Position.Left };

describe("relationship routing", () => {
  it("keeps an unobstructed relationship on its direct curve", () => {
    expect(relationshipPath(edge, [])[2]).toBe(36);
  });
  it("routes a long relationship and its label above an intervening entity", () => {
    const route = relationshipPath(edge, [{ id: "endpoint", x: 260, y: 0, width: 220, height: 180 }]);
    expect(route[2]).toBeLessThan(-16);
    expect(route[0]).toMatch(/^M72,36/);
    expect(route[0]).toMatch(/672,36$/);
  });
  it("excludes the relationship endpoints from obstacles", () => {
    expect(relationshipPath(edge, [{ id: "finding", x: 0, y: 0, width: 220, height: 180 }])[2]).toBe(36);
  });
});
