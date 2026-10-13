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
  it("keeps a diagonal relationship label clear of an intermediate entity", () => {
    const route = relationshipPath({ ...edge, sourceY: 170 }, [{ id: "intermediate", x: 260, y: 0, width: 220, height: 180 }]);
    expect(route[2]).toBeLessThan(-16);
  });
  it("preserves vertical and reverse-direction curves", () => {
    const obstacles = [{ id: "endpoint", x: 260, y: 0, width: 220, height: 180 }];
    const vertical = { ...edge, sourcePosition: Position.Bottom, targetPosition: Position.Top };
    expect(relationshipPath(vertical, obstacles)).toEqual(relationshipPath(vertical, []));
    const reverse = { ...edge, sourceX: 672, targetX: 72, sourcePosition: Position.Left, targetPosition: Position.Right };
    expect(relationshipPath(reverse, obstacles)).toEqual(relationshipPath(reverse, []));
  });
  it("excludes the relationship endpoints from obstacles", () => {
    expect(relationshipPath(edge, [{ id: "finding", x: 0, y: 0, width: 220, height: 180 }])[2]).toBe(36);
  });
});
